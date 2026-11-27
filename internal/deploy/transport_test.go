package deploy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/deploy"
	"ssl-center/internal/model"
)

var hostSeq atomic.Int64

func setupTestDBAndCrypto(t *testing.T) (*db.DB, *crypto.Cipher, *crypto.SecretRedactor) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	key := bytes.Repeat([]byte{0x42}, crypto.MasterKeySize)
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	redactor := crypto.NewSecretRedactor()
	return database, cipher, redactor
}

func createSSHTestHost(t *testing.T, database *db.DB, cipher *crypto.Cipher, srv *mockSSHServer, authType, privKey, passphrase, password, policy, fp string) *model.Host {
	t.Helper()
	var err error
	var privEnc, passEnc, pwdEnc string
	if privKey != "" {
		privEnc, err = cipher.Encrypt(privKey, "hosts:ssh_private_key_enc")
		if err != nil {
			t.Fatal(err)
		}
	}
	if passphrase != "" {
		passEnc, err = cipher.Encrypt(passphrase, "hosts:ssh_passphrase_enc")
		if err != nil {
			t.Fatal(err)
		}
	}
	if password != "" {
		pwdEnc, err = cipher.Encrypt(password, "hosts:ssh_password_enc")
		if err != nil {
			t.Fatal(err)
		}
	}
	h := &model.Host{
		Name:               fmt.Sprintf("mock-ssh-%s-%d", t.Name(), hostSeq.Add(1)),
		Mode:               model.HostModeSSH,
		Host:               srv.addr,
		Port:               srv.port,
		Username:           "root",
		AuthType:           authType,
		SSHPrivateKeyEnc:   privEnc,
		SSHPassphraseEnc:   passEnc,
		SSHPasswordEnc:     pwdEnc,
		HostKeyPolicy:      policy,
		HostKeyFingerprint: fp,
		CaddyEnabled:       true,
		CaddyContainer:     "caddy",
	}
	if _, err := database.CreateHost(context.Background(), h); err != nil {
		t.Fatalf("create host: %v", err)
	}
	return h
}

func TestSSHTransport_AtomicWriteModesAndAuth(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	privPEM, pubKey := generateClientSSHKeyPair(t, "pass-secret-123")
	srv := newMockSSHServer(t, pubKey, "root-pw-secret-999")
	tr := deploy.NewTransport(database, cipher, redactor, nil)

	hostKeyAuth := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "pass-secret-123", "", model.HostKeyPolicyTOFU, "")
	hostPassAuth := createSSHTestHost(t, database, cipher, srv, model.HostAuthPassword, "", "", "root-pw-secret-999", model.HostKeyPolicyInsecure, "")

	targetDir := filepath.Join(t.TempDir(), "nested", "certs")
	fullchainPath := filepath.Join(targetDir, "fullchain.pem")
	privkeyPath := filepath.Join(targetDir, "privkey.pem")

	// 1. Atomic write cert (0644) and key (0600) with key+passphrase auth
	if err := tr.WriteFileAtomic(ctx, hostKeyAuth, fullchainPath, []byte("CERT-V1"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic fullchain: %v", err)
	}
	if err := tr.WriteFileAtomic(ctx, hostKeyAuth, privkeyPath, []byte("KEY-V1"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic privkey: %v", err)
	}

	fiCert, err := os.Stat(fullchainPath)
	if err != nil {
		t.Fatal(err)
	}
	if fiCert.Mode().Perm() != 0o644 {
		t.Fatalf("fullchain mode = %o, want 0644", fiCert.Mode().Perm())
	}
	fiKey, err := os.Stat(privkeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fiKey.Mode().Perm() != 0o600 {
		t.Fatalf("privkey mode = %o, want 0600", fiKey.Mode().Perm())
	}

	// 2. Atomic overwrite existing file via password auth
	if err := tr.WriteFileAtomic(ctx, hostPassAuth, fullchainPath, []byte("CERT-V2"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic overwrite: %v", err)
	}
	got, err := tr.ReadFile(ctx, hostKeyAuth, fullchainPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "CERT-V2" {
		t.Fatalf("ReadFile = %q, want CERT-V2", string(got))
	}

	// Ensure no leftover temp files remain in targetDir
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 files in %s, got %d", targetDir, len(entries))
	}

	// 3. RemoveFile
	if err := tr.RemoveFile(ctx, hostKeyAuth, fullchainPath); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}
	if _, err := tr.ReadFile(ctx, hostKeyAuth, fullchainPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist after RemoveFile, got %v", err)
	}
}

func TestSSHTransport_PosixRenameFallback(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	privPEM, pubKey := generateClientSSHKeyPair(t, "")
	srv := newMockSSHServer(t, pubKey, "")
	srv.SetDisablePosixRename(true)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	tr := deploy.NewTransport(database, cipher, redactor, logger)

	host := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyInsecure, "")

	// Write initial file into in-memory SFTP server
	if err := tr.WriteFileAtomic(ctx, host, "/etc/caddy/certs/fullchain.pem", []byte("INITIAL"), 0o644); err != nil {
		t.Fatalf("initial WriteFileAtomic: %v", err)
	}
	// Overwrite existing file -> PosixRename returns ErrSSHFxOpUnsupported -> fallback Remove+Rename
	if err := tr.WriteFileAtomic(ctx, host, "/etc/caddy/certs/fullchain.pem", []byte("REPLACED"), 0o644); err != nil {
		t.Fatalf("fallback WriteFileAtomic overwrite: %v", err)
	}

	got, err := tr.ReadFile(ctx, host, "/etc/caddy/certs/fullchain.pem")
	if err != nil {
		t.Fatalf("ReadFile after fallback: %v", err)
	}
	if string(got) != "REPLACED" {
		t.Fatalf("content = %q, want REPLACED", string(got))
	}
	if !strings.Contains(logBuf.String(), "posix-rename unsupported") {
		t.Fatalf("expected fallback warning in log, got: %s", logBuf.String())
	}
}

func TestSSHTransport_WriteFileInPlacePreservesInode(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	privPEM, pubKey := generateClientSSHKeyPair(t, "")
	srv := newMockSSHServer(t, pubKey, "")
	tr := deploy.NewTransport(database, cipher, redactor, nil)
	host := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyInsecure, "")

	target := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(target, []byte("old config"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	beforeIno := beforeInfo.Sys().(*syscall.Stat_t).Ino

	if err := tr.WriteFileInPlace(ctx, host, target, []byte("new config content")); err != nil {
		t.Fatalf("WriteFileInPlace: %v", err)
	}
	afterInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	afterIno := afterInfo.Sys().(*syscall.Stat_t).Ino

	if beforeIno != afterIno {
		t.Fatalf("inode changed: before=%d after=%d", beforeIno, afterIno)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new config content" {
		t.Fatalf("content = %q, want new config content", string(got))
	}
}

func TestSSHTransport_HostKeyPolicies(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	privPEM, pubKey := generateClientSSHKeyPair(t, "")
	srv := newMockSSHServer(t, pubKey, "")
	srv.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		switch {
		case strings.Contains(cmd, "docker info"):
			return "26.1.0\n", "", 0
		case strings.Contains(cmd, "docker inspect"):
			return "true\n", "", 0
		case strings.Contains(cmd, "caddy version"):
			return "v2.8.4\n", "", 0
		default:
			return "ok", "", 0
		}
	})

	tr := deploy.NewTransport(database, cipher, redactor, nil)

	// 1. TOFU: first connection pins fingerprint to DB
	tofuHost := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyTOFU, "")
	res1, err := tr.TestConnection(ctx, tofuHost)
	if err != nil {
		t.Fatalf("TestConnection 1: %v", err)
	}
	if !res1.SSHOK || !res1.DockerOK || !res1.CaddyRunning || res1.HostKeyStatus != "pinned" {
		t.Fatalf("unexpected first TOFU test result: %+v", res1)
	}
	if res1.HostKeyFingerprint != srv.HostFingerprint() {
		t.Fatalf("pinned fp = %q, want %q", res1.HostKeyFingerprint, srv.HostFingerprint())
	}

	persisted, err := database.GetHost(ctx, tofuHost.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.HostKeyFingerprint != srv.HostFingerprint() {
		t.Fatalf("DB fp = %q, want %q", persisted.HostKeyFingerprint, srv.HostFingerprint())
	}

	// Second TOFU connection succeeds with status "trusted"
	res2, err := tr.TestConnection(ctx, persisted)
	if err != nil {
		t.Fatalf("TestConnection 2: %v", err)
	}
	if !res2.SSHOK || res2.HostKeyStatus != "trusted" {
		t.Fatalf("unexpected second TOFU test result: %+v", res2)
	}

	// Rotate server host key -> TOFU must reject Exec with ErrHostKeyMismatch and log audit event
	newFP := srv.RotateHostKey()
	_, execErr := tr.Exec(ctx, persisted, "echo hi")
	if !errors.Is(execErr, deploy.ErrHostKeyMismatch) {
		t.Fatalf("expected ErrHostKeyMismatch after key rotation, got %v", execErr)
	}

	res3, err := tr.TestConnection(ctx, persisted)
	if err != nil {
		t.Fatalf("TestConnection after rotation: %v", err)
	}
	if res3.SSHOK || res3.HostKeyStatus != "changed" || res3.HostKeyFingerprint != newFP {
		t.Fatalf("expected changed host key result, got %+v", res3)
	}

	events, err := database.ListRecentAuditEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	foundAudit := false
	for _, ev := range events {
		if ev.EventType == "host.host_key_mismatch" && ev.TargetID != nil && *ev.TargetID == tofuHost.ID {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Fatalf("expected host.host_key_mismatch audit event, got %+v", events)
	}

	// 2. Strict policy: empty fingerprint rejected; matching succeeds; mismatch rejected
	strictEmpty := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyStrict, "")
	if _, err := tr.Exec(ctx, strictEmpty, "echo hi"); !errors.Is(err, deploy.ErrHostKeyMissing) {
		t.Fatalf("expected ErrHostKeyMissing for strict empty fp, got %v", err)
	}

	strictGood := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyStrict, newFP)
	execRes, err := tr.Exec(ctx, strictGood, "echo ok")
	if err != nil || execRes.ExitCode != 0 {
		t.Fatalf("strict matching fp failed: res=%+v err=%v", execRes, err)
	}

	// 3. Insecure policy allows rotated key
	insecureHost := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyInsecure, "SHA256:stale")
	srv.RotateHostKey()
	execRes2, err := tr.Exec(ctx, insecureHost, "echo ok")
	if err != nil || execRes2.ExitCode != 0 {
		t.Fatalf("insecure host failed: res=%+v err=%v", execRes2, err)
	}
}

func TestSSHTransport_ExecWithStdinAndRedaction(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	secretPass := "super-secret-ssh-pass-42"
	srv := newMockSSHServer(t, nil, secretPass)
	srv.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		return "out:" + string(stdin) + ":" + secretPass, "err:" + secretPass, 2
	})

	tr := deploy.NewTransport(database, cipher, redactor, nil)
	host := createSSHTestHost(t, database, cipher, srv, model.HostAuthPassword, "", "", secretPass, model.HostKeyPolicyInsecure, "")

	res, err := tr.ExecWithStdin(ctx, host, "caddy fmt -", []byte("stdin-data"))
	if err != nil {
		t.Fatalf("ExecWithStdin: %v", err)
	}
	if res.ExitCode != 2 {
		t.Fatalf("ExitCode = %d, want 2", res.ExitCode)
	}
	if strings.Contains(res.Stdout, secretPass) || strings.Contains(res.Stderr, secretPass) {
		t.Fatalf("secret leaked in command output: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "stdin-data") || !strings.Contains(res.Stdout, crypto.RedactedPlaceholder) {
		t.Fatalf("unexpected redacted stdout: %q", res.Stdout)
	}
}

func TestLocalTransport_OperationsAndInode(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)
	tr := deploy.NewTransport(database, cipher, redactor, nil)

	localHost, err := database.GetLocalHost(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Disable Caddy check for unit test so missing docker binary doesn't affect file ops
	localHost.CaddyEnabled = false

	testRes, err := tr.TestConnection(ctx, localHost)
	if err != nil || !testRes.SSHOK || testRes.HostKeyStatus != "local" {
		t.Fatalf("local TestConnection = %+v, err=%v", testRes, err)
	}

	dir := t.TempDir()
	f1 := filepath.Join(dir, "sub", "privkey.pem")
	if err := tr.WriteFileAtomic(ctx, localHost, f1, []byte("KEY1"), 0o600); err != nil {
		t.Fatalf("local WriteFileAtomic: %v", err)
	}
	fi, _ := os.Stat(f1)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("local mode = %o, want 0600", fi.Mode().Perm())
	}

	ino1 := fi.Sys().(*syscall.Stat_t).Ino
	if err := tr.WriteFileInPlace(ctx, localHost, f1, []byte("KEY2")); err != nil {
		t.Fatalf("local WriteFileInPlace: %v", err)
	}
	fi2, _ := os.Stat(f1)
	ino2 := fi2.Sys().(*syscall.Stat_t).Ino
	if ino1 != ino2 {
		t.Fatalf("local inode changed: %d -> %d", ino1, ino2)
	}

	data, err := tr.ReadFile(ctx, localHost, f1)
	if err != nil || string(data) != "KEY2" {
		t.Fatalf("local ReadFile = %q, err=%v", string(data), err)
	}

	redactor.Add("local-secret-token-xyz")
	execRes, err := tr.ExecWithStdin(ctx, localHost, "cat; echo local-secret-token-xyz >&2", []byte("hello-local"))
	if err != nil {
		t.Fatalf("local ExecWithStdin: %v", err)
	}
	if execRes.ExitCode != 0 || execRes.Stdout != "hello-local" {
		t.Fatalf("unexpected local exec stdout: %+v", execRes)
	}
	if strings.Contains(execRes.Stderr, "local-secret-token-xyz") {
		t.Fatalf("local secret leaked in stderr: %q", execRes.Stderr)
	}

	if err := tr.RemoveFile(ctx, localHost, f1); err != nil {
		t.Fatalf("local RemoveFile: %v", err)
	}
}

func TestSSHTransport_DockerInfoEmptyStdoutWithZeroExitMarksUnavailable(t *testing.T) {
	ctx := context.Background()
	database, cipher, redactor := setupTestDBAndCrypto(t)

	privPEM, pubKey := generateClientSSHKeyPair(t, "")
	srv := newMockSSHServer(t, pubKey, "")
	srv.SetExecHandler(func(cmd string, stdin []byte) (string, string, int) {
		if strings.Contains(cmd, "docker info") {
			return "\n", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock.", 0
		}
		return "", "", 1
	})

	tr := deploy.NewTransport(database, cipher, redactor, nil)
	host := createSSHTestHost(t, database, cipher, srv, model.HostAuthKey, privPEM, "", "", model.HostKeyPolicyInsecure, "")

	res, err := tr.TestConnection(ctx, host)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if !res.SSHOK {
		t.Fatalf("expected SSHOK=true, got %+v", res)
	}
	if res.DockerOK || res.CaddyRunning {
		t.Fatalf("expected DockerOK=false and CaddyRunning=false, got %+v", res)
	}
	if !strings.Contains(res.Message, "Docker unavailable") || strings.Contains(res.Message, "Docker OK") {
		t.Fatalf("unexpected message: %q", res.Message)
	}
}
