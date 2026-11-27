package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ssl-center/internal/config"
	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

type mockMaint struct {
	mu          sync.Mutex
	active      bool
	beginCount  int
	endCount    int
}

func (m *mockMaint) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

func (m *mockMaint) IsActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *mockMaint) BeginMaintenance(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return errors.New("already active")
	}
	m.active = true
	m.beginCount++
	return nil
}

func (m *mockMaint) EndMaintenance() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active = false
	m.endCount++
}

func (m *mockMaint) RegisterSchedulerHook(pause, resume func()) {}

type mockReloader struct {
	mu           sync.Mutex
	reloadCalls  int
	inspectCalls int
}

func (r *mockReloader) ReloadSchedule(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reloadCalls++
	return nil
}

func (r *mockReloader) TriggerInspectNow(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inspectCalls++
	return nil
}

func setupBackupEnv(t *testing.T) (*configEnv, *Service) {
	t.Helper()
	dataDir := t.TempDir()
	c := &config.Config{
		DataDir: dataDir,
		TZ:      "UTC",
	}
	if err := c.EnsureDataDirs(); err != nil {
		t.Fatal(err)
	}
	key, _, err := crypto.LoadOrCreateMasterKey(c.MasterKeyPath())
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(c.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	redactor := crypto.NewSecretRedactor()
	maint := &mockMaint{}
	reloader := &mockReloader{}
	svc := NewService(c, database, cipher, redactor, maint, reloader)
	return &configEnv{
		cfgObj:   c,
		db:       database,
		cipher:   cipher,
		redactor: redactor,
		maint:    maint,
		reloader: reloader,
		key:      key,
	}, svc
}

type configEnv struct {
	cfgObj   *config.Config
	db       *db.DB
	cipher   *crypto.Cipher
	redactor *crypto.SecretRedactor
	maint    *mockMaint
	reloader *mockReloader
	key      []byte
}

func TestBackupExportAndFullRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Instance A: populate encrypted records, cert files, sessions
	envA, svcA := setupBackupEnv(t)

	acmeKeySecret := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIExampleSecretKeyMaterial123456\n-----END EC PRIVATE KEY-----"
	cfToken := "cf-live-backup-secret-token"
	sshKeySecret := "ssh-private-key-material-backup"
	whSecret := "webhook-hmac-backup-secret"

	encACME, _ := envA.cipher.Encrypt(acmeKeySecret, "ca_accounts:acme_key_enc")
	encDNS, _ := envA.cipher.Encrypt(`{"api_token":"`+cfToken+`"}`, "dns_credentials:config_enc")
	encSSH, _ := envA.cipher.Encrypt(sshKeySecret, "hosts:ssh_private_key_enc")
	encWHSec, _ := envA.cipher.Encrypt(whSecret, "webhooks:secret_enc")

	ca := &model.CAAccount{
		Name: "LE Prod", Provider: model.CAProviderLetsEncrypt, Environment: model.CAEnvProduction,
		Email: "ops@example.com", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		ACMEKeyEnc: encACME, IsDefault: true,
	}
	if _, err := envA.db.CreateCAAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}
	dns := &model.DNSCredential{Name: "CF", Provider: model.DNSProviderCloudflare, ConfigEnc: encDNS}
	if _, err := envA.db.CreateDNSCredential(ctx, dns); err != nil {
		t.Fatal(err)
	}
	host := &model.Host{
		Name: "Edge", Mode: model.HostModeSSH, Host: "10.1.1.1", SSHPrivateKeyEnc: encSSH,
	}
	if _, err := envA.db.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	wh := &model.Webhook{Name: "Ops", URL: "https://hooks.example.com", SecretEnc: encWHSec, Enabled: true}
	if _, err := envA.db.CreateWebhook(ctx, wh); err != nil {
		t.Fatal(err)
	}
	cert := &model.Certificate{
		Name: "Wildcard", Domain: "*.example.com", CAAccountID: ca.ID, DNSCredentialID: dns.ID,
		CertDir: envA.cfgObj.CertDir(1),
	}
	if _, err := envA.db.CreateCertificate(ctx, cert); err != nil {
		t.Fatal(err)
	}

	// Write cert files on disk
	certDir := envA.cfgObj.CertDir(cert.ID)
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "fullchain.pem"), []byte("FULLCHAIN_DATA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "privkey.pem"), []byte("PRIVKEY_DATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create live session in A
	if err := envA.db.CreateSession(ctx, &model.Session{
		ID: "sess-live-a", CSRFToken: "csrf-a", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Export backup from A
	var archiveBuf bytes.Buffer
	if err := svcA.ExportBackup(ctx, &archiveBuf); err != nil {
		t.Fatalf("ExportBackup: %v", err)
	}

	// Live session in A must still exist after export
	if _, err := envA.db.GetSession(ctx, "sess-live-a"); err != nil {
		t.Fatalf("live session lost after export: %v", err)
	}

	// Verify archive contents: manifest.json, master.key, app.db (0 sessions), certs/
	extractedTmp := t.TempDir()
	hashes, err := extractArchiveSafely(bytes.NewReader(archiveBuf.Bytes()), extractedTmp, DefaultMaxBackupBytes)
	if err != nil {
		t.Fatalf("extractArchiveSafely: %v", err)
	}
	for _, required := range []string{"manifest.json", "master.key", "app.db", "certs/cert_1/fullchain.pem", "certs/cert_1/privkey.pem"} {
		if _, ok := hashes[required]; !ok {
			t.Fatalf("exported archive missing %q; got keys=%v", required, hashes)
		}
	}
	expSQL, err := sql.Open("sqlite", filepath.Join(extractedTmp, "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	var expSessCount int
	_ = expSQL.QueryRow("SELECT COUNT(*) FROM sessions").Scan(&expSessCount)
	_ = expSQL.Close()
	if expSessCount != 0 {
		t.Fatalf("exported app.db sessions = %d, want 0", expSessCount)
	}

	// Instance B: fresh instance with different master.key and an active session
	envB, svcB := setupBackupEnv(t)
	if err := envB.db.CreateSession(ctx, &model.Session{
		ID: "sess-live-b", CSRFToken: "csrf-b", ExpiresAt: time.Now().UTC().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := svcB.RestoreBackup(ctx, bytes.NewReader(archiveBuf.Bytes()), DefaultMaxBackupBytes, "127.0.0.1")
	if err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}
	if !res.ReloginRequired || res.PreRestoreDir == "" {
		t.Fatalf("unexpected RestoreResult: %+v", res)
	}
	if envB.maint.IsActive() || envB.maint.beginCount != 1 || envB.maint.endCount != 1 {
		t.Fatalf("unexpected maintenance lock state: %+v", envB.maint)
	}
	if envB.reloader.reloadCalls != 1 {
		t.Fatalf("expected ScheduleReloader.ReloadSchedule called once, got %d", envB.reloader.reloadCalls)
	}

	// pre_restore dir must contain old master.key and app.db
	if _, err := os.Stat(filepath.Join(res.PreRestoreDir, "master.key")); err != nil {
		t.Fatalf("pre_restore missing master.key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(res.PreRestoreDir, "app.db")); err != nil {
		t.Fatalf("pre_restore missing app.db: %v", err)
	}

	// Live sessions in B must be cleared
	if _, err := envB.db.GetSession(ctx, "sess-live-b"); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("expected sess-live-b cleared after restore, got %v", err)
	}

	// Master key permissions must be 0600
	mkInfo, err := os.Stat(envB.cfgObj.MasterKeyPath())
	if err != nil || mkInfo.Mode().Perm() != 0o600 {
		t.Fatalf("restored master.key mode = %v, err=%v", mkInfo.Mode().Perm(), err)
	}

	// Cipher in B must now decrypt restored rows from A!
	gotCert, err := envB.db.GetCertificate(ctx, cert.ID)
	if err != nil || gotCert.Domain != "*.example.com" {
		t.Fatalf("restored cert missing: (%+v, %v)", gotCert, err)
	}
	gotDNS, err := envB.db.GetDNSCredential(ctx, dns.ID)
	if err != nil {
		t.Fatal(err)
	}
	decDNS, err := envB.cipher.Decrypt(gotDNS.ConfigEnc, "dns_credentials:config_enc")
	if err != nil || !strings.Contains(decDNS, cfToken) {
		t.Fatalf("reloaded cipher failed to decrypt restored DNS config: (%q, %v)", decDNS, err)
	}

	// Redactor in B must be hydrated with restored secrets
	redacted := envB.redactor.Redact("token=" + cfToken + " wh=" + whSecret)
	if strings.Contains(redacted, cfToken) || strings.Contains(redacted, whSecret) {
		t.Fatalf("restored SecretRedactor did not redact secrets: %q", redacted)
	}

	// Restored cert files on disk
	fc, err := os.ReadFile(filepath.Join(envB.cfgObj.CertDir(cert.ID), "fullchain.pem"))
	if err != nil || string(fc) != "FULLCHAIN_DATA" {
		t.Fatalf("restored fullchain.pem = (%q, %v)", string(fc), err)
	}

	// PruneLogs integration on restored DB
	_, _ = envB.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType: "old.evt", Message: "old", CreatedAt: time.Now().UTC().AddDate(0, 0, -60),
	})
	pruneRes, err := envB.db.PruneLogs(ctx, 30, 5000)
	if err != nil || pruneRes.AuditEventsDeleted != 1 {
		t.Fatalf("PruneLogs after restore = (%+v, %v)", pruneRes, err)
	}
}

func TestRestoreRejectsTarSlipSymlinkBadChecksumAndWrongKey(t *testing.T) {
	ctx := context.Background()
	env, svc := setupBackupEnv(t)

	// Add a record so we can verify wrong-key rejection and live data preservation
	encDNS, _ := env.cipher.Encrypt(`{"api_token":"live-token-keep"}`, "dns_credentials:config_enc")
	if _, err := env.db.CreateDNSCredential(ctx, &model.DNSCredential{
		Name: "KeepMe", Provider: model.DNSProviderCloudflare, ConfigEnc: encDNS,
	}); err != nil {
		t.Fatal(err)
	}

	var validArchive bytes.Buffer
	if err := svc.ExportBackup(ctx, &validArchive); err != nil {
		t.Fatal(err)
	}

	// 1. Tar-Slip (../evil)
	slipArchive := buildCustomTarGz(t, []tarEntry{
		{name: "../evil.txt", typeflag: tar.TypeReg, data: []byte("pwn")},
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(slipArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("expected tar-slip rejection, got %v", err)
	}

	// 2. Absolute path (/etc/passwd)
	absArchive := buildCustomTarGz(t, []tarEntry{
		{name: "/etc/passwd", typeflag: tar.TypeReg, data: []byte("root:x:0:0")},
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(absArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected absolute path rejection, got %v", err)
	}

	// 3. Symlink rejection
	symArchive := buildCustomTarGz(t, []tarEntry{
		{name: "certs/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(symArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "forbidden tar entry type") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}

	// 4. Hardlink rejection
	linkArchive := buildCustomTarGz(t, []tarEntry{
		{name: "certs/hard", typeflag: tar.TypeLink, linkname: "master.key"},
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(linkArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "forbidden tar entry type") {
		t.Fatalf("expected hardlink rejection, got %v", err)
	}

	// 5. Corrupted SHA-256 in manifest.json
	corruptArchive := mutateTarArchive(t, validArchive.Bytes(), func(entries []tarEntry) []tarEntry {
		for i := range entries {
			if entries[i].name == "manifest.json" {
				var m model.BackupManifest
				_ = json.Unmarshal(entries[i].data, &m)
				m.Files["app.db"] = strings.Repeat("0", 64)
				entries[i].data, _ = json.Marshal(m)
			}
		}
		return entries
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(corruptArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch rejection, got %v", err)
	}

	// 6. Wrong master.key (manifest SHA-256 updated to match wrong key, but test-decrypt must fail!)
	wrongKey := bytes.Repeat([]byte{0x42}, crypto.MasterKeySize)
	wrongKeyArchive := mutateTarArchive(t, validArchive.Bytes(), func(entries []tarEntry) []tarEntry {
		sum := sha256.Sum256(wrongKey)
		wrongHex := hex.EncodeToString(sum[:])
		for i := range entries {
			if entries[i].name == "master.key" {
				entries[i].data = wrongKey
			}
			if entries[i].name == "manifest.json" {
				var m model.BackupManifest
				_ = json.Unmarshal(entries[i].data, &m)
				m.Files["master.key"] = wrongHex
				entries[i].data, _ = json.Marshal(m)
			}
		}
		return entries
	})
	if _, err := svc.RestoreBackup(ctx, bytes.NewReader(wrongKeyArchive), DefaultMaxBackupBytes, ""); err == nil || !strings.Contains(err.Error(), "cannot decrypt") {
		t.Fatalf("expected wrong master.key test-decrypt rejection, got %v", err)
	}

	// Verify live DB and maintenance lock untouched after all failed restores
	if env.maint.IsActive() || env.maint.beginCount != 0 {
		t.Fatalf("failed validation should never engage maintenance mode: %+v", env.maint)
	}
	list, err := env.db.ListDNSCredentials(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "KeepMe" {
		t.Fatalf("live DB was altered by rejected restores: (%+v, %v)", list, err)
	}
}

type tarEntry struct {
	name     string
	typeflag byte
	linkname string
	data     []byte
}

func buildCustomTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Linkname: e.linkname,
			Mode:     0o644,
			Size:     int64(len(e.data)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func mutateTarArchive(t *testing.T, raw []byte, fn func([]tarEntry) []tarEntry) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var entries []tarEntry
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		entries = append(entries, tarEntry{
			name:     hdr.Name,
			typeflag: hdr.Typeflag,
			linkname: hdr.Linkname,
			data:     data,
		})
	}
	_ = gz.Close()
	return buildCustomTarGz(t, fn(entries))
}
