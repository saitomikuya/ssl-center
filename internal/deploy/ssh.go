package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	pathpkg "path"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"ssl-center/internal/model"
)

type sshConnectInfo struct {
	observedFP    string
	hostKeyStatus string
	mismatchErr   error
}

func (t *Transport) testSSHConnection(ctx context.Context, host *model.Host) (*model.HostTestResult, error) {
	res := &model.HostTestResult{}
	caddyStatus := model.CaddyStatusUnknown

	client, info, cleanup, err := t.dialSSH(ctx, host)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		res.SSHOK = false
		res.HostKeyFingerprint = info.observedFP
		if errors.Is(err, ErrHostKeyMismatch) || errors.Is(err, ErrHostKeyMissing) {
			res.HostKeyStatus = "changed"
		}
		res.Message = t.redact(err.Error())
		t.persistCheckResult(ctx, host, false, res.Message, caddyStatus)
		return res, nil
	}
	defer client.Close()

	res.SSHOK = true
	res.HostKeyFingerprint = info.observedFP
	res.HostKeyStatus = info.hostKeyStatus

	if !host.CaddyEnabled {
		res.Message = "SSH connection succeeded"
		t.persistCheckResult(ctx, host, true, res.Message, caddyStatus)
		return res, nil
	}

	container := strings.TrimSpace(host.CaddyContainer)
	if container == "" {
		container = "caddy"
	}
	if err := model.ValidateContainerName(container); err != nil {
		res.Message = t.redact(fmt.Sprintf("SSH connection succeeded; invalid Caddy container name: %v", err))
		t.persistCheckResult(ctx, host, true, res.Message, caddyStatus)
		return res, nil
	}

	infoRes, infoErr := t.execOnSSHClient(ctx, client, "docker info --format '{{.ServerVersion}}'", nil)
	if infoErr == nil && infoRes != nil && infoRes.ExitCode == 0 {
		res.DockerOK = true
		inspectCmd := fmt.Sprintf("docker inspect --format '{{.State.Running}}' %s", model.ShellQuote(container))
		inspectRes, inspectErr := t.execOnSSHClient(ctx, client, inspectCmd, nil)
		if inspectErr == nil && inspectRes != nil && inspectRes.ExitCode == 0 {
			running := strings.EqualFold(strings.TrimSpace(inspectRes.Stdout), "true")
			res.CaddyRunning = running
			if running {
				caddyStatus = model.CaddyStatusRunning
				verCmd := fmt.Sprintf("docker exec %s caddy version", model.ShellQuote(container))
				if verRes, verErr := t.execOnSSHClient(ctx, client, verCmd, nil); verErr == nil && verRes != nil && verRes.ExitCode == 0 {
					res.CaddyVersion = strings.TrimSpace(verRes.Stdout)
				}
				res.Message = "SSH OK; Docker OK; Caddy container running"
			} else {
				caddyStatus = model.CaddyStatusStopped
				res.Message = fmt.Sprintf("SSH OK; Docker OK; Caddy container %q is stopped", container)
			}
		} else {
			caddyStatus = model.CaddyStatusUnknown
			detail := ""
			if inspectRes != nil {
				detail = strings.TrimSpace(firstNonEmpty(inspectRes.Stderr, inspectRes.Stdout))
			}
			res.Message = fmt.Sprintf("SSH OK; Docker OK; Caddy container %q inspect failed: %s", container, detail)
		}
	} else {
		detail := ""
		if infoErr != nil {
			detail = infoErr.Error()
		} else if infoRes != nil {
			detail = strings.TrimSpace(firstNonEmpty(infoRes.Stderr, infoRes.Stdout))
		}
		res.Message = fmt.Sprintf("SSH OK; Docker unavailable: %s", detail)
	}

	res.Message = t.redact(res.Message)
	t.persistCheckResult(ctx, host, true, res.Message, caddyStatus)
	return res, nil
}

func (t *Transport) readSSHFile(ctx context.Context, host *model.Host, filePath string) ([]byte, error) {
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, t.redactErr(fmt.Errorf("open sftp session: %w", err))
	}
	defer sc.Close()

	clean := pathpkg.Clean(filePath)
	f, err := sc.Open(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("open remote file %s: %w", t.redact(clean), os.ErrNotExist)
		}
		return nil, t.redactErr(fmt.Errorf("open remote file %s: %w", clean, err))
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, t.redactErr(fmt.Errorf("read remote file %s: %w", clean, err))
	}
	return data, nil
}

func (t *Transport) writeSSHFileAtomic(ctx context.Context, host *model.Host, filePath string, data []byte, mode uint32) error {
	client, _, cleanupSecrets, err := t.dialSSH(ctx, host)
	if cleanupSecrets != nil {
		defer cleanupSecrets()
	}
	if err != nil {
		return err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return t.redactErr(fmt.Errorf("open sftp session: %w", err))
	}
	defer sc.Close()

	clean := pathpkg.Clean(filePath)
	dir := pathpkg.Dir(clean)
	if dir != "." && dir != "/" {
		if err := sc.MkdirAll(dir); err != nil {
			return t.redactErr(fmt.Errorf("sftp mkdir %s: %w", dir, err))
		}
	}

	tmpPath := pathpkg.Join(dir, fmt.Sprintf(".%s.tmp.%s", pathpkg.Base(clean), randomHex(8)))
	cleanup := true
	defer func() {
		if cleanup {
			_ = sc.Remove(tmpPath)
		}
	}()

	f, err := sc.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return t.redactErr(fmt.Errorf("sftp create temp file %s: %w", tmpPath, err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return t.redactErr(fmt.Errorf("sftp write temp file %s: %w", tmpPath, err))
	}
	if err := f.Close(); err != nil {
		return t.redactErr(fmt.Errorf("sftp close temp file %s: %w", tmpPath, err))
	}

	perm := os.FileMode(mode) & os.ModePerm
	if perm == 0 {
		perm = 0o644
	}
	if err := sc.Chmod(tmpPath, perm); err != nil {
		return t.redactErr(fmt.Errorf("sftp chmod %s: %w", tmpPath, err))
	}

	if err := sc.PosixRename(tmpPath, clean); err != nil {
		if !isUnsupportedSFTPOp(err) {
			return t.redactErr(fmt.Errorf("sftp posix-rename %s -> %s: %w", tmpPath, clean, err))
		}
		if t.logger != nil {
			t.logger.Warn("sftp posix-rename unsupported, falling back to remove+rename",
				"host_id", host.ID, "host", host.Host, "target", clean, "error", t.redact(err.Error()))
		}
		if renErr := sc.Rename(tmpPath, clean); renErr != nil {
			_ = sc.Remove(clean)
			if renErr2 := sc.Rename(tmpPath, clean); renErr2 != nil {
				return t.redactErr(fmt.Errorf("sftp fallback remove+rename %s -> %s: %w", tmpPath, clean, renErr2))
			}
		}
	}

	cleanup = false
	return nil
}

func (t *Transport) writeSSHFileInPlace(ctx context.Context, host *model.Host, filePath string, data []byte) error {
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return t.redactErr(fmt.Errorf("open sftp session: %w", err))
	}
	defer sc.Close()

	clean := pathpkg.Clean(filePath)
	dir := pathpkg.Dir(clean)
	if dir != "." && dir != "/" {
		if err := sc.MkdirAll(dir); err != nil {
			return t.redactErr(fmt.Errorf("sftp mkdir %s: %w", dir, err))
		}
	}

	f, err := sc.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return t.redactErr(fmt.Errorf("sftp open in place %s: %w", clean, err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return t.redactErr(fmt.Errorf("sftp write in place %s: %w", clean, err))
	}
	if err := f.Close(); err != nil {
		return t.redactErr(fmt.Errorf("sftp close in place %s: %w", clean, err))
	}
	return nil
}

func (t *Transport) removeSSHFile(ctx context.Context, host *model.Host, filePath string) error {
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return t.redactErr(fmt.Errorf("open sftp session: %w", err))
	}
	defer sc.Close()

	clean := pathpkg.Clean(filePath)
	if err := sc.Remove(clean); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove remote file %s: %w", t.redact(clean), os.ErrNotExist)
		}
		return t.redactErr(fmt.Errorf("remove remote file %s: %w", clean, err))
	}
	return nil
}

func (t *Transport) execSSH(ctx context.Context, host *model.Host, command string, stdin []byte) (*model.ExecResult, error) {
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("command must not be empty")
	}
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return nil, err
	}
	defer client.Close()

	return t.execOnSSHClient(ctx, client, command, stdin)
}

func (t *Transport) execOnSSHClient(ctx context.Context, client *ssh.Client, command string, stdin []byte) (*model.ExecResult, error) {
	execCtx, cancel := t.withExecTimeout(ctx)
	defer cancel()

	session, err := client.NewSession()
	if err != nil {
		return nil, t.redactErr(fmt.Errorf("create ssh session: %w", err))
	}
	defer session.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf
	if len(stdin) > 0 {
		session.Stdin = bytes.NewReader(stdin)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case err = <-done:
	case <-execCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		<-done
		return nil, t.redactErr(fmt.Errorf("ssh command timed out or cancelled: %w", execCtx.Err()))
	}

	res := &model.ExecResult{
		ExitCode: 0,
		Stdout:   t.redact(stdoutBuf.String()),
		Stderr:   t.redact(stderrBuf.String()),
	}
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitStatus()
			return res, nil
		}
		return nil, t.redactErr(fmt.Errorf("ssh exec: %w", err))
	}
	return res, nil
}

func (t *Transport) dialSSH(ctx context.Context, host *model.Host) (*ssh.Client, sshConnectInfo, func(), error) {
	var info sshConnectInfo
	if strings.TrimSpace(host.Host) == "" {
		return nil, info, nil, errors.New("ssh host address is empty")
	}
	port := host.Port
	if port <= 0 {
		port = 22
	}
	username := strings.TrimSpace(host.Username)
	if username == "" {
		username = "root"
	}

	authMethods, cleanupSecrets, err := t.buildSSHAuthMethods(host)
	if err != nil {
		err = t.redactErr(err)
		if cleanupSecrets != nil {
			cleanupSecrets()
		}
		return nil, info, nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	defer cancel()

	cfg := &ssh.ClientConfig{
		User:    username,
		Auth:    authMethods,
		Timeout: t.dialTimeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			observedFP := ssh.FingerprintSHA256(key)
			info.observedFP = observedFP
			status, verifyErr := t.verifyHostKey(dialCtx, host, observedFP)
			info.hostKeyStatus = status
			if verifyErr != nil {
				info.mismatchErr = verifyErr
			}
			return verifyErr
		},
	}

	addr := net.JoinHostPort(strings.TrimSpace(host.Host), strconv.Itoa(port))
	rawConn, err := (&net.Dialer{Timeout: t.dialTimeout}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		err = t.redactErr(fmt.Errorf("dial ssh %s: %w", addr, err))
		if cleanupSecrets != nil {
			cleanupSecrets()
		}
		return nil, info, nil, err
	}

	stopAfter := context.AfterFunc(dialCtx, func() {
		_ = rawConn.Close()
	})

	c, chans, reqs, err := ssh.NewClientConn(rawConn, addr, cfg)
	if !stopAfter() {
		// Context already cancelled and closed rawConn.
	}
	if err != nil {
		_ = rawConn.Close()
		if info.mismatchErr != nil {
			err = t.redactErr(info.mismatchErr)
			if cleanupSecrets != nil {
				cleanupSecrets()
			}
			return nil, info, nil, err
		}
		err = t.redactErr(fmt.Errorf("ssh handshake %s: %w", addr, err))
		if cleanupSecrets != nil {
			cleanupSecrets()
		}
		return nil, info, nil, err
	}

	return ssh.NewClient(c, chans, reqs), info, cleanupSecrets, nil
}

func (t *Transport) buildSSHAuthMethods(host *model.Host) ([]ssh.AuthMethod, func(), error) {
	authType := host.AuthType
	if authType == "" {
		authType = model.HostAuthKey
	}

	switch authType {
	case model.HostAuthKey:
		privKey, err := t.decryptHostSecret(host.SSHPrivateKeyEnc, "hosts:ssh_private_key_enc")
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt ssh private key: %w", err)
		}
		if strings.TrimSpace(privKey) == "" {
			return nil, nil, errors.New("ssh private key is empty")
		}
		passphrase, err := t.decryptHostSecret(host.SSHPassphraseEnc, "hosts:ssh_passphrase_enc")
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt ssh passphrase: %w", err)
		}
		var cleanup func()
		if t.redactor != nil {
			t.redactor.Add(privKey, passphrase)
			cleanup = func() { t.redactor.Remove(privKey, passphrase) }
		}

		var signer ssh.Signer
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(privKey), []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(privKey))
		}
		if err != nil {
			return nil, cleanup, fmt.Errorf("parse ssh private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, cleanup, nil

	case model.HostAuthPassword:
		password, err := t.decryptHostSecret(host.SSHPasswordEnc, "hosts:ssh_password_enc")
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt ssh password: %w", err)
		}
		if password == "" {
			return nil, nil, errors.New("ssh password is empty")
		}
		var cleanup func()
		if t.redactor != nil {
			t.redactor.Add(password)
			cleanup = func() { t.redactor.Remove(password) }
		}
		return []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = password
				}
				return answers, nil
			}),
		}, cleanup, nil

	case model.HostAuthNone:
		return nil, nil, nil

	default:
		return nil, nil, fmt.Errorf("unsupported ssh auth_type %q", authType)
	}
}

func (t *Transport) decryptHostSecret(enc, aad string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if t.cipher == nil {
		return "", errors.New("cipher is not initialized")
	}
	return t.cipher.Decrypt(enc, aad)
}

func (t *Transport) verifyHostKey(ctx context.Context, host *model.Host, observedFP string) (string, error) {
	unlock := t.lockHostKey(host.ID)
	defer unlock()

	policy := strings.ToLower(strings.TrimSpace(host.HostKeyPolicy))
	expectedFP := strings.TrimSpace(host.HostKeyFingerprint)

	if t.db != nil && host.ID > 0 {
		if fresh, err := t.db.GetHost(ctx, host.ID); err == nil && fresh != nil {
			if fresh.HostKeyPolicy != "" {
				policy = strings.ToLower(strings.TrimSpace(fresh.HostKeyPolicy))
			}
			expectedFP = strings.TrimSpace(fresh.HostKeyFingerprint)
		}
	}
	if policy == "" {
		policy = model.HostKeyPolicyTOFU
	}

	switch policy {
	case model.HostKeyPolicyInsecure:
		return "insecure", nil

	case model.HostKeyPolicyStrict:
		if expectedFP == "" {
			t.logHostKeyAudit(ctx, host, policy, expectedFP, observedFP, "strict host key policy requires a pinned fingerprint")
			return "changed", fmt.Errorf("%w: host %q has strict policy but no pinned fingerprint (observed %s)", ErrHostKeyMissing, host.Name, observedFP)
		}
		if expectedFP != observedFP {
			msg := fmt.Sprintf("host key mismatch for %s (%s): expected %s, observed %s", host.Name, host.Host, expectedFP, observedFP)
			t.logHostKeyAudit(ctx, host, policy, expectedFP, observedFP, msg)
			return "changed", fmt.Errorf("%w: %s", ErrHostKeyMismatch, msg)
		}
		return "trusted", nil

	case model.HostKeyPolicyTOFU:
		if expectedFP == "" {
			if t.db != nil && host.ID > 0 {
				if err := t.db.UpdateHostKeyFingerprint(ctx, host.ID, observedFP); err != nil {
					return "", fmt.Errorf("persist tofu host key fingerprint: %w", err)
				}
			}
			host.HostKeyFingerprint = observedFP
			return "pinned", nil
		}
		if expectedFP != observedFP {
			msg := fmt.Sprintf("TOFU host key mismatch for %s (%s): pinned %s, observed %s", host.Name, host.Host, expectedFP, observedFP)
			t.logHostKeyAudit(ctx, host, policy, expectedFP, observedFP, msg)
			return "changed", fmt.Errorf("%w: %s", ErrHostKeyMismatch, msg)
		}
		return "trusted", nil

	default:
		return "", fmt.Errorf("unsupported host_key_policy %q", policy)
	}
}

func (t *Transport) logHostKeyAudit(ctx context.Context, host *model.Host, policy, expectedFP, observedFP, msg string) {
	if t.db == nil {
		return
	}
	var targetID *int64
	if host.ID > 0 {
		id := host.ID
		targetID = &id
	}
	metaBytes, _ := json.Marshal(map[string]any{
		"host":                 host.Host,
		"port":                 host.Port,
		"policy":               policy,
		"expected_fingerprint": expectedFP,
		"observed_fingerprint": observedFP,
	})
	_, _ = t.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  "host.host_key_mismatch",
		Level:      model.AuditLevelError,
		TargetType: "host",
		TargetID:   targetID,
		TargetName: host.Name,
		Message:    t.redact(msg),
		MetaJSON:   string(metaBytes),
	})
}

func isUnsupportedSFTPOp(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sftp.ErrSSHFxOpUnsupported) {
		return true
	}
	var statusErr *sftp.StatusError
	if errors.As(err, &statusErr) && statusErr.FxCode() == sftp.ErrSSHFxOpUnsupported {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unsupported") || strings.Contains(msg, "not supported")
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b)
}
