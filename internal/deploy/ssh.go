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
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"ssl-center/internal/model"
)

type sshSessionKey struct{}

type sshSessionHandle struct {
	hostID   int64
	hostAddr string
	port     int
	client   *ssh.Client
	mu       sync.Mutex
	sftp     *sftp.Client
}

func (h *sshSessionHandle) matches(host *model.Host) bool {
	if h == nil || host == nil {
		return false
	}
	if h.hostID > 0 && host.ID > 0 {
		return h.hostID == host.ID
	}
	port := host.Port
	if port <= 0 {
		port = 22
	}
	return h.hostID == 0 && host.ID == 0 && h.hostAddr == strings.TrimSpace(host.Host) && h.port == port
}

func (h *sshSessionHandle) getSFTP() (*sftp.Client, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sftp != nil {
		return h.sftp, nil
	}
	sc, err := sftp.NewClient(h.client)
	if err != nil {
		return nil, err
	}
	h.sftp = sc
	return sc, nil
}

func (h *sshSessionHandle) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sftp != nil {
		_ = h.sftp.Close()
		h.sftp = nil
	}
	if h.client != nil {
		_ = h.client.Close()
		h.client = nil
	}
}

func (t *Transport) withSSHSession(ctx context.Context, host *model.Host, fn func(context.Context) error) error {
	if existing, ok := ctx.Value(sshSessionKey{}).(*sshSessionHandle); ok && existing.matches(host) {
		return fn(ctx)
	}
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return err
	}
	port := host.Port
	if port <= 0 {
		port = 22
	}
	handle := &sshSessionHandle{
		hostID:   host.ID,
		hostAddr: strings.TrimSpace(host.Host),
		port:     port,
		client:   client,
	}
	defer func() {
		handle.closeAll()
		if cleanup != nil {
			cleanup()
		}
	}()
	return fn(context.WithValue(ctx, sshSessionKey{}, handle))
}

func (t *Transport) acquireSSHClient(ctx context.Context, host *model.Host) (*ssh.Client, func(), error) {
	if existing, ok := ctx.Value(sshSessionKey{}).(*sshSessionHandle); ok && existing.matches(host) && existing.client != nil {
		return existing.client, func() {}, nil
	}
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, err
	}
	return client, func() {
		_ = client.Close()
		if cleanup != nil {
			cleanup()
		}
	}, nil
}

func (t *Transport) acquireSFTP(ctx context.Context, host *model.Host) (*sftp.Client, func(), error) {
	if existing, ok := ctx.Value(sshSessionKey{}).(*sshSessionHandle); ok && existing.matches(host) && existing.client != nil {
		sc, err := existing.getSFTP()
		if err != nil {
			return nil, nil, t.redactErr(fmt.Errorf("open sftp session: %w", err))
		}
		return sc, func() {}, nil
	}
	client, _, cleanup, err := t.dialSSH(ctx, host)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, err
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		if cleanup != nil {
			cleanup()
		}
		return nil, nil, t.redactErr(fmt.Errorf("open sftp session: %w", err))
	}
	return sc, func() {
		_ = sc.Close()
		_ = client.Close()
		if cleanup != nil {
			cleanup()
		}
	}, nil
}

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

	handle := &sshSessionHandle{
		hostID:   host.ID,
		hostAddr: strings.TrimSpace(host.Host),
		port:     host.Port,
		client:   client,
	}
	defer func() {
		handle.mu.Lock()
		if handle.sftp != nil {
			_ = handle.sftp.Close()
			handle.sftp = nil
		}
		handle.mu.Unlock()
	}()

	res.SSHOK = true
	res.HostKeyFingerprint = info.observedFP
	res.HostKeyStatus = info.hostKeyStatus

	if !host.CaddyEnabled {
		res.Message = "SSH connection succeeded"
		t.persistCheckResult(ctx, host, true, res.Message, caddyStatus)
		return res, nil
	}

	runner := func(cmd string) (*model.ExecResult, error) {
		return t.execOnSSHClient(ctx, client, cmd, nil)
	}
	existsFn := func(filePath string) *bool {
		sc, sErr := handle.getSFTP()
		if sErr != nil {
			return nil
		}
		_, statErr := sc.Stat(pathpkg.Clean(filePath))
		exists := statErr == nil
		return &exists
	}

	caddyStatus, _ = t.diagnoseCaddy(host, res, false, runner, existsFn)
	res.Message = t.redact(res.Message)
	t.persistCheckResult(ctx, host, true, res.Message, caddyStatus)
	return res, nil
}

func (t *Transport) readSSHFile(ctx context.Context, host *model.Host, filePath string) ([]byte, error) {
	sc, release, err := t.acquireSFTP(ctx, host)
	if err != nil {
		return nil, err
	}
	defer release()

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
	sc, release, err := t.acquireSFTP(ctx, host)
	if err != nil {
		return err
	}
	defer release()

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
	sc, release, err := t.acquireSFTP(ctx, host)
	if err != nil {
		return err
	}
	defer release()

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
	sc, release, err := t.acquireSFTP(ctx, host)
	if err != nil {
		return err
	}
	defer release()

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
	client, release, err := t.acquireSSHClient(ctx, host)
	if err != nil {
		return nil, err
	}
	defer release()

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
