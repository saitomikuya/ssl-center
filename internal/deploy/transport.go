package deploy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const (
	defaultDialTimeout = 15 * time.Second
	defaultExecTimeout = 60 * time.Second
)

var (
	// ErrHostKeyMismatch indicates the remote SSH server's host key fingerprint
	// does not match the pinned fingerprint stored for the host.
	ErrHostKeyMismatch = errors.New("ssh host key fingerprint mismatch")
	// ErrHostKeyMissing indicates strict host key policy is enabled without a pinned fingerprint.
	ErrHostKeyMissing = errors.New("strict host key policy requires a pinned fingerprint")
)

// Transport implements model.RemoteTransport for both SSH/SFTP and Local hosts.
type Transport struct {
	db          *db.DB
	cipher      *crypto.Cipher
	redactor    *crypto.SecretRedactor
	logger      *slog.Logger
	dialTimeout time.Duration
	execTimeout time.Duration

	hostLockMu sync.Mutex
	hostLocks  map[int64]*sync.Mutex
}

// NewTransport constructs a Transport shared by the deployment engine and Caddy manager.
func NewTransport(database *db.DB, cipher *crypto.Cipher, redactor *crypto.SecretRedactor, logger *slog.Logger) *Transport {
	return &Transport{
		db:          database,
		cipher:      cipher,
		redactor:    redactor,
		logger:      logger,
		dialTimeout: defaultDialTimeout,
		execTimeout: defaultExecTimeout,
		hostLocks:   make(map[int64]*sync.Mutex),
	}
}

var _ model.RemoteTransport = (*Transport)(nil)

// TestConnection verifies connectivity and optional Docker/Caddy container status.
func (t *Transport) TestConnection(ctx context.Context, host *model.Host) (*model.HostTestResult, error) {
	if host == nil {
		return nil, errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.testLocalConnection(ctx, host)
	}
	return t.testSSHConnection(ctx, host)
}

// ReadFile reads a file from the local or remote host.
func (t *Transport) ReadFile(ctx context.Context, host *model.Host, filePath string) ([]byte, error) {
	if host == nil {
		return nil, errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.readLocalFile(ctx, filePath)
	}
	return t.readSSHFile(ctx, host, filePath)
}

// WriteFileAtomic writes data to filePath atomically via a same-directory temporary file and rename.
func (t *Transport) WriteFileAtomic(ctx context.Context, host *model.Host, filePath string, data []byte, mode uint32) error {
	if host == nil {
		return errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.writeLocalFileAtomic(ctx, filePath, data, mode)
	}
	return t.writeSSHFileAtomic(ctx, host, filePath, data, mode)
}

// WriteFileInPlace truncates and overwrites filePath in place to preserve the existing inode.
func (t *Transport) WriteFileInPlace(ctx context.Context, host *model.Host, filePath string, data []byte) error {
	if host == nil {
		return errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.writeLocalFileInPlace(ctx, filePath, data)
	}
	return t.writeSSHFileInPlace(ctx, host, filePath, data)
}

// RemoveFile deletes filePath on the target host.
func (t *Transport) RemoveFile(ctx context.Context, host *model.Host, filePath string) error {
	if host == nil {
		return errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.removeLocalFile(ctx, filePath)
	}
	return t.removeSSHFile(ctx, host, filePath)
}

// Exec executes cmd on the target host and returns redacted stdout/stderr and exit code.
func (t *Transport) Exec(ctx context.Context, host *model.Host, cmd string) (*model.ExecResult, error) {
	return t.ExecWithStdin(ctx, host, cmd, nil)
}

// ExecWithStdin executes cmd with optional stdin bytes and returns redacted stdout/stderr and exit code.
func (t *Transport) ExecWithStdin(ctx context.Context, host *model.Host, cmd string, stdin []byte) (*model.ExecResult, error) {
	if host == nil {
		return nil, errors.New("host must not be nil")
	}
	if isLocalHost(host) {
		return t.execLocal(ctx, cmd, stdin)
	}
	return t.execSSH(ctx, host, cmd, stdin)
}

func isLocalHost(host *model.Host) bool {
	if host.Mode == model.HostModeLocal {
		return true
	}
	return host.Mode == "" && host.IsLocal
}

func (t *Transport) lockHostKey(hostID int64) func() {
	if hostID <= 0 {
		return func() {}
	}
	t.hostLockMu.Lock()
	mu, ok := t.hostLocks[hostID]
	if !ok {
		mu = &sync.Mutex{}
		t.hostLocks[hostID] = mu
	}
	t.hostLockMu.Unlock()

	mu.Lock()
	return mu.Unlock
}

func (t *Transport) redact(s string) string {
	if t.redactor == nil || s == "" {
		return s
	}
	return t.redactor.Redact(s)
}

func (t *Transport) redactErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: %w", t.redact(strings.TrimSuffix(err.Error(), os.ErrNotExist.Error())), os.ErrNotExist)
	}
	if errors.Is(err, ErrHostKeyMismatch) {
		return fmt.Errorf("%w: %s", ErrHostKeyMismatch, t.redact(strings.TrimPrefix(err.Error(), ErrHostKeyMismatch.Error()+": ")))
	}
	if errors.Is(err, ErrHostKeyMissing) {
		return fmt.Errorf("%w: %s", ErrHostKeyMissing, t.redact(strings.TrimPrefix(err.Error(), ErrHostKeyMissing.Error()+": ")))
	}
	return errors.New(t.redact(err.Error()))
}

func (t *Transport) withExecTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, t.execTimeout)
}
