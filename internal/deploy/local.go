package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"ssl-center/internal/model"
)

func (t *Transport) testLocalConnection(ctx context.Context, host *model.Host) (*model.HostTestResult, error) {
	res := &model.HostTestResult{
		SSHOK:         true,
		HostKeyStatus: "local",
		Message:       "Local host accessible",
	}
	caddyStatus := model.CaddyStatusUnknown
	checkOK := true

	if host.CaddyEnabled {
		runner := func(cmd string) (*model.ExecResult, error) {
			return t.execLocal(ctx, cmd, nil)
		}
		existsFn := func(filePath string) *bool {
			_, statErr := os.Stat(filepath.Clean(filePath))
			exists := statErr == nil
			return &exists
		}
		caddyStatus, checkOK = t.diagnoseCaddy(host, res, true, runner, existsFn)
	}

	res.Message = t.redact(res.Message)
	t.persistCheckResult(ctx, host, checkOK, res.Message, caddyStatus)
	return res, nil
}

func (t *Transport) readLocalFile(ctx context.Context, filePath string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := filepath.Clean(filePath)
	data, err := os.ReadFile(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read local file %s: %w", t.redact(clean), os.ErrNotExist)
		}
		return nil, t.redactErr(fmt.Errorf("read local file %s: %w", clean, err))
	}
	return data, nil
}

func (t *Transport) writeLocalFileAtomic(ctx context.Context, filePath string, data []byte, mode uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clean := filepath.Clean(filePath)
	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return t.redactErr(fmt.Errorf("mkdir %s: %w", dir, err))
	}

	tmp, err := os.CreateTemp(dir, fmt.Sprintf(".%s.tmp.*", filepath.Base(clean)))
	if err != nil {
		return t.redactErr(fmt.Errorf("create temp file in %s: %w", dir, err))
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return t.redactErr(fmt.Errorf("write temp file %s: %w", tmpName, err))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return t.redactErr(fmt.Errorf("sync temp file %s: %w", tmpName, err))
	}
	if err := tmp.Close(); err != nil {
		return t.redactErr(fmt.Errorf("close temp file %s: %w", tmpName, err))
	}

	perm := os.FileMode(mode) & os.ModePerm
	if perm == 0 {
		perm = 0o644
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return t.redactErr(fmt.Errorf("chmod %s: %w", tmpName, err))
	}
	if err := os.Rename(tmpName, clean); err != nil {
		return t.redactErr(fmt.Errorf("rename %s -> %s: %w", tmpName, clean, err))
	}
	cleanup = false
	return nil
}

func (t *Transport) writeLocalFileInPlace(ctx context.Context, filePath string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clean := filepath.Clean(filePath)
	dir := filepath.Dir(clean)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return t.redactErr(fmt.Errorf("mkdir %s: %w", dir, err))
	}

	f, err := os.OpenFile(clean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return t.redactErr(fmt.Errorf("open file in place %s: %w", clean, err))
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return t.redactErr(fmt.Errorf("write file in place %s: %w", clean, err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return t.redactErr(fmt.Errorf("sync file in place %s: %w", clean, err))
	}
	if err := f.Close(); err != nil {
		return t.redactErr(fmt.Errorf("close file in place %s: %w", clean, err))
	}
	return nil
}

func (t *Transport) removeLocalFile(ctx context.Context, filePath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	clean := filepath.Clean(filePath)
	if err := os.Remove(clean); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove local file %s: %w", t.redact(clean), os.ErrNotExist)
		}
		return t.redactErr(fmt.Errorf("remove local file %s: %w", clean, err))
	}
	return nil
}

func (t *Transport) execLocal(ctx context.Context, command string, stdin []byte) (*model.ExecResult, error) {
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("command must not be empty")
	}
	execCtx, cancel := t.withExecTimeout(ctx)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "sh", "-c", command)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	err := cmd.Run()
	res := &model.ExecResult{
		ExitCode: 0,
		Stdout:   t.redact(stdoutBuf.String()),
		Stderr:   t.redact(stderrBuf.String()),
	}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return nil, t.redactErr(fmt.Errorf("exec local command: %w", err))
	}
	return res, nil
}

func (t *Transport) persistCheckResult(ctx context.Context, host *model.Host, ok bool, msg, caddyStatus string) {
	if t.db == nil || host == nil || host.ID <= 0 {
		return
	}
	_ = t.db.UpdateHostCheckResult(ctx, host.ID, ok, msg, caddyStatus, time.Now().UTC())
}

func isDockerDaemonAvailable(res *model.ExecResult, err error) bool {
	return err == nil && res != nil && res.ExitCode == 0 && strings.TrimSpace(res.Stdout) != ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
