package caddy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

type mockTransport struct {
	mu sync.Mutex

	files           map[string][]byte
	atomicWrites    []string
	inPlaceWrites   []string
	removedFiles    []string
	execCmds        []string
	stdinExecCmds   []string
	stdinExecInputs []string

	execHandler      func(cmd string) (*model.ExecResult, error)
	stdinExecHandler func(cmd string, stdin []byte) (*model.ExecResult, error)

	// Optional real directory backing for inode preservation tests
	realRoot string
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		files: make(map[string][]byte),
	}
}

func (m *mockTransport) TestConnection(ctx context.Context, host *model.Host) (*model.HostTestResult, error) {
	return &model.HostTestResult{SSHOK: true, DockerOK: true, CaddyRunning: true}, nil
}

func (m *mockTransport) ReadFile(ctx context.Context, host *model.Host, p string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.realRoot != "" {
		return os.ReadFile(filepath.Join(m.realRoot, strings.TrimPrefix(p, "/")))
	}
	data, ok := m.files[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (m *mockTransport) WriteFileAtomic(ctx context.Context, host *model.Host, p string, data []byte, mode uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.atomicWrites = append(m.atomicWrites, p)
	if m.realRoot != "" {
		full := filepath.Join(m.realRoot, strings.TrimPrefix(p, "/"))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		tmp := full + ".tmp"
		if err := os.WriteFile(tmp, data, os.FileMode(mode)); err != nil {
			return err
		}
		return os.Rename(tmp, full)
	}
	m.files[p] = append([]byte(nil), data...)
	return nil
}

func (m *mockTransport) WriteFileInPlace(ctx context.Context, host *model.Host, p string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inPlaceWrites = append(m.inPlaceWrites, p)
	if m.realRoot != "" {
		full := filepath.Join(m.realRoot, strings.TrimPrefix(p, "/"))
		f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return err
		}
		_, wErr := f.Write(data)
		cErr := f.Close()
		if wErr != nil {
			return wErr
		}
		return cErr
	}
	m.files[p] = append([]byte(nil), data...)
	return nil
}

func (m *mockTransport) RemoveFile(ctx context.Context, host *model.Host, p string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removedFiles = append(m.removedFiles, p)
	if m.realRoot != "" {
		return os.Remove(filepath.Join(m.realRoot, strings.TrimPrefix(p, "/")))
	}
	delete(m.files, p)
	return nil
}

func (m *mockTransport) Exec(ctx context.Context, host *model.Host, cmd string) (*model.ExecResult, error) {
	m.mu.Lock()
	m.execCmds = append(m.execCmds, cmd)
	h := m.execHandler
	m.mu.Unlock()
	if h != nil {
		return h(cmd)
	}
	return &model.ExecResult{ExitCode: 0}, nil
}

func (m *mockTransport) ExecWithStdin(ctx context.Context, host *model.Host, cmd string, stdin []byte) (*model.ExecResult, error) {
	m.mu.Lock()
	m.stdinExecCmds = append(m.stdinExecCmds, cmd)
	m.stdinExecInputs = append(m.stdinExecInputs, string(stdin))
	h := m.stdinExecHandler
	m.mu.Unlock()
	if h != nil {
		return h(cmd, stdin)
	}
	return &model.ExecResult{ExitCode: 0, Stdout: string(stdin)}, nil
}

type mockNotifier struct {
	mu     sync.Mutex
	events []model.WebhookEvent
}

func (n *mockNotifier) Emit(ctx context.Context, event model.WebhookEvent) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append(n.events, event)
	return nil
}

func (n *mockNotifier) SendTest(ctx context.Context, webhookID int64) error {
	return nil
}

func setupCaddyTest(t *testing.T) (*db.DB, *model.Host, *crypto.SecretRedactor) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.Open(filepath.Join(dir, "app.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })

	host := &model.Host{
		Name:                    "Edge-1",
		Mode:                    model.HostModeSSH,
		Host:                    "10.0.0.10",
		Port:                    22,
		Username:                "root",
		AuthType:                model.HostAuthKey,
		CaddyEnabled:            true,
		CaddyContainer:          "caddy-edge",
		CaddyHostCaddyfile:      "/opt/caddy/Caddyfile",
		CaddyContainerCaddyfile: "/etc/caddy/Caddyfile",
	}
	if _, err := database.CreateHost(context.Background(), host); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}
	return database, host, crypto.NewSecretRedactor()
}

func hashStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestGetAndSaveCaddyfileConflict409(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	tr := newMockTransport()
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	liveContent := "example.com {\n\trespond \"v1\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(liveContent)
	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `[{"Type":"bind","Source":"/opt/caddy","Destination":"/etc/caddy","RW":true}]`,
			}, nil
		}
		return &model.ExecResult{ExitCode: 0}, nil
	}

	got, err := mgr.GetCaddyfile(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("GetCaddyfile: %v", err)
	}
	if got.SHA256 != hashStr(liveContent) || got.MountType != MountTypeDir {
		t.Fatalf("unexpected GetCaddyfile: %+v", got)
	}

	// Simulate external modification before save
	externalContent := "example.com {\n\trespond \"external-edit\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(externalContent)

	_, err = mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        "example.com {\n\trespond \"mine\"\n}\n",
		ExpectedSHA256: got.SHA256,
		Force:          false,
	}, "127.0.0.1")
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("expected ConflictError, got %v", err)
	}
	if ce.Details.ExpectedSHA256 != got.SHA256 || ce.Details.RemoteSHA256 != hashStr(externalContent) || ce.Details.RemoteContent != externalContent {
		t.Fatalf("unexpected conflict details: %+v", ce.Details)
	}
	if len(tr.atomicWrites) != 0 || len(tr.inPlaceWrites) != 0 {
		t.Fatal("conflict must block all writes")
	}

	// Empty expected_sha256 on an existing live Caddyfile with force=false must also return 409 Conflict
	_, err = mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        "example.com {\n\trespond \"mine-empty-sha\"\n}\n",
		ExpectedSHA256: "",
		Force:          false,
	}, "127.0.0.1")
	var ceEmpty *ConflictError
	if !errors.As(err, &ceEmpty) {
		t.Fatalf("expected ConflictError for empty expected_sha256 when live file exists, got %v", err)
	}
	if ceEmpty.Details.RemoteSHA256 != hashStr(externalContent) || ceEmpty.Details.RemoteContent != externalContent {
		t.Fatalf("unexpected conflict details for empty sha: %+v", ceEmpty.Details)
	}
	if len(tr.atomicWrites) != 0 || len(tr.inPlaceWrites) != 0 {
		t.Fatal("conflict with empty expected_sha256 must block all writes")
	}
}

func TestSaveCaddyfileDirMountValidateTempAndAtomicWrite(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	tr := newMockTransport()
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	oldContent := "example.com {\n\trespond \"old\"\n}\n"
	newContent := "example.com {\n\trespond \"new\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(oldContent)

	var validatedTmpInContainer string
	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `[{"Type":"bind","Source":"/opt/caddy","Destination":"/etc/caddy","RW":true}]`,
			}, nil
		}
		if strings.Contains(cmd, "caddy validate") {
			// Ensure temp file exists on host during validation
			for k, v := range tr.files {
				if strings.HasPrefix(k, "/opt/caddy/.Caddyfile.validate.") {
					validatedTmpInContainer = "/etc/caddy/" + filepath.Base(k)
					if string(v) != newContent {
						t.Fatalf("temp file content mismatch: %q", string(v))
					}
					if !strings.Contains(cmd, validatedTmpInContainer) {
						t.Fatalf("validate cmd %q missing %q", cmd, validatedTmpInContainer)
					}
				}
			}
			return &model.ExecResult{ExitCode: 0, Stdout: "Valid configuration"}, nil
		}
		if strings.Contains(cmd, "caddy reload") {
			if !strings.Contains(cmd, "--force") {
				t.Fatalf("reload cmd missing --force: %s", cmd)
			}
			return &model.ExecResult{ExitCode: 0, Stdout: "reloaded"}, nil
		}
		return &model.ExecResult{ExitCode: 0}, nil
	}

	res, err := mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        newContent,
		ExpectedSHA256: hashStr(oldContent),
		Summary:        "Update response",
	}, "10.0.0.1")
	if err != nil {
		t.Fatalf("SaveCaddyfile: %v", err)
	}
	if !res.ReloadOK || res.RolledBack || res.SHA256 != hashStr(newContent) {
		t.Fatalf("unexpected save response: %+v", res)
	}
	if validatedTmpInContainer == "" {
		t.Fatal("directory mount did not write same-dir temp validation file")
	}
	if len(tr.removedFiles) != 1 || !strings.HasPrefix(tr.removedFiles[0], "/opt/caddy/.Caddyfile.validate.") {
		t.Fatalf("temp validation file not cleaned up: %+v", tr.removedFiles)
	}
	if len(tr.inPlaceWrites) != 0 {
		t.Fatalf("directory mount should use atomic write, got in-place: %+v", tr.inPlaceWrites)
	}
	if len(tr.atomicWrites) < 2 || tr.atomicWrites[len(tr.atomicWrites)-1] != host.CaddyHostCaddyfile {
		t.Fatalf("expected final atomic write to %s, got %+v", host.CaddyHostCaddyfile, tr.atomicWrites)
	}
	if string(tr.files[host.CaddyHostCaddyfile]) != newContent {
		t.Fatalf("live file content = %q, want %q", string(tr.files[host.CaddyHostCaddyfile]), newContent)
	}

	// Verify baseline + publish snapshots created
	snaps, err := mgr.Snapshots(context.Background(), host.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].Action != model.CaddyActionPublish || snaps[1].Action != model.CaddyActionBaseline {
		t.Fatalf("unexpected snapshots: %+v", snaps)
	}
}

func TestSaveCaddyfileSingleFileMountPreservesInode(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	rootDir := t.TempDir()
	tr := newMockTransport()
	tr.realRoot = rootDir
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	oldContent := "example.com {\n\trespond \"v1\"\n}\n"
	newContent := "example.com {\n\trespond \"v2\"\n}\n"

	hostRealPath := filepath.Join(rootDir, "opt/caddy/Caddyfile")
	if err := os.MkdirAll(filepath.Dir(hostRealPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostRealPath, []byte(oldContent), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(hostRealPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeIno := beforeInfo.Sys().(*syscall.Stat_t).Ino

	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `[{"Type":"bind","Source":"/opt/caddy/Caddyfile","Destination":"/etc/caddy/Caddyfile","RW":true}]`,
			}, nil
		}
		return &model.ExecResult{ExitCode: 0, Stdout: "ok"}, nil
	}
	tr.stdinExecHandler = func(cmd string, stdin []byte) (*model.ExecResult, error) {
		if !strings.Contains(cmd, "caddy validate --config") || string(stdin) != newContent {
			t.Fatalf("unexpected stdin validate cmd=%q stdin=%q", cmd, string(stdin))
		}
		return &model.ExecResult{ExitCode: 0, Stdout: "Valid configuration"}, nil
	}

	res, err := mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        newContent,
		ExpectedSHA256: hashStr(oldContent),
	}, "127.0.0.1")
	if err != nil {
		t.Fatalf("SaveCaddyfile single-file: %v", err)
	}
	if !res.ReloadOK {
		t.Fatalf("expected ReloadOK=true, got %+v", res)
	}
	if len(tr.atomicWrites) != 0 {
		t.Fatalf("single-file mount must NOT use atomic rename, got %+v", tr.atomicWrites)
	}
	if len(tr.inPlaceWrites) != 1 || tr.inPlaceWrites[0] != host.CaddyHostCaddyfile {
		t.Fatalf("expected single in-place write, got %+v", tr.inPlaceWrites)
	}

	afterInfo, err := os.Stat(hostRealPath)
	if err != nil {
		t.Fatal(err)
	}
	afterIno := afterInfo.Sys().(*syscall.Stat_t).Ino
	if beforeIno != afterIno {
		t.Fatalf("inode changed on single-file mount write: before=%d after=%d", beforeIno, afterIno)
	}
}

func TestSaveCaddyfileValidateErrorBlocksWrite(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	tr := newMockTransport()
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	oldContent := "example.com {\n\trespond \"ok\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(oldContent)
	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `[{"Type":"bind","Source":"/opt/caddy/Caddyfile","Destination":"/etc/caddy/Caddyfile","RW":true}]`,
			}, nil
		}
		return &model.ExecResult{ExitCode: 0}, nil
	}
	tr.stdinExecHandler = func(cmd string, stdin []byte) (*model.ExecResult, error) {
		return &model.ExecResult{
			ExitCode: 1,
			Stderr:   "Error: adapting config using caddyfile: /tmp/Caddyfile.xyz123:4: unrecognized directive: bad_directive",
		}, nil
	}

	_, err := mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        "example.com {\n\trespond \"ok\"\n\n\tbad_directive\n}\n",
		ExpectedSHA256: hashStr(oldContent),
	}, "127.0.0.1")
	var ve *ValidateError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidateError, got %v", err)
	}
	if ve.Details.Line != 4 {
		t.Fatalf("parsed line = %d, want 4 (details=%+v)", ve.Details.Line, ve.Details)
	}
	if !strings.Contains(ve.Details.Message, "unrecognized directive") {
		t.Fatalf("unexpected message: %q", ve.Details.Message)
	}
	if len(tr.inPlaceWrites) != 0 || len(tr.atomicWrites) != 0 {
		t.Fatal("validate failure must block writing live Caddyfile")
	}
	if string(tr.files[host.CaddyHostCaddyfile]) != oldContent {
		t.Fatal("live Caddyfile was mutated on validate failure")
	}
}

func TestSaveCaddyfileReloadFailureAutoRollbackAndWebhook(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	tr := newMockTransport()
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	oldContent := "example.com {\n\trespond \"v1\"\n}\n"
	badReloadContent := "example.com {\n\trespond \"v2-runtime-err\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(oldContent)

	reloadAttempt := 0
	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `[{"Type":"bind","Source":"/opt/caddy/Caddyfile","Destination":"/etc/caddy/Caddyfile","RW":true}]`,
			}, nil
		}
		if strings.Contains(cmd, "caddy reload") {
			reloadAttempt++
			if reloadAttempt == 1 {
				return &model.ExecResult{ExitCode: 1, Stderr: "reload: loading new config: port 443 already in use"}, nil
			}
			// Rollback reload succeeds
			return &model.ExecResult{ExitCode: 0, Stdout: "reloaded old"}, nil
		}
		return &model.ExecResult{ExitCode: 0}, nil
	}
	tr.stdinExecHandler = func(cmd string, stdin []byte) (*model.ExecResult, error) {
		return &model.ExecResult{ExitCode: 0, Stdout: "Valid"}, nil
	}

	res, err := mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        badReloadContent,
		ExpectedSHA256: hashStr(oldContent),
		Summary:        "Bad reload test",
	}, "10.0.0.2")
	if err != nil {
		t.Fatalf("SaveCaddyfile unexpected err: %v", err)
	}
	if res.ReloadOK || !res.RolledBack || res.SHA256 != hashStr(oldContent) {
		t.Fatalf("expected RolledBack=true & ReloadOK=false, got %+v", res)
	}
	if string(tr.files[host.CaddyHostCaddyfile]) != oldContent {
		t.Fatalf("live file not rolled back to old content: %q", string(tr.files[host.CaddyHostCaddyfile]))
	}
	if reloadAttempt != 2 {
		t.Fatalf("expected 2 reload attempts (failed + rollback), got %d", reloadAttempt)
	}
	if len(tr.inPlaceWrites) != 2 {
		t.Fatalf("single-file rollback must preserve in-place writes (write + rollback), got %d", len(tr.inPlaceWrites))
	}

	snaps, err := mgr.Snapshots(context.Background(), host.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(snaps) != 2 || snaps[0].ReloadOK || snaps[0].SHA256 != hashStr(badReloadContent) {
		t.Fatalf("expected failed snapshot recorded with reload_ok=false, got %+v", snaps)
	}

	if len(nt.events) != 1 || nt.events[0].Event != model.WebhookEventCaddyReloadFailed {
		t.Fatalf("expected caddy.reload_failed webhook, got %+v", nt.events)
	}
}

func TestFormatValidateReloadDiffRollbackAndContainerInfo(t *testing.T) {
	database, host, redactor := setupCaddyTest(t)
	secret := "cf-super-secret-token-xyz"
	redactor.Add(secret)

	tr := newMockTransport()
	nt := &mockNotifier{}
	mgr := NewManager(database, tr, nt, redactor)

	v1 := "example.com {\n\trespond \"v1\"\n}\n"
	v2 := "example.com {\n\trespond \"v2\"\n}\n"
	tr.files[host.CaddyHostCaddyfile] = []byte(v1)

	tr.execHandler = func(cmd string) (*model.ExecResult, error) {
		if strings.Contains(cmd, "docker inspect") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   `{"State":{"Status":"running","Running":true},"Config":{"Image":"caddy:2.8-alpine"},"Mounts":[{"Type":"bind","Source":"/opt/caddy","Destination":"/etc/caddy","RW":true}]}`,
			}, nil
		}
		if strings.Contains(cmd, "docker logs --tail 50") {
			return &model.ExecResult{
				ExitCode: 0,
				Stdout:   "INF server running with token=" + secret + "\n",
			}, nil
		}
		return &model.ExecResult{ExitCode: 0, Stdout: "ok"}, nil
	}
	tr.stdinExecHandler = func(cmd string, stdin []byte) (*model.ExecResult, error) {
		if strings.Contains(cmd, "caddy fmt") {
			return &model.ExecResult{ExitCode: 0, Stdout: "example.com {\n\trespond \"formatted\"\n}\n"}, nil
		}
		return &model.ExecResult{ExitCode: 0}, nil
	}

	// Format
	formatted, err := mgr.Format(context.Background(), host.ID, "example.com{respond \"formatted\"}")
	if err != nil || !strings.Contains(formatted, "\trespond") {
		t.Fatalf("Format failed: (%q, %v)", formatted, err)
	}

	// Validate (does not write live file)
	valRes, err := mgr.Validate(context.Background(), host.ID, v2)
	if err != nil || !valRes.Valid {
		t.Fatalf("Validate failed: (%+v, %v)", valRes, err)
	}
	if string(tr.files[host.CaddyHostCaddyfile]) != v1 {
		t.Fatal("Validate must not overwrite live file")
	}

	// Publish v2 so baseline v1 and publish v2 exist
	if _, err := mgr.SaveCaddyfile(context.Background(), host.ID, model.SaveCaddyfileRequest{
		Content:        v2,
		ExpectedSHA256: hashStr(v1),
		Summary:        "v2",
	}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}

	// ReloadOnly
	relRes, err := mgr.ReloadOnly(context.Background(), host.ID, "127.0.0.1")
	if err != nil || !relRes.ReloadOK {
		t.Fatalf("ReloadOnly failed: (%+v, %v)", relRes, err)
	}

	// SnapshotDiff between v1 baseline and current v2
	snaps, err := mgr.Snapshots(context.Background(), host.ID, 10)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("Snapshots = (%+v, %v)", snaps, err)
	}
	baseline := snaps[1]
	diff, err := mgr.SnapshotDiff(context.Background(), host.ID, baseline.ID)
	if err != nil {
		t.Fatalf("SnapshotDiff: %v", err)
	}
	if !strings.Contains(diff.DiffText, "-\trespond \"v1\"") || !strings.Contains(diff.DiffText, "+\trespond \"v2\"") {
		t.Fatalf("unexpected diff text:\n%s", diff.DiffText)
	}

	// Rollback to v1 baseline
	rbRes, err := mgr.Rollback(context.Background(), host.ID, baseline.ID, "127.0.0.1")
	if err != nil || !rbRes.ReloadOK || rbRes.SHA256 != hashStr(v1) {
		t.Fatalf("Rollback failed: (%+v, %v)", rbRes, err)
	}
	if string(tr.files[host.CaddyHostCaddyfile]) != v1 {
		t.Fatalf("live file after rollback = %q, want %q", string(tr.files[host.CaddyHostCaddyfile]), v1)
	}

	// ContainerInfo & secret redaction
	info, err := mgr.ContainerInfo(context.Background(), host.ID, 50)
	if err != nil {
		t.Fatalf("ContainerInfo: %v", err)
	}
	if !info.Running || info.Image != "caddy:2.8-alpine" || info.MountType != MountTypeDir || len(info.Mounts) != 1 {
		t.Fatalf("unexpected ContainerInfo: %+v", info)
	}
	if strings.Contains(info.Logs, secret) || !strings.Contains(info.Logs, crypto.RedactedPlaceholder) {
		t.Fatalf("ContainerInfo logs not redacted: %q", info.Logs)
	}

	// Container name injection check
	host.CaddyContainer = "caddy; rm -rf /"
	if err := database.UpdateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.GetCaddyfile(context.Background(), host.ID); err == nil {
		t.Fatal("expected invalid container name to be rejected")
	}
}
