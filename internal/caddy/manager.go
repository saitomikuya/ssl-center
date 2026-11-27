package caddy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const (
	MountTypeDir     = "dir"
	MountTypeFile    = "file"
	MountTypeLocal   = "local"
	MountTypeUnknown = "unknown"

	defaultHostCaddyfile      = "/opt/caddy/Caddyfile"
	defaultContainerCaddyfile = "/etc/caddy/Caddyfile"
	defaultContainerName      = "caddy"
	defaultTailLines          = 100
	maxTailLines              = 1000
)

var (
	ErrCaddyDisabled        = errors.New("caddy management is not enabled for this host")
	ErrSnapshotHostMismatch = errors.New("snapshot does not belong to the specified host")
)

// ConflictError indicates the remote Caddyfile changed since it was loaded.
type ConflictError struct {
	Details model.CaddyConflictDetails
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("caddyfile conflict: expected sha256 %s, remote sha256 %s", e.Details.ExpectedSHA256, e.Details.RemoteSHA256)
}

// ValidateError indicates `caddy validate` rejected the candidate Caddyfile.
type ValidateError struct {
	Details model.CaddyValidateErrorDetails
}

func (e *ValidateError) Error() string {
	if e.Details.Line > 0 {
		return fmt.Sprintf("caddy validate failed at line %d: %s", e.Details.Line, e.Details.Message)
	}
	return fmt.Sprintf("caddy validate failed: %s", e.Details.Message)
}

// Manager orchestrates safe Caddyfile retrieval, validation, atomic/in-place publishing,
// snapshot history, diff/rollback, and container inspection over RemoteTransport.
type Manager struct {
	db        *db.DB
	transport model.RemoteTransport
	notifier  model.Notifier
	redactor  *crypto.SecretRedactor
	clock     func() time.Time
}

// NewManager constructs a Caddy Manager.
func NewManager(database *db.DB, transport model.RemoteTransport, notifier model.Notifier, redactor *crypto.SecretRedactor) *Manager {
	return &Manager{
		db:        database,
		transport: transport,
		notifier:  notifier,
		redactor:  redactor,
		clock:     func() time.Time { return time.Now().UTC() },
	}
}

type dockerMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

type dockerInspectState struct {
	Status  string `json:"Status"`
	Running bool   `json:"Running"`
}

type dockerInspectConfig struct {
	Image string `json:"Image"`
}

type dockerInspectObject struct {
	State  dockerInspectState  `json:"State"`
	Config dockerInspectConfig `json:"Config"`
	Mounts []dockerMount       `json:"Mounts"`
}

// GetCaddyfile reads the host's Caddyfile, computes its SHA-256, and detects mount type.
func (m *Manager) GetCaddyfile(ctx context.Context, hostID int64) (*model.CaddyfileResponse, error) {
	host, hostPath, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}

	raw, err := m.transport.ReadFile(ctx, host, hostPath)
	if err != nil {
		return nil, fmt.Errorf("read caddyfile %s: %w", hostPath, err)
	}

	mountType := m.detectMountType(ctx, host, containerName, containerPath)
	return &model.CaddyfileResponse{
		HostID:            host.ID,
		HostName:          host.Name,
		Content:           string(raw),
		SHA256:            sha256Hex(raw),
		MountType:         mountType,
		HostCaddyfilePath: hostPath,
		ContainerName:     containerName,
	}, nil
}

// SaveCaddyfile performs conflict detection, mount-aware validation, baseline snapshotting,
// atomic/in-place write, `--force` reload, and automatic rollback + webhook alert on reload failure.
func (m *Manager) SaveCaddyfile(ctx context.Context, hostID int64, req model.SaveCaddyfileRequest, actorIP string) (*model.CaddySaveResponse, error) {
	host, hostPath, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}

	remoteBytes, hadLive, err := m.readLiveOptional(ctx, host, hostPath)
	if err != nil {
		return nil, fmt.Errorf("read live caddyfile %s: %w", hostPath, err)
	}
	remoteContent := string(remoteBytes)
	remoteSHA := ""
	if hadLive {
		remoteSHA = sha256Hex(remoteBytes)
	}

	if !req.Force && hadLive && req.ExpectedSHA256 != remoteSHA {
		return nil, &ConflictError{
			Details: model.CaddyConflictDetails{
				ExpectedSHA256: req.ExpectedSHA256,
				RemoteSHA256:   remoteSHA,
				RemoteContent:  remoteContent,
			},
		}
	}

	mountType := m.detectMountType(ctx, host, containerName, containerPath)

	summary := strings.TrimSpace(req.Summary)
	if summary == "" {
		summary = "Publish Caddyfile"
	}

	return m.validateAndPublish(ctx, host, hostPath, containerPath, containerName, mountType,
		remoteBytes, remoteSHA, hadLive, req.Content, model.CaddyActionPublish, summary, actorIP)
}

// Format formats candidate Caddyfile content using `caddy fmt -` inside the container via stdin.
func (m *Manager) Format(ctx context.Context, hostID int64, content string) (string, error) {
	host, _, _, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return "", err
	}

	cmd := fmt.Sprintf("docker exec -i %s caddy fmt -", model.ShellQuote(containerName))
	res, err := m.transport.ExecWithStdin(ctx, host, cmd, []byte(content))
	if err != nil {
		return "", fmt.Errorf("exec caddy fmt: %w", err)
	}
	if res.ExitCode != 0 {
		out := m.redact(combineExecOutput(res))
		line, msg := parseValidateError(out)
		return "", &ValidateError{
			Details: model.CaddyValidateErrorDetails{
				Line:    line,
				Message: msg,
				Output:  out,
			},
		}
	}
	return res.Stdout, nil
}

// Validate validates candidate Caddyfile content without modifying the live Caddyfile.
func (m *Manager) Validate(ctx context.Context, hostID int64, content string) (*model.CaddyValidateResponse, error) {
	host, hostPath, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}

	mountType := m.detectMountType(ctx, host, containerName, containerPath)
	out, vErr := m.runValidate(ctx, host, hostPath, containerPath, containerName, mountType, content)
	if vErr != nil {
		var ve *ValidateError
		if errors.As(vErr, &ve) {
			return &model.CaddyValidateResponse{
				Valid:   false,
				Output:  ve.Details.Output,
				Line:    ve.Details.Line,
				Message: ve.Details.Message,
			}, nil
		}
		return nil, vErr
	}
	return &model.CaddyValidateResponse{
		Valid:  true,
		Output: out,
	}, nil
}

// ReloadOnly runs `docker exec '<container>' caddy reload --config '<container_caddyfile>' --force`.
func (m *Manager) ReloadOnly(ctx context.Context, hostID int64, actorIP string) (*model.CaddySaveResponse, error) {
	host, _, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}

	cmd := model.DefaultCaddyReloadCmd(containerName, containerPath)
	res, execErr := m.transport.Exec(ctx, host, cmd)
	output := m.redact(formatExecOutput(res, execErr))
	ok := execErr == nil && res != nil && res.ExitCode == 0

	if !ok {
		m.emitReloadFailed(ctx, host, output, false)
		_, _ = m.db.CreateAuditEvent(ctx, &model.AuditEvent{
			EventType:  "caddy.reload_failed",
			Level:      model.AuditLevelError,
			TargetType: "host",
			TargetID:   &host.ID,
			TargetName: host.Name,
			Message:    "Caddy reload failed",
			ActorIP:    actorIP,
		})
	} else {
		_, _ = m.db.CreateAuditEvent(ctx, &model.AuditEvent{
			EventType:  "caddy.reloaded",
			Level:      model.AuditLevelInfo,
			TargetType: "host",
			TargetID:   &host.ID,
			TargetName: host.Name,
			Message:    "Caddy reloaded successfully",
			ActorIP:    actorIP,
		})
	}

	return &model.CaddySaveResponse{
		ReloadOK: ok,
		Output:   output,
	}, nil
}

// Snapshots lists historical Caddyfile snapshots for hostID.
func (m *Manager) Snapshots(ctx context.Context, hostID int64, limit int) ([]model.CaddySnapshotDTO, error) {
	if _, err := m.db.GetHost(ctx, hostID); err != nil {
		return nil, err
	}
	snaps, err := m.db.ListCaddySnapshotsByHost(ctx, hostID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]model.CaddySnapshotDTO, 0, len(snaps))
	for i := range snaps {
		out = append(out, snapshotToDTO(&snaps[i]))
	}
	return out, nil
}

// SnapshotDiff compares a historical snapshot against the current live Caddyfile.
func (m *Manager) SnapshotDiff(ctx context.Context, hostID, snapID int64) (*model.CaddyDiffResponse, error) {
	host, hostPath, _, _, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}
	snap, err := m.db.GetCaddySnapshot(ctx, snapID)
	if err != nil {
		return nil, err
	}
	if snap.HostID != hostID {
		return nil, ErrSnapshotHostMismatch
	}

	liveBytes, hadLive, err := m.readLiveOptional(ctx, host, hostPath)
	if err != nil {
		return nil, fmt.Errorf("read live caddyfile: %w", err)
	}
	currentContent := string(liveBytes)
	currentSHA := ""
	if hadLive {
		currentSHA = sha256Hex(liveBytes)
	}

	diffText := buildUnifiedDiff(
		fmt.Sprintf("snapshot v%d (%s)", snap.Version, snap.SHA256),
		fmt.Sprintf("current (%s)", currentSHA),
		snap.Content,
		currentContent,
	)

	return &model.CaddyDiffResponse{
		SnapshotID:      snap.ID,
		Version:         snap.Version,
		SnapshotSHA256:  snap.SHA256,
		CurrentSHA256:   currentSHA,
		SnapshotContent: snap.Content,
		CurrentContent:  currentContent,
		DiffText:        diffText,
	}, nil
}

// Rollback restores a historical snapshot, validates it, writes it safely, and reloads Caddy.
func (m *Manager) Rollback(ctx context.Context, hostID, snapID int64, actorIP string) (*model.CaddySaveResponse, error) {
	host, hostPath, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}
	snap, err := m.db.GetCaddySnapshot(ctx, snapID)
	if err != nil {
		return nil, err
	}
	if snap.HostID != hostID {
		return nil, ErrSnapshotHostMismatch
	}

	remoteBytes, hadLive, err := m.readLiveOptional(ctx, host, hostPath)
	if err != nil {
		return nil, fmt.Errorf("read live caddyfile %s: %w", hostPath, err)
	}
	remoteSHA := ""
	if hadLive {
		remoteSHA = sha256Hex(remoteBytes)
	}

	mountType := m.detectMountType(ctx, host, containerName, containerPath)
	summary := fmt.Sprintf("Rollback to v%d", snap.Version)

	return m.validateAndPublish(ctx, host, hostPath, containerPath, containerName, mountType,
		remoteBytes, remoteSHA, hadLive, snap.Content, model.CaddyActionRollback, summary, actorIP)
}

// ContainerInfo inspects the host's Caddy Docker container and retrieves sanitized tail logs.
func (m *Manager) ContainerInfo(ctx context.Context, hostID int64, tailLines int) (*model.CaddyContainerInfo, error) {
	host, _, containerPath, containerName, err := m.loadHostAndValidate(ctx, hostID)
	if err != nil {
		return nil, err
	}

	if tailLines <= 0 {
		tailLines = defaultTailLines
	}
	if tailLines > maxTailLines {
		tailLines = maxTailLines
	}

	info := &model.CaddyContainerInfo{
		HostID:        host.ID,
		ContainerName: containerName,
		Status:        model.CaddyStatusUnknown,
		MountType:     MountTypeUnknown,
		Mounts:        make([]string, 0),
		InspectedAt:   m.clock().UTC(),
	}
	if host.Mode == model.HostModeLocal {
		info.MountType = MountTypeLocal
	}

	inspectCmd := fmt.Sprintf("docker inspect --format '{{json .}}' %s", model.ShellQuote(containerName))
	inspectRes, inspectErr := m.transport.Exec(ctx, host, inspectCmd)
	if inspectErr == nil && inspectRes != nil && inspectRes.ExitCode == 0 {
		if obj, parseErr := parseDockerInspect(inspectRes.Stdout); parseErr == nil {
			if obj.State.Status != "" {
				info.Status = obj.State.Status
			} else if obj.State.Running {
				info.Status = model.CaddyStatusRunning
			} else {
				info.Status = model.CaddyStatusStopped
			}
			info.Running = obj.State.Running
			info.Image = obj.Config.Image
			info.MountType = resolveMountTypeFromMounts(obj.Mounts, containerPath, host.Mode)
			for _, mt := range obj.Mounts {
				info.Mounts = append(info.Mounts, fmt.Sprintf("%s: %s -> %s (rw=%v)", mt.Type, mt.Source, mt.Destination, mt.RW))
			}
		}
	} else {
		errText := m.redact(formatExecOutput(inspectRes, inspectErr))
		if errText != "" {
			info.Logs = errText
		}
	}

	logsCmd := fmt.Sprintf("docker logs --tail %d %s", tailLines, model.ShellQuote(containerName))
	logsRes, logsErr := m.transport.Exec(ctx, host, logsCmd)
	if logsErr == nil && logsRes != nil {
		combined := combineExecOutput(logsRes)
		info.Logs = m.redact(combined)
	} else if logsErr != nil && info.Logs == "" {
		info.Logs = m.redact(logsErr.Error())
	}

	return info, nil
}

func (m *Manager) validateAndPublish(
	ctx context.Context,
	host *model.Host,
	hostPath, containerPath, containerName, mountType string,
	remoteBytes []byte,
	remoteSHA string,
	hadLive bool,
	newContent, action, summary, actorIP string,
) (*model.CaddySaveResponse, error) {
	if _, err := m.runValidate(ctx, host, hostPath, containerPath, containerName, mountType, newContent); err != nil {
		return nil, err
	}

	// Ensure pre-write live content is captured as a baseline snapshot if missing or drifted.
	if hadLive {
		existing, err := m.db.ListCaddySnapshotsByHost(ctx, host.ID, 1)
		if err == nil && (len(existing) == 0 || existing[0].SHA256 != remoteSHA) {
			_, _ = m.db.CreateCaddySnapshot(ctx, &model.CaddySnapshot{
				HostID:       host.ID,
				Content:      string(remoteBytes),
				SHA256:       remoteSHA,
				Action:       model.CaddyActionBaseline,
				Summary:      "Pre-edit baseline",
				ReloadOK:     true,
				ReloadOutput: "",
			})
		}
	}

	newBytes := []byte(newContent)
	newSHA := sha256Hex(newBytes)

	if err := m.writeCaddyfile(ctx, host, hostPath, mountType, newBytes); err != nil {
		return nil, fmt.Errorf("write caddyfile %s: %w", hostPath, err)
	}

	reloadCmd := model.DefaultCaddyReloadCmd(containerName, containerPath)
	reloadRes, reloadErr := m.transport.Exec(ctx, host, reloadCmd)
	reloadOutput := m.redact(formatExecOutput(reloadRes, reloadErr))
	reloadOK := reloadErr == nil && reloadRes != nil && reloadRes.ExitCode == 0

	if !reloadOK {
		// Automatic rollback to previous content + reload old config.
		var rbErr error
		if hadLive {
			rbErr = m.writeCaddyfile(ctx, host, hostPath, mountType, remoteBytes)
		} else {
			rbErr = m.transport.RemoveFile(ctx, host, hostPath)
		}
		if rbErr != nil {
			reloadOutput = strings.TrimSpace(reloadOutput + "\nrollback write error: " + m.redact(rbErr.Error()))
		} else {
			rbRes, rbExecErr := m.transport.Exec(ctx, host, reloadCmd)
			if rbExecErr != nil || rbRes == nil || rbRes.ExitCode != 0 {
				reloadOutput = strings.TrimSpace(reloadOutput + "\nrollback reload output: " + m.redact(formatExecOutput(rbRes, rbExecErr)))
			}
		}

		snap := &model.CaddySnapshot{
			HostID:       host.ID,
			Content:      newContent,
			SHA256:       newSHA,
			Action:       action,
			Summary:      summary,
			ReloadOK:     false,
			ReloadOutput: reloadOutput,
		}
		if _, err := m.db.CreateCaddySnapshot(ctx, snap); err != nil {
			return nil, fmt.Errorf("record failed snapshot: %w", err)
		}

		m.emitReloadFailed(ctx, host, reloadOutput, rbErr == nil)
		_, _ = m.db.CreateAuditEvent(ctx, &model.AuditEvent{
			EventType:  "caddy.reload_failed",
			Level:      model.AuditLevelError,
			TargetType: "host",
			TargetID:   &host.ID,
			TargetName: host.Name,
			Message:    fmt.Sprintf("Caddy reload failed and rolled back (%s)", summary),
			ActorIP:    actorIP,
		})

		dto := snapshotToDTO(snap)
		return &model.CaddySaveResponse{
			SHA256:     remoteSHA,
			ReloadOK:   false,
			Output:     reloadOutput,
			RolledBack: rbErr == nil,
			Snapshot:   &dto,
		}, nil
	}

	snap := &model.CaddySnapshot{
		HostID:       host.ID,
		Content:      newContent,
		SHA256:       newSHA,
		Action:       action,
		Summary:      summary,
		ReloadOK:     true,
		ReloadOutput: reloadOutput,
	}
	if _, err := m.db.CreateCaddySnapshot(ctx, snap); err != nil {
		return nil, fmt.Errorf("record caddy snapshot: %w", err)
	}

	evtType := "caddy.published"
	if action == model.CaddyActionRollback {
		evtType = "caddy.rolled_back"
	}
	_, _ = m.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  evtType,
		Level:      model.AuditLevelInfo,
		TargetType: "host",
		TargetID:   &host.ID,
		TargetName: host.Name,
		Message:    fmt.Sprintf("%s (v%d)", summary, snap.Version),
		ActorIP:    actorIP,
	})

	dto := snapshotToDTO(snap)
	return &model.CaddySaveResponse{
		SHA256:     newSHA,
		ReloadOK:   true,
		Output:     reloadOutput,
		RolledBack: false,
		Snapshot:   &dto,
	}, nil
}

func (m *Manager) writeCaddyfile(ctx context.Context, host *model.Host, hostPath, mountType string, data []byte) error {
	if mountType == MountTypeFile {
		return m.transport.WriteFileInPlace(ctx, host, hostPath, data)
	}
	return m.transport.WriteFileAtomic(ctx, host, hostPath, data, 0o644)
}

func (m *Manager) runValidate(ctx context.Context, host *model.Host, hostPath, containerPath, containerName, mountType, content string) (string, error) {
	if mountType == MountTypeDir {
		suffix := randomHex(6)
		tmpName := ".Caddyfile.validate." + suffix + ".tmp"
		hostTmpPath := path.Join(path.Dir(hostPath), tmpName)
		containerTmpPath := path.Join(path.Dir(containerPath), tmpName)

		if err := m.transport.WriteFileAtomic(ctx, host, hostTmpPath, []byte(content), 0o644); err != nil {
			return "", fmt.Errorf("write validation temp file %s: %w", hostTmpPath, err)
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = m.transport.RemoveFile(cleanupCtx, host, hostTmpPath)
		}()

		cmd := fmt.Sprintf("docker exec %s caddy validate --config %s --adapter caddyfile",
			model.ShellQuote(containerName), model.ShellQuote(containerTmpPath))
		res, err := m.transport.Exec(ctx, host, cmd)
		out := m.redact(formatExecOutput(res, err))
		if err != nil || res == nil || res.ExitCode != 0 {
			line, msg := parseValidateError(out)
			return "", &ValidateError{
				Details: model.CaddyValidateErrorDetails{
					Line:    line,
					Message: msg,
					Output:  out,
				},
			}
		}
		return out, nil
	}

	// Single-file bind mount (or local/unknown): validate inside container /tmp via stdin
	// so we never mutate the bind-mounted host file before validation passes.
	cmd := fmt.Sprintf(
		"docker exec -i %s sh -c 'tmp=$(mktemp /tmp/Caddyfile.XXXXXX) && cat > \"$tmp\" && caddy validate --config \"$tmp\" --adapter caddyfile; rc=$?; rm -f \"$tmp\"; exit $rc'",
		model.ShellQuote(containerName),
	)
	res, err := m.transport.ExecWithStdin(ctx, host, cmd, []byte(content))
	out := m.redact(formatExecOutput(res, err))
	if err != nil || res == nil || res.ExitCode != 0 {
		line, msg := parseValidateError(out)
		return "", &ValidateError{
			Details: model.CaddyValidateErrorDetails{
				Line:    line,
				Message: msg,
				Output:  out,
			},
		}
	}
	return out, nil
}

func (m *Manager) detectMountType(ctx context.Context, host *model.Host, containerName, containerPath string) string {
	cmd := fmt.Sprintf("docker inspect --format '{{json .Mounts}}' %s", model.ShellQuote(containerName))
	res, err := m.transport.Exec(ctx, host, cmd)
	if err == nil && res != nil && res.ExitCode == 0 {
		if mounts, parseErr := parseDockerMounts(res.Stdout); parseErr == nil {
			return resolveMountTypeFromMounts(mounts, containerPath, host.Mode)
		}
	}
	if host.Mode == model.HostModeLocal {
		return MountTypeLocal
	}
	return MountTypeUnknown
}

func (m *Manager) loadHostAndValidate(ctx context.Context, hostID int64) (*model.Host, string, string, string, error) {
	host, err := m.db.GetHost(ctx, hostID)
	if err != nil {
		return nil, "", "", "", err
	}
	if !host.CaddyEnabled {
		return nil, "", "", "", ErrCaddyDisabled
	}
	containerName := strings.TrimSpace(host.CaddyContainer)
	if containerName == "" {
		containerName = defaultContainerName
	}
	if err := model.ValidateContainerName(containerName); err != nil {
		return nil, "", "", "", err
	}
	hostPath := strings.TrimSpace(host.CaddyHostCaddyfile)
	if hostPath == "" {
		hostPath = defaultHostCaddyfile
	}
	containerPath := strings.TrimSpace(host.CaddyContainerCaddyfile)
	if containerPath == "" {
		containerPath = defaultContainerCaddyfile
	}
	return host, hostPath, containerPath, containerName, nil
}

func (m *Manager) readLiveOptional(ctx context.Context, host *model.Host, hostPath string) ([]byte, bool, error) {
	data, err := m.transport.ReadFile(ctx, host, hostPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func (m *Manager) emitReloadFailed(ctx context.Context, host *model.Host, output string, rolledBack bool) {
	if m.notifier == nil {
		return
	}
	_ = m.notifier.Emit(ctx, model.WebhookEvent{
		Event:   model.WebhookEventCaddyReloadFailed,
		Level:   model.AuditLevelError,
		Title:   fmt.Sprintf("Caddy reload failed on %s", host.Name),
		Message: fmt.Sprintf("Failed to reload Caddy container %q on host %q", host.CaddyContainer, host.Name),
		Host: &model.WebhookHostRef{
			ID:   host.ID,
			Name: host.Name,
			Host: host.Host,
		},
		Error: output,
		Metadata: map[string]any{
			"container":   host.CaddyContainer,
			"rolled_back": rolledBack,
		},
	})
}

func (m *Manager) redact(s string) string {
	if s == "" || m.redactor == nil {
		return s
	}
	return m.redactor.Redact(s)
}

func parseDockerMounts(raw string) ([]dockerMount, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var mounts []dockerMount
	if err := json.Unmarshal([]byte(trimmed), &mounts); err != nil {
		return nil, err
	}
	return mounts, nil
}

func parseDockerInspect(raw string) (*dockerInspectObject, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty docker inspect output")
	}
	if strings.HasPrefix(trimmed, "[") {
		var arr []dockerInspectObject
		if err := json.Unmarshal([]byte(trimmed), &arr); err != nil {
			return nil, err
		}
		if len(arr) == 0 {
			return nil, errors.New("docker inspect returned empty array")
		}
		return &arr[0], nil
	}
	var obj dockerInspectObject
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

func resolveMountTypeFromMounts(mounts []dockerMount, containerCaddyfile, hostMode string) string {
	target := path.Clean(containerCaddyfile)
	bestLen := -1
	bestType := ""

	for _, mt := range mounts {
		dest := path.Clean(strings.TrimSpace(mt.Destination))
		if dest == "" || dest == "." {
			continue
		}
		if dest == target {
			if len(dest) > bestLen {
				bestLen = len(dest)
				bestType = MountTypeFile
			}
			continue
		}
		if dest == "/" || strings.HasPrefix(target, dest+"/") {
			if len(dest) > bestLen {
				bestLen = len(dest)
				bestType = MountTypeDir
			}
		}
	}

	if bestType != "" {
		return bestType
	}
	if hostMode == model.HostModeLocal {
		return MountTypeLocal
	}
	return MountTypeUnknown
}

var (
	reCaddyFileLine = regexp.MustCompile(`(?i)(?:Caddyfile[^:\s]*|/[^:\s]+):(\d+)(?::\d+)?\s*(?:-|—|:)\s*(.+)`)
	reGenericLine   = regexp.MustCompile(`(?i)\bline\s+(\d+)\b[:\s-]*(.*)`)
)

func parseValidateError(output string) (int, string) {
	lines := strings.Split(output, "\n")
	var fallbackMsg string
	for _, rawLine := range lines {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" {
			continue
		}
		if fallbackMsg == "" {
			fallbackMsg = trimmed
		}
		if matches := reCaddyFileLine.FindStringSubmatch(trimmed); len(matches) == 3 {
			var lineNum int
			_, _ = fmt.Sscanf(matches[1], "%d", &lineNum)
			msg := strings.TrimSpace(matches[2])
			if msg == "" {
				msg = trimmed
			}
			return lineNum, msg
		}
		if matches := reGenericLine.FindStringSubmatch(trimmed); len(matches) == 3 {
			var lineNum int
			_, _ = fmt.Sscanf(matches[1], "%d", &lineNum)
			msg := strings.TrimSpace(matches[2])
			if msg == "" {
				msg = trimmed
			}
			return lineNum, msg
		}
	}
	if fallbackMsg == "" {
		fallbackMsg = "Caddy configuration validation failed"
	}
	return 0, fallbackMsg
}

func combineExecOutput(res *model.ExecResult) string {
	if res == nil {
		return ""
	}
	out := strings.TrimSpace(res.Stdout)
	errOut := strings.TrimSpace(res.Stderr)
	switch {
	case out != "" && errOut != "":
		return out + "\n" + errOut
	case errOut != "":
		return errOut
	default:
		return out
	}
}

func formatExecOutput(res *model.ExecResult, execErr error) string {
	combined := combineExecOutput(res)
	if execErr != nil {
		if combined == "" {
			return execErr.Error()
		}
		return combined + "\n" + execErr.Error()
	}
	return combined
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func snapshotToDTO(s *model.CaddySnapshot) model.CaddySnapshotDTO {
	return model.CaddySnapshotDTO{
		ID:           s.ID,
		HostID:       s.HostID,
		Version:      s.Version,
		Content:      s.Content,
		SHA256:       s.SHA256,
		Action:       s.Action,
		Summary:      s.Summary,
		ReloadOK:     s.ReloadOK,
		ReloadOutput: s.ReloadOutput,
		CreatedAt:    s.CreatedAt,
	}
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	line string
}

func buildUnifiedDiff(fromLabel, toLabel, fromText, toText string) string {
	if fromText == toText {
		return ""
	}
	a := splitLines(fromText)
	b := splitLines(toText)

	ops := lcsDiff(a, b)
	var sb strings.Builder
	sb.WriteString("--- ")
	sb.WriteString(fromLabel)
	sb.WriteByte('\n')
	sb.WriteString("+++ ")
	sb.WriteString(toLabel)
	sb.WriteByte('\n')
	sb.WriteString(fmt.Sprintf("@@ -1,%d +1,%d @@\n", len(a), len(b)))
	for _, op := range ops {
		sb.WriteByte(op.kind)
		sb.WriteString(op.line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

func lcsDiff(a, b []string) []diffOp {
	n := len(a)
	m := len(b)
	// Bound DP table for extremely large files by falling back to simple replacement.
	if n*m > 250000 {
		ops := make([]diffOp, 0, n+m)
		for _, line := range a {
			ops = append(ops, diffOp{kind: '-', line: line})
		}
		for _, line := range b {
			ops = append(ops, diffOp{kind: '+', line: line})
		}
		return ops
	}

	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			ops = append(ops, diffOp{kind: ' ', line: a[i]})
			i++
			j++
		} else if dp[i+1][j] >= dp[i][j+1] {
			ops = append(ops, diffOp{kind: '-', line: a[i]})
			i++
		} else {
			ops = append(ops, diffOp{kind: '+', line: b[j]})
			j++
		}
	}
	for i < n {
		ops = append(ops, diffOp{kind: '-', line: a[i]})
		i++
	}
	for j < m {
		ops = append(ops, diffOp{kind: '+', line: b[j]})
		j++
	}
	return ops
}
