package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// ErrCertificateNotIssued indicates a deployment cannot run because certificate files do not exist yet.
var ErrCertificateNotIssued = errors.New("certificate has not been issued yet")

// Engine implements model.DeployTrigger for concurrent fan-out and single-target push deployments.
type Engine struct {
	db         *db.DB
	transport  model.RemoteTransport
	notifier   model.Notifier
	redactor   *crypto.SecretRedactor
	logger     *slog.Logger
	httpClient *http.Client
}

// NewEngine constructs a push deployment engine.
func NewEngine(database *db.DB, transport model.RemoteTransport, notifier model.Notifier, redactor *crypto.SecretRedactor, logger *slog.Logger) *Engine {
	return &Engine{
		db:         database,
		transport:  transport,
		notifier:   notifier,
		redactor:   redactor,
		logger:     logger,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

var _ model.DeployTrigger = (*Engine)(nil)

// FanoutCertificate pushes an issued certificate concurrently to all enabled deployments,
// isolating per-target failures so one failing target never cancels or blocks others.
func (e *Engine) FanoutCertificate(ctx context.Context, certID int64, triggerType string, certJobID *int64) error {
	cert, err := e.db.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}
	deps, err := e.db.ListDeploymentsByCertificate(ctx, certID)
	if err != nil {
		return err
	}

	var enabled []model.Deployment
	for _, d := range deps {
		if d.Enabled {
			enabled = append(enabled, d)
		}
	}
	if len(enabled) == 0 {
		return nil
	}

	if triggerType == "" {
		triggerType = model.TriggerAuto
	}

	type targetOutcome struct {
		dep model.Deployment
		err error
	}
	outcomes := make([]targetOutcome, len(enabled))
	var wg sync.WaitGroup

	for i := range enabled {
		wg.Add(1)
		go func(idx int, dep model.Deployment) {
			defer wg.Done()
			// Per-target failure isolation: each target runs independently without cancelling siblings.
			_, deployErr := e.deployOne(ctx, cert, &dep, triggerType, certJobID, false)
			outcomes[idx] = targetOutcome{dep: dep, err: deployErr}
		}(i, enabled[i])
	}
	wg.Wait()

	var errMsgs []string
	for _, out := range outcomes {
		if out.err != nil {
			errMsgs = append(errMsgs, fmt.Sprintf("%s (id=%d): %v", out.dep.Name, out.dep.ID, out.err))
		}
	}

	if len(errMsgs) > 0 {
		return fmt.Errorf("%d/%d deployments failed: %s", len(errMsgs), len(enabled), strings.Join(errMsgs, "; "))
	}

	e.emitEvent(ctx, model.WebhookEvent{
		Event:   model.WebhookEventCertDeployed,
		Level:   model.AuditLevelInfo,
		Title:   "Certificate deployed to all targets",
		Message: fmt.Sprintf("Certificate %s deployed to %d target(s)", cert.Domain, len(enabled)),
		Certificate: &model.WebhookCertRef{
			ID:     cert.ID,
			Domain: cert.Domain,
		},
		Metadata: map[string]any{
			"trigger_type": triggerType,
			"target_count": len(enabled),
		},
	})

	return nil
}

// DeployTarget pushes a certificate to a single deployment target.
func (e *Engine) DeployTarget(ctx context.Context, deploymentID int64, triggerType string) (*model.DeployLog, error) {
	dep, err := e.db.GetDeployment(ctx, deploymentID)
	if err != nil {
		return nil, err
	}
	cert, err := e.db.GetCertificate(ctx, dep.CertificateID)
	if err != nil {
		return nil, err
	}
	if triggerType == "" {
		triggerType = model.TriggerManual
	}
	return e.deployOne(ctx, cert, dep, triggerType, nil, true)
}

func (e *Engine) deployOne(
	ctx context.Context,
	cert *model.Certificate,
	dep *model.Deployment,
	triggerType string,
	certJobID *int64,
	emitSuccessEvent bool,
) (*model.DeployLog, error) {
	host, err := e.db.GetHost(ctx, dep.HostID)
	if err != nil {
		return nil, err
	}

	fullchainBytes, privkeyBytes, issuerBytes, expectedFP, err := loadCertificateFiles(cert)
	if err != nil {
		return nil, err
	}

	logEntry := &model.DeployLog{
		DeploymentID:  dep.ID,
		CertificateID: cert.ID,
		HostID:        host.ID,
		CertJobID:     certJobID,
		TriggerType:   triggerType,
		Status:        model.JobStatusRunning,
		StartedAt:     time.Now().UTC(),
	}
	if _, err := e.db.CreateDeployLog(ctx, logEntry); err != nil {
		return nil, err
	}
	isInitialDeploy := dep.LastDeployedAt == nil
	_ = e.db.UpdateDeploymentStatus(ctx, dep.ID, model.JobStatusRunning, dep.LastCertFingerprint, "", nil)

	finishFail := func(errMsg string, exitCode *int, stdout, stderr string, tlsVerified bool, tlsObservedFP string) (*model.DeployLog, error) {
		now := time.Now().UTC()
		errMsg = e.redact(errMsg)
		stdout = e.redact(stdout)
		stderr = e.redact(stderr)

		logEntry.Status = model.JobStatusFailed
		logEntry.ExitCode = exitCode
		logEntry.Stdout = stdout
		logEntry.Stderr = stderr
		logEntry.TLSVerified = tlsVerified
		logEntry.TLSObservedFP = tlsObservedFP
		logEntry.ErrorMessage = errMsg
		logEntry.FinishedAt = &now

		_ = e.db.UpdateDeployLog(ctx, logEntry)
		_ = e.db.UpdateDeploymentStatus(ctx, dep.ID, model.JobStatusFailed, dep.LastCertFingerprint, errMsg, nil)

		e.emitEvent(ctx, model.WebhookEvent{
			Event:   model.WebhookEventDeployFailed,
			Level:   model.AuditLevelError,
			Title:   "Certificate deployment failed",
			Message: fmt.Sprintf("Deployment %q for %s on host %q failed: %s", dep.Name, cert.Domain, host.Name, errMsg),
			Certificate: &model.WebhookCertRef{
				ID:     cert.ID,
				Domain: cert.Domain,
			},
			Host: &model.WebhookHostRef{
				ID:   host.ID,
				Name: host.Name,
				Host: host.Host,
			},
			Deployment: &model.WebhookDeployRef{
				ID:   dep.ID,
				Name: dep.Name,
			},
			Error: errMsg,
		})

		return logEntry, errors.New(errMsg)
	}

	fullchainPath, privkeyPath, issuerPath := resolveDeploymentPaths(cert, dep, host)
	if fullchainPath == "" || privkeyPath == "" {
		return finishFail("deployment fullchain_path and privkey_path must not be empty", nil, "", "", false, "")
	}

	certMode := parseFileMode(dep.CertFileMode, 0o644)
	keyMode := parseFileMode(dep.KeyFileMode, 0o600)

	var (
		exitCode  *int
		stdout    string
		stderr    string
		reloadErr error
		writeErr  error
	)
	_ = model.WithTransportSession(ctx, e.transport, host, func(sCtx context.Context) error {
		if err := e.transport.WriteFileAtomic(sCtx, host, fullchainPath, fullchainBytes, certMode); err != nil {
			writeErr = fmt.Errorf("write fullchain %s: %w", fullchainPath, err)
			return writeErr
		}
		if err := e.transport.WriteFileAtomic(sCtx, host, privkeyPath, privkeyBytes, keyMode); err != nil {
			writeErr = fmt.Errorf("write privkey %s: %w", privkeyPath, err)
			return writeErr
		}
		if issuerPath != "" && len(issuerBytes) > 0 {
			if err := e.transport.WriteFileAtomic(sCtx, host, issuerPath, issuerBytes, certMode); err != nil {
				writeErr = fmt.Errorf("write issuer %s: %w", issuerPath, err)
				return writeErr
			}
		}

		exitCode, stdout, stderr, reloadErr = e.executeReload(sCtx, cert, dep, host, fullchainPath, privkeyPath)
		return nil
	})
	if writeErr != nil {
		return finishFail(writeErr.Error(), nil, "", "", false, "")
	}
	if reloadErr != nil {
		return finishFail(reloadErr.Error(), exitCode, stdout, stderr, false, "")
	}

	tlsVerified := false
	tlsObservedFP := ""
	tlsWarning := ""
	deployedFP := expectedFP
	if dep.TLSVerifyEnabled && exitCode != nil && *exitCode == 0 {
		vHost, vPort, vSNI := resolveTLSVerifyTarget(cert, dep, host)
		observedFP, verifyErr := VerifyTLSFingerprint(ctx, vHost, vPort, vSNI, expectedFP)
		tlsObservedFP = observedFP
		if verifyErr != nil {
			if isInitialDeploy {
				deployedFP = ""
				tlsWarning = e.redact(fmt.Sprintf(
					"Initial deploy succeeded, but live TLS verification on %s:%d (SNI %s) has not matched yet (%v). Update Caddyfile/server config to use the new certificate path and re-push to complete strict verification.",
					vHost, vPort, vSNI, verifyErr,
				))
			} else {
				return finishFail(fmt.Sprintf("TLS verification failed on %s:%d (SNI %s): %v", vHost, vPort, vSNI, verifyErr), exitCode, stdout, stderr, false, observedFP)
			}
		} else {
			tlsVerified = true
		}
	}

	now := time.Now().UTC()
	logEntry.Status = model.JobStatusSuccess
	logEntry.ExitCode = exitCode
	logEntry.Stdout = e.redact(stdout)
	logEntry.Stderr = e.redact(stderr)
	logEntry.TLSVerified = tlsVerified
	logEntry.TLSObservedFP = tlsObservedFP
	logEntry.ErrorMessage = tlsWarning
	logEntry.FinishedAt = &now

	if err := e.db.UpdateDeployLog(ctx, logEntry); err != nil {
		return logEntry, err
	}
	if err := e.db.UpdateDeploymentStatus(ctx, dep.ID, model.JobStatusSuccess, deployedFP, tlsWarning, &now); err != nil {
		return logEntry, err
	}

	if emitSuccessEvent {
		e.emitEvent(ctx, model.WebhookEvent{
			Event:   model.WebhookEventCertDeployed,
			Level:   model.AuditLevelInfo,
			Title:   "Certificate deployed",
			Message: fmt.Sprintf("Deployment %q for %s on host %q succeeded", dep.Name, cert.Domain, host.Name),
			Certificate: &model.WebhookCertRef{
				ID:     cert.ID,
				Domain: cert.Domain,
			},
			Host: &model.WebhookHostRef{
				ID:   host.ID,
				Name: host.Name,
				Host: host.Host,
			},
			Deployment: &model.WebhookDeployRef{
				ID:   dep.ID,
				Name: dep.Name,
			},
		})
	}

	return logEntry, nil
}

func (e *Engine) executeReload(
	ctx context.Context,
	cert *model.Certificate,
	dep *model.Deployment,
	host *model.Host,
	fullchainPath, privkeyPath string,
) (*int, string, string, error) {
	mode := dep.ReloadMode
	if mode == "" {
		if dep.Template == model.DeployTemplateCaddyDocker {
			mode = model.ReloadModeDockerExec
		} else {
			mode = model.ReloadModeNone
		}
	}

	switch mode {
	case model.ReloadModeNone:
		zero := 0
		return &zero, "", "", nil

	case model.ReloadModeDockerExec:
		cmd := strings.TrimSpace(dep.ReloadCommand)
		if cmd == "" {
			container := strings.TrimSpace(host.CaddyContainer)
			if container == "" {
				container = "caddy"
			}
			if err := model.ValidateContainerName(container); err != nil {
				return nil, "", "", fmt.Errorf("invalid caddy container name: %w", err)
			}
			cmd = model.DefaultCaddyReloadCmd(container, host.CaddyContainerCaddyfile)
		}
		res, err := e.transport.Exec(ctx, host, cmd)
		if err != nil {
			return nil, "", "", fmt.Errorf("reload docker_exec: %w", err)
		}
		code := res.ExitCode
		if code != 0 {
			return &code, res.Stdout, res.Stderr, fmt.Errorf("reload command exited with code %d: %s", code, firstNonEmpty(res.Stderr, res.Stdout))
		}
		return &code, res.Stdout, res.Stderr, nil

	case model.ReloadModeCustomCmd:
		cmd := strings.TrimSpace(dep.ReloadCommand)
		if cmd == "" {
			return nil, "", "", errors.New("reload_command is required for custom_cmd mode")
		}
		res, err := e.transport.Exec(ctx, host, cmd)
		if err != nil {
			return nil, "", "", fmt.Errorf("reload custom_cmd: %w", err)
		}
		code := res.ExitCode
		if code != 0 {
			return &code, res.Stdout, res.Stderr, fmt.Errorf("reload command exited with code %d: %s", code, firstNonEmpty(res.Stderr, res.Stdout))
		}
		return &code, res.Stdout, res.Stderr, nil

	case model.ReloadModeCaddyAdminAPI:
		return e.executeCaddyAdminAPIReload(ctx, dep, host)

	case model.ReloadModeWebhook:
		return e.executeWebhookReload(ctx, cert, dep, host, fullchainPath, privkeyPath)

	default:
		return nil, "", "", fmt.Errorf("unsupported reload_mode %q", mode)
	}
}

func (e *Engine) executeCaddyAdminAPIReload(ctx context.Context, dep *model.Deployment, host *model.Host) (*int, string, string, error) {
	rawURL := strings.TrimSpace(dep.ReloadWebhookURL)
	if rawURL == "" {
		rawURL = "http://127.0.0.1:2019/load"
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, "", "", fmt.Errorf("invalid caddy admin api URL %q", rawURL)
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/load"
	}

	contentType := "application/json"
	var body []byte

	if strings.HasSuffix(parsed.Path, "/load") && host.CaddyHostCaddyfile != "" {
		if cfBytes, readErr := e.transport.ReadFile(ctx, host, host.CaddyHostCaddyfile); readErr == nil && len(cfBytes) > 0 {
			contentType = "text/caddyfile"
			body = cfBytes
		} else {
			body = []byte("{}")
		}
	} else {
		body = []byte("{}")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		code := 1
		return &code, "", err.Error(), fmt.Errorf("caddy admin api request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	respStr := string(respBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := 1
		return &code, "", respStr, fmt.Errorf("caddy admin api returned HTTP %d: %s", resp.StatusCode, respStr)
	}
	zero := 0
	return &zero, fmt.Sprintf("HTTP %d %s", resp.StatusCode, respStr), "", nil
}

func (e *Engine) executeWebhookReload(ctx context.Context, cert *model.Certificate, dep *model.Deployment, host *model.Host, fullchainPath, privkeyPath string) (*int, string, string, error) {
	rawURL := strings.TrimSpace(dep.ReloadWebhookURL)
	if rawURL == "" {
		return nil, "", "", errors.New("reload_webhook_url is required for webhook reload mode")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, "", "", fmt.Errorf("invalid reload_webhook_url %q", rawURL)
	}

	payload, _ := json.Marshal(map[string]any{
		"event":          "deploy.reload",
		"certificate_id": cert.ID,
		"domain":         cert.Domain,
		"deployment_id":  dep.ID,
		"host_id":        host.ID,
		"fullchain_path": fullchainPath,
		"privkey_path":   privkeyPath,
		"timestamp":      time.Now().UTC(),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		code := 1
		return &code, "", err.Error(), fmt.Errorf("reload webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	respStr := string(respBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := 1
		return &code, "", respStr, fmt.Errorf("reload webhook returned HTTP %d: %s", resp.StatusCode, respStr)
	}
	zero := 0
	return &zero, fmt.Sprintf("HTTP %d %s", resp.StatusCode, respStr), "", nil
}

func (e *Engine) emitEvent(ctx context.Context, evt model.WebhookEvent) {
	if e.notifier == nil {
		return
	}
	if err := e.notifier.Emit(ctx, evt); err != nil && e.logger != nil {
		e.logger.Warn("failed to emit webhook event", "event", evt.Event, "error", e.redact(err.Error()))
	}
}

func (e *Engine) redact(s string) string {
	if e.redactor == nil || s == "" {
		return s
	}
	return e.redactor.Redact(s)
}

func loadCertificateFiles(cert *model.Certificate) (fullchain, privkey, issuer []byte, fingerprint string, err error) {
	if strings.TrimSpace(cert.CertDir) == "" {
		return nil, nil, nil, "", ErrCertificateNotIssued
	}
	fullchainPath := filepath.Join(cert.CertDir, "fullchain.pem")
	privkeyPath := filepath.Join(cert.CertDir, "privkey.pem")
	issuerPath := filepath.Join(cert.CertDir, "issuer.pem")

	fullchain, err = os.ReadFile(fullchainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, "", fmt.Errorf("%w: missing %s", ErrCertificateNotIssued, fullchainPath)
		}
		return nil, nil, nil, "", fmt.Errorf("read fullchain.pem: %w", err)
	}
	privkey, err = os.ReadFile(privkeyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil, "", fmt.Errorf("%w: missing %s", ErrCertificateNotIssued, privkeyPath)
		}
		return nil, nil, nil, "", fmt.Errorf("read privkey.pem: %w", err)
	}
	if b, readErr := os.ReadFile(issuerPath); readErr == nil {
		issuer = b
	}

	fingerprint = strings.ToLower(strings.TrimSpace(cert.FingerprintSHA256))
	if fingerprint == "" {
		fp, fpErr := model.ParseLeafFingerprintSHA256(fullchain)
		if fpErr != nil {
			return nil, nil, nil, "", fmt.Errorf("compute leaf fingerprint: %w", fpErr)
		}
		fingerprint = strings.ToLower(fp)
	}
	return fullchain, privkey, issuer, fingerprint, nil
}

func resolveDeploymentPaths(cert *model.Certificate, dep *model.Deployment, host *model.Host) (fullchain, privkey, issuer string) {
	fullchain = strings.TrimSpace(dep.FullchainPath)
	privkey = strings.TrimSpace(dep.PrivkeyPath)
	issuer = strings.TrimSpace(dep.IssuerPath)

	if dep.Template == model.DeployTemplateCaddyDocker && (fullchain == "" || privkey == "") {
		baseDir := strings.TrimSpace(host.CaddyHostCertDir)
		if baseDir == "" {
			baseDir = "/opt/caddy/certs"
		}
		sub := CertSubdirName(cert)
		if fullchain == "" {
			fullchain = pathpkg.Join(baseDir, sub, "fullchain.pem")
		}
		if privkey == "" {
			privkey = pathpkg.Join(baseDir, sub, "privkey.pem")
		}
		if issuer == "" {
			issuer = pathpkg.Join(baseDir, sub, "issuer.pem")
		}
	}
	return fullchain, privkey, issuer
}

// CertSubdirName derives a clean, safe directory name under Caddy's certificate directory.
func CertSubdirName(cert *model.Certificate) string {
	if cert == nil {
		return "cert"
	}
	d := strings.TrimSpace(cert.Domain)
	d = strings.TrimPrefix(d, "*.")
	var b strings.Builder
	for _, r := range d {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	s := strings.Trim(b.String(), "._-")
	if s == "" {
		return fmt.Sprintf("cert_%d", cert.ID)
	}
	return s
}

func parseFileMode(raw string, def uint32) uint32 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	v, err := strconv.ParseUint(raw, 8, 32)
	if err != nil || v == 0 {
		return def
	}
	return uint32(v)
}
