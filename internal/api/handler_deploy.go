package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"

	"ssl-center/internal/db"
	"ssl-center/internal/deploy"
	"ssl-center/internal/model"
)

// DeployHandler serves certificate deployment and push endpoints.
type DeployHandler struct {
	db     *db.DB
	engine model.DeployTrigger
}

// NewDeployHandler constructs a DeployHandler.
func NewDeployHandler(database *db.DB, engine model.DeployTrigger) *DeployHandler {
	return &DeployHandler{
		db:     database,
		engine: engine,
	}
}

// ListCertDeployments handles GET /api/v1/certificates/{id}/deployments.
func (h *DeployHandler) ListCertDeployments(w http.ResponseWriter, r *http.Request) {
	certID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(r.Context(), certID)
	if err != nil {
		MapDBError(w, err)
		return
	}
	deps, err := h.db.ListDeploymentsByCertificate(r.Context(), certID)
	if err != nil {
		MapDBError(w, err)
		return
	}

	hostsCache := make(map[int64]*model.Host)
	out := make([]model.DeploymentDTO, 0, len(deps))
	for i := range deps {
		host, ok := hostsCache[deps[i].HostID]
		if !ok {
			if got, hErr := h.db.GetHost(r.Context(), deps[i].HostID); hErr == nil {
				host = got
			}
			hostsCache[deps[i].HostID] = host
		}
		out = append(out, deploymentToDTO(&deps[i], cert.Domain, host))
	}
	OK(w, out)
}

// CreateDeployment handles POST /api/v1/certificates/{id}/deployments.
func (h *DeployHandler) CreateDeployment(w http.ResponseWriter, r *http.Request) {
	certID, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(r.Context(), certID)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var req model.CreateDeploymentRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}
	if req.HostID <= 0 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "host_id is required", nil)
		return
	}

	host, err := h.db.GetHost(r.Context(), req.HostID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Target host does not exist", nil)
			return
		}
		MapDBError(w, err)
		return
	}

	template := strings.TrimSpace(req.Template)
	if template == "" {
		template = model.DeployTemplateCaddyDocker
	}
	switch template {
	case model.DeployTemplateCaddyDocker, model.DeployTemplateLocalDir, model.DeployTemplateCustomSSH:
	default:
		Fail(w, http.StatusBadRequest, CodeBadRequest, "template must be 'caddy_docker', 'local_dir', or 'custom_ssh'", nil)
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	fullchainPath := strings.TrimSpace(req.FullchainPath)
	privkeyPath := strings.TrimSpace(req.PrivkeyPath)
	issuerPath := strings.TrimSpace(req.IssuerPath)

	if template == model.DeployTemplateCaddyDocker {
		baseDir := strings.TrimSpace(host.CaddyHostCertDir)
		if baseDir == "" {
			baseDir = "/opt/caddy/certs"
		}
		sub := deploy.CertSubdirName(cert)
		if fullchainPath == "" {
			fullchainPath = pathpkg.Join(baseDir, sub, "fullchain.pem")
		}
		if privkeyPath == "" {
			privkeyPath = pathpkg.Join(baseDir, sub, "privkey.pem")
		}
		if issuerPath == "" {
			issuerPath = pathpkg.Join(baseDir, sub, "issuer.pem")
		}
	} else {
		if fullchainPath == "" || privkeyPath == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "fullchain_path and privkey_path are required", nil)
			return
		}
	}

	certMode := defaultString(strings.TrimSpace(req.CertFileMode), "0644")
	if !isValidOctalMode(certMode) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "cert_file_mode must be a valid octal file mode (e.g. 0644)", nil)
		return
	}
	keyMode := defaultString(strings.TrimSpace(req.KeyFileMode), "0600")
	if !isValidOctalMode(keyMode) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "key_file_mode must be a valid octal file mode (e.g. 0600)", nil)
		return
	}

	reloadMode := strings.TrimSpace(req.ReloadMode)
	if reloadMode == "" {
		switch template {
		case model.DeployTemplateCaddyDocker:
			reloadMode = model.ReloadModeDockerExec
		case model.DeployTemplateLocalDir:
			reloadMode = model.ReloadModeNone
		case model.DeployTemplateCustomSSH:
			if strings.TrimSpace(req.ReloadCommand) != "" {
				reloadMode = model.ReloadModeCustomCmd
			} else {
				reloadMode = model.ReloadModeNone
			}
		}
	}

	reloadCmd := strings.TrimSpace(req.ReloadCommand)
	reloadWebhookURL := strings.TrimSpace(req.ReloadWebhookURL)

	if errMsg := validateReloadConfig(reloadMode, reloadCmd, reloadWebhookURL, host); errMsg != "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, errMsg, nil)
		return
	}
	if reloadMode == model.ReloadModeDockerExec && reloadCmd == "" {
		container := defaultString(strings.TrimSpace(host.CaddyContainer), "caddy")
		if err := model.ValidateContainerName(container); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
		reloadCmd = model.DefaultCaddyReloadCmd(container, host.CaddyContainerCaddyfile)
	}

	tlsVerifyEnabled := true
	if req.TLSVerifyEnabled != nil {
		tlsVerifyEnabled = *req.TLSVerifyEnabled
	}
	tlsVerifyPort := req.TLSVerifyPort
	if tlsVerifyPort == 0 {
		tlsVerifyPort = 443
	}
	if tlsVerifyPort < 1 || tlsVerifyPort > 65535 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "tls_verify_port must be between 1 and 65535", nil)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("%s (%s)", host.Name, template)
	}

	dep := &model.Deployment{
		CertificateID:    certID,
		HostID:           host.ID,
		Name:             name,
		Template:         template,
		Enabled:          enabled,
		FullchainPath:    fullchainPath,
		PrivkeyPath:      privkeyPath,
		IssuerPath:       issuerPath,
		CertFileMode:     certMode,
		KeyFileMode:      keyMode,
		ReloadMode:       reloadMode,
		ReloadCommand:    reloadCmd,
		ReloadWebhookURL: reloadWebhookURL,
		TLSVerifyEnabled: tlsVerifyEnabled,
		TLSVerifyHost:    strings.TrimSpace(req.TLSVerifyHost),
		TLSVerifyPort:    tlsVerifyPort,
		TLSVerifySNI:     strings.TrimSpace(req.TLSVerifySNI),
		LastStatus:       model.JobStatusPending,
	}

	if _, err := h.db.CreateDeployment(r.Context(), dep); err != nil {
		MapDBError(w, err)
		return
	}

	h.auditDeployment(r, "deployment.created", dep, "Deployment target created")
	Created(w, deploymentToDTO(dep, cert.Domain, host))
}

// UpdateDeployment handles PUT /api/v1/deployments/{id}.
func (h *DeployHandler) UpdateDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	existing, err := h.db.GetDeployment(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	cert, err := h.db.GetCertificate(r.Context(), existing.CertificateID)
	if err != nil {
		MapDBError(w, err)
		return
	}
	host, err := h.db.GetHost(r.Context(), existing.HostID)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var req model.UpdateDeploymentRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Deployment name must not be empty", nil)
			return
		}
		existing.Name = trimmed
	}
	if req.Template != nil {
		tpl := strings.TrimSpace(*req.Template)
		switch tpl {
		case model.DeployTemplateCaddyDocker, model.DeployTemplateLocalDir, model.DeployTemplateCustomSSH:
			existing.Template = tpl
		default:
			Fail(w, http.StatusBadRequest, CodeBadRequest, "template must be 'caddy_docker', 'local_dir', or 'custom_ssh'", nil)
			return
		}
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.FullchainPath != nil {
		trimmed := strings.TrimSpace(*req.FullchainPath)
		if trimmed == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "fullchain_path must not be empty", nil)
			return
		}
		existing.FullchainPath = trimmed
	}
	if req.PrivkeyPath != nil {
		trimmed := strings.TrimSpace(*req.PrivkeyPath)
		if trimmed == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "privkey_path must not be empty", nil)
			return
		}
		existing.PrivkeyPath = trimmed
	}
	if req.IssuerPath != nil {
		existing.IssuerPath = strings.TrimSpace(*req.IssuerPath)
	}
	if req.CertFileMode != nil {
		m := strings.TrimSpace(*req.CertFileMode)
		if !isValidOctalMode(m) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "cert_file_mode must be a valid octal file mode", nil)
			return
		}
		existing.CertFileMode = m
	}
	if req.KeyFileMode != nil {
		m := strings.TrimSpace(*req.KeyFileMode)
		if !isValidOctalMode(m) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "key_file_mode must be a valid octal file mode", nil)
			return
		}
		existing.KeyFileMode = m
	}
	if req.ReloadMode != nil {
		existing.ReloadMode = strings.TrimSpace(*req.ReloadMode)
	}
	if req.ReloadCommand != nil {
		existing.ReloadCommand = strings.TrimSpace(*req.ReloadCommand)
	}
	if req.ReloadWebhookURL != nil {
		existing.ReloadWebhookURL = strings.TrimSpace(*req.ReloadWebhookURL)
	}

	if errMsg := validateReloadConfig(existing.ReloadMode, existing.ReloadCommand, existing.ReloadWebhookURL, host); errMsg != "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, errMsg, nil)
		return
	}
	if existing.ReloadMode == model.ReloadModeDockerExec && existing.ReloadCommand == "" {
		container := defaultString(strings.TrimSpace(host.CaddyContainer), "caddy")
		if err := model.ValidateContainerName(container); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
		existing.ReloadCommand = model.DefaultCaddyReloadCmd(container, host.CaddyContainerCaddyfile)
	}

	if req.TLSVerifyEnabled != nil {
		existing.TLSVerifyEnabled = *req.TLSVerifyEnabled
	}
	if req.TLSVerifyHost != nil {
		existing.TLSVerifyHost = strings.TrimSpace(*req.TLSVerifyHost)
	}
	if req.TLSVerifyPort != nil {
		if *req.TLSVerifyPort < 1 || *req.TLSVerifyPort > 65535 {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "tls_verify_port must be between 1 and 65535", nil)
			return
		}
		existing.TLSVerifyPort = *req.TLSVerifyPort
	}
	if req.TLSVerifySNI != nil {
		existing.TLSVerifySNI = strings.TrimSpace(*req.TLSVerifySNI)
	}

	if err := h.db.UpdateDeployment(r.Context(), existing); err != nil {
		MapDBError(w, err)
		return
	}

	h.auditDeployment(r, "deployment.updated", existing, "Deployment target updated")
	OK(w, deploymentToDTO(existing, cert.Domain, host))
}

// DeleteDeployment handles DELETE /api/v1/deployments/{id}.
func (h *DeployHandler) DeleteDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	existing, err := h.db.GetDeployment(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if err := h.db.DeleteDeployment(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}

	h.auditDeployment(r, "deployment.deleted", existing, "Deployment target deleted")
	OK(w, map[string]any{"deleted": true})
}

// PushDeployment handles POST /api/v1/deployments/{id}/push.
func (h *DeployHandler) PushDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if _, err := h.db.GetDeployment(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}
	if h.engine == nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Deployment engine is not configured", nil)
		return
	}

	logEntry, err := h.engine.DeployTarget(r.Context(), id, model.TriggerManual)
	if logEntry != nil {
		OK(w, logEntry)
		return
	}
	if errors.Is(err, deploy.ErrCertificateNotIssued) {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if err != nil {
		MapDBError(w, err)
		return
	}
}

// ListDeploymentLogs handles GET /api/v1/deployments/{id}/logs.
func (h *DeployHandler) ListDeploymentLogs(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if _, err := h.db.GetDeployment(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}

	limit := 20
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, convErr := strconv.Atoi(raw)
		if convErr != nil || n < 1 {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "limit must be a positive integer", nil)
			return
		}
		if n > 200 {
			n = 200
		}
		limit = n
	}

	logs, err := h.db.ListDeployLogsByDeployment(r.Context(), id, limit)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if logs == nil {
		logs = make([]model.DeployLog, 0)
	}
	OK(w, logs)
}

func (h *DeployHandler) auditDeployment(r *http.Request, eventType string, dep *model.Deployment, msg string) {
	if h.db == nil || dep == nil {
		return
	}
	id := dep.ID
	meta, _ := json.Marshal(map[string]any{
		"certificate_id": dep.CertificateID,
		"host_id":        dep.HostID,
		"template":       dep.Template,
		"reload_mode":    dep.ReloadMode,
	})
	_, _ = h.db.CreateAuditEvent(context.Background(), &model.AuditEvent{
		EventType:  eventType,
		Level:      model.AuditLevelInfo,
		TargetType: "deployment",
		TargetID:   &id,
		TargetName: dep.Name,
		Message:    msg,
		MetaJSON:   string(meta),
		ActorIP:    ClientIPFromContext(r.Context()),
	})
}

func validateReloadConfig(reloadMode, reloadCmd, reloadWebhookURL string, host *model.Host) string {
	switch reloadMode {
	case model.ReloadModeDockerExec:
		if reloadCmd == "" && host != nil {
			container := defaultString(strings.TrimSpace(host.CaddyContainer), "caddy")
			if err := model.ValidateContainerName(container); err != nil {
				return err.Error()
			}
		}
		return ""
	case model.ReloadModeCaddyAdminAPI:
		if reloadWebhookURL != "" && !isValidHTTPURL(reloadWebhookURL) {
			return "reload_webhook_url must be a valid http:// or https:// URL"
		}
		return ""
	case model.ReloadModeWebhook:
		if !isValidHTTPURL(reloadWebhookURL) {
			return "reload_webhook_url must be a valid http:// or https:// URL for webhook reload mode"
		}
		return ""
	case model.ReloadModeCustomCmd:
		if reloadCmd == "" {
			return "reload_command is required for custom_cmd reload mode"
		}
		return ""
	case model.ReloadModeNone:
		return ""
	default:
		return "reload_mode must be 'docker_exec', 'caddy_admin_api', 'webhook', 'custom_cmd', or 'none'"
	}
}

func isValidOctalMode(raw string) bool {
	if raw == "" {
		return false
	}
	v, err := strconv.ParseUint(raw, 8, 32)
	return err == nil && v > 0 && v <= 0o7777
}

func isValidHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func deploymentToDTO(dep *model.Deployment, certDomain string, host *model.Host) model.DeploymentDTO {
	var hostName, hostMode string
	if host != nil {
		hostName = host.Name
		hostMode = host.Mode
	}
	return model.DeploymentDTO{
		ID:                  dep.ID,
		CertificateID:       dep.CertificateID,
		CertDomain:          certDomain,
		HostID:              dep.HostID,
		HostName:            hostName,
		HostMode:            hostMode,
		Name:                dep.Name,
		Template:            dep.Template,
		Enabled:             dep.Enabled,
		FullchainPath:       dep.FullchainPath,
		PrivkeyPath:         dep.PrivkeyPath,
		IssuerPath:          dep.IssuerPath,
		CertFileMode:        dep.CertFileMode,
		KeyFileMode:         dep.KeyFileMode,
		ReloadMode:          dep.ReloadMode,
		ReloadCommand:       dep.ReloadCommand,
		ReloadWebhookURL:    dep.ReloadWebhookURL,
		TLSVerifyEnabled:    dep.TLSVerifyEnabled,
		TLSVerifyHost:       dep.TLSVerifyHost,
		TLSVerifyPort:       dep.TLSVerifyPort,
		TLSVerifySNI:        dep.TLSVerifySNI,
		LastStatus:          dep.LastStatus,
		LastDeployedAt:      dep.LastDeployedAt,
		LastCertFingerprint: dep.LastCertFingerprint,
		LastError:           dep.LastError,
		CreatedAt:           dep.CreatedAt,
		UpdatedAt:           dep.UpdatedAt,
	}
}
