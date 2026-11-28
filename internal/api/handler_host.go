package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

type caddyDiscoverer interface {
	DiscoverCaddy(ctx context.Context, host *model.Host, targetContainer string) (*model.DiscoverCaddyResponse, error)
}

// HostHandler serves /api/v1/hosts endpoints.
type HostHandler struct {
	db        *db.DB
	cipher    *crypto.Cipher
	redactor  *crypto.SecretRedactor
	transport model.RemoteTransport
}

// NewHostHandler constructs a HostHandler.
func NewHostHandler(database *db.DB, cipher *crypto.Cipher, redactor *crypto.SecretRedactor, transport model.RemoteTransport) *HostHandler {
	return &HostHandler{
		db:        database,
		cipher:    cipher,
		redactor:  redactor,
		transport: transport,
	}
}

// ListHosts handles GET /api/v1/hosts.
func (h *HostHandler) ListHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.db.ListHosts(r.Context())
	if err != nil {
		MapDBError(w, err)
		return
	}
	counts, err := h.db.CountDeploymentsByHostMap(r.Context())
	if err != nil {
		counts = map[int64]int{}
	}
	out := make([]model.HostDTO, 0, len(hosts))
	for i := range hosts {
		out = append(out, hostToDTO(&hosts[i], counts[hosts[i].ID]))
	}
	OK(w, out)
}

// CreateHost handles POST /api/v1/hosts.
func (h *HostHandler) CreateHost(w http.ResponseWriter, r *http.Request) {
	var req model.CreateHostRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Host name is required", nil)
		return
	}

	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = model.HostModeSSH
	}
	if mode != model.HostModeSSH {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Only ssh mode hosts can be created (Local host is built-in)", nil)
		return
	}

	hostAddr := strings.TrimSpace(req.Host)
	if hostAddr == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "SSH host address is required", nil)
		return
	}

	port := req.Port
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Port must be between 1 and 65535", nil)
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		username = "root"
	}

	authType := strings.TrimSpace(req.AuthType)
	if authType == "" {
		authType = model.HostAuthKey
	}
	switch authType {
	case model.HostAuthKey:
		if strings.TrimSpace(req.SSHPrivateKey) == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_private_key is required for key authentication", nil)
			return
		}
	case model.HostAuthPassword:
		if req.SSHPassword == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_password is required for password authentication", nil)
			return
		}
	default:
		Fail(w, http.StatusBadRequest, CodeBadRequest, "auth_type must be 'key' or 'password'", nil)
		return
	}

	policy := strings.TrimSpace(req.HostKeyPolicy)
	if policy == "" {
		policy = model.HostKeyPolicyTOFU
	}
	switch policy {
	case model.HostKeyPolicyTOFU, model.HostKeyPolicyStrict, model.HostKeyPolicyInsecure:
	default:
		Fail(w, http.StatusBadRequest, CodeBadRequest, "host_key_policy must be 'tofu', 'strict', or 'insecure'", nil)
		return
	}

	caddyEnabled := true
	if req.CaddyEnabled != nil {
		caddyEnabled = *req.CaddyEnabled
	}
	caddyContainer := strings.TrimSpace(req.CaddyContainer)
	if caddyContainer == "" {
		caddyContainer = "caddy"
	}
	if caddyEnabled || strings.TrimSpace(req.CaddyContainer) != "" {
		if err := model.ValidateContainerName(caddyContainer); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
	}

	privKeyEnc, err := h.encryptHostSecret(req.SSHPrivateKey, "hosts:ssh_private_key_enc")
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH private key", nil)
		return
	}
	passphraseEnc, err := h.encryptHostSecret(req.SSHPassphrase, "hosts:ssh_passphrase_enc")
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH passphrase", nil)
		return
	}
	passwordEnc, err := h.encryptHostSecret(req.SSHPassword, "hosts:ssh_password_enc")
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH password", nil)
		return
	}

	host := &model.Host{
		Name:                    name,
		IsLocal:                 false,
		Mode:                    mode,
		Host:                    hostAddr,
		Port:                    port,
		Username:                username,
		AuthType:                authType,
		SSHPrivateKeyEnc:        privKeyEnc,
		SSHPassphraseEnc:        passphraseEnc,
		SSHPasswordEnc:          passwordEnc,
		HostKeyPolicy:           policy,
		CaddyEnabled:            caddyEnabled,
		CaddyContainer:          caddyContainer,
		CaddyHostCaddyfile:      defaultString(strings.TrimSpace(req.CaddyHostCaddyfile), "/opt/caddy/Caddyfile"),
		CaddyContainerCaddyfile: defaultString(strings.TrimSpace(req.CaddyContainerCaddyfile), "/etc/caddy/Caddyfile"),
		CaddyHostCertDir:        defaultString(strings.TrimSpace(req.CaddyHostCertDir), "/opt/caddy/certs"),
		CaddyContainerCertDir:   defaultString(strings.TrimSpace(req.CaddyContainerCertDir), "/certs"),
		CaddyStatus:             model.CaddyStatusUnknown,
	}

	if _, err := h.db.CreateHost(r.Context(), host); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil {
		h.redactor.Add(req.SSHPrivateKey, req.SSHPassphrase, req.SSHPassword)
	}

	h.auditHost(r, "host.created", host, "Host created")
	Created(w, hostToDTO(host, 0))
}

// GetHost handles GET /api/v1/hosts/{id}.
func (h *HostHandler) GetHost(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	host, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	cnt, _ := h.db.CountDeploymentsByHost(r.Context(), id)
	OK(w, hostToDTO(host, cnt))
}

// UpdateHost handles PUT /api/v1/hosts/{id}.
func (h *HostHandler) UpdateHost(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	existing, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var req model.UpdateHostRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Host name must not be empty", nil)
			return
		}
		existing.Name = trimmed
	}

	if !existing.IsLocal {
		if req.Host != nil {
			trimmed := strings.TrimSpace(*req.Host)
			if trimmed == "" {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "SSH host address must not be empty", nil)
				return
			}
			existing.Host = trimmed
		}
		if req.Port != nil {
			if *req.Port < 1 || *req.Port > 65535 {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "Port must be between 1 and 65535", nil)
				return
			}
			existing.Port = *req.Port
		}
		if req.Username != nil {
			trimmed := strings.TrimSpace(*req.Username)
			if trimmed == "" {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "Username must not be empty", nil)
				return
			}
			existing.Username = trimmed
		}
		if req.AuthType != nil {
			at := strings.TrimSpace(*req.AuthType)
			if at != model.HostAuthKey && at != model.HostAuthPassword {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "auth_type must be 'key' or 'password'", nil)
				return
			}
			existing.AuthType = at
		}
		if req.HostKeyPolicy != nil {
			pol := strings.TrimSpace(*req.HostKeyPolicy)
			if pol != model.HostKeyPolicyTOFU && pol != model.HostKeyPolicyStrict && pol != model.HostKeyPolicyInsecure {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "host_key_policy must be 'tofu', 'strict', or 'insecure'", nil)
				return
			}
			existing.HostKeyPolicy = pol
		}
	}

	if req.CaddyEnabled != nil {
		existing.CaddyEnabled = *req.CaddyEnabled
	}
	if req.CaddyContainer != nil {
		c := strings.TrimSpace(*req.CaddyContainer)
		if c == "" {
			c = "caddy"
		}
		if err := model.ValidateContainerName(c); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
		existing.CaddyContainer = c
	} else if existing.CaddyEnabled {
		if err := model.ValidateContainerName(existing.CaddyContainer); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
	}

	if req.CaddyHostCaddyfile != nil && strings.TrimSpace(*req.CaddyHostCaddyfile) != "" {
		existing.CaddyHostCaddyfile = strings.TrimSpace(*req.CaddyHostCaddyfile)
	}
	if req.CaddyContainerCaddyfile != nil && strings.TrimSpace(*req.CaddyContainerCaddyfile) != "" {
		existing.CaddyContainerCaddyfile = strings.TrimSpace(*req.CaddyContainerCaddyfile)
	}
	if req.CaddyHostCertDir != nil && strings.TrimSpace(*req.CaddyHostCertDir) != "" {
		existing.CaddyHostCertDir = strings.TrimSpace(*req.CaddyHostCertDir)
	}
	if req.CaddyContainerCertDir != nil && strings.TrimSpace(*req.CaddyContainerCertDir) != "" {
		existing.CaddyContainerCertDir = strings.TrimSpace(*req.CaddyContainerCertDir)
	}

	var secretsToRemove, secretsToAdd []string
	if !existing.IsLocal {
		var err error
		existing.SSHPrivateKeyEnc, secretsToRemove, secretsToAdd, err = h.updateOptionalSecret(
			existing.SSHPrivateKeyEnc, req.SSHPrivateKey, "hosts:ssh_private_key_enc", secretsToRemove, secretsToAdd,
		)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to update SSH private key", nil)
			return
		}
		existing.SSHPassphraseEnc, secretsToRemove, secretsToAdd, err = h.updateOptionalSecret(
			existing.SSHPassphraseEnc, req.SSHPassphrase, "hosts:ssh_passphrase_enc", secretsToRemove, secretsToAdd,
		)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to update SSH passphrase", nil)
			return
		}
		existing.SSHPasswordEnc, secretsToRemove, secretsToAdd, err = h.updateOptionalSecret(
			existing.SSHPasswordEnc, req.SSHPassword, "hosts:ssh_password_enc", secretsToRemove, secretsToAdd,
		)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to update SSH password", nil)
			return
		}

		if existing.AuthType == model.HostAuthKey && existing.SSHPrivateKeyEnc == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_private_key is required for key authentication", nil)
			return
		}
		if existing.AuthType == model.HostAuthPassword && existing.SSHPasswordEnc == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_password is required for password authentication", nil)
			return
		}
	}

	if err := h.db.UpdateHost(r.Context(), existing); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil {
		if len(secretsToRemove) > 0 {
			h.redactor.Remove(secretsToRemove...)
		}
		if len(secretsToAdd) > 0 {
			h.redactor.Add(secretsToAdd...)
		}
	}

	h.auditHost(r, "host.updated", existing, "Host updated")
	cnt, _ := h.db.CountDeploymentsByHost(r.Context(), id)
	OK(w, hostToDTO(existing, cnt))
}

// DeleteHost handles DELETE /api/v1/hosts/{id}.
func (h *HostHandler) DeleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	existing, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if existing.IsLocal {
		Fail(w, http.StatusForbidden, CodeLocalHostProtected, "Built-in Local host cannot be deleted", nil)
		return
	}

	// Capture old secrets before deletion so SecretRedactor refcounts can be decremented.
	oldSecrets := h.decryptHostSecretsForCleanup(existing)

	if err := h.db.DeleteHost(r.Context(), id); err != nil {
		MapDBError(w, err)
		return
	}

	if h.redactor != nil && len(oldSecrets) > 0 {
		h.redactor.Remove(oldSecrets...)
	}

	h.auditHost(r, "host.deleted", existing, "Host deleted")
	OK(w, map[string]any{"deleted": true})
}

// TestHost handles POST /api/v1/hosts/{id}/test.
func (h *HostHandler) TestHost(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	host, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if h.transport == nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Remote transport is not configured", nil)
		return
	}

	res, err := h.transport.TestConnection(r.Context(), host)
	if res == nil && err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
		return
	}
	OK(w, res)
}

// ProbeHost handles POST /api/v1/hosts/probe to test SSH/Docker/Caddy connectivity without saving.
func (h *HostHandler) ProbeHost(w http.ResponseWriter, r *http.Request) {
	var req model.HostProbeRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}
	if h.transport == nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Remote transport is not configured", nil)
		return
	}

	probe := &model.Host{
		Name:                    defaultString(strings.TrimSpace(req.Name), "probe"),
		Mode:                    defaultString(strings.TrimSpace(req.Mode), model.HostModeSSH),
		Host:                    strings.TrimSpace(req.Host),
		Port:                    req.Port,
		Username:                defaultString(strings.TrimSpace(req.Username), "root"),
		AuthType:                defaultString(strings.TrimSpace(req.AuthType), model.HostAuthKey),
		HostKeyPolicy:           defaultString(strings.TrimSpace(req.HostKeyPolicy), model.HostKeyPolicyTOFU),
		CaddyEnabled:            true,
		CaddyContainer:          defaultString(strings.TrimSpace(req.CaddyContainer), "caddy"),
		CaddyHostCaddyfile:      defaultString(strings.TrimSpace(req.CaddyHostCaddyfile), "/opt/caddy/Caddyfile"),
		CaddyContainerCaddyfile: defaultString(strings.TrimSpace(req.CaddyContainerCaddyfile), "/etc/caddy/Caddyfile"),
		CaddyHostCertDir:        defaultString(strings.TrimSpace(req.CaddyHostCertDir), "/opt/caddy/certs"),
		CaddyContainerCertDir:   defaultString(strings.TrimSpace(req.CaddyContainerCertDir), "/certs"),
	}
	if req.CaddyEnabled != nil {
		probe.CaddyEnabled = *req.CaddyEnabled
	}
	if strings.TrimSpace(req.TargetContainer) != "" {
		probe.CaddyContainer = strings.TrimSpace(req.TargetContainer)
	}

	if req.HostID > 0 {
		existing, err := h.db.GetHost(r.Context(), req.HostID)
		if err != nil {
			MapDBError(w, err)
			return
		}
		probe.IsLocal = existing.IsLocal
		if existing.IsLocal {
			probe.Mode = existing.Mode
		}
		if probe.Host == "" {
			probe.Host = existing.Host
		}
		if probe.Port == 0 {
			probe.Port = existing.Port
		}
		if strings.TrimSpace(req.Username) == "" {
			probe.Username = existing.Username
		}
		if strings.TrimSpace(req.AuthType) == "" {
			probe.AuthType = existing.AuthType
		}
		if strings.TrimSpace(req.HostKeyPolicy) == "" {
			probe.HostKeyPolicy = existing.HostKeyPolicy
		}
		probe.HostKeyFingerprint = existing.HostKeyFingerprint
		probe.SSHPrivateKeyEnc = existing.SSHPrivateKeyEnc
		probe.SSHPassphraseEnc = existing.SSHPassphraseEnc
		probe.SSHPasswordEnc = existing.SSHPasswordEnc
	}

	if !probe.IsLocal {
		if probe.Host == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "SSH host address is required", nil)
			return
		}
		if probe.Port == 0 {
			probe.Port = 22
		}
		if probe.Port < 1 || probe.Port > 65535 {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Port must be between 1 and 65535", nil)
			return
		}
		var tempSecrets []string
		if strings.TrimSpace(req.SSHPrivateKey) != "" {
			enc, err := h.encryptHostSecret(req.SSHPrivateKey, "hosts:ssh_private_key_enc")
			if err != nil {
				Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH private key", nil)
				return
			}
			probe.SSHPrivateKeyEnc = enc
			tempSecrets = append(tempSecrets, req.SSHPrivateKey)
		}
		if req.SSHPassphrase != "" {
			enc, err := h.encryptHostSecret(req.SSHPassphrase, "hosts:ssh_passphrase_enc")
			if err != nil {
				Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH passphrase", nil)
				return
			}
			probe.SSHPassphraseEnc = enc
			tempSecrets = append(tempSecrets, req.SSHPassphrase)
		}
		if req.SSHPassword != "" {
			enc, err := h.encryptHostSecret(req.SSHPassword, "hosts:ssh_password_enc")
			if err != nil {
				Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to encrypt SSH password", nil)
				return
			}
			probe.SSHPasswordEnc = enc
			tempSecrets = append(tempSecrets, req.SSHPassword)
		}
		if h.redactor != nil && len(tempSecrets) > 0 {
			h.redactor.Add(tempSecrets...)
			defer h.redactor.Remove(tempSecrets...)
		}
		if probe.AuthType == model.HostAuthKey && probe.SSHPrivateKeyEnc == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_private_key is required for key authentication", nil)
			return
		}
		if probe.AuthType == model.HostAuthPassword && probe.SSHPasswordEnc == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ssh_password is required for password authentication", nil)
			return
		}
	}

	res, err := h.transport.TestConnection(r.Context(), probe)
	if res == nil && err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
		return
	}
	OK(w, res)
}

// DiscoverCaddy handles POST /api/v1/hosts/{id}/discover-caddy.
func (h *HostHandler) DiscoverCaddy(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	host, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if h.transport == nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Remote transport is not configured", nil)
		return
	}

	var req model.DiscoverCaddyRequest
	if r.Body != nil {
		if bindErr := BindJSON(r, &req); bindErr != nil && !errors.Is(bindErr, io.EOF) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
			return
		}
	}

	disc, ok := h.transport.(caddyDiscoverer)
	if !ok {
		Fail(w, http.StatusNotImplemented, CodeInternalError, "Caddy discovery is not supported by current transport", nil)
		return
	}
	resp, err := disc.DiscoverCaddy(r.Context(), host, req.ContainerName)
	if err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, err.Error(), nil)
		return
	}
	OK(w, resp)
}

// ResetHostKey handles POST /api/v1/hosts/{id}/reset-host-key.
func (h *HostHandler) ResetHostKey(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	host, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if err := h.db.UpdateHostKeyFingerprint(r.Context(), id, ""); err != nil {
		MapDBError(w, err)
		return
	}
	host.HostKeyFingerprint = ""
	h.auditHost(r, "host.host_key_reset", host, "SSH host key fingerprint reset")
	cnt, _ := h.db.CountDeploymentsByHost(r.Context(), id)
	OK(w, hostToDTO(host, cnt))
}

// ListHostDeployments handles GET /api/v1/hosts/{id}/deployments.
func (h *HostHandler) ListHostDeployments(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	host, err := h.db.GetHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	deps, err := h.db.ListDeploymentsByHost(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	certDomains := make(map[int64]string)
	out := make([]model.DeploymentDTO, 0, len(deps))
	for i := range deps {
		dom, ok := certDomains[deps[i].CertificateID]
		if !ok {
			if cert, cErr := h.db.GetCertificate(r.Context(), deps[i].CertificateID); cErr == nil {
				dom = cert.Domain
			}
			certDomains[deps[i].CertificateID] = dom
		}
		out = append(out, deploymentToDTO(&deps[i], dom, host))
	}
	OK(w, out)
}

func (h *HostHandler) encryptHostSecret(plain, aad string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if h.cipher == nil {
		return "", errors.New("cipher is not initialized")
	}
	return h.cipher.Encrypt(plain, aad)
}

func (h *HostHandler) updateOptionalSecret(
	currentEnc string,
	incoming *string,
	aad string,
	toRemove, toAdd []string,
) (string, []string, []string, error) {
	if incoming == nil || *incoming == "" {
		return currentEnc, toRemove, toAdd, nil
	}
	if currentEnc != "" && h.cipher != nil {
		if oldPlain, err := h.cipher.Decrypt(currentEnc, aad); err == nil && oldPlain != "" {
			toRemove = append(toRemove, oldPlain)
		}
	}
	newEnc, err := h.encryptHostSecret(*incoming, aad)
	if err != nil {
		return currentEnc, toRemove, toAdd, err
	}
	toAdd = append(toAdd, *incoming)
	return newEnc, toRemove, toAdd, nil
}

func (h *HostHandler) decryptHostSecretsForCleanup(host *model.Host) []string {
	if h.cipher == nil || host == nil {
		return nil
	}
	var out []string
	pairs := [][2]string{
		{host.SSHPrivateKeyEnc, "hosts:ssh_private_key_enc"},
		{host.SSHPassphraseEnc, "hosts:ssh_passphrase_enc"},
		{host.SSHPasswordEnc, "hosts:ssh_password_enc"},
	}
	for _, p := range pairs {
		if p[0] == "" {
			continue
		}
		if plain, err := h.cipher.Decrypt(p[0], p[1]); err == nil && plain != "" {
			out = append(out, plain)
		}
	}
	return out
}

func (h *HostHandler) auditHost(r *http.Request, eventType string, host *model.Host, msg string) {
	if h.db == nil || host == nil {
		return
	}
	id := host.ID
	meta, _ := json.Marshal(map[string]any{
		"mode":            host.Mode,
		"host":            host.Host,
		"port":            host.Port,
		"host_key_policy": host.HostKeyPolicy,
	})
	_, _ = h.db.CreateAuditEvent(context.Background(), &model.AuditEvent{
		EventType:  eventType,
		Level:      model.AuditLevelInfo,
		TargetType: "host",
		TargetID:   &id,
		TargetName: host.Name,
		Message:    msg,
		MetaJSON:   string(meta),
		ActorIP:    ClientIPFromContext(r.Context()),
	})
}

func hostToDTO(host *model.Host, deploymentCount int) model.HostDTO {
	return model.HostDTO{
		ID:                      host.ID,
		Name:                    host.Name,
		IsLocal:                 host.IsLocal,
		Mode:                    host.Mode,
		Host:                    host.Host,
		Port:                    host.Port,
		Username:                host.Username,
		AuthType:                host.AuthType,
		HasPrivateKey:           host.SSHPrivateKeyEnc != "",
		HasPassphrase:           host.SSHPassphraseEnc != "",
		HasPassword:             host.SSHPasswordEnc != "",
		HostKeyPolicy:           host.HostKeyPolicy,
		HostKeyFingerprint:      host.HostKeyFingerprint,
		CaddyEnabled:            host.CaddyEnabled,
		CaddyContainer:          host.CaddyContainer,
		CaddyHostCaddyfile:      host.CaddyHostCaddyfile,
		CaddyContainerCaddyfile: host.CaddyContainerCaddyfile,
		CaddyHostCertDir:        host.CaddyHostCertDir,
		CaddyContainerCertDir:   host.CaddyContainerCertDir,
		LastCheckAt:             host.LastCheckAt,
		LastCheckOK:             host.LastCheckOK,
		LastCheckMsg:            host.LastCheckMsg,
		CaddyStatus:             host.CaddyStatus,
		DeploymentCount:         deploymentCount,
		CreatedAt:               host.CreatedAt,
		UpdatedAt:               host.UpdatedAt,
	}
}

func defaultString(val, fallback string) string {
	if val != "" {
		return val
	}
	return fallback
}
