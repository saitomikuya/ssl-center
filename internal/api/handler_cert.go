package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ssl-center/internal/acme"
	"ssl-center/internal/config"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// CertHandler serves /api/v1/certificates and /api/v1/cert-jobs endpoints.
type CertHandler struct {
	db     *db.DB
	cfg    *config.Config
	issuer *acme.Issuer
}

// NewCertHandler constructs a CertHandler.
func NewCertHandler(database *db.DB, cfg *config.Config, issuer *acme.Issuer) *CertHandler {
	return &CertHandler{
		db:     database,
		cfg:    cfg,
		issuer: issuer,
	}
}

// List handles GET /api/v1/certificates.
func (h *CertHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	certs, err := h.db.ListCertificates(ctx)
	if err != nil {
		MapDBError(w, err)
		return
	}

	caNames := make(map[int64]string)
	if cas, err := h.db.ListCAAccounts(ctx); err == nil {
		for _, ca := range cas {
			caNames[ca.ID] = ca.Name
		}
	}

	dnsNames := make(map[int64]string)
	if creds, err := h.db.ListDNSCredentials(ctx); err == nil {
		for _, c := range creds {
			dnsNames[c.ID] = c.Name
		}
	}

	type depStats struct {
		total   int
		success int
		failed  int
	}
	depMap := make(map[int64]depStats)
	if deps, err := h.db.ListAllDeployments(ctx); err == nil {
		for _, d := range deps {
			st := depMap[d.CertificateID]
			st.total++
			switch d.LastStatus {
			case model.JobStatusSuccess:
				st.success++
			case model.JobStatusFailed:
				st.failed++
			}
			depMap[d.CertificateID] = st
		}
	}

	now := time.Now().UTC()
	out := make([]model.CertificateDTO, 0, len(certs))
	for i := range certs {
		st := depMap[certs[i].ID]
		out = append(out, toCertificateDTO(&certs[i], caNames[certs[i].CAAccountID], dnsNames[certs[i].DNSCredentialID], st.total, st.success, st.failed, now))
	}
	OK(w, out)
}

// Create handles POST /api/v1/certificates.
func (h *CertHandler) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req model.CreateCertRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	domain := model.NormalizeDomain(req.Domain)
	if domain == "" {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "domain is required", nil)
		return
	}

	caID := req.CAAccountID
	if caID == 0 {
		defCA, err := h.db.GetDefaultCAAccount(ctx)
		if err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "ca_account_id is required when no default CA account is set", nil)
			return
		}
		caID = defCA.ID
	} else if _, err := h.db.GetCAAccount(ctx, caID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Referenced ca_account_id does not exist", nil)
			return
		}
		MapDBError(w, err)
		return
	}

	if req.DNSCredentialID <= 0 {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "dns_credential_id is required", nil)
		return
	}
	if _, err := h.db.GetDNSCredential(ctx, req.DNSCredentialID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "Referenced dns_credential_id does not exist", nil)
			return
		}
		MapDBError(w, err)
		return
	}

	keyType := strings.ToUpper(strings.TrimSpace(req.KeyType))
	if keyType == "" {
		keyType = model.KeyTypeEC256
	}
	if _, err := acme.KeyTypeToLego(keyType); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}

	renewBefore := 30
	if req.RenewBeforeDays != nil && *req.RenewBeforeDays > 0 {
		renewBefore = *req.RenewBeforeDays
	}
	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}

	sans := normalizeSANs(req.SANs)
	sansJSON, _ := json.Marshal(sans)

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = domain
	}

	cert := &model.Certificate{
		Name:            name,
		Domain:          domain,
		SANsJSON:        string(sansJSON),
		CAAccountID:     caID,
		DNSCredentialID: req.DNSCredentialID,
		ZoneOverride:    model.NormalizeDomain(req.ZoneOverride),
		KeyType:         keyType,
		RenewBeforeDays: renewBefore,
		AutoRenew:       autoRenew,
		Status:          model.CertStatusPending,
		IssuedSANsJSON:  "[]",
	}

	if _, err := h.db.CreateCertificate(ctx, cert); err != nil {
		MapDBError(w, err)
		return
	}
	cert.CertDir = h.cfg.CertDir(cert.ID)
	_ = h.db.UpdateCertificate(ctx, cert)

	h.recordAudit(ctx, "cert.created", model.AuditLevelInfo, cert.ID, cert.Domain, fmt.Sprintf("Created certificate %s", cert.Domain), ClientIPFromContext(ctx))

	dto, err := h.buildCertificateDTO(ctx, cert)
	if err != nil {
		MapDBError(w, err)
		return
	}
	Created(w, dto)
}

// Get handles GET /api/v1/certificates/{id}.
func (h *CertHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(r.Context(), id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	dto, err := h.buildCertificateDTO(r.Context(), cert)
	if err != nil {
		MapDBError(w, err)
		return
	}
	OK(w, dto)
}

// Update handles PUT /api/v1/certificates/{id}.
// If the primary domain changes, removes old on-disk artifacts and resets issued state.
func (h *CertHandler) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(ctx, id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	var req model.UpdateCertRequest
	if err := BindJSON(r, &req); err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, "Invalid JSON request body", nil)
		return
	}

	domainChanged := false
	if req.Domain != nil {
		nd := model.NormalizeDomain(*req.Domain)
		if nd == "" {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "domain cannot be empty", nil)
			return
		}
		if nd != cert.Domain {
			domainChanged = true
			cert.Domain = nd
		}
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed != "" {
			cert.Name = trimmed
		}
	}
	if req.SANs != nil {
		sans := normalizeSANs(req.SANs)
		b, _ := json.Marshal(sans)
		cert.SANsJSON = string(b)
	}
	if req.CAAccountID != nil {
		if _, err := h.db.GetCAAccount(ctx, *req.CAAccountID); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "Referenced ca_account_id does not exist", nil)
				return
			}
			MapDBError(w, err)
			return
		}
		cert.CAAccountID = *req.CAAccountID
	}
	if req.DNSCredentialID != nil {
		if _, err := h.db.GetDNSCredential(ctx, *req.DNSCredentialID); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				Fail(w, http.StatusBadRequest, CodeBadRequest, "Referenced dns_credential_id does not exist", nil)
				return
			}
			MapDBError(w, err)
			return
		}
		cert.DNSCredentialID = *req.DNSCredentialID
	}
	if req.ZoneOverride != nil {
		cert.ZoneOverride = model.NormalizeDomain(*req.ZoneOverride)
	}
	if req.KeyType != nil {
		kt := strings.ToUpper(strings.TrimSpace(*req.KeyType))
		if _, err := acme.KeyTypeToLego(kt); err != nil {
			Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
			return
		}
		cert.KeyType = kt
	}
	if req.RenewBeforeDays != nil {
		if *req.RenewBeforeDays <= 0 {
			Fail(w, http.StatusBadRequest, CodeBadRequest, "renew_before_days must be > 0", nil)
			return
		}
		cert.RenewBeforeDays = *req.RenewBeforeDays
	}
	if req.AutoRenew != nil {
		cert.AutoRenew = *req.AutoRenew
	}

	if domainChanged {
		cleanupCertDiskDir(h.cfg, cert)
		cert.Status = model.CertStatusPending
		cert.IssuerName = ""
		cert.IssuedSANsJSON = "[]"
		cert.FingerprintSHA256 = ""
		cert.NotBefore = nil
		cert.NotAfter = nil
		cert.LastIssuedAt = nil
		cert.LastError = ""
		cert.RetryCount = 0
		cert.NextRetryAt = nil
		cert.LastExpiringNotifiedAt = nil
		cert.CertDir = h.cfg.CertDir(cert.ID)
	}

	if err := h.db.UpdateCertificate(ctx, cert); err != nil {
		MapDBError(w, err)
		return
	}

	h.recordAudit(ctx, "cert.updated", model.AuditLevelInfo, cert.ID, cert.Domain, fmt.Sprintf("Updated certificate %s", cert.Domain), ClientIPFromContext(ctx))

	dto, err := h.buildCertificateDTO(ctx, cert)
	if err != nil {
		MapDBError(w, err)
		return
	}
	OK(w, dto)
}

// Delete handles DELETE /api/v1/certificates/{id}.
// Removes DB record (cascading deployments/jobs) and deletes on-disk cert directory.
func (h *CertHandler) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(ctx, id)
	if err != nil {
		MapDBError(w, err)
		return
	}
	if err := h.db.DeleteCertificate(ctx, id); err != nil {
		MapDBError(w, err)
		return
	}
	cleanupCertDiskDir(h.cfg, cert)
	h.recordAudit(ctx, "cert.deleted", model.AuditLevelInfo, cert.ID, cert.Domain, fmt.Sprintf("Deleted certificate %s", cert.Domain), ClientIPFromContext(ctx))
	OK(w, map[string]any{"deleted": true})
}

// Issue handles POST /api/v1/certificates/{id}/issue.
func (h *CertHandler) Issue(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	job, err := h.issuer.StartIssueAsync(r.Context(), id, model.TriggerManual)
	if err != nil {
		if errors.Is(err, acme.ErrIssuanceInProgress) {
			Fail(w, http.StatusConflict, CodeConflict, "Certificate issuance already in progress", nil)
			return
		}
		MapDBError(w, err)
		return
	}
	Accepted(w, model.IssueCertResponse{JobID: job.ID})
}

// ListJobs handles GET /api/v1/certificates/{id}/jobs.
func (h *CertHandler) ListJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	if _, err := h.db.GetCertificate(ctx, id); err != nil {
		MapDBError(w, err)
		return
	}
	jobs, err := h.db.ListCertJobsByCertificate(ctx, id, 50)
	if err != nil {
		MapDBError(w, err)
		return
	}
	out := make([]model.CertJobDTO, 0, len(jobs))
	for i := range jobs {
		out = append(out, toCertJobDTO(&jobs[i]))
	}
	OK(w, out)
}

// GetJob handles GET /api/v1/cert-jobs/{jobId}.
func (h *CertHandler) GetJob(w http.ResponseWriter, r *http.Request) {
	jobID, err := URLParamInt64(r, "jobId")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	job, err := h.db.GetCertJob(r.Context(), jobID)
	if err != nil {
		MapDBError(w, err)
		return
	}
	OK(w, toCertJobDTO(job))
}

// GetPEM handles POST /api/v1/certificates/{id}/pem.
func (h *CertHandler) GetPEM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	var req model.CertPEMRequest
	if r.Body != nil {
		_ = BindJSON(r, &req)
	}

	cert, err := h.db.GetCertificate(ctx, id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	dir := resolveCertDir(h.cfg, cert)
	fullchain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		Fail(w, http.StatusNotFound, CodeNotFound, "Certificate PEM files not found; please issue the certificate first", nil)
		return
	}
	issuerPEM, _ := os.ReadFile(filepath.Join(dir, "issuer.pem"))

	resp := model.CertPEMResponse{
		FullchainPEM:      string(fullchain),
		IssuerPEM:         string(issuerPEM),
		FingerprintSHA256: cert.FingerprintSHA256,
	}
	if req.IncludePrivateKey {
		privkey, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
		if err != nil {
			Fail(w, http.StatusNotFound, CodeNotFound, "Private key PEM file not found", nil)
			return
		}
		resp.PrivkeyPEM = string(privkey)
		h.recordAudit(ctx, "cert.key_exported", model.AuditLevelWarn, cert.ID, cert.Domain, fmt.Sprintf("Exported private key PEM for %s", cert.Domain), ClientIPFromContext(ctx))
	}

	OK(w, resp)
}

// DownloadBundle handles GET /api/v1/certificates/{id}/bundle.zip.
func (h *CertHandler) DownloadBundle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Fail(w, http.StatusBadRequest, CodeBadRequest, err.Error(), nil)
		return
	}
	cert, err := h.db.GetCertificate(ctx, id)
	if err != nil {
		MapDBError(w, err)
		return
	}

	dir := resolveCertDir(h.cfg, cert)
	fullchain, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		Fail(w, http.StatusNotFound, CodeNotFound, "Certificate bundle not found; please issue the certificate first", nil)
		return
	}
	privkey, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		Fail(w, http.StatusNotFound, CodeNotFound, "Private key not found; please issue the certificate first", nil)
		return
	}
	issuerPEM, _ := os.ReadFile(filepath.Join(dir, "issuer.pem"))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"fullchain.pem", fullchain, 0o644},
		{"privkey.pem", privkey, 0o600},
		{"issuer.pem", issuerPEM, 0o644},
	}
	for _, f := range files {
		hdr := &zip.FileHeader{
			Name:     f.name,
			Method:   zip.Deflate,
			Modified: time.Now().UTC(),
		}
		hdr.SetMode(f.mode)
		wEntry, err := zw.CreateHeader(hdr)
		if err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to create zip entry", nil)
			return
		}
		if _, err := wEntry.Write(f.data); err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to write zip entry", nil)
			return
		}
	}
	if err := zw.Close(); err != nil {
		Fail(w, http.StatusInternalServerError, CodeInternalError, "Failed to finalize zip archive", nil)
		return
	}

	h.recordAudit(ctx, "cert.bundle_downloaded", model.AuditLevelWarn, cert.ID, cert.Domain, fmt.Sprintf("Downloaded certificate ZIP bundle for %s", cert.Domain), ClientIPFromContext(ctx))

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="cert_%d.zip"`, cert.ID))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

func (h *CertHandler) buildCertificateDTO(ctx context.Context, cert *model.Certificate) (model.CertificateDTO, error) {
	var caName, dnsName string
	if ca, err := h.db.GetCAAccount(ctx, cert.CAAccountID); err == nil {
		caName = ca.Name
	}
	if dns, err := h.db.GetDNSCredential(ctx, cert.DNSCredentialID); err == nil {
		dnsName = dns.Name
	}
	var total, success, failed int
	if deps, err := h.db.ListDeploymentsByCertificate(ctx, cert.ID); err == nil {
		total = len(deps)
		for _, d := range deps {
			switch d.LastStatus {
			case model.JobStatusSuccess:
				success++
			case model.JobStatusFailed:
				failed++
			}
		}
	}
	return toCertificateDTO(cert, caName, dnsName, total, success, failed, time.Now().UTC()), nil
}

func (h *CertHandler) recordAudit(ctx context.Context, evtType, level string, certID int64, domain, msg, actorIP string) {
	meta, _ := json.Marshal(map[string]any{"certificate_id": certID, "domain": domain})
	_, _ = h.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  evtType,
		Level:      level,
		TargetType: "certificate",
		TargetID:   &certID,
		TargetName: domain,
		Message:    msg,
		MetaJSON:   string(meta),
		ActorIP:    actorIP,
	})
}

func toCertificateDTO(cert *model.Certificate, caName, dnsName string, depTotal, depSuccess, depFailed int, now time.Time) model.CertificateDTO {
	var daysRemaining *int
	if cert.NotAfter != nil {
		days := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
		daysRemaining = &days
	}

	return model.CertificateDTO{
		ID:                cert.ID,
		Name:              cert.Name,
		Domain:            cert.Domain,
		SANs:              parseStringSlice(cert.SANsJSON),
		CAAccountID:       cert.CAAccountID,
		CAAccountName:     caName,
		DNSCredentialID:   cert.DNSCredentialID,
		DNSCredentialName: dnsName,
		ZoneOverride:      cert.ZoneOverride,
		KeyType:           cert.KeyType,
		RenewBeforeDays:   cert.RenewBeforeDays,
		AutoRenew:         cert.AutoRenew,
		Status:            cert.Status,
		IssuerName:        cert.IssuerName,
		IssuedSANs:        parseStringSlice(cert.IssuedSANsJSON),
		FingerprintSHA256: cert.FingerprintSHA256,
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		DaysRemaining:     daysRemaining,
		LastIssuedAt:      cert.LastIssuedAt,
		LastError:         cert.LastError,
		RetryCount:        cert.RetryCount,
		NextRetryAt:       cert.NextRetryAt,
		CertDir:           cert.CertDir,
		DeploymentTotal:   depTotal,
		DeploymentSuccess: depSuccess,
		DeploymentFailed:  depFailed,
		CreatedAt:         cert.CreatedAt,
		UpdatedAt:         cert.UpdatedAt,
	}
}

func toCertJobDTO(job *model.CertJob) model.CertJobDTO {
	return model.CertJobDTO{
		ID:            job.ID,
		CertificateID: job.CertificateID,
		TriggerType:   job.TriggerType,
		Status:        job.Status,
		CurrentStage:  job.CurrentStage,
		Stages:        parseJobStages(job.StagesJSON),
		Logs:          job.Logs,
		ErrorMessage:  job.ErrorMessage,
		StartedAt:     job.StartedAt,
		FinishedAt:    job.FinishedAt,
	}
}

func normalizeSANs(sans []string) []string {
	out := make([]string, 0, len(sans))
	seen := make(map[string]struct{}, len(sans))
	for _, s := range sans {
		ns := model.NormalizeDomain(s)
		if ns == "" {
			continue
		}
		if _, ok := seen[ns]; !ok {
			seen[ns] = struct{}{}
			out = append(out, ns)
		}
	}
	return out
}

func parseStringSlice(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return make([]string, 0)
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return make([]string, 0)
	}
	return out
}

func resolveCertDir(cfg *config.Config, cert *model.Certificate) string {
	if cert != nil && strings.TrimSpace(cert.CertDir) != "" {
		return cert.CertDir
	}
	if cfg != nil && cert != nil {
		return cfg.CertDir(cert.ID)
	}
	return ""
}

func cleanupCertDiskDir(cfg *config.Config, cert *model.Certificate) {
	acme.CleanupCertDir(cfg, cert)
}
