package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"

	"ssl-center/internal/config"
	appcrypto "ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

// DefaultRetryBackoffs defines the 3-step failure backoff schedule: 15m -> 1h -> 6h.
var DefaultRetryBackoffs = []time.Duration{
	15 * time.Minute,
	1 * time.Hour,
	6 * time.Hour,
}

var ErrIssuanceInProgress = errors.New("certificate issuance already in progress")

// ACMEOrderFunc executes the ACME certificate order given a CA account, ACME user,
// ordered SAN list, key type, observable DNS provider, and stage tracker.
type ACMEOrderFunc func(
	ctx context.Context,
	ca *model.CAAccount,
	user *ACMEUser,
	domains []string,
	keyType certcrypto.KeyType,
	obsProvider *ObservableDNSProvider,
	tracker *StageTracker,
) (*certificate.Resource, error)

// IssuerOption configures optional behavior on Issuer.
type IssuerOption func(*Issuer)

// WithACMEOrderFunc injects a custom ACME order runner (used in unit tests).
func WithACMEOrderFunc(fn ACMEOrderFunc) IssuerOption {
	return func(i *Issuer) {
		if fn != nil {
			i.orderFn = fn
		}
	}
}

// WithPropagationConfig overrides DNS propagation check settings (e.g. resolvers/timeouts in tests).
func WithPropagationConfig(cfg PropagationConfig) IssuerOption {
	return func(i *Issuer) {
		i.propCfg = cfg
	}
}

// WithIssuerHTTPClient injects a custom HTTP client for ACME orders.
func WithIssuerHTTPClient(client *http.Client) IssuerOption {
	return func(i *Issuer) {
		if client != nil {
			i.httpClient = client
		}
	}
}

// WithRetryBackoffs overrides the retry backoff schedule (defaults to 15m -> 1h -> 6h).
func WithRetryBackoffs(backoffs []time.Duration) IssuerOption {
	return func(i *Issuer) {
		if len(backoffs) > 0 {
			i.backoffs = append([]time.Duration(nil), backoffs...)
		}
	}
}

// WithIssuerClock overrides the clock used for timestamps and retry scheduling.
func WithIssuerClock(clk model.Clock) IssuerOption {
	return func(i *Issuer) {
		if clk != nil {
			i.clock = clk
		}
	}
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// Issuer orchestrates single-flight ACME certificate issuance, 6-stage observability,
// atomic PEM persistence, and deployment fanout.
type Issuer struct {
	db            *db.DB
	cfg           *config.Config
	caSvc         *CAService
	dnsSvc        *DNSService
	redactor      *appcrypto.SecretRedactor
	broker        model.CertJobBroker
	deployTrigger model.DeployTrigger
	notifier      model.Notifier
	propCfg       PropagationConfig
	httpClient    *http.Client
	orderFn       ACMEOrderFunc
	backoffs      []time.Duration
	clock         model.Clock

	activeMu sync.Mutex
	active   map[int64]bool
	wg       sync.WaitGroup
}

// NewIssuer constructs an Issuer.
func NewIssuer(
	database *db.DB,
	cfg *config.Config,
	caSvc *CAService,
	dnsSvc *DNSService,
	redactor *appcrypto.SecretRedactor,
	broker model.CertJobBroker,
	deployTrigger model.DeployTrigger,
	notifier model.Notifier,
	opts ...IssuerOption,
) *Issuer {
	iss := &Issuer{
		db:            database,
		cfg:           cfg,
		caSvc:         caSvc,
		dnsSvc:        dnsSvc,
		redactor:      redactor,
		broker:        broker,
		deployTrigger: deployTrigger,
		notifier:      notifier,
		propCfg: PropagationConfig{
			RecursiveResolvers: DefaultRecursiveResolvers,
			Timeout:            120 * time.Second,
			Interval:           3 * time.Second,
			CheckAuthoritative: true,
		},
		httpClient: &http.Client{Timeout: 60 * time.Second},
		backoffs:   append([]time.Duration(nil), DefaultRetryBackoffs...),
		clock:      realClock{},
		active:     make(map[int64]bool),
	}
	iss.orderFn = iss.obtainWithLego
	for _, opt := range opts {
		if opt != nil {
			opt(iss)
		}
	}
	return iss
}

// StartIssueAsync creates a CertJob immediately and executes issuance in a background goroutine.
// Enforces a single-flight lock per certID.
func (i *Issuer) StartIssueAsync(ctx context.Context, certID int64, triggerType string) (*model.CertJob, error) {
	if _, err := i.db.GetCertificate(ctx, certID); err != nil {
		return nil, err
	}
	if !i.tryAcquire(certID) {
		return nil, ErrIssuanceInProgress
	}

	job, err := i.createInitialJob(ctx, certID, triggerType)
	if err != nil {
		i.release(certID)
		return nil, err
	}

	i.wg.Add(1)
	go func() {
		defer i.wg.Done()
		defer i.release(certID)
		i.executeJob(context.Background(), certID, job)
	}()
	return job, nil
}

// IssueSync runs certificate issuance synchronously (used by scheduler and tests).
func (i *Issuer) IssueSync(ctx context.Context, certID int64, triggerType string) (*model.CertJob, error) {
	if _, err := i.db.GetCertificate(ctx, certID); err != nil {
		return nil, err
	}
	if !i.tryAcquire(certID) {
		return nil, ErrIssuanceInProgress
	}
	defer i.release(certID)

	job, err := i.createInitialJob(ctx, certID, triggerType)
	if err != nil {
		return nil, err
	}
	i.executeJob(ctx, certID, job)
	return i.db.GetCertJob(context.Background(), job.ID)
}

// Wait blocks until all in-flight asynchronous issuances finish.
func (i *Issuer) Wait() {
	i.wg.Wait()
}

func (i *Issuer) tryAcquire(certID int64) bool {
	i.activeMu.Lock()
	defer i.activeMu.Unlock()
	if i.active[certID] {
		return false
	}
	i.active[certID] = true
	return true
}

func (i *Issuer) release(certID int64) {
	i.activeMu.Lock()
	delete(i.active, certID)
	i.activeMu.Unlock()
}

func (i *Issuer) createInitialJob(ctx context.Context, certID int64, triggerType string) (*model.CertJob, error) {
	if triggerType == "" {
		triggerType = model.TriggerManual
	}
	job := &model.CertJob{
		CertificateID: certID,
		TriggerType:   triggerType,
		Status:        model.JobStatusRunning,
		CurrentStage:  model.StageCreateOrder,
		StagesJSON:    "[]",
		StartedAt:     i.clock.Now(),
	}
	if _, err := i.db.CreateCertJob(ctx, job); err != nil {
		return nil, err
	}
	return job, nil
}

func (i *Issuer) executeJob(ctx context.Context, certID int64, job *model.CertJob) {
	tracker := NewStageTracker(i.db, i.broker, i.redactor, job)

	cert, err := i.db.GetCertificate(ctx, certID)
	if err != nil {
		tracker.Fail(fmt.Sprintf("load certificate: %v", err))
		return
	}

	prevStatus := cert.Status
	cert.Status = model.CertStatusIssuing
	_ = i.db.UpdateCertificate(context.Background(), cert)

	failJob := func(err error) {
		errMsg := err.Error()
		if i.redactor != nil {
			errMsg = i.redactor.Redact(errMsg)
		}
		tracker.Logf("Issuance failed: %s", errMsg)
		tracker.Fail(errMsg)
		i.recordFailure(context.Background(), cert, prevStatus, job.TriggerType, errMsg)
	}

	domains, err := buildDomainList(cert)
	if err != nil {
		failJob(err)
		return
	}
	keyType, err := KeyTypeToLego(cert.KeyType)
	if err != nil {
		failJob(err)
		return
	}

	tracker.Logf("Starting ACME order for %s (SANs: %s, key_type: %s, trigger: %s)",
		cert.Domain, strings.Join(domains, ", "), cert.KeyType, job.TriggerType)

	ca, user, err := i.caSvc.LoadACMEUser(ctx, cert.CAAccountID)
	if err != nil {
		failJob(fmt.Errorf("load CA account: %w", err))
		return
	}

	dnsProvider, err := i.dnsSvc.BuildProvider(ctx, cert.DNSCredentialID, cert.ZoneOverride)
	if err != nil {
		failJob(fmt.Errorf("build DNS provider: %w", err))
		return
	}

	obsProvider := NewObservableDNSProvider(dnsProvider, tracker, i.propCfg)
	res, err := i.orderFn(ctx, ca, user, domains, keyType, obsProvider, tracker)
	if err != nil {
		failJob(fmt.Errorf("ACME order failed: %w", err))
		return
	}
	if res == nil || len(res.Certificate) == 0 || len(res.PrivateKey) == 0 {
		failJob(errors.New("ACME returned empty certificate or private key"))
		return
	}

	// Stage 5: Save certificate artifacts atomically.
	tracker.EnterStage(model.StageSaveCert, "Persisting certificate PEM artifacts")
	certDir := i.cfg.CertDir(cert.ID)
	meta, err := saveCertificateFiles(certDir, res)
	if err != nil {
		failJob(fmt.Errorf("save certificate files: %w", err))
		return
	}
	tracker.Logf("Saved certificate files to %s (fingerprint=%s, not_after=%s)",
		certDir, meta.fingerprint, meta.notAfter.Format(time.RFC3339))

	now := i.clock.Now()
	warnDays := 7
	if settings, sErr := i.db.GetSettingsDTO(context.Background()); sErr == nil && settings.ExpiringWarnDays > 0 {
		warnDays = settings.ExpiringWarnDays
	}
	newStatus := model.CertStatusValid
	if meta.notAfter.Sub(now) <= time.Duration(warnDays)*24*time.Hour {
		newStatus = model.CertStatusExpiring
	}
	if meta.notAfter.Before(now) {
		newStatus = model.CertStatusExpired
	}

	issuedSANsJSON, _ := json.Marshal(meta.issuedSANs)
	cert.Status = newStatus
	cert.IssuerName = meta.issuerName
	cert.IssuedSANsJSON = string(issuedSANsJSON)
	cert.FingerprintSHA256 = meta.fingerprint
	cert.NotBefore = &meta.notBefore
	cert.NotAfter = &meta.notAfter
	cert.LastIssuedAt = &now
	cert.LastError = ""
	cert.RetryCount = 0
	cert.NextRetryAt = nil
	cert.LastExpiringNotifiedAt = nil
	cert.CertDir = certDir

	if err := i.db.UpdateCertificate(context.Background(), cert); err != nil {
		failJob(fmt.Errorf("update certificate metadata: %w", err))
		return
	}
	tracker.CompleteStage(model.StageSaveCert, "Certificate artifacts saved")

	// Stage 6: Trigger deployment fanout.
	tracker.EnterStage(model.StageTriggerDeploy, "Fanning out certificate to enabled deployments")
	if i.deployTrigger != nil {
		jobID := job.ID
		if err := i.deployTrigger.FanoutCertificate(ctx, cert.ID, model.TriggerAuto, &jobID); err != nil {
			msg := err.Error()
			if i.redactor != nil {
				msg = i.redactor.Redact(msg)
			}
			tracker.Logf("Deployment fanout completed with error: %s", msg)
			tracker.CompleteStage(model.StageTriggerDeploy, "Deployment fanout finished with warnings: "+msg)
		} else {
			tracker.Logf("Deployment fanout completed successfully")
			tracker.CompleteStage(model.StageTriggerDeploy, "Deployment fanout succeeded")
		}
	} else {
		tracker.Logf("No deploy trigger configured; skipping deployment fanout")
		tracker.CompleteStage(model.StageTriggerDeploy, "No deployment targets")
	}

	i.recordAudit(context.Background(), "cert.issued", model.AuditLevelInfo, cert.ID, cert.Domain,
		fmt.Sprintf("Issued certificate for %s (fingerprint %s)", cert.Domain, meta.fingerprint))
	tracker.Succeed()
}

func (i *Issuer) obtainWithLego(
	ctx context.Context,
	ca *model.CAAccount,
	user *ACMEUser,
	domains []string,
	keyType certcrypto.KeyType,
	obsProvider *ObservableDNSProvider,
	tracker *StageTracker,
) (*certificate.Resource, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = ca.DirectoryURL
	cfg.UserAgent = "ssl-center/1.0"
	cfg.Certificate.KeyType = keyType
	if i.httpClient != nil {
		cfg.HTTPClient = i.httpClient
	}

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create lego client: %w", err)
	}

	opts := []dns01.ChallengeOption{
		dns01.AddRecursiveNameservers(obsProvider.propCfg.RecursiveResolvers),
		dns01.AddDNSTimeout(obsProvider.propCfg.Timeout),
		dns01.WrapPreCheck(obsProvider.PreCheck),
	}
	if !obsProvider.propCfg.CheckAuthoritative {
		opts = append(opts, dns01.DisableAuthoritativeNssPropagationRequirement())
	} else {
		opts = append(opts, dns01.RecursiveNSsPropagationRequirement())
	}

	if err := client.Challenge.SetDNS01Provider(obsProvider, opts...); err != nil {
		return nil, fmt.Errorf("set DNS-01 provider: %w", err)
	}

	type obtainResult struct {
		res *certificate.Resource
		err error
	}
	ch := make(chan obtainResult, 1)
	go func() {
		res, err := client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: domains,
			Bundle:  true,
		})
		ch <- obtainResult{res: res, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case out := <-ch:
		return out.res, out.err
	}
}

func (i *Issuer) recordFailure(ctx context.Context, cert *model.Certificate, prevStatus, triggerType, errMsg string) {
	now := i.clock.Now()
	cert.LastError = errMsg
	cert.Status = model.CertStatusError

	emitIssueFailed := false
	if triggerType == model.TriggerSchedule || triggerType == model.TriggerRetry {
		idx := cert.RetryCount
		if idx < len(i.backoffs) {
			next := now.Add(i.backoffs[idx])
			cert.RetryCount = idx + 1
			cert.NextRetryAt = &next
		} else {
			// All 3 retries (15m -> 1h -> 6h) exhausted; stop auto-retry and alert.
			cert.NextRetryAt = nil
			emitIssueFailed = true
		}
	} else {
		// Manual failure leaves auto-retry schedule cleared unless already valid? Keep NextRetryAt nil.
		if cert.NotAfter != nil && prevStatus != model.CertStatusPending {
			cert.Status = model.CertStatusError
		}
	}

	_ = i.db.UpdateCertificate(ctx, cert)

	i.recordAudit(ctx, "cert.issue_failed", model.AuditLevelError, cert.ID, cert.Domain,
		fmt.Sprintf("Certificate issuance failed for %s: %s", cert.Domain, errMsg))

	if emitIssueFailed && i.notifier != nil {
		_ = i.notifier.Emit(ctx, model.WebhookEvent{
			Event:   model.WebhookEventCertIssueFailed,
			Level:   model.AuditLevelError,
			Title:   fmt.Sprintf("Certificate issuance failed: %s", cert.Domain),
			Message: fmt.Sprintf("Certificate %s failed after %d retry attempts: %s", cert.Domain, len(i.backoffs), errMsg),
			Certificate: &model.WebhookCertRef{
				ID:     cert.ID,
				Domain: cert.Domain,
			},
			Error: errMsg,
			Metadata: map[string]any{
				"retry_count":  cert.RetryCount,
				"trigger_type": triggerType,
			},
		})
	}
}

func (i *Issuer) recordAudit(ctx context.Context, evtType, level string, certID int64, domain, msg string) {
	meta, _ := json.Marshal(map[string]any{"certificate_id": certID, "domain": domain})
	_, _ = i.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  evtType,
		Level:      level,
		TargetType: "certificate",
		TargetID:   &certID,
		TargetName: domain,
		Message:    msg,
		MetaJSON:   string(meta),
	})
}

type parsedCertMeta struct {
	fingerprint string
	issuerName  string
	issuedSANs  []string
	notBefore   time.Time
	notAfter    time.Time
}

func saveCertificateFiles(certDir string, res *certificate.Resource) (*parsedCertMeta, error) {
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cert dir %s: %w", certDir, err)
	}

	certs, err := certcrypto.ParsePEMBundle(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate PEM bundle: %w", err)
	}
	leaf := certs[0]

	fp, err := model.ParseLeafFingerprintSHA256(res.Certificate)
	if err != nil {
		return nil, fmt.Errorf("compute leaf SHA-256 fingerprint: %w", err)
	}

	issuerPEM := res.IssuerCertificate
	if len(issuerPEM) == 0 && len(certs) > 1 {
		for _, c := range certs[1:] {
			issuerPEM = append(issuerPEM, certcrypto.PEMEncode(c)...)
		}
	}

	if err := writeFileAtomic(filepath.Join(certDir, "fullchain.pem"), res.Certificate, 0o644); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(certDir, "privkey.pem"), res.PrivateKey, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(certDir, "issuer.pem"), issuerPEM, 0o644); err != nil {
		return nil, err
	}

	issuerName := strings.TrimSpace(leaf.Issuer.CommonName)
	if issuerName == "" {
		issuerName = leaf.Issuer.String()
	}

	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	seen := make(map[string]struct{})
	for _, d := range leaf.DNSNames {
		nd := model.NormalizeDomain(d)
		if nd != "" {
			if _, ok := seen[nd]; !ok {
				seen[nd] = struct{}{}
				sans = append(sans, nd)
			}
		}
	}
	for _, ip := range leaf.IPAddresses {
		s := ip.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			sans = append(sans, s)
		}
	}

	return &parsedCertMeta{
		fingerprint: fp,
		issuerName:  issuerName,
		issuedSANs:  sans,
		notBefore:   leaf.NotBefore.UTC(),
		notAfter:    leaf.NotAfter.UTC(),
	}, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cert-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file %s: %w", path, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod before rename %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// CleanupCertDir removes on-disk certificate artifacts for cert when deleted or when primary domain changes.
func CleanupCertDir(cfg *config.Config, cert *model.Certificate) {
	if cert == nil {
		return
	}
	if cfg != nil && cert.ID > 0 {
		_ = os.RemoveAll(cfg.CertDir(cert.ID))
	}
	if cert.CertDir != "" {
		_ = os.RemoveAll(cert.CertDir)
	}
}

func buildDomainList(cert *model.Certificate) ([]string, error) {
	primary := model.NormalizeDomain(cert.Domain)
	if primary == "" {
		return nil, errors.New("certificate primary domain is empty")
	}
	domains := []string{primary}
	seen := map[string]struct{}{primary: {}}

	if strings.TrimSpace(cert.SANsJSON) != "" {
		var sans []string
		if err := json.Unmarshal([]byte(cert.SANsJSON), &sans); err == nil {
			for _, s := range sans {
				ns := model.NormalizeDomain(s)
				if ns == "" {
					continue
				}
				if _, exists := seen[ns]; !exists {
					seen[ns] = struct{}{}
					domains = append(domains, ns)
				}
			}
		}
	}
	return domains, nil
}
