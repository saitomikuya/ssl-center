package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	appcrypto "ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const aadDNSConfigEnc = "dns_credentials:config_enc"

var (
	ErrInvalidDNSInput = errors.New("invalid DNS credential input")
	ErrZoneNotFound    = errors.New("matching DNS zone not found")
)

// DNSProvider combines lego's challenge.Provider with Zone discovery and override support.
type DNSProvider interface {
	challenge.Provider
	ListZones(ctx context.Context) ([]model.DNSZone, error)
	SetZoneOverride(zone string)
}

// zoneLockRegistry provides per-zone mutexes so concurrent TXT record
// modifications (e.g. apex + wildcard challenges) serialize safely.
type zoneLockRegistry struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newZoneLockRegistry() *zoneLockRegistry {
	return &zoneLockRegistry{
		locks: make(map[string]*sync.Mutex),
	}
}

func normalizeChallengeFQDN(fqdn string) string {
	fqdn = strings.TrimSpace(fqdn)
	lower := strings.ToLower(fqdn)
	if strings.HasPrefix(lower, "_acme-challenge.*.") {
		return "_acme-challenge." + fqdn[len("_acme-challenge.*."):]
	}
	return fqdn
}

func (r *zoneLockRegistry) get(key string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.locks[key]
	if !ok {
		m = &sync.Mutex{}
		r.locks[key] = m
	}
	return m
}

// MatchZone resolves the target DNSZone for domain from zones.
// If zoneOverride is non-empty, it must match a zone's normalized Name or ID.
// Otherwise, it picks the zone with the longest domain suffix match.
func MatchZone(domain string, zones []model.DNSZone, zoneOverride string) (model.DNSZone, error) {
	if len(zones) == 0 {
		return model.DNSZone{}, fmt.Errorf("%w: no zones available", ErrZoneNotFound)
	}

	override := model.NormalizeDomain(zoneOverride)
	if override != "" {
		override = strings.TrimPrefix(override, "*.")
		for _, z := range zones {
			zName := model.NormalizeDomain(z.Name)
			if zName == override || strings.TrimSpace(z.ID) == strings.TrimSpace(zoneOverride) {
				return model.DNSZone{ID: z.ID, Name: zName}, nil
			}
		}
		return model.DNSZone{}, fmt.Errorf("%w: zone_override %q not found in account zones", ErrZoneNotFound, zoneOverride)
	}

	d := model.NormalizeDomain(domain)
	d = strings.TrimPrefix(d, "*.")
	if d == "" {
		return model.DNSZone{}, fmt.Errorf("%w: domain is empty", ErrZoneNotFound)
	}

	var best model.DNSZone
	bestLen := -1
	for _, z := range zones {
		zName := model.NormalizeDomain(z.Name)
		if zName == "" {
			continue
		}
		if d == zName || strings.HasSuffix(d, "."+zName) {
			if len(zName) > bestLen {
				bestLen = len(zName)
				best = model.DNSZone{ID: z.ID, Name: zName}
			}
		}
	}

	if bestLen < 0 {
		return model.DNSZone{}, fmt.Errorf("%w: no zone matches domain %q", ErrZoneNotFound, domain)
	}
	return best, nil
}

// DNSServiceOption configures optional overrides on DNSService (primarily for testing).
type DNSServiceOption func(*DNSService)

// WithDNSHTTPClient sets a custom HTTP client for DNS provider API calls.
func WithDNSHTTPClient(client *http.Client) DNSServiceOption {
	return func(s *DNSService) {
		if client != nil {
			s.httpClient = client
		}
	}
}

// WithCloudflareBaseURL overrides the Cloudflare API base URL.
func WithCloudflareBaseURL(baseURL string) DNSServiceOption {
	return func(s *DNSService) {
		s.cfBaseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHuaweiBaseURL overrides the Huawei Cloud DNS base URL (or template).
func WithHuaweiBaseURL(baseURL string) DNSServiceOption {
	return func(s *DNSService) {
		s.huaweiBaseURL = strings.TrimRight(baseURL, "/")
	}
}

// DNSService manages DNS credentials and instantiates Cloudflare / Huawei Cloud providers.
type DNSService struct {
	db            *db.DB
	cipher        *appcrypto.Cipher
	redactor      *appcrypto.SecretRedactor
	httpClient    *http.Client
	cfBaseURL     string
	huaweiBaseURL string
	huaweiLocks   *zoneLockRegistry

	zoneCacheMu sync.RWMutex
	zoneCache   map[int64]dnsZoneCacheEntry
}

type dnsZoneCacheEntry struct {
	zones     []model.DNSZone
	expiresAt time.Time
}

const defaultDNSZoneCacheTTL = 60 * time.Second

// NewDNSService constructs a DNSService.
func NewDNSService(database *db.DB, cipher *appcrypto.Cipher, redactor *appcrypto.SecretRedactor, opts ...DNSServiceOption) *DNSService {
	s := &DNSService{
		db:       database,
		cipher:   cipher,
		redactor: redactor,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cfBaseURL:   defaultCloudflareBaseURL,
		huaweiLocks: newZoneLockRegistry(),
		zoneCache:   make(map[int64]dnsZoneCacheEntry),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// CreateCredential validates, encrypts, registers secrets in SecretRedactor, and stores a DNS credential.
func (s *DNSService) CreateCredential(ctx context.Context, req model.CreateDNSRequest, actorIP string) (*model.DNSCredentialDTO, error) {
	name := strings.TrimSpace(req.Name)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidDNSInput)
	}

	var configJSON []byte
	var newSecrets []string
	var region string

	switch provider {
	case model.DNSProviderCloudflare:
		tok := strings.TrimSpace(req.APIToken)
		if tok == "" {
			return nil, fmt.Errorf("%w: api_token is required for cloudflare", ErrInvalidDNSInput)
		}
		cfg := model.CloudflareCredConfig{APIToken: tok}
		var err error
		configJSON, err = json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		newSecrets = []string{tok}
	case model.DNSProviderHuaweiCloud:
		ak := strings.TrimSpace(req.AccessKey)
		sk := strings.TrimSpace(req.SecretKey)
		region = normalizeHuaweiRegion(req.Region)
		if ak == "" || sk == "" {
			return nil, fmt.Errorf("%w: access_key and secret_key are required for huaweicloud", ErrInvalidDNSInput)
		}
		cfg := model.HuaweiCredConfig{
			AccessKey: ak,
			SecretKey: sk,
			Region:    region,
		}
		var err error
		configJSON, err = json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		newSecrets = []string{ak, sk}
	default:
		return nil, fmt.Errorf("%w: unsupported DNS provider %q", ErrInvalidDNSInput, req.Provider)
	}

	enc, err := s.cipher.Encrypt(string(configJSON), aadDNSConfigEnc)
	appcrypto.ZeroBytes(configJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt DNS config: %w", err)
	}

	if s.redactor != nil && len(newSecrets) > 0 {
		s.redactor.Add(newSecrets...)
	}

	cred := &model.DNSCredential{
		Name:      name,
		Provider:  provider,
		ConfigEnc: enc,
	}
	if _, err := s.db.CreateDNSCredential(ctx, cred); err != nil {
		if s.redactor != nil && len(newSecrets) > 0 {
			s.redactor.Remove(newSecrets...)
		}
		return nil, err
	}

	s.recordAudit(ctx, "dns.created", model.AuditLevelInfo, cred.ID, cred.Name, fmt.Sprintf("Created DNS credential %s (%s)", cred.Name, cred.Provider), actorIP)
	dto := s.toDTO(cred, region)
	return &dto, nil
}

// ListCredentials lists all DNS credentials with secrets masked.
func (s *DNSService) ListCredentials(ctx context.Context) ([]model.DNSCredentialDTO, error) {
	rows, err := s.db.ListDNSCredentials(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.DNSCredentialDTO, 0, len(rows))
	for i := range rows {
		region := s.extractRegion(&rows[i])
		out = append(out, s.toDTO(&rows[i], region))
	}
	return out, nil
}

// UpdateCredential updates name and optionally replaces encrypted secrets, preserving omitted/empty secrets.
func (s *DNSService) UpdateCredential(ctx context.Context, id int64, req model.UpdateDNSRequest, actorIP string) (*model.DNSCredentialDTO, error) {
	cred, err := s.db.GetDNSCredential(ctx, id)
	if err != nil {
		return nil, err
	}

	plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt existing DNS config: %w", err)
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: name cannot be empty", ErrInvalidDNSInput)
		}
		cred.Name = trimmed
	}

	var oldSecrets, newSecrets []string
	var configJSON []byte
	var region string

	switch cred.Provider {
	case model.DNSProviderCloudflare:
		var cfg model.CloudflareCredConfig
		if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
			return nil, fmt.Errorf("parse existing cloudflare config: %w", err)
		}
		if req.APIToken != nil && strings.TrimSpace(*req.APIToken) != "" {
			newTok := strings.TrimSpace(*req.APIToken)
			if newTok != cfg.APIToken {
				if cfg.APIToken != "" {
					oldSecrets = append(oldSecrets, cfg.APIToken)
				}
				newSecrets = append(newSecrets, newTok)
				cfg.APIToken = newTok
			}
		}
		configJSON, err = json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
	case model.DNSProviderHuaweiCloud:
		var cfg model.HuaweiCredConfig
		if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
			return nil, fmt.Errorf("parse existing huaweicloud config: %w", err)
		}
		if req.AccessKey != nil && strings.TrimSpace(*req.AccessKey) != "" {
			newAK := strings.TrimSpace(*req.AccessKey)
			if newAK != cfg.AccessKey {
				if cfg.AccessKey != "" {
					oldSecrets = append(oldSecrets, cfg.AccessKey)
				}
				newSecrets = append(newSecrets, newAK)
				cfg.AccessKey = newAK
			}
		}
		if req.SecretKey != nil && strings.TrimSpace(*req.SecretKey) != "" {
			newSK := strings.TrimSpace(*req.SecretKey)
			if newSK != cfg.SecretKey {
				if cfg.SecretKey != "" {
					oldSecrets = append(oldSecrets, cfg.SecretKey)
				}
				newSecrets = append(newSecrets, newSK)
				cfg.SecretKey = newSK
			}
		}
		if req.Region != nil && strings.TrimSpace(*req.Region) != "" {
			cfg.Region = normalizeHuaweiRegion(*req.Region)
		}
		region = cfg.Region
		configJSON, err = json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: unsupported provider %q", ErrInvalidDNSInput, cred.Provider)
	}

	enc, err := s.cipher.Encrypt(string(configJSON), aadDNSConfigEnc)
	appcrypto.ZeroBytes(configJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt DNS config: %w", err)
	}
	cred.ConfigEnc = enc

	if err := s.db.UpdateDNSCredential(ctx, cred); err != nil {
		return nil, err
	}

	if s.redactor != nil {
		if len(newSecrets) > 0 {
			s.redactor.Add(newSecrets...)
		}
		if len(oldSecrets) > 0 {
			s.redactor.Remove(oldSecrets...)
		}
	}

	s.invalidateZoneCache(cred.ID)
	s.recordAudit(ctx, "dns.updated", model.AuditLevelInfo, cred.ID, cred.Name, fmt.Sprintf("Updated DNS credential %s", cred.Name), actorIP)
	dto := s.toDTO(cred, region)
	return &dto, nil
}

// DeleteCredential deletes a DNS credential and unregisters its secrets from SecretRedactor.
func (s *DNSService) DeleteCredential(ctx context.Context, id int64, actorIP string) error {
	cred, err := s.db.GetDNSCredential(ctx, id)
	if err != nil {
		return err
	}
	secrets := s.extractSecrets(cred)
	if err := s.db.DeleteDNSCredential(ctx, id); err != nil {
		return err
	}
	s.invalidateZoneCache(id)
	if s.redactor != nil && len(secrets) > 0 {
		s.redactor.Remove(secrets...)
	}
	s.recordAudit(ctx, "dns.deleted", model.AuditLevelInfo, cred.ID, cred.Name, fmt.Sprintf("Deleted DNS credential %s", cred.Name), actorIP)
	return nil
}

// TestCredential verifies connectivity against the DNS provider API and persists last test result.
func (s *DNSService) TestCredential(ctx context.Context, id int64) (*model.DNSTestResponse, error) {
	provider, err := s.BuildProvider(ctx, id, "")
	if err != nil {
		return nil, err
	}

	zones, err := provider.ListZones(ctx)
	now := time.Now().UTC()
	if err != nil {
		msg := err.Error()
		if s.redactor != nil {
			msg = s.redactor.Redact(msg)
		}
		_ = s.db.UpdateDNSTestResult(ctx, id, false, msg, now)
		return &model.DNSTestResponse{
			OK:      false,
			Message: msg,
			Zones:   make([]model.DNSZone, 0),
		}, nil
	}

	if zones == nil {
		zones = make([]model.DNSZone, 0)
	}
	s.setCachedZones(id, zones)
	msg := fmt.Sprintf("Connected successfully; %d zone(s) visible", len(zones))
	_ = s.db.UpdateDNSTestResult(ctx, id, true, msg, now)
	return &model.DNSTestResponse{
		OK:      true,
		Message: msg,
		Zones:   zones,
	}, nil
}

// TestAdhoc verifies DNS provider connectivity before saving (or during editing with fallback secrets).
func (s *DNSService) TestAdhoc(ctx context.Context, req model.TestDNSAdhocRequest) (*model.DNSTestResponse, error) {
	providerName := strings.ToLower(strings.TrimSpace(req.Provider))
	if providerName == "" && req.CredentialID > 0 {
		cred, err := s.db.GetDNSCredential(ctx, req.CredentialID)
		if err != nil {
			return nil, err
		}
		providerName = cred.Provider
	}

	var (
		provider DNSProvider
		secrets  []string
	)

	switch providerName {
	case model.DNSProviderCloudflare:
		tok := strings.TrimSpace(req.APIToken)
		if tok == "" && req.CredentialID > 0 {
			cred, err := s.db.GetDNSCredential(ctx, req.CredentialID)
			if err != nil {
				return nil, err
			}
			if cred.Provider != model.DNSProviderCloudflare {
				return nil, fmt.Errorf("%w: credential provider mismatch", ErrInvalidDNSInput)
			}
			plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
			if err != nil {
				return nil, fmt.Errorf("decrypt existing DNS config: %w", err)
			}
			var existing model.CloudflareCredConfig
			if err := json.Unmarshal([]byte(plain), &existing); err != nil {
				return nil, fmt.Errorf("parse existing cloudflare config: %w", err)
			}
			tok = existing.APIToken
		}
		if tok == "" {
			return nil, fmt.Errorf("%w: api_token is required for cloudflare", ErrInvalidDNSInput)
		}
		secrets = []string{tok}
		provider = NewCloudflareProvider(tok, s.cfBaseURL, s.httpClient)

	case model.DNSProviderHuaweiCloud:
		ak := strings.TrimSpace(req.AccessKey)
		sk := strings.TrimSpace(req.SecretKey)
		region := strings.TrimSpace(req.Region)
		if (ak == "" || sk == "" || region == "") && req.CredentialID > 0 {
			cred, err := s.db.GetDNSCredential(ctx, req.CredentialID)
			if err != nil {
				return nil, err
			}
			if cred.Provider != model.DNSProviderHuaweiCloud {
				return nil, fmt.Errorf("%w: credential provider mismatch", ErrInvalidDNSInput)
			}
			plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
			if err != nil {
				return nil, fmt.Errorf("decrypt existing DNS config: %w", err)
			}
			var existing model.HuaweiCredConfig
			if err := json.Unmarshal([]byte(plain), &existing); err != nil {
				return nil, fmt.Errorf("parse existing huaweicloud config: %w", err)
			}
			if ak == "" {
				ak = existing.AccessKey
			}
			if sk == "" {
				sk = existing.SecretKey
			}
			if region == "" {
				region = existing.Region
			}
		}
		if ak == "" || sk == "" {
			return nil, fmt.Errorf("%w: access_key and secret_key are required for huaweicloud", ErrInvalidDNSInput)
		}
		region = normalizeHuaweiRegion(region)
		baseURL := s.huaweiBaseURL
		if baseURL == "" {
			baseURL = fmt.Sprintf("https://dns.%s.myhuaweicloud.com", region)
		}
		secrets = []string{ak, sk}
		provider = NewHuaweiCloudProvider(ak, sk, region, baseURL, s.httpClient, s.huaweiLocks)

	default:
		return nil, fmt.Errorf("%w: unsupported DNS provider %q", ErrInvalidDNSInput, req.Provider)
	}

	if s.redactor != nil && len(secrets) > 0 {
		s.redactor.Add(secrets...)
		defer s.redactor.Remove(secrets...)
	}

	zones, err := provider.ListZones(ctx)
	if err != nil {
		msg := err.Error()
		if s.redactor != nil {
			msg = s.redactor.Redact(msg)
		}
		return &model.DNSTestResponse{
			OK:      false,
			Message: msg,
			Zones:   make([]model.DNSZone, 0),
		}, nil
	}
	if zones == nil {
		zones = make([]model.DNSZone, 0)
	}
	return &model.DNSTestResponse{
		OK:      true,
		Message: fmt.Sprintf("Connected successfully; %d zone(s) visible", len(zones)),
		Zones:   zones,
	}, nil
}

// ListZonesForDomain fetches visible zones for a credential and performs longest-suffix matching if domain != "".
func (s *DNSService) ListZonesForDomain(ctx context.Context, id int64, domain string) (*model.DNSZonesResponse, error) {
	zones, ok := s.getCachedZones(id)
	if !ok {
		provider, err := s.BuildProvider(ctx, id, "")
		if err != nil {
			return nil, err
		}
		fetched, err := provider.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		if fetched == nil {
			fetched = make([]model.DNSZone, 0)
		}
		zones = fetched
		s.setCachedZones(id, zones)
	}

	var matched string
	if strings.TrimSpace(domain) != "" {
		if z, matchErr := MatchZone(domain, zones, ""); matchErr == nil {
			matched = z.Name
		}
	}
	return &model.DNSZonesResponse{
		Zones:       zones,
		MatchedZone: matched,
	}, nil
}

func (s *DNSService) getCachedZones(id int64) ([]model.DNSZone, bool) {
	if s.zoneCache == nil {
		return nil, false
	}
	s.zoneCacheMu.RLock()
	entry, ok := s.zoneCache[id]
	s.zoneCacheMu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	out := make([]model.DNSZone, len(entry.zones))
	copy(out, entry.zones)
	return out, true
}

func (s *DNSService) setCachedZones(id int64, zones []model.DNSZone) {
	if s.zoneCache == nil {
		return
	}
	copied := make([]model.DNSZone, len(zones))
	copy(copied, zones)
	s.zoneCacheMu.Lock()
	s.zoneCache[id] = dnsZoneCacheEntry{
		zones:     copied,
		expiresAt: time.Now().Add(defaultDNSZoneCacheTTL),
	}
	s.zoneCacheMu.Unlock()
}

func (s *DNSService) invalidateZoneCache(id int64) {
	if s.zoneCache == nil {
		return
	}
	s.zoneCacheMu.Lock()
	delete(s.zoneCache, id)
	s.zoneCacheMu.Unlock()
}

// BuildProvider instantiates a DNSProvider for the given credential ID and optional zone override.
func (s *DNSService) BuildProvider(ctx context.Context, id int64, zoneOverride string) (DNSProvider, error) {
	cred, err := s.db.GetDNSCredential(ctx, id)
	if err != nil {
		return nil, err
	}
	plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt DNS config: %w", err)
	}

	switch cred.Provider {
	case model.DNSProviderCloudflare:
		var cfg model.CloudflareCredConfig
		if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
			return nil, fmt.Errorf("parse cloudflare config: %w", err)
		}
		p := NewCloudflareProvider(cfg.APIToken, s.cfBaseURL, s.httpClient)
		p.SetZoneOverride(zoneOverride)
		return p, nil
	case model.DNSProviderHuaweiCloud:
		var cfg model.HuaweiCredConfig
		if err := json.Unmarshal([]byte(plain), &cfg); err != nil {
			return nil, fmt.Errorf("parse huaweicloud config: %w", err)
		}
		baseURL := s.huaweiBaseURL
		region := normalizeHuaweiRegion(cfg.Region)
		if baseURL == "" {
			baseURL = fmt.Sprintf("https://dns.%s.myhuaweicloud.com", region)
		}
		p := NewHuaweiCloudProvider(cfg.AccessKey, cfg.SecretKey, region, baseURL, s.httpClient, s.huaweiLocks)
		p.SetZoneOverride(zoneOverride)
		return p, nil
	default:
		return nil, fmt.Errorf("unsupported DNS provider %q", cred.Provider)
	}
}

// CollectSecrets returns all decrypted DNS secrets for SecretRedactor hydration.
func (s *DNSService) CollectSecrets(ctx context.Context) ([]string, error) {
	creds, err := s.db.ListDNSCredentials(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for i := range creds {
		out = append(out, s.extractSecrets(&creds[i])...)
	}
	return out, nil
}

func (s *DNSService) extractSecrets(cred *model.DNSCredential) []string {
	if cred.ConfigEnc == "" {
		return nil
	}
	plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
	if err != nil {
		return nil
	}
	switch cred.Provider {
	case model.DNSProviderCloudflare:
		var cfg model.CloudflareCredConfig
		if json.Unmarshal([]byte(plain), &cfg) == nil && cfg.APIToken != "" {
			return []string{cfg.APIToken}
		}
	case model.DNSProviderHuaweiCloud:
		var cfg model.HuaweiCredConfig
		if json.Unmarshal([]byte(plain), &cfg) == nil {
			var res []string
			if cfg.AccessKey != "" {
				res = append(res, cfg.AccessKey)
			}
			if cfg.SecretKey != "" {
				res = append(res, cfg.SecretKey)
			}
			return res
		}
	}
	return nil
}

func (s *DNSService) extractRegion(cred *model.DNSCredential) string {
	if cred.Provider != model.DNSProviderHuaweiCloud || cred.ConfigEnc == "" {
		return ""
	}
	plain, err := s.cipher.Decrypt(cred.ConfigEnc, aadDNSConfigEnc)
	if err != nil {
		return ""
	}
	var cfg model.HuaweiCredConfig
	if json.Unmarshal([]byte(plain), &cfg) == nil {
		return cfg.Region
	}
	return ""
}

func (s *DNSService) toDTO(cred *model.DNSCredential, region string) model.DNSCredentialDTO {
	return model.DNSCredentialDTO{
		ID:           cred.ID,
		Name:         cred.Name,
		Provider:     cred.Provider,
		Region:       region,
		HasSecret:    cred.ConfigEnc != "",
		LastTestedAt: cred.LastTestedAt,
		LastTestOK:   cred.LastTestOK,
		LastTestMsg:  cred.LastTestMsg,
		CreatedAt:    cred.CreatedAt,
		UpdatedAt:    cred.UpdatedAt,
	}
}

func (s *DNSService) recordAudit(ctx context.Context, evtType, level string, id int64, name, msg, actorIP string) {
	meta, _ := json.Marshal(map[string]any{"dns_credential_id": id})
	_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  evtType,
		Level:      level,
		TargetType: "dns_credential",
		TargetID:   &id,
		TargetName: name,
		Message:    msg,
		MetaJSON:   string(meta),
		ActorIP:    actorIP,
	})
}
