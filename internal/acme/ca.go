package acme

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	appcrypto "ssl-center/internal/crypto"
	"ssl-center/internal/db"
	"ssl-center/internal/model"
)

const (
	// Directory URLs for supported CAs.
	LetsEncryptProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	GTSProdURL            = "https://dv.acme-v02.api.pki.goog/directory"
	GTSStagingURL         = "https://dv.acme-v02.test-api.pki.goog/directory"

	aadCAKeyEnc = "ca_accounts:acme_key_enc"
)

var (
	ErrInvalidCAInput     = errors.New("invalid CA account input")
	ErrCARegistration     = errors.New("ACME account registration failed")
	ErrCAKeyValidation    = errors.New("ACME account key validation failed")
)

// ACMEUser implements lego's registration.User interface.
type ACMEUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *ACMEUser) GetEmail() string {
	return u.Email
}

func (u *ACMEUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *ACMEUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

// ResolveDirectoryURL returns the ACME directory URL for a provider and environment.
func ResolveDirectoryURL(provider, environment string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case model.CAProviderLetsEncrypt:
		switch strings.ToLower(strings.TrimSpace(environment)) {
		case model.CAEnvProduction:
			return LetsEncryptProdURL, nil
		case model.CAEnvStaging:
			return LetsEncryptStagingURL, nil
		default:
			return "", fmt.Errorf("%w: invalid environment %q", ErrInvalidCAInput, environment)
		}
	case model.CAProviderGTS:
		switch strings.ToLower(strings.TrimSpace(environment)) {
		case model.CAEnvProduction:
			return GTSProdURL, nil
		case model.CAEnvStaging:
			return GTSStagingURL, nil
		default:
			return "", fmt.Errorf("%w: invalid environment %q", ErrInvalidCAInput, environment)
		}
	default:
		return "", fmt.Errorf("%w: unsupported CA provider %q", ErrInvalidCAInput, provider)
	}
}

// KeyTypeToLego maps frozen model key_type strings to lego certcrypto.KeyType.
func KeyTypeToLego(keyType string) (certcrypto.KeyType, error) {
	switch strings.ToUpper(strings.TrimSpace(keyType)) {
	case "", model.KeyTypeEC256:
		return certcrypto.EC256, nil
	case model.KeyTypeEC384:
		return certcrypto.EC384, nil
	case model.KeyTypeRSA2048:
		return certcrypto.RSA2048, nil
	default:
		return "", fmt.Errorf("unsupported key_type %q", keyType)
	}
}

// CAServiceOption configures optional overrides on CAService (primarily for testing).
type CAServiceOption func(*CAService)

// WithCAHTTPClient injects a custom HTTP client for ACME directory/account calls.
func WithCAHTTPClient(client *http.Client) CAServiceOption {
	return func(s *CAService) {
		if client != nil {
			s.httpClient = client
		}
	}
}

// WithCADirectoryOverride overrides the resolved ACME directory URL (e.g. for mock ACME servers).
func WithCADirectoryOverride(provider, environment, url string) CAServiceOption {
	return func(s *CAService) {
		if s.dirOverrides == nil {
			s.dirOverrides = make(map[string]string)
		}
		s.dirOverrides[strings.ToLower(provider)+":"+strings.ToLower(environment)] = url
	}
}

// CAService manages ACME CA accounts, encrypted keys, and EAB registration.
type CAService struct {
	db           *db.DB
	cipher       *appcrypto.Cipher
	redactor     *appcrypto.SecretRedactor
	httpClient   *http.Client
	dirOverrides map[string]string
}

// NewCAService constructs a CAService.
func NewCAService(database *db.DB, cipher *appcrypto.Cipher, redactor *appcrypto.SecretRedactor, opts ...CAServiceOption) *CAService {
	s := &CAService{
		db:       database,
		cipher:   cipher,
		redactor: redactor,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

func (s *CAService) directoryURL(provider, environment string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(provider)) + ":" + strings.ToLower(strings.TrimSpace(environment))
	if u, ok := s.dirOverrides[key]; ok && u != "" {
		return u, nil
	}
	return ResolveDirectoryURL(provider, environment)
}

func (s *CAService) newLegoClient(dirURL string, user *ACMEUser) (*lego.Client, error) {
	cfg := lego.NewConfig(user)
	cfg.CADirURL = dirURL
	cfg.UserAgent = "ssl-center/1.0"
	if s.httpClient != nil {
		cfg.HTTPClient = s.httpClient
	}
	return lego.NewClient(cfg)
}

// CreateAccount registers a new ACME account (Let's Encrypt or GTS with EAB)
// or imports and online-validates an existing ACME private key PEM.
// EAB credentials are zeroed in memory immediately after registration and never persisted.
func (s *CAService) CreateAccount(ctx context.Context, req *model.CreateCARequest, actorIP string) (*model.CAAccountDTO, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: request is nil", ErrInvalidCAInput)
	}

	// Copy EAB credentials into mutable byte slices and ensure immediate zeroing.
	eabKIDBytes := []byte(strings.TrimSpace(req.EABKeyID))
	eabHMACBytes := []byte(strings.TrimSpace(req.EABHMACKey))
	req.EABKeyID = ""
	req.EABHMACKey = ""
	defer func() {
		appcrypto.ZeroBytes(eabKIDBytes)
		appcrypto.ZeroBytes(eabHMACBytes)
	}()

	name := strings.TrimSpace(req.Name)
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	env := strings.ToLower(strings.TrimSpace(req.Environment))
	email := strings.TrimSpace(req.Email)
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrInvalidCAInput)
	}
	if email == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("%w: valid email is required", ErrInvalidCAInput)
	}
	dirURL, err := s.directoryURL(provider, env)
	if err != nil {
		return nil, err
	}

	var privKey crypto.PrivateKey
	var acmeKeyPEM string
	var accountURI string

	importedPEM := strings.TrimSpace(req.ACMEKeyPEM)
	req.ACMEKeyPEM = ""

	if importedPEM != "" {
		// Online validation of imported acme.key PEM via ResolveAccountByKey.
		pemBytes := []byte(importedPEM)
		parsed, err := certcrypto.ParsePEMPrivateKey(pemBytes)
		appcrypto.ZeroBytes(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid acme_key_pem: %v", ErrInvalidCAInput, err)
		}
		privKey = parsed
		acmeKeyPEM = string(certcrypto.PEMEncode(privKey))

		user := &ACMEUser{
			Email: email,
			Key:   privKey,
		}
		client, err := s.newLegoClient(dirURL, user)
		if err != nil {
			return nil, fmt.Errorf("%w: initialize ACME client: %v", ErrCAKeyValidation, err)
		}
		reg, err := client.Registration.ResolveAccountByKey()
		if err != nil {
			return nil, fmt.Errorf("%w: resolve account by key: %v", ErrCAKeyValidation, err)
		}
		accountURI = reg.URI
		if req.AccountURI != "" && accountURI != "" && strings.TrimSpace(req.AccountURI) != accountURI {
			return nil, fmt.Errorf("%w: provided account_uri %q does not match resolved URI %q", ErrCAKeyValidation, req.AccountURI, accountURI)
		}
		if accountURI == "" {
			accountURI = strings.TrimSpace(req.AccountURI)
		}
	} else {
		if provider == model.CAProviderGTS && (len(eabKIDBytes) == 0 || len(eabHMACBytes) == 0) {
			return nil, fmt.Errorf("%w: GTS requires eab_kid and eab_mac_key (or acme_key_pem import)", ErrInvalidCAInput)
		}
		generatedKey, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
		if err != nil {
			return nil, fmt.Errorf("generate ACME account key: %w", err)
		}
		privKey = generatedKey
		acmeKeyPEM = string(certcrypto.PEMEncode(privKey))

		user := &ACMEUser{
			Email: email,
			Key:   privKey,
		}
		client, err := s.newLegoClient(dirURL, user)
		if err != nil {
			return nil, fmt.Errorf("%w: initialize ACME client: %v", ErrCARegistration, err)
		}

		var reg *registration.Resource
		if provider == model.CAProviderGTS {
			reg, err = client.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
				TermsOfServiceAgreed: true,
				Kid:                  string(eabKIDBytes),
				HmacEncoded:          string(eabHMACBytes),
			})
			appcrypto.ZeroBytes(eabKIDBytes)
			appcrypto.ZeroBytes(eabHMACBytes)
		} else {
			reg, err = client.Registration.Register(registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCARegistration, err)
		}
		if reg != nil {
			accountURI = reg.URI
		}
	}

	encKey, err := s.cipher.Encrypt(acmeKeyPEM, aadCAKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("encrypt ACME key: %w", err)
	}

	if s.redactor != nil {
		s.redactor.Add(acmeKeyPEM)
	}

	ca := &model.CAAccount{
		Name:         name,
		Provider:     provider,
		Environment:  env,
		Email:        email,
		DirectoryURL: dirURL,
		ACMEKeyEnc:   encKey,
		AccountURI:   accountURI,
		IsDefault:    req.IsDefault,
		Status:       model.CAStatusActive,
	}
	if _, err := s.db.CreateCAAccount(ctx, ca); err != nil {
		if s.redactor != nil {
			s.redactor.Remove(acmeKeyPEM)
		}
		return nil, err
	}

	s.recordAudit(ctx, "ca.created", model.AuditLevelInfo, ca.ID, ca.Name, fmt.Sprintf("Created CA account %s (%s/%s)", ca.Name, ca.Provider, ca.Environment), actorIP)
	dto := toCAAccountDTO(ca)
	return &dto, nil
}

// ListAccounts returns all CA accounts without encrypted keys.
func (s *CAService) ListAccounts(ctx context.Context) ([]model.CAAccountDTO, error) {
	rows, err := s.db.ListCAAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.CAAccountDTO, 0, len(rows))
	for i := range rows {
		out = append(out, toCAAccountDTO(&rows[i]))
	}
	return out, nil
}

// UpdateAccount updates mutable metadata (name, email, is_default) of a CA account.
func (s *CAService) UpdateAccount(ctx context.Context, id int64, req model.UpdateCARequest, actorIP string) (*model.CAAccountDTO, error) {
	ca, err := s.db.GetCAAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return nil, fmt.Errorf("%w: name cannot be empty", ErrInvalidCAInput)
		}
		ca.Name = trimmed
	}
	if req.Email != nil {
		trimmed := strings.TrimSpace(*req.Email)
		if trimmed == "" || !strings.Contains(trimmed, "@") {
			return nil, fmt.Errorf("%w: valid email is required", ErrInvalidCAInput)
		}
		ca.Email = trimmed
	}
	if req.IsDefault != nil {
		ca.IsDefault = *req.IsDefault
	}

	if err := s.db.UpdateCAAccount(ctx, ca); err != nil {
		return nil, err
	}
	s.recordAudit(ctx, "ca.updated", model.AuditLevelInfo, ca.ID, ca.Name, fmt.Sprintf("Updated CA account %s", ca.Name), actorIP)
	dto := toCAAccountDTO(ca)
	return &dto, nil
}

// DeleteAccount deletes a CA account and removes its ACME key from SecretRedactor.
func (s *CAService) DeleteAccount(ctx context.Context, id int64, actorIP string) error {
	ca, err := s.db.GetCAAccount(ctx, id)
	if err != nil {
		return err
	}
	var plainPEM string
	if ca.ACMEKeyEnc != "" {
		plainPEM, _ = s.cipher.Decrypt(ca.ACMEKeyEnc, aadCAKeyEnc)
	}
	if err := s.db.DeleteCAAccount(ctx, id); err != nil {
		return err
	}
	if s.redactor != nil && plainPEM != "" {
		s.redactor.Remove(plainPEM)
	}
	s.recordAudit(ctx, "ca.deleted", model.AuditLevelInfo, ca.ID, ca.Name, fmt.Sprintf("Deleted CA account %s", ca.Name), actorIP)
	return nil
}

// SetDefault marks the given CA account as the single default CA.
func (s *CAService) SetDefault(ctx context.Context, id int64, actorIP string) (*model.CAAccountDTO, error) {
	if err := s.db.SetDefaultCAAccount(ctx, id); err != nil {
		return nil, err
	}
	ca, err := s.db.GetCAAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	s.recordAudit(ctx, "ca.default_set", model.AuditLevelInfo, ca.ID, ca.Name, fmt.Sprintf("Set default CA account to %s", ca.Name), actorIP)
	dto := toCAAccountDTO(ca)
	return &dto, nil
}

// ExportKey decrypts and returns the ACME account key PEM offline for backup/migration.
func (s *CAService) ExportKey(ctx context.Context, id int64, actorIP string) (*model.ExportCAKeyResponse, error) {
	ca, err := s.db.GetCAAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	pemKey, err := s.cipher.Decrypt(ca.ACMEKeyEnc, aadCAKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt ACME account key: %w", err)
	}
	s.recordAudit(ctx, "ca.key_exported", model.AuditLevelWarn, ca.ID, ca.Name, fmt.Sprintf("Exported ACME private key for CA account %s", ca.Name), actorIP)
	return &model.ExportCAKeyResponse{
		ID:           ca.ID,
		Name:         ca.Name,
		Provider:     ca.Provider,
		Environment:  ca.Environment,
		Email:        ca.Email,
		DirectoryURL: ca.DirectoryURL,
		AccountURI:   ca.AccountURI,
		ACMEKeyPEM:   pemKey,
	}, nil
}

// LoadACMEUser loads and decrypts the ACME private key for issuing certificates.
func (s *CAService) LoadACMEUser(ctx context.Context, caID int64) (*model.CAAccount, *ACMEUser, error) {
	ca, err := s.db.GetCAAccount(ctx, caID)
	if err != nil {
		return nil, nil, err
	}
	pemStr, err := s.cipher.Decrypt(ca.ACMEKeyEnc, aadCAKeyEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt ACME account key: %w", err)
	}
	privKey, err := certcrypto.ParsePEMPrivateKey([]byte(pemStr))
	if err != nil {
		return nil, nil, fmt.Errorf("parse ACME private key: %w", err)
	}
	var reg *registration.Resource
	if ca.AccountURI != "" {
		reg = &registration.Resource{URI: ca.AccountURI}
	}
	user := &ACMEUser{
		Email:        ca.Email,
		Registration: reg,
		Key:          privKey,
	}
	return ca, user, nil
}

// CollectSecrets returns all decrypted ACME private key PEMs for SecretRedactor hydration.
func (s *CAService) CollectSecrets(ctx context.Context) ([]string, error) {
	accounts, err := s.db.ListCAAccounts(ctx)
	if err != nil {
		return nil, err
	}
	secrets := make([]string, 0, len(accounts))
	for _, ca := range accounts {
		if ca.ACMEKeyEnc == "" {
			continue
		}
		plain, err := s.cipher.Decrypt(ca.ACMEKeyEnc, aadCAKeyEnc)
		if err == nil && plain != "" {
			secrets = append(secrets, plain)
		}
	}
	return secrets, nil
}

func (s *CAService) recordAudit(ctx context.Context, evtType, level string, id int64, name, msg, actorIP string) {
	meta, _ := json.Marshal(map[string]any{"ca_account_id": id})
	_, _ = s.db.CreateAuditEvent(ctx, &model.AuditEvent{
		EventType:  evtType,
		Level:      level,
		TargetType: "ca_account",
		TargetID:   &id,
		TargetName: name,
		Message:    msg,
		MetaJSON:   string(meta),
		ActorIP:    actorIP,
	})
}

func toCAAccountDTO(ca *model.CAAccount) model.CAAccountDTO {
	return model.CAAccountDTO{
		ID:           ca.ID,
		Name:         ca.Name,
		Provider:     ca.Provider,
		Environment:  ca.Environment,
		Email:        ca.Email,
		DirectoryURL: ca.DirectoryURL,
		AccountURI:   ca.AccountURI,
		IsDefault:    ca.IsDefault,
		Status:       ca.Status,
		CreatedAt:    ca.CreatedAt,
		UpdatedAt:    ca.UpdatedAt,
	}
}
