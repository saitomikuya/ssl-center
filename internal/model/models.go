package model

import "time"

// Domain enums and constants frozen across Phase 1-3.
const (
	CAProviderLetsEncrypt = "letsencrypt"
	CAProviderGTS         = "gts"

	CAEnvProduction = "production"
	CAEnvStaging    = "staging"

	CAStatusActive = "active"
	CAStatusError  = "error"

	DNSProviderCloudflare  = "cloudflare"
	DNSProviderHuaweiCloud = "huaweicloud"

	KeyTypeEC256   = "EC256"
	KeyTypeEC384   = "EC384"
	KeyTypeRSA2048 = "RSA2048"

	CertStatusPending  = "pending"
	CertStatusIssuing  = "issuing"
	CertStatusValid    = "valid"
	CertStatusExpiring = "expiring"
	CertStatusExpired  = "expired"
	CertStatusError    = "error"

	HostModeLocal = "local"
	HostModeSSH   = "ssh"

	HostAuthNone     = "none"
	HostAuthKey      = "key"
	HostAuthPassword = "password"

	HostKeyPolicyTOFU     = "tofu"
	HostKeyPolicyStrict   = "strict"
	HostKeyPolicyInsecure = "insecure"

	CaddyStatusRunning = "running"
	CaddyStatusStopped = "stopped"
	CaddyStatusUnknown = "unknown"

	DeployTemplateCaddyDocker = "caddy_docker"
	DeployTemplateLocalDir    = "local_dir"
	DeployTemplateCustomSSH   = "custom_ssh"

	ReloadModeDockerExec    = "docker_exec"
	ReloadModeCaddyAdminAPI = "caddy_admin_api"
	ReloadModeWebhook       = "webhook"
	ReloadModeCustomCmd     = "custom_cmd"
	ReloadModeNone          = "none"

	JobStatusPending = "pending"
	JobStatusRunning = "running"
	JobStatusSuccess = "success"
	JobStatusFailed  = "failed"

	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
	TriggerRetry    = "retry"
	TriggerAuto     = "auto"

	CaddyActionPublish  = "publish"
	CaddyActionRollback = "rollback"
	CaddyActionBaseline = "baseline"

	WebhookEventCertIssueFailed   = "cert.issue_failed"
	WebhookEventCertExpiringSoon  = "cert.expiring_soon"
	WebhookEventDeployFailed      = "deploy.failed"
	WebhookEventCaddyReloadFailed = "caddy.reload_failed"
	WebhookEventCertDeployed      = "cert.deployed"

	AuditLevelInfo  = "info"
	AuditLevelWarn  = "warn"
	AuditLevelError = "error"
)

// AllWebhookEvents lists all 5 supported webhook event names.
var AllWebhookEvents = []string{
	WebhookEventCertIssueFailed,
	WebhookEventCertExpiringSoon,
	WebhookEventDeployFailed,
	WebhookEventCaddyReloadFailed,
	WebhookEventCertDeployed,
}

// DefaultWebhookEvents lists the 4 events enabled by default.
var DefaultWebhookEvents = []string{
	WebhookEventCertIssueFailed,
	WebhookEventCertExpiringSoon,
	WebhookEventDeployFailed,
	WebhookEventCaddyReloadFailed,
}

// CertJobStage constants for the 6-stage issuance pipeline.
const (
	StageCreateOrder     = "create_order"
	StageWriteDNSTXT     = "write_dns_txt"
	StageWaitPropagation = "wait_propagation"
	StageCAValidate      = "ca_validate"
	StageSaveCert        = "save_cert"
	StageTriggerDeploy   = "trigger_deploy"
)

// AllCertStages defines the ordered 6 stages for a certificate issuance job.
var AllCertStages = []string{
	StageCreateOrder,
	StageWriteDNSTXT,
	StageWaitPropagation,
	StageCAValidate,
	StageSaveCert,
	StageTriggerDeploy,
}

// Setting keys in the `settings` table.
const (
	SettingInspectTime        = "inspect_time"
	SettingRenewBeforeDays    = "renew_before_days"
	SettingExpiringWarnDays   = "expiring_warn_days"
	SettingLogRetentionDays   = "log_retention_days"
	SettingLogMaxRows         = "log_max_rows"
	SettingAdminPasswordHash  = "admin_password_hash"
	SettingMustChangePassword = "must_change_password"
)

// ============================================================================
// 12 Database Entity Models
// ============================================================================

// Setting maps to table `settings`.
type Setting struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session maps to table `sessions`.
type Session struct {
	ID         string    `json:"id"`
	CSRFToken  string    `json:"csrf_token"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// CAAccount maps to table `ca_accounts`.
type CAAccount struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Provider     string    `json:"provider"`
	Environment  string    `json:"environment"`
	Email        string    `json:"email"`
	DirectoryURL string    `json:"directory_url"`
	ACMEKeyEnc   string    `json:"-"`
	AccountURI   string    `json:"account_uri"`
	IsDefault    bool      `json:"is_default"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DNSCredential maps to table `dns_credentials`.
type DNSCredential struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Provider     string     `json:"provider"`
	ConfigEnc    string     `json:"-"`
	LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
	LastTestOK   *bool      `json:"last_test_ok,omitempty"`
	LastTestMsg  string     `json:"last_test_msg"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Certificate maps to table `certificates`.
type Certificate struct {
	ID                     int64      `json:"id"`
	Name                   string     `json:"name"`
	Domain                 string     `json:"domain"`
	SANsJSON               string     `json:"-"`
	CAAccountID            int64      `json:"ca_account_id"`
	DNSCredentialID        int64      `json:"dns_credential_id"`
	ZoneOverride           string     `json:"zone_override"`
	KeyType                string     `json:"key_type"`
	RenewBeforeDays        int        `json:"renew_before_days"`
	AutoRenew              bool       `json:"auto_renew"`
	Status                 string     `json:"status"`
	IssuerName             string     `json:"issuer_name"`
	IssuedSANsJSON         string     `json:"-"`
	FingerprintSHA256      string     `json:"fingerprint_sha256"`
	NotBefore              *time.Time `json:"not_before,omitempty"`
	NotAfter               *time.Time `json:"not_after,omitempty"`
	LastIssuedAt           *time.Time `json:"last_issued_at,omitempty"`
	LastError              string     `json:"last_error"`
	RetryCount             int        `json:"retry_count"`
	NextRetryAt            *time.Time `json:"next_retry_at,omitempty"`
	LastExpiringNotifiedAt *time.Time `json:"last_expiring_notified_at,omitempty"`
	CertDir                string     `json:"cert_dir"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// Host maps to table `hosts`.
type Host struct {
	ID                      int64      `json:"id"`
	Name                    string     `json:"name"`
	IsLocal                 bool       `json:"is_local"`
	Mode                    string     `json:"mode"`
	Host                    string     `json:"host"`
	Port                    int        `json:"port"`
	Username                string     `json:"username"`
	AuthType                string     `json:"auth_type"`
	SSHPrivateKeyEnc        string     `json:"-"`
	SSHPassphraseEnc        string     `json:"-"`
	SSHPasswordEnc          string     `json:"-"`
	HostKeyPolicy           string     `json:"host_key_policy"`
	HostKeyFingerprint      string     `json:"host_key_fingerprint"`
	CaddyEnabled            bool       `json:"caddy_enabled"`
	CaddyContainer          string     `json:"caddy_container"`
	CaddyHostCaddyfile      string     `json:"caddy_host_caddyfile"`
	CaddyContainerCaddyfile string     `json:"caddy_container_caddyfile"`
	CaddyHostCertDir        string     `json:"caddy_host_cert_dir"`
	CaddyContainerCertDir   string     `json:"caddy_container_cert_dir"`
	LastCheckAt             *time.Time `json:"last_check_at,omitempty"`
	LastCheckOK             *bool      `json:"last_check_ok,omitempty"`
	LastCheckMsg            string     `json:"last_check_msg"`
	CaddyStatus             string     `json:"caddy_status"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

// Deployment maps to table `deployments`.
type Deployment struct {
	ID                  int64      `json:"id"`
	CertificateID       int64      `json:"certificate_id"`
	HostID              int64      `json:"host_id"`
	Name                string     `json:"name"`
	Template            string     `json:"template"`
	Enabled             bool       `json:"enabled"`
	FullchainPath       string     `json:"fullchain_path"`
	PrivkeyPath         string     `json:"privkey_path"`
	IssuerPath          string     `json:"issuer_path"`
	CertFileMode        string     `json:"cert_file_mode"`
	KeyFileMode         string     `json:"key_file_mode"`
	ReloadMode          string     `json:"reload_mode"`
	ReloadCommand       string     `json:"reload_command"`
	ReloadWebhookURL    string     `json:"reload_webhook_url"`
	TLSVerifyEnabled    bool       `json:"tls_verify_enabled"`
	TLSVerifyHost       string     `json:"tls_verify_host"`
	TLSVerifyPort       int        `json:"tls_verify_port"`
	TLSVerifySNI        string     `json:"tls_verify_sni"`
	LastStatus          string     `json:"last_status"`
	LastDeployedAt      *time.Time `json:"last_deployed_at,omitempty"`
	LastCertFingerprint string     `json:"last_cert_fingerprint"`
	LastError           string     `json:"last_error"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// CertJob maps to table `cert_jobs`.
type CertJob struct {
	ID            int64      `json:"id"`
	CertificateID int64      `json:"certificate_id"`
	TriggerType   string     `json:"trigger_type"`
	Status        string     `json:"status"`
	CurrentStage  string     `json:"current_stage"`
	StagesJSON    string     `json:"-"`
	Logs          string     `json:"logs"`
	ErrorMessage  string     `json:"error_message"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// DeployLog maps to table `deploy_logs`.
type DeployLog struct {
	ID            int64      `json:"id"`
	DeploymentID  int64      `json:"deployment_id"`
	CertificateID int64      `json:"certificate_id"`
	HostID        int64      `json:"host_id"`
	CertJobID     *int64     `json:"cert_job_id,omitempty"`
	TriggerType   string     `json:"trigger_type"`
	Status        string     `json:"status"`
	ExitCode      *int       `json:"exit_code,omitempty"`
	Stdout        string     `json:"stdout"`
	Stderr        string     `json:"stderr"`
	TLSVerified   bool       `json:"tls_verified"`
	TLSObservedFP string     `json:"tls_observed_fp"`
	ErrorMessage  string     `json:"error_message"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
}

// CaddySnapshot maps to table `caddy_snapshots`.
type CaddySnapshot struct {
	ID           int64     `json:"id"`
	HostID       int64     `json:"host_id"`
	Version      int       `json:"version"`
	Content      string    `json:"content"`
	SHA256       string    `json:"sha256"`
	Action       string    `json:"action"`
	Summary      string    `json:"summary"`
	ReloadOK     bool      `json:"reload_ok"`
	ReloadOutput string    `json:"reload_output"`
	CreatedAt    time.Time `json:"created_at"`
}

// Webhook maps to table `webhooks`.
type Webhook struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	HeadersEnc      string     `json:"-"`
	SecretEnc       string     `json:"-"`
	EventsJSON      string     `json:"-"`
	Enabled         bool       `json:"enabled"`
	LastStatusCode  *int       `json:"last_status_code,omitempty"`
	LastError       string     `json:"last_error"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AuditEvent maps to table `audit_events`.
type AuditEvent struct {
	ID         int64     `json:"id"`
	EventType  string    `json:"event_type"`
	Level      string    `json:"level"`
	TargetType string    `json:"target_type"`
	TargetID   *int64    `json:"target_id,omitempty"`
	TargetName string    `json:"target_name"`
	Message    string    `json:"message"`
	MetaJSON   string    `json:"meta_json"`
	ActorIP    string    `json:"actor_ip"`
	CreatedAt  time.Time `json:"created_at"`
}

// ============================================================================
// Decrypted Secret Payloads (internal use only, never serialized directly to API)
// ============================================================================

// CloudflareCredConfig is the decrypted JSON stored in dns_credentials.config_enc.
type CloudflareCredConfig struct {
	APIToken string `json:"api_token"`
}

// HuaweiCredConfig is the decrypted JSON stored in dns_credentials.config_enc.
type HuaweiCredConfig struct {
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	Region    string `json:"region"`
}

// ============================================================================
// Auth DTOs
// ============================================================================

type LoginRequest struct {
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type AuthMeResponse struct {
	Authenticated      bool   `json:"authenticated"`
	MustChangePassword bool   `json:"must_change_password"`
	CSRFToken          string `json:"csrf_token"`
	IP                 string `json:"ip"`
}

// ============================================================================
// CA Account DTOs
// ============================================================================

type CAAccountDTO struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Provider     string    `json:"provider"`
	Environment  string    `json:"environment"`
	Email        string    `json:"email"`
	DirectoryURL string    `json:"directory_url"`
	AccountURI   string    `json:"account_uri"`
	IsDefault    bool      `json:"is_default"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateCARequest struct {
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Environment string `json:"environment"`
	Email       string `json:"email"`
	IsDefault   bool   `json:"is_default"`
	EABKeyID    string `json:"eab_kid,omitempty"`
	EABHMACKey  string `json:"eab_mac_key,omitempty"`
	ACMEKeyPEM  string `json:"acme_key_pem,omitempty"`
	AccountURI  string `json:"account_uri,omitempty"`
}

type UpdateCARequest struct {
	Name      *string `json:"name,omitempty"`
	Email     *string `json:"email,omitempty"`
	IsDefault *bool   `json:"is_default,omitempty"`
}

type ExportCAKeyResponse struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	Environment  string `json:"environment"`
	Email        string `json:"email"`
	DirectoryURL string `json:"directory_url"`
	AccountURI   string `json:"account_uri"`
	ACMEKeyPEM   string `json:"acme_key_pem"`
}

// ============================================================================
// DNS Credential DTOs
// ============================================================================

type DNSCredentialDTO struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Provider     string     `json:"provider"`
	Region       string     `json:"region,omitempty"`
	HasSecret    bool       `json:"has_secret"`
	LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
	LastTestOK   *bool      `json:"last_test_ok,omitempty"`
	LastTestMsg  string     `json:"last_test_msg"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type CreateDNSRequest struct {
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	APIToken  string `json:"api_token,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	Region    string `json:"region,omitempty"`
}

type UpdateDNSRequest struct {
	Name      *string `json:"name,omitempty"`
	APIToken  *string `json:"api_token,omitempty"`
	AccessKey *string `json:"access_key,omitempty"`
	SecretKey *string `json:"secret_key,omitempty"`
	Region    *string `json:"region,omitempty"`
}

type DNSZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type DNSTestResponse struct {
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	Zones   []DNSZone `json:"zones"`
}

type DNSZonesResponse struct {
	Zones       []DNSZone `json:"zones"`
	MatchedZone string    `json:"matched_zone"`
}

type TestDNSAdhocRequest struct {
	CredentialID int64  `json:"credential_id,omitempty"`
	Name         string `json:"name,omitempty"`
	Provider     string `json:"provider"`
	APIToken     string `json:"api_token,omitempty"`
	AccessKey    string `json:"access_key,omitempty"`
	SecretKey    string `json:"secret_key,omitempty"`
	Region       string `json:"region,omitempty"`
}

// ============================================================================
// Certificate & Job DTOs
// ============================================================================

type CertificateDTO struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	Domain            string     `json:"domain"`
	SANs              []string   `json:"sans"`
	CAAccountID       int64      `json:"ca_account_id"`
	CAAccountName     string     `json:"ca_account_name,omitempty"`
	DNSCredentialID   int64      `json:"dns_credential_id"`
	DNSCredentialName string     `json:"dns_credential_name,omitempty"`
	ZoneOverride      string     `json:"zone_override"`
	KeyType           string     `json:"key_type"`
	RenewBeforeDays   int        `json:"renew_before_days"`
	AutoRenew         bool       `json:"auto_renew"`
	Status            string     `json:"status"`
	IssuerName        string     `json:"issuer_name"`
	IssuedSANs        []string   `json:"issued_sans"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	DaysRemaining     *int       `json:"days_remaining,omitempty"`
	LastIssuedAt      *time.Time `json:"last_issued_at,omitempty"`
	LastError         string     `json:"last_error"`
	RetryCount        int        `json:"retry_count"`
	NextRetryAt       *time.Time `json:"next_retry_at,omitempty"`
	CertDir           string     `json:"cert_dir"`
	DeploymentTotal   int        `json:"deployment_total"`
	DeploymentSuccess int        `json:"deployment_success"`
	DeploymentFailed  int        `json:"deployment_failed"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type CreateCertRequest struct {
	Name            string   `json:"name"`
	Domain          string   `json:"domain"`
	SANs            []string `json:"sans"`
	CAAccountID     int64    `json:"ca_account_id"`
	DNSCredentialID int64    `json:"dns_credential_id"`
	ZoneOverride    string   `json:"zone_override"`
	KeyType         string   `json:"key_type"`
	RenewBeforeDays *int     `json:"renew_before_days,omitempty"`
	AutoRenew       *bool    `json:"auto_renew,omitempty"`
}

type UpdateCertRequest struct {
	Name            *string  `json:"name,omitempty"`
	Domain          *string  `json:"domain,omitempty"`
	SANs            []string `json:"sans,omitempty"`
	CAAccountID     *int64   `json:"ca_account_id,omitempty"`
	DNSCredentialID *int64   `json:"dns_credential_id,omitempty"`
	ZoneOverride    *string  `json:"zone_override,omitempty"`
	KeyType         *string  `json:"key_type,omitempty"`
	RenewBeforeDays *int     `json:"renew_before_days,omitempty"`
	AutoRenew       *bool    `json:"auto_renew,omitempty"`
}

type CertPEMRequest struct {
	IncludePrivateKey bool `json:"include_private_key"`
}

type CertPEMResponse struct {
	FullchainPEM      string `json:"fullchain_pem"`
	PrivkeyPEM        string `json:"privkey_pem,omitempty"`
	IssuerPEM         string `json:"issuer_pem"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type CertJobStage struct {
	Stage      string     `json:"stage"`
	Label      string     `json:"label"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Message    string     `json:"message,omitempty"`
}

type CertJobDTO struct {
	ID            int64          `json:"id"`
	CertificateID int64          `json:"certificate_id"`
	TriggerType   string         `json:"trigger_type"`
	Status        string         `json:"status"`
	CurrentStage  string         `json:"current_stage"`
	Stages        []CertJobStage `json:"stages"`
	Logs          string         `json:"logs"`
	ErrorMessage  string         `json:"error_message"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    *time.Time     `json:"finished_at,omitempty"`
}

type IssueCertResponse struct {
	JobID int64 `json:"job_id"`
}

type CertJobSSEEvent struct {
	Type         string         `json:"type"` // stage | log | done
	JobID        int64          `json:"job_id"`
	Status       string         `json:"status"`
	CurrentStage string         `json:"current_stage"`
	Stages       []CertJobStage `json:"stages,omitempty"`
	LogLine      string         `json:"log_line,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
}

// ============================================================================
// Host & Deployment DTOs
// ============================================================================

type HostDTO struct {
	ID                      int64      `json:"id"`
	Name                    string     `json:"name"`
	IsLocal                 bool       `json:"is_local"`
	Mode                    string     `json:"mode"`
	Host                    string     `json:"host"`
	Port                    int        `json:"port"`
	Username                string     `json:"username"`
	AuthType                string     `json:"auth_type"`
	HasPrivateKey           bool       `json:"has_private_key"`
	HasPassphrase           bool       `json:"has_passphrase"`
	HasPassword             bool       `json:"has_password"`
	HostKeyPolicy           string     `json:"host_key_policy"`
	HostKeyFingerprint      string     `json:"host_key_fingerprint"`
	CaddyEnabled            bool       `json:"caddy_enabled"`
	CaddyContainer          string     `json:"caddy_container"`
	CaddyHostCaddyfile      string     `json:"caddy_host_caddyfile"`
	CaddyContainerCaddyfile string     `json:"caddy_container_caddyfile"`
	CaddyHostCertDir        string     `json:"caddy_host_cert_dir"`
	CaddyContainerCertDir   string     `json:"caddy_container_cert_dir"`
	LastCheckAt             *time.Time `json:"last_check_at,omitempty"`
	LastCheckOK             *bool      `json:"last_check_ok,omitempty"`
	LastCheckMsg            string     `json:"last_check_msg"`
	CaddyStatus             string     `json:"caddy_status"`
	DeploymentCount         int        `json:"deployment_count"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
}

type CreateHostRequest struct {
	Name                    string `json:"name"`
	Mode                    string `json:"mode"`
	Host                    string `json:"host"`
	Port                    int    `json:"port"`
	Username                string `json:"username"`
	AuthType                string `json:"auth_type"`
	SSHPrivateKey           string `json:"ssh_private_key,omitempty"`
	SSHPassphrase           string `json:"ssh_passphrase,omitempty"`
	SSHPassword             string `json:"ssh_password,omitempty"`
	HostKeyPolicy           string `json:"host_key_policy"`
	CaddyEnabled            *bool  `json:"caddy_enabled,omitempty"`
	CaddyContainer          string `json:"caddy_container"`
	CaddyHostCaddyfile      string `json:"caddy_host_caddyfile"`
	CaddyContainerCaddyfile string `json:"caddy_container_caddyfile"`
	CaddyHostCertDir        string `json:"caddy_host_cert_dir"`
	CaddyContainerCertDir   string `json:"caddy_container_cert_dir"`
}

type UpdateHostRequest struct {
	Name                    *string `json:"name,omitempty"`
	Host                    *string `json:"host,omitempty"`
	Port                    *int    `json:"port,omitempty"`
	Username                *string `json:"username,omitempty"`
	AuthType                *string `json:"auth_type,omitempty"`
	SSHPrivateKey           *string `json:"ssh_private_key,omitempty"`
	SSHPassphrase           *string `json:"ssh_passphrase,omitempty"`
	SSHPassword             *string `json:"ssh_password,omitempty"`
	HostKeyPolicy           *string `json:"host_key_policy,omitempty"`
	CaddyEnabled            *bool   `json:"caddy_enabled,omitempty"`
	CaddyContainer          *string `json:"caddy_container,omitempty"`
	CaddyHostCaddyfile      *string `json:"caddy_host_caddyfile,omitempty"`
	CaddyContainerCaddyfile *string `json:"caddy_container_caddyfile,omitempty"`
	CaddyHostCertDir        *string `json:"caddy_host_cert_dir,omitempty"`
	CaddyContainerCertDir   *string `json:"caddy_container_cert_dir,omitempty"`
}

type DeploymentDTO struct {
	ID                  int64      `json:"id"`
	CertificateID       int64      `json:"certificate_id"`
	CertDomain          string     `json:"cert_domain,omitempty"`
	HostID              int64      `json:"host_id"`
	HostName            string     `json:"host_name,omitempty"`
	HostMode            string     `json:"host_mode,omitempty"`
	Name                string     `json:"name"`
	Template            string     `json:"template"`
	Enabled             bool       `json:"enabled"`
	FullchainPath       string     `json:"fullchain_path"`
	PrivkeyPath         string     `json:"privkey_path"`
	IssuerPath          string     `json:"issuer_path"`
	CertFileMode        string     `json:"cert_file_mode"`
	KeyFileMode         string     `json:"key_file_mode"`
	ReloadMode          string     `json:"reload_mode"`
	ReloadCommand       string     `json:"reload_command"`
	ReloadWebhookURL    string     `json:"reload_webhook_url"`
	TLSVerifyEnabled    bool       `json:"tls_verify_enabled"`
	TLSVerifyHost       string     `json:"tls_verify_host"`
	TLSVerifyPort       int        `json:"tls_verify_port"`
	TLSVerifySNI        string     `json:"tls_verify_sni"`
	LastStatus          string     `json:"last_status"`
	LastDeployedAt      *time.Time `json:"last_deployed_at,omitempty"`
	LastCertFingerprint string     `json:"last_cert_fingerprint"`
	LastError           string     `json:"last_error"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type CreateDeploymentRequest struct {
	HostID           int64  `json:"host_id"`
	Name             string `json:"name"`
	Template         string `json:"template"`
	Enabled          *bool  `json:"enabled,omitempty"`
	FullchainPath    string `json:"fullchain_path"`
	PrivkeyPath      string `json:"privkey_path"`
	IssuerPath       string `json:"issuer_path"`
	CertFileMode     string `json:"cert_file_mode"`
	KeyFileMode      string `json:"key_file_mode"`
	ReloadMode       string `json:"reload_mode"`
	ReloadCommand    string `json:"reload_command"`
	ReloadWebhookURL string `json:"reload_webhook_url"`
	TLSVerifyEnabled *bool  `json:"tls_verify_enabled,omitempty"`
	TLSVerifyHost    string `json:"tls_verify_host"`
	TLSVerifyPort    int    `json:"tls_verify_port"`
	TLSVerifySNI     string `json:"tls_verify_sni"`
}

type UpdateDeploymentRequest struct {
	Name             *string `json:"name,omitempty"`
	Template         *string `json:"template,omitempty"`
	Enabled          *bool   `json:"enabled,omitempty"`
	FullchainPath    *string `json:"fullchain_path,omitempty"`
	PrivkeyPath      *string `json:"privkey_path,omitempty"`
	IssuerPath       *string `json:"issuer_path,omitempty"`
	CertFileMode     *string `json:"cert_file_mode,omitempty"`
	KeyFileMode      *string `json:"key_file_mode,omitempty"`
	ReloadMode       *string `json:"reload_mode,omitempty"`
	ReloadCommand    *string `json:"reload_command,omitempty"`
	ReloadWebhookURL *string `json:"reload_webhook_url,omitempty"`
	TLSVerifyEnabled *bool   `json:"tls_verify_enabled,omitempty"`
	TLSVerifyHost    *string `json:"tls_verify_host,omitempty"`
	TLSVerifyPort    *int    `json:"tls_verify_port,omitempty"`
	TLSVerifySNI     *string `json:"tls_verify_sni,omitempty"`
}

// ============================================================================
// Caddy Management DTOs
// ============================================================================

type CaddyfileResponse struct {
	HostID            int64  `json:"host_id"`
	HostName          string `json:"host_name"`
	Content           string `json:"content"`
	SHA256            string `json:"sha256"`
	MountType         string `json:"mount_type"` // dir | file | local | unknown
	HostCaddyfilePath string `json:"host_caddyfile_path"`
	ContainerName     string `json:"container_name"`
}

type SaveCaddyfileRequest struct {
	Content        string `json:"content"`
	ExpectedSHA256 string `json:"expected_sha256"`
	Force          bool   `json:"force"`
	Summary        string `json:"summary"`
}

type CaddyConflictDetails struct {
	ExpectedSHA256 string `json:"expected_sha256"`
	RemoteSHA256   string `json:"remote_sha256"`
	RemoteContent  string `json:"remote_content"`
}

type CaddyValidateErrorDetails struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
	Output  string `json:"output"`
}

type CaddyFormatRequest struct {
	Content string `json:"content"`
}

type CaddyFormatResponse struct {
	Content string `json:"content"`
}

type CaddyValidateRequest struct {
	Content string `json:"content"`
}

type CaddyValidateResponse struct {
	Valid   bool   `json:"valid"`
	Output  string `json:"output"`
	Line    int    `json:"line,omitempty"`
	Message string `json:"message,omitempty"`
}

type CaddySnapshotDTO struct {
	ID           int64     `json:"id"`
	HostID       int64     `json:"host_id"`
	Version      int       `json:"version"`
	Content      string    `json:"content"`
	SHA256       string    `json:"sha256"`
	Action       string    `json:"action"`
	Summary      string    `json:"summary"`
	ReloadOK     bool      `json:"reload_ok"`
	ReloadOutput string    `json:"reload_output"`
	CreatedAt    time.Time `json:"created_at"`
}

type CaddySaveResponse struct {
	SHA256     string            `json:"sha256"`
	ReloadOK   bool              `json:"reload_ok"`
	Output     string            `json:"output"`
	RolledBack bool              `json:"rolled_back"`
	Snapshot   *CaddySnapshotDTO `json:"snapshot,omitempty"`
}

type CaddyDiffResponse struct {
	SnapshotID      int64  `json:"snapshot_id"`
	Version         int    `json:"version"`
	SnapshotSHA256  string `json:"snapshot_sha256"`
	CurrentSHA256   string `json:"current_sha256"`
	SnapshotContent string `json:"snapshot_content"`
	CurrentContent  string `json:"current_content"`
	DiffText        string `json:"diff_text"`
}

type CaddyContainerInfo struct {
	HostID        int64     `json:"host_id"`
	ContainerName string    `json:"container_name"`
	Status        string    `json:"status"`
	Running       bool      `json:"running"`
	Image         string    `json:"image"`
	MountType     string    `json:"mount_type"`
	Mounts        []string  `json:"mounts"`
	Logs          string    `json:"logs"`
	InspectedAt   time.Time `json:"inspected_at"`
}

type DetectedContainer struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Running bool   `json:"running"`
	IsCaddy bool   `json:"is_caddy"`
}

type DetectedCaddyConfig struct {
	ContainerName           string `json:"container_name"`
	HostCaddyfile           string `json:"host_caddyfile,omitempty"`
	ContainerCaddyfile      string `json:"container_caddyfile,omitempty"`
	HostCertDir             string `json:"host_cert_dir,omitempty"`
	ContainerCertDir        string `json:"container_cert_dir,omitempty"`
	MountType               string `json:"mount_type,omitempty"`
}

type HostProbeRequest struct {
	HostID                  int64  `json:"host_id,omitempty"`
	Name                    string `json:"name,omitempty"`
	Mode                    string `json:"mode,omitempty"`
	Host                    string `json:"host,omitempty"`
	Port                    int    `json:"port,omitempty"`
	Username                string `json:"username,omitempty"`
	AuthType                string `json:"auth_type,omitempty"`
	SSHPrivateKey           string `json:"ssh_private_key,omitempty"`
	SSHPassphrase           string `json:"ssh_passphrase,omitempty"`
	SSHPassword             string `json:"ssh_password,omitempty"`
	HostKeyPolicy           string `json:"host_key_policy,omitempty"`
	CaddyEnabled            *bool  `json:"caddy_enabled,omitempty"`
	CaddyContainer          string `json:"caddy_container,omitempty"`
	CaddyHostCaddyfile      string `json:"caddy_host_caddyfile,omitempty"`
	CaddyContainerCaddyfile string `json:"caddy_container_caddyfile,omitempty"`
	CaddyHostCertDir        string `json:"caddy_host_cert_dir,omitempty"`
	CaddyContainerCertDir   string `json:"caddy_container_cert_dir,omitempty"`
	TargetContainer         string `json:"target_container,omitempty"`
}

type DiscoverCaddyRequest struct {
	ContainerName string `json:"container_name,omitempty"`
}

type DiscoverCaddyResponse struct {
	DockerOK            bool                 `json:"docker_ok"`
	CaddyIssueCode      string               `json:"caddy_issue_code,omitempty"`
	CaddyfileExists     *bool                `json:"caddyfile_exists,omitempty"`
	DetectedContainers  []DetectedContainer  `json:"detected_containers"`
	DetectedCaddyConfig *DetectedCaddyConfig `json:"detected_caddy_config,omitempty"`
	Message             string               `json:"message"`
}

// ============================================================================
// Webhook DTOs
// ============================================================================

type WebhookDTO struct {
	ID              int64      `json:"id"`
	Name            string     `json:"name"`
	URL             string     `json:"url"`
	HeaderKeys      []string   `json:"header_keys"`
	HasSecret       bool       `json:"has_secret"`
	Events          []string   `json:"events"`
	Enabled         bool       `json:"enabled"`
	LastStatusCode  *int       `json:"last_status_code,omitempty"`
	LastError       string     `json:"last_error"`
	LastTriggeredAt *time.Time `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type CreateWebhookRequest struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Secret  string            `json:"secret,omitempty"`
	Events  []string          `json:"events"`
	Enabled *bool             `json:"enabled,omitempty"`
}

type UpdateWebhookRequest struct {
	Name    *string           `json:"name,omitempty"`
	URL     *string           `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Secret  *string           `json:"secret,omitempty"`
	Events  []string          `json:"events,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// WebhookEvent is passed internally by producers to Notifier.Emit.
type WebhookEvent struct {
	Event       string            `json:"event"`
	Level       string            `json:"level"`
	Title       string            `json:"title"`
	Message     string            `json:"message"`
	Certificate *WebhookCertRef   `json:"certificate,omitempty"`
	Host        *WebhookHostRef   `json:"host,omitempty"`
	Deployment  *WebhookDeployRef `json:"deployment,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

// WebhookPayload is the unified JSON envelope sent to external Webhook endpoints.
type WebhookPayload struct {
	Event       string            `json:"event"`
	Timestamp   time.Time         `json:"timestamp"`
	Level       string            `json:"level"`
	Title       string            `json:"title"`
	Message     string            `json:"message"`
	Certificate *WebhookCertRef   `json:"certificate,omitempty"`
	Host        *WebhookHostRef   `json:"host,omitempty"`
	Deployment  *WebhookDeployRef `json:"deployment,omitempty"`
	Error       string            `json:"error,omitempty"`
	Metadata    map[string]any    `json:"metadata,omitempty"`
}

type WebhookCertRef struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"`
}

type WebhookHostRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Host string `json:"host,omitempty"`
}

type WebhookDeployRef struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ============================================================================
// Dashboard, Settings, Prune & Backup DTOs
// ============================================================================

type CertHealthStats struct {
	Total    int `json:"total"`
	Valid    int `json:"valid"`
	Expiring int `json:"expiring"`
	Expired  int `json:"expired"`
	Error    int `json:"error"`
	Pending  int `json:"pending"`
}

type HostOverviewStats struct {
	Total        int `json:"total"`
	Reachable    int `json:"reachable"`
	Unreachable  int `json:"unreachable"`
	CaddyRunning int `json:"caddy_running"`
}

type DeploymentOverviewStats struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
	Pending int `json:"pending"`
}

type ChecklistItem struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Done  bool   `json:"done"`
	Href  string `json:"href"`
}

type DashboardResponse struct {
	CertStats       CertHealthStats         `json:"cert_stats"`
	HostStats       HostOverviewStats       `json:"host_stats"`
	DeploymentStats DeploymentOverviewStats `json:"deployment_stats"`
	RecentEvents    []AuditEvent            `json:"recent_events"`
	Checklist       []ChecklistItem         `json:"checklist"`
}

type SettingsDTO struct {
	InspectTime      string `json:"inspect_time"`
	RenewBeforeDays  int    `json:"renew_before_days"`
	ExpiringWarnDays int    `json:"expiring_warn_days"`
	LogRetentionDays int    `json:"log_retention_days"`
	LogMaxRows       int    `json:"log_max_rows"`
	Timezone         string `json:"timezone,omitempty"`
}

type UpdateSettingsRequest struct {
	InspectTime      *string `json:"inspect_time,omitempty"`
	RenewBeforeDays  *int    `json:"renew_before_days,omitempty"`
	ExpiringWarnDays *int    `json:"expiring_warn_days,omitempty"`
	LogRetentionDays *int    `json:"log_retention_days,omitempty"`
	LogMaxRows       *int    `json:"log_max_rows,omitempty"`
}

type PruneResult struct {
	CertJobsDeleted    int64 `json:"cert_jobs_deleted"`
	DeployLogsDeleted  int64 `json:"deploy_logs_deleted"`
	AuditEventsDeleted int64 `json:"audit_events_deleted"`
	TotalDeleted       int64 `json:"total_deleted"`
	VacuumRan          bool  `json:"vacuum_ran"`
}

type BackupManifest struct {
	Version    int               `json:"version"`
	AppVersion string            `json:"app_version"`
	CreatedAt  time.Time         `json:"created_at"`
	Files      map[string]string `json:"files"` // archive relative path -> lowercase sha256 hex
}

type RestoreResult struct {
	RestoredAt      time.Time `json:"restored_at"`
	PreRestoreDir   string    `json:"pre_restore_dir"`
	ReloginRequired bool      `json:"relogin_required"`
	Message         string    `json:"message"`
}
