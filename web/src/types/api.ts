export interface ApiErrorBody<T = unknown> {
  code: string
  message: string
  details?: T
}

export interface ApiEnvelope<T = unknown, E = unknown> {
  ok: boolean
  data?: T
  error?: ApiErrorBody<E>
}

// ============================================================================
// Auth
// ============================================================================

export interface AuthMeResponse {
  authenticated: boolean
  must_change_password: boolean
  csrf_token: string
  ip: string
}

export interface LoginRequest {
  password: string
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface RateLimitDetails {
  retry_after_seconds: number
}

// ============================================================================
// Dashboard & Audit
// ============================================================================

export interface AuditEvent {
  id: number
  event_type: string
  level: 'info' | 'warn' | 'error' | string
  target_type: string
  target_id?: number | null
  target_name: string
  message: string
  meta_json: string
  actor_ip: string
  created_at: string
}

export interface CertHealthStats {
  total: number
  valid: number
  expiring: number
  expired: number
  error: number
  pending: number
}

export interface HostOverviewStats {
  total: number
  reachable: number
  unreachable: number
  caddy_running: number
}

export interface DeploymentOverviewStats {
  total: number
  success: number
  failed: number
  pending: number
}

export interface ChecklistItem {
  key: string
  title: string
  done: boolean
  href: string
}

export interface DashboardResponse {
  cert_stats: CertHealthStats
  host_stats: HostOverviewStats
  deployment_stats: DeploymentOverviewStats
  recent_events: AuditEvent[]
  checklist: ChecklistItem[]
}

// ============================================================================
// CA Accounts
// ============================================================================

export type CAProvider = 'letsencrypt' | 'gts'
export type CAEnvironment = 'production' | 'staging'

export interface CAAccountDTO {
  id: number
  name: string
  provider: CAProvider | string
  environment: CAEnvironment | string
  email: string
  directory_url: string
  account_uri: string
  is_default: boolean
  status: string
  created_at: string
  updated_at: string
}

export interface CreateCARequest {
  name: string
  provider: CAProvider
  environment: CAEnvironment
  email: string
  is_default: boolean
  eab_kid?: string
  eab_mac_key?: string
  acme_key_pem?: string
  account_uri?: string
}

export interface UpdateCARequest {
  name?: string
  email?: string
  is_default?: boolean
}

export interface ExportCAKeyResponse {
  id: number
  name: string
  provider: string
  environment: string
  email: string
  directory_url: string
  account_uri: string
  acme_key_pem: string
}

// ============================================================================
// DNS Credentials
// ============================================================================

export type DNSProvider = 'cloudflare' | 'huaweicloud'

export interface DNSCredentialDTO {
  id: number
  name: string
  provider: DNSProvider | string
  region?: string
  has_secret: boolean
  last_tested_at?: string | null
  last_test_ok?: boolean | null
  last_test_msg: string
  created_at: string
  updated_at: string
}

export interface CreateDNSRequest {
  name: string
  provider: DNSProvider
  api_token?: string
  access_key?: string
  secret_key?: string
  region?: string
}

export interface UpdateDNSRequest {
  name?: string
  api_token?: string
  access_key?: string
  secret_key?: string
  region?: string
}

export interface DNSZone {
  id: string
  name: string
}

export interface DNSTestResponse {
  ok: boolean
  message: string
  zones: DNSZone[]
}

export interface DNSZonesResponse {
  zones: DNSZone[]
  matched_zone: string
}

// ============================================================================
// Certificates & Jobs
// ============================================================================

export type KeyType = 'EC256' | 'EC384' | 'RSA2048'
export type CertStatus = 'pending' | 'issuing' | 'valid' | 'expiring' | 'expired' | 'error'

export interface CertificateDTO {
  id: number
  name: string
  domain: string
  sans: string[]
  ca_account_id: number
  ca_account_name?: string
  dns_credential_id: number
  dns_credential_name?: string
  zone_override: string
  key_type: KeyType | string
  renew_before_days: number
  auto_renew: boolean
  status: CertStatus | string
  issuer_name: string
  issued_sans: string[]
  fingerprint_sha256: string
  not_before?: string | null
  not_after?: string | null
  days_remaining?: number | null
  last_issued_at?: string | null
  last_error: string
  retry_count: number
  next_retry_at?: string | null
  cert_dir: string
  deployment_total: number
  deployment_success: number
  deployment_failed: number
  created_at: string
  updated_at: string
}

export interface CreateCertRequest {
  name: string
  domain: string
  sans: string[]
  ca_account_id: number
  dns_credential_id: number
  zone_override: string
  key_type: KeyType
  renew_before_days?: number
  auto_renew?: boolean
}

export interface UpdateCertRequest {
  name?: string
  domain?: string
  sans?: string[]
  ca_account_id?: number
  dns_credential_id?: number
  zone_override?: string
  key_type?: KeyType
  renew_before_days?: number
  auto_renew?: boolean
}

export interface CertPEMRequest {
  include_private_key: boolean
}

export interface CertPEMResponse {
  fullchain_pem: string
  privkey_pem?: string
  issuer_pem: string
  fingerprint_sha256: string
}

export interface CertJobStage {
  stage: string
  label: string
  status: 'pending' | 'running' | 'success' | 'failed' | string
  started_at?: string | null
  finished_at?: string | null
  message?: string
}

export interface CertJobDTO {
  id: number
  certificate_id: number
  trigger_type: string
  status: 'pending' | 'running' | 'success' | 'failed' | string
  current_stage: string
  stages: CertJobStage[]
  logs: string
  error_message: string
  started_at: string
  finished_at?: string | null
}

export interface IssueCertResponse {
  job_id: number
}

export interface CertJobSSEEvent {
  type: 'stage' | 'log' | 'done' | string
  job_id: number
  status: string
  current_stage: string
  stages?: CertJobStage[]
  log_line?: string
  error_message?: string
  timestamp: string
}

// ============================================================================
// Hosts & Deployments
// ============================================================================

export type HostAuthType = 'none' | 'key' | 'password'
export type HostKeyPolicy = 'tofu' | 'strict' | 'insecure'

export interface HostDTO {
  id: number
  name: string
  is_local: boolean
  mode: 'local' | 'ssh' | string
  host: string
  port: number
  username: string
  auth_type: HostAuthType | string
  has_private_key: boolean
  has_passphrase: boolean
  has_password: boolean
  host_key_policy: HostKeyPolicy | string
  host_key_fingerprint: string
  caddy_enabled: boolean
  caddy_container: string
  caddy_host_caddyfile: string
  caddy_container_caddyfile: string
  caddy_host_cert_dir: string
  caddy_container_cert_dir: string
  last_check_at?: string | null
  last_check_ok?: boolean | null
  last_check_msg: string
  caddy_status: string
  deployment_count: number
  created_at: string
  updated_at: string
}

export interface CreateHostRequest {
  name: string
  mode: 'ssh'
  host: string
  port: number
  username: string
  auth_type: 'key' | 'password'
  ssh_private_key?: string
  ssh_passphrase?: string
  ssh_password?: string
  host_key_policy: HostKeyPolicy
  caddy_enabled?: boolean
  caddy_container: string
  caddy_host_caddyfile: string
  caddy_container_caddyfile: string
  caddy_host_cert_dir: string
  caddy_container_cert_dir: string
}

export interface UpdateHostRequest {
  name?: string
  host?: string
  port?: number
  username?: string
  auth_type?: 'key' | 'password'
  ssh_private_key?: string
  ssh_passphrase?: string
  ssh_password?: string
  host_key_policy?: HostKeyPolicy
  caddy_enabled?: boolean
  caddy_container?: string
  caddy_host_caddyfile?: string
  caddy_container_caddyfile?: string
  caddy_host_cert_dir?: string
  caddy_container_cert_dir?: string
}

export interface HostTestResult {
  ssh_ok: boolean
  docker_ok: boolean
  caddy_running: boolean
  host_key_fingerprint: string
  host_key_status: string
  message: string
  caddy_version?: string
}

export type DeployTemplate = 'caddy_docker' | 'local_dir' | 'custom_ssh'
export type ReloadMode = 'docker_exec' | 'caddy_admin_api' | 'webhook' | 'custom_cmd' | 'none'

export interface DeploymentDTO {
  id: number
  certificate_id: number
  cert_domain?: string
  host_id: number
  host_name?: string
  host_mode?: string
  name: string
  template: DeployTemplate | string
  enabled: boolean
  fullchain_path: string
  privkey_path: string
  issuer_path: string
  cert_file_mode: string
  key_file_mode: string
  reload_mode: ReloadMode | string
  reload_command: string
  reload_webhook_url: string
  tls_verify_enabled: boolean
  tls_verify_host: string
  tls_verify_port: number
  tls_verify_sni: string
  last_status: string
  last_deployed_at?: string | null
  last_cert_fingerprint: string
  last_error: string
  created_at: string
  updated_at: string
}

export interface CreateDeploymentRequest {
  host_id: number
  name: string
  template: DeployTemplate
  enabled?: boolean
  fullchain_path: string
  privkey_path: string
  issuer_path: string
  cert_file_mode: string
  key_file_mode: string
  reload_mode: ReloadMode
  reload_command: string
  reload_webhook_url: string
  tls_verify_enabled?: boolean
  tls_verify_host: string
  tls_verify_port: number
  tls_verify_sni: string
}

export interface UpdateDeploymentRequest {
  name?: string
  template?: DeployTemplate
  enabled?: boolean
  fullchain_path?: string
  privkey_path?: string
  issuer_path?: string
  cert_file_mode?: string
  key_file_mode?: string
  reload_mode?: ReloadMode
  reload_command?: string
  reload_webhook_url?: string
  tls_verify_enabled?: boolean
  tls_verify_host?: string
  tls_verify_port?: number
  tls_verify_sni?: string
}

export interface DeployLog {
  id: number
  deployment_id: number
  certificate_id: number
  host_id: number
  cert_job_id?: number | null
  trigger_type: string
  status: string
  exit_code?: number | null
  stdout: string
  stderr: string
  tls_verified: boolean
  tls_observed_fp: string
  error_message: string
  started_at: string
  finished_at?: string | null
}

// ============================================================================
// Caddy Management
// ============================================================================

export interface CaddyfileResponse {
  host_id: number
  host_name: string
  content: string
  sha256: string
  mount_type: string
  host_caddyfile_path: string
  container_name: string
}

export interface SaveCaddyfileRequest {
  content: string
  expected_sha256: string
  force: boolean
  summary: string
}

export interface CaddyConflictDetails {
  expected_sha256: string
  remote_sha256: string
  remote_content: string
}

export interface CaddyValidateErrorDetails {
  line: number
  message: string
  output: string
}

export interface CaddyValidateResponse {
  valid: boolean
  output: string
  line?: number
  message?: string
}

export interface CaddySnapshotDTO {
  id: number
  host_id: number
  version: number
  content: string
  sha256: string
  action: string
  summary: string
  reload_ok: boolean
  reload_output: string
  created_at: string
}

export interface CaddySaveResponse {
  sha256: string
  reload_ok: boolean
  output: string
  rolled_back: boolean
  snapshot?: CaddySnapshotDTO
}

export interface CaddyDiffResponse {
  snapshot_id: number
  version: number
  snapshot_sha256: string
  current_sha256: string
  snapshot_content: string
  current_content: string
  diff_text: string
}

export interface CaddyContainerInfo {
  host_id: number
  container_name: string
  status: string
  running: boolean
  image: string
  mount_type: string
  mounts: string[]
  logs: string
  inspected_at: string
}

// ============================================================================
// Webhooks, Settings & Backup
// ============================================================================

export type WebhookEventName =
  | 'cert.issue_failed'
  | 'cert.expiring_soon'
  | 'deploy.failed'
  | 'caddy.reload_failed'
  | 'cert.deployed'

export interface WebhookDTO {
  id: number
  name: string
  url: string
  header_keys: string[]
  has_secret: boolean
  events: string[]
  enabled: boolean
  last_status_code?: number | null
  last_error: string
  last_triggered_at?: string | null
  created_at: string
  updated_at: string
}

export interface CreateWebhookRequest {
  name: string
  url: string
  headers?: Record<string, string>
  secret?: string
  events: string[]
  enabled?: boolean
}

export interface UpdateWebhookRequest {
  name?: string
  url?: string
  headers?: Record<string, string>
  secret?: string
  events?: string[]
  enabled?: boolean
}

export interface WebhookTestResponse {
  ok: boolean
  status_code: number
  error?: string
  message?: string
}

export interface SettingsDTO {
  inspect_time: string
  renew_before_days: number
  expiring_warn_days: number
  log_retention_days: number
  log_max_rows: number
}

export interface UpdateSettingsRequest {
  inspect_time?: string
  renew_before_days?: number
  expiring_warn_days?: number
  log_retention_days?: number
  log_max_rows?: number
}

export interface PruneResult {
  cert_jobs_deleted: number
  deploy_logs_deleted: number
  audit_events_deleted: number
  total_deleted: number
  vacuum_ran: boolean
}

export interface RestoreResult {
  restored_at: string
  pre_restore_dir: string
  relogin_required: boolean
  message: string
}
