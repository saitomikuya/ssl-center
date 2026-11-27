-- 001_init.sql: Initial 12-table schema for ssl-center V1
-- Strictly 12 tables:
--   1. settings
--   2. sessions
--   3. ca_accounts
--   4. dns_credentials
--   5. certificates
--   6. hosts
--   7. deployments
--   8. cert_jobs
--   9. deploy_logs
--  10. caddy_snapshots
--  11. webhooks
--  12. audit_events

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO settings (key, value) VALUES
    ('inspect_time', '03:00'),
    ('renew_before_days', '30'),
    ('expiring_warn_days', '7'),
    ('log_retention_days', '30'),
    ('log_max_rows', '5000');

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS ca_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL CHECK(provider IN ('letsencrypt', 'gts')),
    environment TEXT NOT NULL CHECK(environment IN ('production', 'staging')),
    email TEXT NOT NULL,
    directory_url TEXT NOT NULL,
    acme_key_enc TEXT NOT NULL,
    account_uri TEXT NOT NULL DEFAULT '',
    is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'error')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ca_accounts_single_default
    ON ca_accounts(is_default) WHERE is_default = 1;

CREATE TABLE IF NOT EXISTS dns_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL CHECK(provider IN ('cloudflare', 'huaweicloud')),
    config_enc TEXT NOT NULL,
    last_tested_at DATETIME,
    last_test_ok INTEGER,
    last_test_msg TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL UNIQUE,
    sans_json TEXT NOT NULL DEFAULT '[]',
    ca_account_id INTEGER NOT NULL REFERENCES ca_accounts(id) ON DELETE RESTRICT,
    dns_credential_id INTEGER NOT NULL REFERENCES dns_credentials(id) ON DELETE RESTRICT,
    zone_override TEXT NOT NULL DEFAULT '',
    key_type TEXT NOT NULL DEFAULT 'EC256' CHECK(key_type IN ('EC256', 'EC384', 'RSA2048')),
    renew_before_days INTEGER NOT NULL DEFAULT 30,
    auto_renew INTEGER NOT NULL DEFAULT 1 CHECK(auto_renew IN (0, 1)),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'issuing', 'valid', 'expiring', 'expired', 'error')),
    issuer_name TEXT NOT NULL DEFAULT '',
    issued_sans_json TEXT NOT NULL DEFAULT '[]',
    fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    not_before DATETIME,
    not_after DATETIME,
    last_issued_at DATETIME,
    last_error TEXT NOT NULL DEFAULT '',
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at DATETIME,
    last_expiring_notified_at DATETIME,
    cert_dir TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_next_retry ON certificates(next_retry_at);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    is_local INTEGER NOT NULL DEFAULT 0 CHECK(is_local IN (0, 1)),
    mode TEXT NOT NULL DEFAULT 'ssh' CHECK(mode IN ('local', 'ssh')),
    host TEXT NOT NULL DEFAULT '',
    port INTEGER NOT NULL DEFAULT 22,
    username TEXT NOT NULL DEFAULT 'root',
    auth_type TEXT NOT NULL DEFAULT 'key' CHECK(auth_type IN ('none', 'key', 'password')),
    ssh_private_key_enc TEXT NOT NULL DEFAULT '',
    ssh_passphrase_enc TEXT NOT NULL DEFAULT '',
    ssh_password_enc TEXT NOT NULL DEFAULT '',
    host_key_policy TEXT NOT NULL DEFAULT 'tofu' CHECK(host_key_policy IN ('tofu', 'strict', 'insecure')),
    host_key_fingerprint TEXT NOT NULL DEFAULT '',
    caddy_enabled INTEGER NOT NULL DEFAULT 1 CHECK(caddy_enabled IN (0, 1)),
    caddy_container TEXT NOT NULL DEFAULT 'caddy',
    caddy_host_caddyfile TEXT NOT NULL DEFAULT '/opt/caddy/Caddyfile',
    caddy_container_caddyfile TEXT NOT NULL DEFAULT '/etc/caddy/Caddyfile',
    caddy_host_cert_dir TEXT NOT NULL DEFAULT '/opt/caddy/certs',
    caddy_container_cert_dir TEXT NOT NULL DEFAULT '/certs',
    last_check_at DATETIME,
    last_check_ok INTEGER,
    last_check_msg TEXT NOT NULL DEFAULT '',
    caddy_status TEXT NOT NULL DEFAULT 'unknown' CHECK(caddy_status IN ('running', 'stopped', 'unknown')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_hosts_single_local
    ON hosts(is_local) WHERE is_local = 1;

INSERT OR IGNORE INTO hosts (
    name, is_local, mode, host, port, username, auth_type,
    host_key_policy, caddy_enabled, caddy_container,
    caddy_host_caddyfile, caddy_container_caddyfile,
    caddy_host_cert_dir, caddy_container_cert_dir
) VALUES (
    'Local', 1, 'local', 'localhost', 0, '', 'none',
    'insecure', 1, 'caddy',
    '/opt/caddy/Caddyfile', '/etc/caddy/Caddyfile',
    '/opt/caddy/certs', '/certs'
);

CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE RESTRICT,
    name TEXT NOT NULL DEFAULT '',
    template TEXT NOT NULL DEFAULT 'caddy_docker' CHECK(template IN ('caddy_docker', 'local_dir', 'custom_ssh')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    fullchain_path TEXT NOT NULL,
    privkey_path TEXT NOT NULL,
    issuer_path TEXT NOT NULL DEFAULT '',
    cert_file_mode TEXT NOT NULL DEFAULT '0644',
    key_file_mode TEXT NOT NULL DEFAULT '0600',
    reload_mode TEXT NOT NULL DEFAULT 'docker_exec' CHECK(reload_mode IN ('docker_exec', 'caddy_admin_api', 'webhook', 'custom_cmd', 'none')),
    reload_command TEXT NOT NULL DEFAULT '',
    reload_webhook_url TEXT NOT NULL DEFAULT '',
    tls_verify_enabled INTEGER NOT NULL DEFAULT 1 CHECK(tls_verify_enabled IN (0, 1)),
    tls_verify_host TEXT NOT NULL DEFAULT '',
    tls_verify_port INTEGER NOT NULL DEFAULT 443,
    tls_verify_sni TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT 'pending' CHECK(last_status IN ('pending', 'running', 'success', 'failed')),
    last_deployed_at DATETIME,
    last_cert_fingerprint TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_deployments_cert_id ON deployments(certificate_id);
CREATE INDEX IF NOT EXISTS idx_deployments_host_id ON deployments(host_id);

CREATE TABLE IF NOT EXISTS cert_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    trigger_type TEXT NOT NULL CHECK(trigger_type IN ('manual', 'schedule', 'retry')),
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('pending', 'running', 'success', 'failed')),
    current_stage TEXT NOT NULL DEFAULT 'create_order',
    stages_json TEXT NOT NULL DEFAULT '[]',
    logs TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_cert_jobs_cert_id ON cert_jobs(certificate_id);
CREATE INDEX IF NOT EXISTS idx_cert_jobs_started_at ON cert_jobs(started_at DESC);

CREATE TABLE IF NOT EXISTS deploy_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    cert_job_id INTEGER REFERENCES cert_jobs(id) ON DELETE SET NULL,
    trigger_type TEXT NOT NULL CHECK(trigger_type IN ('auto', 'manual', 'retry')),
    status TEXT NOT NULL CHECK(status IN ('running', 'success', 'failed')),
    exit_code INTEGER,
    stdout TEXT NOT NULL DEFAULT '',
    stderr TEXT NOT NULL DEFAULT '',
    tls_verified INTEGER NOT NULL DEFAULT 0 CHECK(tls_verified IN (0, 1)),
    tls_observed_fp TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_deploy_logs_deployment_id ON deploy_logs(deployment_id);
CREATE INDEX IF NOT EXISTS idx_deploy_logs_started_at ON deploy_logs(started_at DESC);

CREATE TABLE IF NOT EXISTS caddy_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('publish', 'rollback', 'baseline')),
    summary TEXT NOT NULL DEFAULT '',
    reload_ok INTEGER NOT NULL DEFAULT 1 CHECK(reload_ok IN (0, 1)),
    reload_output TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_caddy_snapshots_host_version ON caddy_snapshots(host_id, version DESC);

CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    headers_enc TEXT NOT NULL DEFAULT '',
    secret_enc TEXT NOT NULL DEFAULT '',
    events_json TEXT NOT NULL DEFAULT '["cert.issue_failed","cert.expiring_soon","deploy.failed","caddy.reload_failed"]',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_status_code INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    last_triggered_at DATETIME,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info' CHECK(level IN ('info', 'warn', 'error')),
    target_type TEXT NOT NULL DEFAULT '',
    target_id INTEGER,
    target_name TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}',
    actor_ip TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
