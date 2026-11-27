package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

const deploySelectCols = `
	id, certificate_id, host_id, name, template, enabled,
	fullchain_path, privkey_path, issuer_path, cert_file_mode, key_file_mode,
	reload_mode, reload_command, reload_webhook_url,
	tls_verify_enabled, tls_verify_host, tls_verify_port, tls_verify_sni,
	last_status, last_deployed_at, last_cert_fingerprint, last_error,
	created_at, updated_at
`

func (d *DB) CreateDeployment(ctx context.Context, dep *model.Deployment) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	if dep.Template == "" {
		dep.Template = model.DeployTemplateCaddyDocker
	}
	if dep.CertFileMode == "" {
		dep.CertFileMode = "0644"
	}
	if dep.KeyFileMode == "" {
		dep.KeyFileMode = "0600"
	}
	if dep.ReloadMode == "" {
		dep.ReloadMode = model.ReloadModeDockerExec
	}
	if dep.TLSVerifyPort == 0 {
		dep.TLSVerifyPort = 443
	}
	if dep.LastStatus == "" {
		dep.LastStatus = model.JobStatusPending
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO deployments (
			certificate_id, host_id, name, template, enabled,
			fullchain_path, privkey_path, issuer_path, cert_file_mode, key_file_mode,
			reload_mode, reload_command, reload_webhook_url,
			tls_verify_enabled, tls_verify_host, tls_verify_port, tls_verify_sni,
			last_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, dep.CertificateID, dep.HostID, dep.Name, dep.Template, boolToInt(dep.Enabled),
		dep.FullchainPath, dep.PrivkeyPath, dep.IssuerPath, dep.CertFileMode, dep.KeyFileMode,
		dep.ReloadMode, dep.ReloadCommand, dep.ReloadWebhookURL,
		boolToInt(dep.TLSVerifyEnabled), dep.TLSVerifyHost, dep.TLSVerifyPort, dep.TLSVerifySNI,
		dep.LastStatus, nowStr, nowStr)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	dep.ID = id
	dep.CreatedAt = now
	dep.UpdatedAt = now
	return id, nil
}

func (d *DB) GetDeployment(ctx context.Context, id int64) (*model.Deployment, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `SELECT `+deploySelectCols+` FROM deployments WHERE id = ?`, id)
	return scanDeployment(row)
}

func (d *DB) ListDeploymentsByCertificate(ctx context.Context, certID int64) ([]model.Deployment, error) {
	return d.queryDeployments(ctx, `SELECT `+deploySelectCols+` FROM deployments WHERE certificate_id = ? ORDER BY id ASC`, certID)
}

func (d *DB) ListDeploymentsByHost(ctx context.Context, hostID int64) ([]model.Deployment, error) {
	return d.queryDeployments(ctx, `SELECT `+deploySelectCols+` FROM deployments WHERE host_id = ? ORDER BY id ASC`, hostID)
}

func (d *DB) ListAllDeployments(ctx context.Context) ([]model.Deployment, error) {
	return d.queryDeployments(ctx, `SELECT `+deploySelectCols+` FROM deployments ORDER BY id ASC`)
}

func (d *DB) queryDeployments(ctx context.Context, query string, args ...any) ([]model.Deployment, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	rows, err := sqlDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Deployment, 0)
	for rows.Next() {
		dep, err := scanDeployment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *dep)
	}
	return out, rows.Err()
}

func (d *DB) UpdateDeployment(ctx context.Context, dep *model.Deployment) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE deployments SET
			name = ?, template = ?, enabled = ?,
			fullchain_path = ?, privkey_path = ?, issuer_path = ?,
			cert_file_mode = ?, key_file_mode = ?,
			reload_mode = ?, reload_command = ?, reload_webhook_url = ?,
			tls_verify_enabled = ?, tls_verify_host = ?, tls_verify_port = ?, tls_verify_sni = ?,
			updated_at = ?
		WHERE id = ?
	`, dep.Name, dep.Template, boolToInt(dep.Enabled),
		dep.FullchainPath, dep.PrivkeyPath, dep.IssuerPath,
		dep.CertFileMode, dep.KeyFileMode,
		dep.ReloadMode, dep.ReloadCommand, dep.ReloadWebhookURL,
		boolToInt(dep.TLSVerifyEnabled), dep.TLSVerifyHost, dep.TLSVerifyPort, dep.TLSVerifySNI,
		formatDBTime(now), dep.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	dep.UpdatedAt = now
	return nil
}

func (d *DB) UpdateDeploymentStatus(ctx context.Context, id int64, status, fp, errMsg string, deployedAt *time.Time) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	nowStr := formatDBTime(time.Now().UTC())
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE deployments SET
			last_status = ?, last_cert_fingerprint = ?, last_error = ?,
			last_deployed_at = COALESCE(?, last_deployed_at), updated_at = ?
		WHERE id = ?
	`, status, fp, errMsg, formatNullDBTime(deployedAt), nowStr, id)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) DeleteDeployment(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	res, err := sqlDB.ExecContext(ctx, `DELETE FROM deployments WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) CreateDeployLog(ctx context.Context, l *model.DeployLog) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	if l.StartedAt.IsZero() {
		l.StartedAt = now
	}
	if l.Status == "" {
		l.Status = model.JobStatusRunning
	}

	var exitCodeArg any
	if l.ExitCode != nil {
		exitCodeArg = *l.ExitCode
	}
	var certJobIDArg any
	if l.CertJobID != nil {
		certJobIDArg = *l.CertJobID
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO deploy_logs (
			deployment_id, certificate_id, host_id, cert_job_id,
			trigger_type, status, exit_code, stdout, stderr,
			tls_verified, tls_observed_fp, error_message, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, l.DeploymentID, l.CertificateID, l.HostID, certJobIDArg,
		l.TriggerType, l.Status, exitCodeArg, l.Stdout, l.Stderr,
		boolToInt(l.TLSVerified), l.TLSObservedFP, l.ErrorMessage,
		formatDBTime(l.StartedAt), formatNullDBTime(l.FinishedAt))
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	l.ID = id
	return id, nil
}

func (d *DB) UpdateDeployLog(ctx context.Context, l *model.DeployLog) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	var exitCodeArg any
	if l.ExitCode != nil {
		exitCodeArg = *l.ExitCode
	}
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE deploy_logs SET
			status = ?, exit_code = ?, stdout = ?, stderr = ?,
			tls_verified = ?, tls_observed_fp = ?, error_message = ?, finished_at = ?
		WHERE id = ?
	`, l.Status, exitCodeArg, l.Stdout, l.Stderr,
		boolToInt(l.TLSVerified), l.TLSObservedFP, l.ErrorMessage, formatNullDBTime(l.FinishedAt), l.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) GetDeployLog(ctx context.Context, id int64) (*model.DeployLog, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, deployment_id, certificate_id, host_id, cert_job_id,
		       trigger_type, status, exit_code, stdout, stderr,
		       tls_verified, tls_observed_fp, error_message, started_at, finished_at
		FROM deploy_logs WHERE id = ?
	`, id)
	return scanDeployLog(row)
}

func (d *DB) ListDeployLogsByDeployment(ctx context.Context, deploymentID int64, limit int) ([]model.DeployLog, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT id, deployment_id, certificate_id, host_id, cert_job_id,
		       trigger_type, status, exit_code, stdout, stderr,
		       tls_verified, tls_observed_fp, error_message, started_at, finished_at
		FROM deploy_logs WHERE deployment_id = ?
		ORDER BY started_at DESC, id DESC LIMIT ?
	`, deploymentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.DeployLog, 0)
	for rows.Next() {
		l, err := scanDeployLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}

func scanDeployment(r rowScanner) (*model.Deployment, error) {
	var dep model.Deployment
	var enabled, tlsVerify int
	var lastDeployed sql.NullString
	var createdAt, updatedAt string
	err := r.Scan(
		&dep.ID, &dep.CertificateID, &dep.HostID, &dep.Name, &dep.Template, &enabled,
		&dep.FullchainPath, &dep.PrivkeyPath, &dep.IssuerPath, &dep.CertFileMode, &dep.KeyFileMode,
		&dep.ReloadMode, &dep.ReloadCommand, &dep.ReloadWebhookURL,
		&tlsVerify, &dep.TLSVerifyHost, &dep.TLSVerifyPort, &dep.TLSVerifySNI,
		&dep.LastStatus, &lastDeployed, &dep.LastCertFingerprint, &dep.LastError,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	dep.Enabled = enabled != 0
	dep.TLSVerifyEnabled = tlsVerify != 0
	dep.LastDeployedAt = scanNullTime(lastDeployed)
	dep.CreatedAt = parseDBTime(createdAt)
	dep.UpdatedAt = parseDBTime(updatedAt)
	return &dep, nil
}

func scanDeployLog(r rowScanner) (*model.DeployLog, error) {
	var l model.DeployLog
	var certJobID, exitCode sql.NullInt64
	var tlsVerified int
	var startedAt string
	var finishedAt sql.NullString
	err := r.Scan(
		&l.ID, &l.DeploymentID, &l.CertificateID, &l.HostID, &certJobID,
		&l.TriggerType, &l.Status, &exitCode, &l.Stdout, &l.Stderr,
		&tlsVerified, &l.TLSObservedFP, &l.ErrorMessage, &startedAt, &finishedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	l.CertJobID = scanNullInt64(certJobID)
	l.ExitCode = scanNullInt(exitCode)
	l.TLSVerified = tlsVerified != 0
	l.StartedAt = parseDBTime(startedAt)
	l.FinishedAt = scanNullTime(finishedAt)
	return &l, nil
}
