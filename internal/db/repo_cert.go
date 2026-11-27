package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

const certSelectCols = `
	id, name, domain, sans_json, ca_account_id, dns_credential_id, zone_override,
	key_type, renew_before_days, auto_renew, status, issuer_name, issued_sans_json,
	fingerprint_sha256, not_before, not_after, last_issued_at, last_error,
	retry_count, next_retry_at, last_expiring_notified_at, cert_dir, created_at, updated_at
`

func (d *DB) CreateCertificate(ctx context.Context, cert *model.Certificate) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	if cert.SANsJSON == "" {
		cert.SANsJSON = "[]"
	}
	if cert.IssuedSANsJSON == "" {
		cert.IssuedSANsJSON = "[]"
	}
	if cert.KeyType == "" {
		cert.KeyType = model.KeyTypeEC256
	}
	if cert.RenewBeforeDays <= 0 {
		cert.RenewBeforeDays = 30
	}
	if cert.Status == "" {
		cert.Status = model.CertStatusPending
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO certificates (
			name, domain, sans_json, ca_account_id, dns_credential_id, zone_override,
			key_type, renew_before_days, auto_renew, status, issued_sans_json,
			cert_dir, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cert.Name, cert.Domain, cert.SANsJSON, cert.CAAccountID, cert.DNSCredentialID,
		cert.ZoneOverride, cert.KeyType, cert.RenewBeforeDays, boolToInt(cert.AutoRenew),
		cert.Status, cert.IssuedSANsJSON, cert.CertDir, nowStr, nowStr)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	cert.ID = id
	cert.CreatedAt = now
	cert.UpdatedAt = now
	return id, nil
}

func (d *DB) GetCertificate(ctx context.Context, id int64) (*model.Certificate, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `SELECT `+certSelectCols+` FROM certificates WHERE id = ?`, id)
	return scanCertificate(row)
}

func (d *DB) GetCertificateByDomain(ctx context.Context, domain string) (*model.Certificate, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `SELECT `+certSelectCols+` FROM certificates WHERE domain = ?`, domain)
	return scanCertificate(row)
}

func (d *DB) ListCertificates(ctx context.Context) ([]model.Certificate, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	rows, err := sqlDB.QueryContext(ctx, `SELECT `+certSelectCols+` FROM certificates ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Certificate, 0)
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (d *DB) ListCertificatesDueForRetry(ctx context.Context, now time.Time) ([]model.Certificate, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT `+certSelectCols+`
		FROM certificates
		WHERE auto_renew = 1
		  AND next_retry_at IS NOT NULL
		  AND next_retry_at <= ?
		  AND status != 'issuing'
		ORDER BY next_retry_at ASC
	`, formatDBTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Certificate, 0)
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (d *DB) UpdateCertificate(ctx context.Context, cert *model.Certificate) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE certificates SET
			name = ?, domain = ?, sans_json = ?, ca_account_id = ?, dns_credential_id = ?,
			zone_override = ?, key_type = ?, renew_before_days = ?, auto_renew = ?,
			status = ?, issuer_name = ?, issued_sans_json = ?, fingerprint_sha256 = ?,
			not_before = ?, not_after = ?, last_issued_at = ?, last_error = ?,
			retry_count = ?, next_retry_at = ?, last_expiring_notified_at = ?,
			cert_dir = ?, updated_at = ?
		WHERE id = ?
	`, cert.Name, cert.Domain, cert.SANsJSON, cert.CAAccountID, cert.DNSCredentialID,
		cert.ZoneOverride, cert.KeyType, cert.RenewBeforeDays, boolToInt(cert.AutoRenew),
		cert.Status, cert.IssuerName, cert.IssuedSANsJSON, cert.FingerprintSHA256,
		formatNullDBTime(cert.NotBefore), formatNullDBTime(cert.NotAfter), formatNullDBTime(cert.LastIssuedAt), cert.LastError,
		cert.RetryCount, formatNullDBTime(cert.NextRetryAt), formatNullDBTime(cert.LastExpiringNotifiedAt),
		cert.CertDir, formatDBTime(now), cert.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	cert.UpdatedAt = now
	return nil
}

func (d *DB) DeleteCertificate(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	res, err := sqlDB.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) CreateCertJob(ctx context.Context, job *model.CertJob) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	if job.StartedAt.IsZero() {
		job.StartedAt = now
	}
	if job.StagesJSON == "" {
		job.StagesJSON = "[]"
	}
	if job.Status == "" {
		job.Status = model.JobStatusRunning
	}
	if job.CurrentStage == "" {
		job.CurrentStage = model.StageCreateOrder
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO cert_jobs (
			certificate_id, trigger_type, status, current_stage, stages_json,
			logs, error_message, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, job.CertificateID, job.TriggerType, job.Status, job.CurrentStage, job.StagesJSON,
		job.Logs, job.ErrorMessage, formatDBTime(job.StartedAt), formatNullDBTime(job.FinishedAt))
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	job.ID = id
	return id, nil
}

func (d *DB) GetCertJob(ctx context.Context, id int64) (*model.CertJob, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, certificate_id, trigger_type, status, current_stage, stages_json,
		       logs, error_message, started_at, finished_at
		FROM cert_jobs WHERE id = ?
	`, id)
	return scanCertJob(row)
}

func (d *DB) ListCertJobsByCertificate(ctx context.Context, certID int64, limit int) ([]model.CertJob, error) {
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
		SELECT id, certificate_id, trigger_type, status, current_stage, stages_json,
		       logs, error_message, started_at, finished_at
		FROM cert_jobs WHERE certificate_id = ?
		ORDER BY started_at DESC, id DESC LIMIT ?
	`, certID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.CertJob, 0)
	for rows.Next() {
		j, err := scanCertJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *j)
	}
	return out, rows.Err()
}

func (d *DB) UpdateCertJob(ctx context.Context, job *model.CertJob) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE cert_jobs SET
			status = ?, current_stage = ?, stages_json = ?, logs = ?,
			error_message = ?, finished_at = ?
		WHERE id = ?
	`, job.Status, job.CurrentStage, job.StagesJSON, job.Logs,
		job.ErrorMessage, formatNullDBTime(job.FinishedAt), job.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) AppendCertJobLog(ctx context.Context, jobID int64, line string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE cert_jobs SET logs = logs || ? WHERE id = ?
	`, line, jobID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanCertificate(r rowScanner) (*model.Certificate, error) {
	var c model.Certificate
	var autoRenew int
	var notBefore, notAfter, lastIssued, nextRetry, lastExpiring sql.NullString
	var createdAt, updatedAt string
	err := r.Scan(
		&c.ID, &c.Name, &c.Domain, &c.SANsJSON, &c.CAAccountID, &c.DNSCredentialID, &c.ZoneOverride,
		&c.KeyType, &c.RenewBeforeDays, &autoRenew, &c.Status, &c.IssuerName, &c.IssuedSANsJSON,
		&c.FingerprintSHA256, &notBefore, &notAfter, &lastIssued, &c.LastError,
		&c.RetryCount, &nextRetry, &lastExpiring, &c.CertDir, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	c.AutoRenew = autoRenew != 0
	c.NotBefore = scanNullTime(notBefore)
	c.NotAfter = scanNullTime(notAfter)
	c.LastIssuedAt = scanNullTime(lastIssued)
	c.NextRetryAt = scanNullTime(nextRetry)
	c.LastExpiringNotifiedAt = scanNullTime(lastExpiring)
	c.CreatedAt = parseDBTime(createdAt)
	c.UpdatedAt = parseDBTime(updatedAt)
	return &c, nil
}

func scanCertJob(r rowScanner) (*model.CertJob, error) {
	var j model.CertJob
	var startedAt string
	var finishedAt sql.NullString
	err := r.Scan(
		&j.ID, &j.CertificateID, &j.TriggerType, &j.Status, &j.CurrentStage,
		&j.StagesJSON, &j.Logs, &j.ErrorMessage, &startedAt, &finishedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	j.StartedAt = parseDBTime(startedAt)
	j.FinishedAt = scanNullTime(finishedAt)
	return &j, nil
}
