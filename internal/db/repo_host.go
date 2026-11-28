package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

const hostSelectCols = `
	id, name, is_local, mode, host, port, username, auth_type,
	ssh_private_key_enc, ssh_passphrase_enc, ssh_password_enc,
	host_key_policy, host_key_fingerprint,
	caddy_enabled, caddy_container, caddy_host_caddyfile, caddy_container_caddyfile,
	caddy_host_cert_dir, caddy_container_cert_dir,
	last_check_at, last_check_ok, last_check_msg, caddy_status,
	created_at, updated_at
`

func (d *DB) CreateHost(ctx context.Context, h *model.Host) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	if h.Mode == "" {
		h.Mode = model.HostModeSSH
	}
	if h.Port == 0 && h.Mode == model.HostModeSSH {
		h.Port = 22
	}
	if h.Username == "" && h.Mode == model.HostModeSSH {
		h.Username = "root"
	}
	if h.AuthType == "" {
		h.AuthType = model.HostAuthKey
	}
	if h.HostKeyPolicy == "" {
		h.HostKeyPolicy = model.HostKeyPolicyTOFU
	}
	if h.CaddyContainer == "" {
		h.CaddyContainer = "caddy"
	}
	if h.CaddyHostCaddyfile == "" {
		h.CaddyHostCaddyfile = "/opt/caddy/Caddyfile"
	}
	if h.CaddyContainerCaddyfile == "" {
		h.CaddyContainerCaddyfile = "/etc/caddy/Caddyfile"
	}
	if h.CaddyHostCertDir == "" {
		h.CaddyHostCertDir = "/opt/caddy/certs"
	}
	if h.CaddyContainerCertDir == "" {
		h.CaddyContainerCertDir = "/certs"
	}
	if h.CaddyStatus == "" {
		h.CaddyStatus = model.CaddyStatusUnknown
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO hosts (
			name, is_local, mode, host, port, username, auth_type,
			ssh_private_key_enc, ssh_passphrase_enc, ssh_password_enc,
			host_key_policy, host_key_fingerprint,
			caddy_enabled, caddy_container, caddy_host_caddyfile, caddy_container_caddyfile,
			caddy_host_cert_dir, caddy_container_cert_dir,
			last_check_msg, caddy_status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, h.Name, boolToInt(h.IsLocal), h.Mode, h.Host, h.Port, h.Username, h.AuthType,
		h.SSHPrivateKeyEnc, h.SSHPassphraseEnc, h.SSHPasswordEnc,
		h.HostKeyPolicy, h.HostKeyFingerprint,
		boolToInt(h.CaddyEnabled), h.CaddyContainer, h.CaddyHostCaddyfile, h.CaddyContainerCaddyfile,
		h.CaddyHostCertDir, h.CaddyContainerCertDir,
		h.LastCheckMsg, h.CaddyStatus, nowStr, nowStr)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	h.ID = id
	h.CreatedAt = now
	h.UpdatedAt = now
	return id, nil
}

func (d *DB) GetHost(ctx context.Context, id int64) (*model.Host, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `SELECT `+hostSelectCols+` FROM hosts WHERE id = ?`, id)
	return scanHost(row)
}

func (d *DB) GetLocalHost(ctx context.Context) (*model.Host, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `SELECT `+hostSelectCols+` FROM hosts WHERE is_local = 1 LIMIT 1`)
	return scanHost(row)
}

func (d *DB) ListHosts(ctx context.Context) ([]model.Host, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	rows, err := sqlDB.QueryContext(ctx, `SELECT `+hostSelectCols+` FROM hosts ORDER BY is_local DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.Host, 0)
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

func (d *DB) UpdateHost(ctx context.Context, h *model.Host) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE hosts SET
			name = ?, host = ?, port = ?, username = ?, auth_type = ?,
			ssh_private_key_enc = ?, ssh_passphrase_enc = ?, ssh_password_enc = ?,
			host_key_policy = ?, host_key_fingerprint = ?,
			caddy_enabled = ?, caddy_container = ?, caddy_host_caddyfile = ?, caddy_container_caddyfile = ?,
			caddy_host_cert_dir = ?, caddy_container_cert_dir = ?,
			updated_at = ?
		WHERE id = ?
	`, h.Name, h.Host, h.Port, h.Username, h.AuthType,
		h.SSHPrivateKeyEnc, h.SSHPassphraseEnc, h.SSHPasswordEnc,
		h.HostKeyPolicy, h.HostKeyFingerprint,
		boolToInt(h.CaddyEnabled), h.CaddyContainer, h.CaddyHostCaddyfile, h.CaddyContainerCaddyfile,
		h.CaddyHostCertDir, h.CaddyContainerCertDir,
		formatDBTime(now), h.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	h.UpdatedAt = now
	return nil
}

func (d *DB) UpdateHostCheckResult(ctx context.Context, id int64, ok bool, msg, caddyStatus string, checkedAt time.Time) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	if caddyStatus == "" {
		caddyStatus = model.CaddyStatusUnknown
	}
	nowStr := formatDBTime(checkedAt)
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE hosts
		SET last_check_at = ?, last_check_ok = ?, last_check_msg = ?, caddy_status = ?, updated_at = ?
		WHERE id = ?
	`, nowStr, boolToInt(ok), msg, caddyStatus, nowStr, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) UpdateHostKeyFingerprint(ctx context.Context, id int64, fp string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	nowStr := formatDBTime(time.Now().UTC())
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE hosts SET host_key_fingerprint = ?, updated_at = ? WHERE id = ?
	`, fp, nowStr, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) DeleteHost(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	var isLocal int
	err = sqlDB.QueryRowContext(ctx, `SELECT is_local FROM hosts WHERE id = ?`, id).Scan(&isLocal)
	if err != nil {
		return mapSQLiteErr(err)
	}
	if isLocal != 0 {
		return ErrLocalHostProtected
	}

	res, err := sqlDB.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) CountDeploymentsByHost(ctx context.Context, hostID int64) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}
	var count int
	err = sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM deployments WHERE host_id = ?`, hostID).Scan(&count)
	return count, err
}

// CountDeploymentsByHostMap returns deployment counts grouped by host_id in a single query.
func (d *DB) CountDeploymentsByHostMap(ctx context.Context) (map[int64]int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	rows, err := sqlDB.QueryContext(ctx, `SELECT host_id, COUNT(*) FROM deployments GROUP BY host_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[int64]int)
	for rows.Next() {
		var hostID int64
		var count int
		if err := rows.Scan(&hostID, &count); err != nil {
			return nil, err
		}
		counts[hostID] = count
	}
	return counts, rows.Err()
}

func scanHost(r rowScanner) (*model.Host, error) {
	var h model.Host
	var isLocal, caddyEnabled int
	var lastCheckAt sql.NullString
	var lastCheckOK sql.NullInt64
	var createdAt, updatedAt string
	err := r.Scan(
		&h.ID, &h.Name, &isLocal, &h.Mode, &h.Host, &h.Port, &h.Username, &h.AuthType,
		&h.SSHPrivateKeyEnc, &h.SSHPassphraseEnc, &h.SSHPasswordEnc,
		&h.HostKeyPolicy, &h.HostKeyFingerprint,
		&caddyEnabled, &h.CaddyContainer, &h.CaddyHostCaddyfile, &h.CaddyContainerCaddyfile,
		&h.CaddyHostCertDir, &h.CaddyContainerCertDir,
		&lastCheckAt, &lastCheckOK, &h.LastCheckMsg, &h.CaddyStatus,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	h.IsLocal = isLocal != 0
	h.CaddyEnabled = caddyEnabled != 0
	h.LastCheckAt = scanNullTime(lastCheckAt)
	h.LastCheckOK = scanNullBool(lastCheckOK)
	h.CreatedAt = parseDBTime(createdAt)
	h.UpdatedAt = parseDBTime(updatedAt)
	return &h, nil
}
