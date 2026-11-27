package db

import (
	"context"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) NextCaddySnapshotVersion(ctx context.Context, hostID int64) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}
	var maxVer int
	err = sqlDB.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM caddy_snapshots WHERE host_id = ?`, hostID).Scan(&maxVer)
	if err != nil {
		return 0, err
	}
	return maxVer + 1, nil
}

func (d *DB) CreateCaddySnapshot(ctx context.Context, s *model.CaddySnapshot) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if s.Version <= 0 {
		var maxVer int
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM caddy_snapshots WHERE host_id = ?`, s.HostID).Scan(&maxVer); err != nil {
			return 0, err
		}
		s.Version = maxVer + 1
	}

	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO caddy_snapshots (
			host_id, version, content, sha256, action, summary, reload_ok, reload_output, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, s.HostID, s.Version, s.Content, s.SHA256, s.Action, s.Summary, boolToInt(s.ReloadOK), s.ReloadOutput, formatDBTime(s.CreatedAt))
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.ID = id
	return id, nil
}

func (d *DB) GetCaddySnapshot(ctx context.Context, id int64) (*model.CaddySnapshot, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, host_id, version, content, sha256, action, summary, reload_ok, reload_output, created_at
		FROM caddy_snapshots WHERE id = ?
	`, id)
	return scanCaddySnapshot(row)
}

func (d *DB) ListCaddySnapshotsByHost(ctx context.Context, hostID int64, limit int) ([]model.CaddySnapshot, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT id, host_id, version, content, sha256, action, summary, reload_ok, reload_output, created_at
		FROM caddy_snapshots WHERE host_id = ?
		ORDER BY version DESC, id DESC LIMIT ?
	`, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.CaddySnapshot, 0)
	for rows.Next() {
		s, err := scanCaddySnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func scanCaddySnapshot(r rowScanner) (*model.CaddySnapshot, error) {
	var s model.CaddySnapshot
	var reloadOK int
	var createdAt string
	err := r.Scan(
		&s.ID, &s.HostID, &s.Version, &s.Content, &s.SHA256,
		&s.Action, &s.Summary, &reloadOK, &s.ReloadOutput, &createdAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	s.ReloadOK = reloadOK != 0
	s.CreatedAt = parseDBTime(createdAt)
	return &s, nil
}
