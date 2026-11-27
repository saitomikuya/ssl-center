package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) CreateAuditEvent(ctx context.Context, evt *model.AuditEvent) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	if evt.CreatedAt.IsZero() {
		evt.CreatedAt = now
	}
	if evt.Level == "" {
		evt.Level = model.AuditLevelInfo
	}
	if evt.MetaJSON == "" {
		evt.MetaJSON = "{}"
	}
	var targetIDArg any
	if evt.TargetID != nil {
		targetIDArg = *evt.TargetID
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO audit_events (
			event_type, level, target_type, target_id, target_name, message, meta_json, actor_ip, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, evt.EventType, evt.Level, evt.TargetType, targetIDArg, evt.TargetName, evt.Message, evt.MetaJSON, evt.ActorIP, formatDBTime(evt.CreatedAt))
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	evt.ID = id
	return id, nil
}

func (d *DB) ListRecentAuditEvents(ctx context.Context, limit int) ([]model.AuditEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 30
	}
	rows, err := sqlDB.QueryContext(ctx, `
		SELECT id, event_type, level, target_type, target_id, target_name, message, meta_json, actor_ip, created_at
		FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.AuditEvent, 0)
	for rows.Next() {
		var e model.AuditEvent
		var targetID sql.NullInt64
		var createdAt string
		if err := rows.Scan(
			&e.ID, &e.EventType, &e.Level, &e.TargetType, &targetID,
			&e.TargetName, &e.Message, &e.MetaJSON, &e.ActorIP, &createdAt,
		); err != nil {
			return nil, err
		}
		e.TargetID = scanNullInt64(targetID)
		e.CreatedAt = parseDBTime(createdAt)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) GetDashboardCounts(ctx context.Context) (model.CertHealthStats, model.HostOverviewStats, model.DeploymentOverviewStats, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var cs model.CertHealthStats
	var hs model.HostOverviewStats
	var ds model.DeploymentOverviewStats

	sqlDB, err := d.conn()
	if err != nil {
		return cs, hs, ds, err
	}

	err = sqlDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'valid' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'expiring' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status IN ('pending', 'issuing') THEN 1 ELSE 0 END), 0)
		FROM certificates
	`).Scan(&cs.Total, &cs.Valid, &cs.Expiring, &cs.Expired, &cs.Error, &cs.Pending)
	if err != nil {
		return cs, hs, ds, err
	}

	err = sqlDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN last_check_ok = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN last_check_ok = 0 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN caddy_status = 'running' THEN 1 ELSE 0 END), 0)
		FROM hosts
	`).Scan(&hs.Total, &hs.Reachable, &hs.Unreachable, &hs.CaddyRunning)
	if err != nil {
		return cs, hs, ds, err
	}

	err = sqlDB.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN last_status = 'success' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN last_status = 'failed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN last_status IN ('pending', 'running') THEN 1 ELSE 0 END), 0)
		FROM deployments
	`).Scan(&ds.Total, &ds.Success, &ds.Failed, &ds.Pending)
	if err != nil {
		return cs, hs, ds, err
	}

	return cs, hs, ds, nil
}
