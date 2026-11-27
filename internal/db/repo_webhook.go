package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) CreateWebhook(ctx context.Context, w *model.Webhook) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	if w.EventsJSON == "" {
		w.EventsJSON = `["cert.issue_failed","cert.expiring_soon","deploy.failed","caddy.reload_failed"]`
	}

	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO webhooks (
			name, url, headers_enc, secret_enc, events_json, enabled, last_error, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, w.Name, w.URL, w.HeadersEnc, w.SecretEnc, w.EventsJSON, boolToInt(w.Enabled), w.LastError, nowStr, nowStr)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	w.ID = id
	w.CreatedAt = now
	w.UpdatedAt = now
	return id, nil
}

func (d *DB) GetWebhook(ctx context.Context, id int64) (*model.Webhook, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}
	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, name, url, headers_enc, secret_enc, events_json, enabled,
		       last_status_code, last_error, last_triggered_at, created_at, updated_at
		FROM webhooks WHERE id = ?
	`, id)
	return scanWebhook(row)
}

func (d *DB) ListWebhooks(ctx context.Context) ([]model.Webhook, error) {
	return d.queryWebhooks(ctx, `
		SELECT id, name, url, headers_enc, secret_enc, events_json, enabled,
		       last_status_code, last_error, last_triggered_at, created_at, updated_at
		FROM webhooks ORDER BY id ASC
	`)
}

func (d *DB) ListEnabledWebhooks(ctx context.Context) ([]model.Webhook, error) {
	return d.queryWebhooks(ctx, `
		SELECT id, name, url, headers_enc, secret_enc, events_json, enabled,
		       last_status_code, last_error, last_triggered_at, created_at, updated_at
		FROM webhooks WHERE enabled = 1 ORDER BY id ASC
	`)
}

func (d *DB) queryWebhooks(ctx context.Context, query string, args ...any) ([]model.Webhook, error) {
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

	out := make([]model.Webhook, 0)
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

func (d *DB) UpdateWebhook(ctx context.Context, w *model.Webhook) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE webhooks SET
			name = ?, url = ?, headers_enc = ?, secret_enc = ?, events_json = ?, enabled = ?, updated_at = ?
		WHERE id = ?
	`, w.Name, w.URL, w.HeadersEnc, w.SecretEnc, w.EventsJSON, boolToInt(w.Enabled), formatDBTime(now), w.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	w.UpdatedAt = now
	return nil
}

func (d *DB) UpdateWebhookDeliveryResult(ctx context.Context, id int64, statusCode *int, errMsg string, triggeredAt time.Time) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	var codeArg any
	if statusCode != nil {
		codeArg = *statusCode
	}
	nowStr := formatDBTime(triggeredAt)
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE webhooks
		SET last_status_code = ?, last_error = ?, last_triggered_at = ?, updated_at = ?
		WHERE id = ?
	`, codeArg, errMsg, nowStr, nowStr, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) DeleteWebhook(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}
	res, err := sqlDB.ExecContext(ctx, `DELETE FROM webhooks WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanWebhook(r rowScanner) (*model.Webhook, error) {
	var w model.Webhook
	var enabled int
	var lastCode sql.NullInt64
	var lastTriggered sql.NullString
	var createdAt, updatedAt string
	err := r.Scan(
		&w.ID, &w.Name, &w.URL, &w.HeadersEnc, &w.SecretEnc, &w.EventsJSON, &enabled,
		&lastCode, &w.LastError, &lastTriggered, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	w.Enabled = enabled != 0
	w.LastStatusCode = scanNullInt(lastCode)
	w.LastTriggeredAt = scanNullTime(lastTriggered)
	w.CreatedAt = parseDBTime(createdAt)
	w.UpdatedAt = parseDBTime(updatedAt)
	return &w, nil
}
