package db

import (
	"context"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) CreateSession(ctx context.Context, s *model.Session) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	if s.LastSeenAt.IsZero() {
		s.LastSeenAt = now
	}

	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO sessions (id, csrf_token, ip, user_agent, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, s.ID, s.CSRFToken, s.IP, s.UserAgent, formatDBTime(s.ExpiresAt), formatDBTime(s.CreatedAt), formatDBTime(s.LastSeenAt))
	return mapSQLiteErr(err)
}

func (d *DB) GetSession(ctx context.Context, id string) (*model.Session, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	var s model.Session
	var expiresAt, createdAt, lastSeenAt string
	err = sqlDB.QueryRowContext(ctx, `
		SELECT id, csrf_token, ip, user_agent, expires_at, created_at, last_seen_at
		FROM sessions WHERE id = ?
	`, id).Scan(&s.ID, &s.CSRFToken, &s.IP, &s.UserAgent, &expiresAt, &createdAt, &lastSeenAt)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	s.ExpiresAt = parseDBTime(expiresAt)
	s.CreatedAt = parseDBTime(createdAt)
	s.LastSeenAt = parseDBTime(lastSeenAt)
	return &s, nil
}

func (d *DB) TouchSession(ctx context.Context, id string, lastSeen time.Time) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	_, err = sqlDB.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, formatDBTime(lastSeen), id)
	return err
}

func (d *DB) DeleteSession(ctx context.Context, id string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	_, err = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (d *DB) DeleteAllSessions(ctx context.Context) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	_, err = sqlDB.ExecContext(ctx, `DELETE FROM sessions`)
	return err
}

func (d *DB) DeleteOtherSessions(ctx context.Context, keepID string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	_, err = sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE id != ?`, keepID)
	return err
}

func (d *DB) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	res, err := sqlDB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, formatDBTime(now))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}
