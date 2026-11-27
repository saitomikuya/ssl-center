package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) CreateDNSCredential(ctx context.Context, cred *model.DNSCredential) (int64, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	res, err := sqlDB.ExecContext(ctx, `
		INSERT INTO dns_credentials (name, provider, config_enc, last_test_msg, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, cred.Name, cred.Provider, cred.ConfigEnc, cred.LastTestMsg, nowStr, nowStr)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	cred.ID = id
	cred.CreatedAt = now
	cred.UpdatedAt = now
	return id, nil
}

func (d *DB) GetDNSCredential(ctx context.Context, id int64) (*model.DNSCredential, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, name, provider, config_enc, last_tested_at, last_test_ok, last_test_msg, created_at, updated_at
		FROM dns_credentials WHERE id = ?
	`, id)
	return scanDNSCredential(row)
}

func (d *DB) ListDNSCredentials(ctx context.Context) ([]model.DNSCredential, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT id, name, provider, config_enc, last_tested_at, last_test_ok, last_test_msg, created_at, updated_at
		FROM dns_credentials ORDER BY id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.DNSCredential, 0)
	for rows.Next() {
		cred, err := scanDNSCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cred)
	}
	return out, rows.Err()
}

func (d *DB) UpdateDNSCredential(ctx context.Context, cred *model.DNSCredential) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE dns_credentials
		SET name = ?, config_enc = ?, updated_at = ?
		WHERE id = ?
	`, cred.Name, cred.ConfigEnc, formatDBTime(now), cred.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	cred.UpdatedAt = now
	return nil
}

func (d *DB) UpdateDNSTestResult(ctx context.Context, id int64, ok bool, msg string, testedAt time.Time) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	nowStr := formatDBTime(testedAt)
	res, err := sqlDB.ExecContext(ctx, `
		UPDATE dns_credentials
		SET last_tested_at = ?, last_test_ok = ?, last_test_msg = ?, updated_at = ?
		WHERE id = ?
	`, nowStr, boolToInt(ok), msg, nowStr, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) DeleteDNSCredential(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	res, err := sqlDB.ExecContext(ctx, `DELETE FROM dns_credentials WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanDNSCredential(r rowScanner) (*model.DNSCredential, error) {
	var c model.DNSCredential
	var lastTested sql.NullString
	var lastTestOK sql.NullInt64
	var createdAt, updatedAt string
	err := r.Scan(
		&c.ID, &c.Name, &c.Provider, &c.ConfigEnc,
		&lastTested, &lastTestOK, &c.LastTestMsg, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	c.LastTestedAt = scanNullTime(lastTested)
	c.LastTestOK = scanNullBool(lastTestOK)
	c.CreatedAt = parseDBTime(createdAt)
	c.UpdatedAt = parseDBTime(updatedAt)
	return &c, nil
}
