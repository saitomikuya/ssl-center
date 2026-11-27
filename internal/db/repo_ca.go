package db

import (
	"context"
	"database/sql"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) CreateCAAccount(ctx context.Context, ca *model.CAAccount) (int64, error) {
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

	if ca.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE ca_accounts SET is_default = 0 WHERE is_default = 1`); err != nil {
			return 0, err
		}
	}

	now := time.Now().UTC()
	nowStr := formatDBTime(now)
	status := ca.Status
	if status == "" {
		status = model.CAStatusActive
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO ca_accounts (
			name, provider, environment, email, directory_url,
			acme_key_enc, account_uri, is_default, status, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, ca.Name, ca.Provider, ca.Environment, ca.Email, ca.DirectoryURL,
		ca.ACMEKeyEnc, ca.AccountURI, boolToInt(ca.IsDefault), status, nowStr, nowStr)
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
	ca.ID = id
	ca.Status = status
	ca.CreatedAt = now
	ca.UpdatedAt = now
	return id, nil
}

func (d *DB) GetCAAccount(ctx context.Context, id int64) (*model.CAAccount, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, name, provider, environment, email, directory_url,
		       acme_key_enc, account_uri, is_default, status, created_at, updated_at
		FROM ca_accounts WHERE id = ?
	`, id)
	return scanCAAccount(row)
}

func (d *DB) GetDefaultCAAccount(ctx context.Context) (*model.CAAccount, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	row := sqlDB.QueryRowContext(ctx, `
		SELECT id, name, provider, environment, email, directory_url,
		       acme_key_enc, account_uri, is_default, status, created_at, updated_at
		FROM ca_accounts WHERE is_default = 1 LIMIT 1
	`)
	return scanCAAccount(row)
}

func (d *DB) ListCAAccounts(ctx context.Context) ([]model.CAAccount, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	rows, err := sqlDB.QueryContext(ctx, `
		SELECT id, name, provider, environment, email, directory_url,
		       acme_key_enc, account_uri, is_default, status, created_at, updated_at
		FROM ca_accounts ORDER BY is_default DESC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.CAAccount, 0)
	for rows.Next() {
		ca, err := scanCAAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ca)
	}
	return out, rows.Err()
}

func (d *DB) UpdateCAAccount(ctx context.Context, ca *model.CAAccount) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if ca.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE ca_accounts SET is_default = 0 WHERE is_default = 1 AND id != ?`, ca.ID); err != nil {
			return err
		}
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx, `
		UPDATE ca_accounts
		SET name = ?, email = ?, account_uri = ?, is_default = ?, status = ?, updated_at = ?
		WHERE id = ?
	`, ca.Name, ca.Email, ca.AccountURI, boolToInt(ca.IsDefault), ca.Status, formatDBTime(now), ca.ID)
	if err != nil {
		return mapSQLiteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	ca.UpdatedAt = now
	return nil
}

func (d *DB) SetDefaultCAAccount(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	tx, err := sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM ca_accounts WHERE id = ?`, id).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return ErrNotFound
	}

	nowStr := formatDBTime(time.Now().UTC())
	if _, err := tx.ExecContext(ctx, `UPDATE ca_accounts SET is_default = 0, updated_at = ? WHERE is_default = 1`, nowStr); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE ca_accounts SET is_default = 1, updated_at = ? WHERE id = ?`, nowStr, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) DeleteCAAccount(ctx context.Context, id int64) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	res, err := sqlDB.ExecContext(ctx, `DELETE FROM ca_accounts WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteDeleteErr(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (d *DB) CountCertificatesByCA(ctx context.Context, caID int64) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return 0, err
	}
	var count int
	err = sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM certificates WHERE ca_account_id = ?`, caID).Scan(&count)
	return count, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCAAccount(r rowScanner) (*model.CAAccount, error) {
	var ca model.CAAccount
	var isDefaultInt int
	var createdAt, updatedAt string
	err := r.Scan(
		&ca.ID, &ca.Name, &ca.Provider, &ca.Environment, &ca.Email, &ca.DirectoryURL,
		&ca.ACMEKeyEnc, &ca.AccountURI, &isDefaultInt, &ca.Status, &createdAt, &updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, mapSQLiteErr(err)
	}
	ca.IsDefault = isDefaultInt != 0
	ca.CreatedAt = parseDBTime(createdAt)
	ca.UpdatedAt = parseDBTime(updatedAt)
	return &ca, nil
}
