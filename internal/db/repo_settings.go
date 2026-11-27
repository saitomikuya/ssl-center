package db

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"time"

	"ssl-center/internal/model"
)

func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return "", err
	}

	var value string
	err = sqlDB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return value, nil
}

func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	now := formatDBTime(time.Now().UTC())
	_, err = sqlDB.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, key, value, now)
	return err
}

func (d *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	rows, err := sqlDB.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (d *DB) GetSettingsDTO(ctx context.Context) (*model.SettingsDTO, error) {
	all, err := d.GetAllSettings(ctx)
	if err != nil {
		return nil, err
	}

	dto := &model.SettingsDTO{
		InspectTime:      "03:00",
		RenewBeforeDays:  30,
		ExpiringWarnDays: 7,
		LogRetentionDays: 30,
		LogMaxRows:       5000,
	}
	if v, ok := all[model.SettingInspectTime]; ok && v != "" {
		dto.InspectTime = v
	}
	if v, ok := all[model.SettingRenewBeforeDays]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			dto.RenewBeforeDays = n
		}
	}
	if v, ok := all[model.SettingExpiringWarnDays]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			dto.ExpiringWarnDays = n
		}
	}
	if v, ok := all[model.SettingLogRetentionDays]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			dto.LogRetentionDays = n
		}
	}
	if v, ok := all[model.SettingLogMaxRows]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			dto.LogMaxRows = n
		}
	}
	return dto, nil
}

func (d *DB) UpdateSettings(ctx context.Context, req model.UpdateSettingsRequest) error {
	if req.InspectTime != nil {
		if err := d.SetSetting(ctx, model.SettingInspectTime, *req.InspectTime); err != nil {
			return err
		}
	}
	if req.RenewBeforeDays != nil {
		if err := d.SetSetting(ctx, model.SettingRenewBeforeDays, strconv.Itoa(*req.RenewBeforeDays)); err != nil {
			return err
		}
	}
	if req.ExpiringWarnDays != nil {
		if err := d.SetSetting(ctx, model.SettingExpiringWarnDays, strconv.Itoa(*req.ExpiringWarnDays)); err != nil {
			return err
		}
	}
	if req.LogRetentionDays != nil {
		if err := d.SetSetting(ctx, model.SettingLogRetentionDays, strconv.Itoa(*req.LogRetentionDays)); err != nil {
			return err
		}
	}
	if req.LogMaxRows != nil {
		if err := d.SetSetting(ctx, model.SettingLogMaxRows, strconv.Itoa(*req.LogMaxRows)); err != nil {
			return err
		}
	}
	return nil
}
