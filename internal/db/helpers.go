package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const dbTimeLayout = "2006-01-02 15:04:05.000000000"

func formatDBTime(t time.Time) string {
	return t.UTC().Format(dbTimeLayout)
}

func formatNullDBTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(dbTimeLayout)
}

func parseDBTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	layouts := []string{
		dbTimeLayout,
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func scanTime(v any) time.Time {
	switch val := v.(type) {
	case time.Time:
		return val.UTC()
	case string:
		return parseDBTime(val)
	case []byte:
		return parseDBTime(string(val))
	default:
		return time.Time{}
	}
}

func scanNullTime(nt sql.NullString) *time.Time {
	if !nt.Valid || strings.TrimSpace(nt.String) == "" {
		return nil
	}
	t := parseDBTime(nt.String)
	if t.IsZero() {
		return nil
	}
	return &t
}

func scanNullBool(ni sql.NullInt64) *bool {
	if !ni.Valid {
		return nil
	}
	b := ni.Int64 != 0
	return &b
}

func scanNullInt(ni sql.NullInt64) *int {
	if !ni.Valid {
		return nil
	}
	v := int(ni.Int64)
	return &v
}

func scanNullInt64(ni sql.NullInt64) *int64 {
	if !ni.Valid {
		return nil
	}
	v := ni.Int64
	return &v
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func mapSQLiteErr(err error) error {
	return mapSQLiteErrOp(err, false)
}

func mapSQLiteDeleteErr(err error) error {
	return mapSQLiteErrOp(err, true)
}

func mapSQLiteErrOp(err error, isDelete bool) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "foreign key constraint failed") {
		if isDelete {
			return ErrResourceInUse
		}
		return ErrInvalidReference
	}
	if strings.Contains(msg, "unique constraint failed") {
		return ErrConflict
	}
	return err
}
