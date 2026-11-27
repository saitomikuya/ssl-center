package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var initSQL string

const ExpectedTableCount = 12

var (
	ErrNotFound           = errors.New("record not found")
	ErrConflict           = errors.New("resource already exists or conflicts")
	ErrLocalHostProtected = errors.New("built-in Local host cannot be deleted")
	ErrResourceInUse      = errors.New("resource is referenced by existing records")
	ErrInvalidReference   = errors.New("referenced parent record does not exist")
)

// DB wraps the SQLite connection pool and protects atomic database swaps
// during backup restoration.
type DB struct {
	mu   sync.RWMutex
	sql  *sql.DB
	path string
}

// Open opens or creates the SQLite database at path, enforces WAL/FK/busy_timeout
// pragmas, applies embedded migrations, and verifies the 12-table schema.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("database path must not be empty")
	}
	absPath := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	sqlDB, err := openSQLiteConn(absPath)
	if err != nil {
		return nil, err
	}

	if err := runMigrations(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	if err := verifySchema(sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}

	return &DB{
		sql:  sqlDB,
		path: absPath,
	}, nil
}

func openSQLiteConn(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)", path)
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA journal_mode = WAL;",
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
	}
	for _, p := range pragmas {
		if _, err := sqlDB.Exec(p); err != nil {
			_ = sqlDB.Close()
			return nil, fmt.Errorf("apply pragma %q: %w", p, err)
		}
	}
	return sqlDB, nil
}

func runMigrations(sqlDB *sql.DB) error {
	var userVersion int
	if err := sqlDB.QueryRow("PRAGMA user_version;").Scan(&userVersion); err != nil {
		return fmt.Errorf("read user_version: %w", err)
	}
	if userVersion < 1 {
		tx, err := sqlDB.Begin()
		if err != nil {
			return fmt.Errorf("begin migration tx: %w", err)
		}
		if _, err := tx.Exec(initSQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("execute 001_init.sql: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration tx: %w", err)
		}

		if _, err := sqlDB.Exec("PRAGMA user_version = 1;"); err != nil {
			return fmt.Errorf("set user_version: %w", err)
		}
	}

	// Repair stale Local host check state recorded before Caddy/Docker reachability was enforced.
	if _, err := sqlDB.Exec(`
		UPDATE hosts
		SET last_check_ok = 0
		WHERE is_local = 1 AND caddy_enabled = 1 AND caddy_status = 'unknown' AND last_check_ok = 1
	`); err != nil {
		return fmt.Errorf("repair local host check status: %w", err)
	}
	return nil
}

func verifySchema(sqlDB *sql.DB) error {
	var count int
	err := sqlDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("verify table count: %w", err)
	}
	if count != ExpectedTableCount {
		return fmt.Errorf("expected %d tables, found %d", ExpectedTableCount, count)
	}
	return nil
}

// DBPath returns the filesystem path of the SQLite database file.
func (d *DB) DBPath() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.path
}

// Close closes the underlying SQLite connection.
func (d *DB) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sql == nil {
		return nil
	}
	err := d.sql.Close()
	d.sql = nil
	return err
}

// CheckIntegrity runs PRAGMA integrity_check on the live database.
func (d *DB) CheckIntegrity(ctx context.Context) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.sql == nil {
		return errors.New("database is closed")
	}
	return checkIntegrityConn(ctx, d.sql)
}

func checkIntegrityConn(ctx context.Context, sqlDB *sql.DB) error {
	var res string
	if err := sqlDB.QueryRowContext(ctx, "PRAGMA integrity_check;").Scan(&res); err != nil {
		return fmt.Errorf("integrity_check: %w", err)
	}
	if strings.ToLower(strings.TrimSpace(res)) != "ok" {
		return fmt.Errorf("integrity_check failed: %s", res)
	}
	return nil
}

// SwapDB safely closes the active SQLite handle, snapshots the current DB for rollback,
// cleans stale -wal/-shm files, invokes replaceFn to swap the database file on disk,
// and reopens the handle with full WAL/FK pragmas, schema verification, and integrity check.
// If any step fails, the original DB file is restored and reopened so d.sql is not left nil.
func (d *DB) SwapDB(replaceFn func(dbPath string) error) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sql != nil {
		_, _ = d.sql.Exec("PRAGMA wal_checkpoint(TRUNCATE);")
		if err := d.sql.Close(); err != nil {
			return fmt.Errorf("close db before swap: %w", err)
		}
		d.sql = nil
	}

	_ = os.Remove(d.path + "-wal")
	_ = os.Remove(d.path + "-shm")

	var rollbackPath string
	if _, statErr := os.Stat(d.path); statErr == nil {
		tmpFile, err := os.CreateTemp(filepath.Dir(d.path), ".db-rollback-*")
		if err != nil {
			if reopened, reopenErr := openSQLiteConn(d.path); reopenErr == nil {
				d.sql = reopened
			}
			return fmt.Errorf("create rollback snapshot: %w", err)
		}
		rollbackPath = tmpFile.Name()
		_ = tmpFile.Close()
		defer func() {
			if rollbackPath != "" {
				_ = os.Remove(rollbackPath)
			}
		}()
		if err := copyFile(d.path, rollbackPath); err != nil {
			if reopened, reopenErr := openSQLiteConn(d.path); reopenErr == nil {
				d.sql = reopened
			}
			return fmt.Errorf("snapshot db before swap: %w", err)
		}
	}

	restoreOriginal := func() error {
		_ = os.Remove(d.path + "-wal")
		_ = os.Remove(d.path + "-shm")
		if rollbackPath != "" {
			if err := os.Rename(rollbackPath, d.path); err != nil {
				if copyErr := copyFile(rollbackPath, d.path); copyErr != nil {
					return fmt.Errorf("restore rollback snapshot: rename=%w copy=%v", err, copyErr)
				}
				_ = os.Remove(rollbackPath)
			}
			rollbackPath = ""
		}
		_ = os.Remove(d.path + "-wal")
		_ = os.Remove(d.path + "-shm")
		reopened, err := openSQLiteConn(d.path)
		if err != nil {
			return fmt.Errorf("reopen original db: %w", err)
		}
		d.sql = reopened
		return nil
	}

	failWithRollback := func(cause error) error {
		if restoreErr := restoreOriginal(); restoreErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", cause, restoreErr)
		}
		return cause
	}

	if err := replaceFn(d.path); err != nil {
		return failWithRollback(fmt.Errorf("swap db file: %w", err))
	}

	_ = os.Remove(d.path + "-wal")
	_ = os.Remove(d.path + "-shm")

	sqlDB, err := openSQLiteConn(d.path)
	if err != nil {
		return failWithRollback(fmt.Errorf("reopen swapped db: %w", err))
	}
	if err := runMigrations(sqlDB); err != nil {
		_ = sqlDB.Close()
		return failWithRollback(fmt.Errorf("migrate swapped db: %w", err))
	}
	if err := verifySchema(sqlDB); err != nil {
		_ = sqlDB.Close()
		return failWithRollback(fmt.Errorf("verify swapped db schema: %w", err))
	}
	if err := checkIntegrityConn(context.Background(), sqlDB); err != nil {
		_ = sqlDB.Close()
		return failWithRollback(fmt.Errorf("verify swapped db integrity: %w", err))
	}
	d.sql = sqlDB
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	mode := os.FileMode(0o600)
	if info, statErr := in.Stat(); statErr == nil {
		mode = info.Mode().Perm()
	}

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (d *DB) conn() (*sql.DB, error) {
	if d.sql == nil {
		return nil, errors.New("database is closed")
	}
	return d.sql, nil
}
