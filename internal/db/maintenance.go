package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"ssl-center/internal/model"
)

// PruneLogs enforces log retention by age (retentionDays) and row cap (maxRows)
// across cert_jobs, deploy_logs, and audit_events while skipping running jobs.
// It also runs PRAGMA wal_checkpoint(TRUNCATE) and conditionally runs VACUUM.
func (d *DB) PruneLogs(ctx context.Context, retentionDays, maxRows int) (*model.PruneResult, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return nil, err
	}

	res := &model.PruneResult{}
	now := time.Now().UTC()

	if retentionDays > 0 {
		cutoff := formatDBTime(now.AddDate(0, 0, -retentionDays))

		r1, err := sqlDB.ExecContext(ctx,
			`DELETE FROM cert_jobs WHERE status != 'running' AND started_at < ?`, cutoff)
		if err != nil {
			return nil, fmt.Errorf("prune cert_jobs by age: %w", err)
		}
		n1, _ := r1.RowsAffected()
		res.CertJobsDeleted += n1

		r2, err := sqlDB.ExecContext(ctx,
			`DELETE FROM deploy_logs WHERE status != 'running' AND started_at < ?`, cutoff)
		if err != nil {
			return nil, fmt.Errorf("prune deploy_logs by age: %w", err)
		}
		n2, _ := r2.RowsAffected()
		res.DeployLogsDeleted += n2

		r3, err := sqlDB.ExecContext(ctx,
			`DELETE FROM audit_events WHERE created_at < ?`, cutoff)
		if err != nil {
			return nil, fmt.Errorf("prune audit_events by age: %w", err)
		}
		n3, _ := r3.RowsAffected()
		res.AuditEventsDeleted += n3
	}

	if maxRows > 0 {
		r1, err := sqlDB.ExecContext(ctx,
			`DELETE FROM cert_jobs WHERE status != 'running' AND id NOT IN (
				SELECT id FROM cert_jobs ORDER BY started_at DESC, id DESC LIMIT ?
			)`, maxRows)
		if err != nil {
			return nil, fmt.Errorf("prune cert_jobs by count: %w", err)
		}
		n1, _ := r1.RowsAffected()
		res.CertJobsDeleted += n1

		r2, err := sqlDB.ExecContext(ctx,
			`DELETE FROM deploy_logs WHERE status != 'running' AND id NOT IN (
				SELECT id FROM deploy_logs ORDER BY started_at DESC, id DESC LIMIT ?
			)`, maxRows)
		if err != nil {
			return nil, fmt.Errorf("prune deploy_logs by count: %w", err)
		}
		n2, _ := r2.RowsAffected()
		res.DeployLogsDeleted += n2

		r3, err := sqlDB.ExecContext(ctx,
			`DELETE FROM audit_events WHERE id NOT IN (
				SELECT id FROM audit_events ORDER BY created_at DESC, id DESC LIMIT ?
			)`, maxRows)
		if err != nil {
			return nil, fmt.Errorf("prune audit_events by count: %w", err)
		}
		n3, _ := r3.RowsAffected()
		res.AuditEventsDeleted += n3
	}

	res.TotalDeleted = res.CertJobsDeleted + res.DeployLogsDeleted + res.AuditEventsDeleted

	if _, err := sqlDB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		return nil, fmt.Errorf("wal_checkpoint: %w", err)
	}

	var freelist int64
	_ = sqlDB.QueryRowContext(ctx, "PRAGMA freelist_count;").Scan(&freelist)
	if res.TotalDeleted > 0 || freelist > 64 {
		if _, err := sqlDB.ExecContext(ctx, "VACUUM;"); err != nil {
			return nil, fmt.Errorf("vacuum: %w", err)
		}
		res.VacuumRan = true
	}

	return res, nil
}

// ExportVacuumInto writes a consistent SQLite snapshot via VACUUM INTO to destDBPath,
// deletes all rows from `sessions` inside the exported file (preserving the live DB),
// and checkpoints the exported file cleanly.
func (d *DB) ExportVacuumInto(ctx context.Context, destDBPath string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sqlDB, err := d.conn()
	if err != nil {
		return err
	}

	_ = os.Remove(destDBPath)
	escaped := strings.ReplaceAll(destDBPath, "'", "''")
	if _, err := sqlDB.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s';", escaped)); err != nil {
		return fmt.Errorf("vacuum into %s: %w", destDBPath, err)
	}

	expDB, err := sql.Open("sqlite", destDBPath)
	if err != nil {
		return fmt.Errorf("open exported db: %w", err)
	}
	defer expDB.Close()

	if _, err := expDB.ExecContext(ctx, "DELETE FROM sessions;"); err != nil {
		return fmt.Errorf("clear sessions in exported db: %w", err)
	}
	if _, err := expDB.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		return fmt.Errorf("checkpoint exported db: %w", err)
	}
	return nil
}
