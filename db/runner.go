package schema

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const advisoryLockID int64 = 0x4352544E5343484D // "CRTNSCHM"

// Runner applies and verifies the one shared schema catalog. It intentionally has no dependency on either
// service, so the validator and proofs service can use identical history and checksum rules.
type Runner struct {
	DB               *sql.DB
	LockTimeout      time.Duration
	StatementTimeout time.Duration
}

func (r Runner) defaults() Runner {
	if r.LockTimeout <= 0 {
		r.LockTimeout = 15 * time.Second
	}
	if r.StatementTimeout <= 0 {
		r.StatementTimeout = 2 * time.Minute
	}
	return r
}

func (r Runner) ensureHistory(ctx context.Context) error {
	_, err := r.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS certen_schema_history (
version varchar(16) PRIMARY KEY, name text NOT NULL, sha256 char(64) NOT NULL,
applied_at timestamptz NOT NULL DEFAULT now(), applied_by text NOT NULL, duration_ms bigint NOT NULL)`)
	return err
}

func (r Runner) withLock(ctx context.Context, fn func() error) error {
	conn, err := r.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		return err
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockID)
	return fn()
}

// Up applies missing migrations atomically, after validating every existing history row's checksum.
func (r Runner) Up(ctx context.Context, appliedBy string) error {
	r = r.defaults()
	if r.DB == nil {
		return errors.New("schema runner requires a database")
	}
	migrations, err := Migrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		if err := Lint(m); err != nil {
			return err
		}
	}
	return r.withLock(ctx, func() error {
		if err := r.ensureHistory(ctx); err != nil {
			return fmt.Errorf("create schema history: %w", err)
		}
		history := map[string]string{}
		rows, err := r.DB.QueryContext(ctx, "SELECT version, sha256 FROM certen_schema_history")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v, sum string
			if err := rows.Scan(&v, &sum); err != nil {
				return err
			}
			history[v] = sum
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, m := range migrations {
			sum := hex.EncodeToString(m.SHA256[:])
			if actual, ok := history[m.Version]; ok {
				if actual != sum {
					return fmt.Errorf("migration %s checksum mismatch", m.Name)
				}
				continue
			}
			started := time.Now()
			tx, err := r.DB.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'; SET LOCAL statement_timeout = '%dms'", r.LockTimeout.Milliseconds(), r.StatementTimeout.Milliseconds())); err == nil {
				_, err = tx.ExecContext(ctx, string(m.SQL))
			}
			if err == nil {
				_, err = tx.ExecContext(ctx, "INSERT INTO certen_schema_history(version,name,sha256,applied_by,duration_ms) VALUES($1,$2,$3,$4,$5)", m.Version, m.Name, sum, appliedBy, time.Since(started).Milliseconds())
			}
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("apply migration %s: %w", m.Name, err)
			}
			if err = tx.Commit(); err != nil {
				return fmt.Errorf("commit migration %s: %w", m.Name, err)
			}
		}
		return nil
	})
}

// Verify checks that all migrations through requiredVersion have been applied with their expected checksum.
// Newer rows are permitted to support rolling deployments.
func (r Runner) Verify(ctx context.Context, requiredVersion string) error {
	migrations, err := Migrations()
	if err != nil {
		return err
	}
	rows, err := r.DB.QueryContext(ctx, "SELECT version, sha256 FROM certen_schema_history")
	if err != nil {
		return fmt.Errorf("schema history unavailable: %w", err)
	}
	defer rows.Close()
	history := map[string]string{}
	for rows.Next() {
		var v, sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return err
		}
		history[v] = sum
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, m := range migrations {
		if requiredVersion != "" && m.Version > requiredVersion {
			break
		}
		actual, ok := history[m.Version]
		if !ok {
			return fmt.Errorf("schema is older than required migration %s", m.Version)
		}
		if actual != hex.EncodeToString(m.SHA256[:]) {
			return fmt.Errorf("migration %s checksum mismatch", m.Name)
		}
	}
	return nil
}
