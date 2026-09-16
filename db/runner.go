package schema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const advisoryLockID int64 = 0x4352544E5343484D // "CRTNSCHM"

const catalogFingerprintQuery = `WITH objects AS (
 SELECT format('C|%I|%I|%s|%s|%s|%s', n.nspname,c.relname,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_get_expr(ad.adbin,ad.adrelid),'')) AS entry
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
 WHERE c.relkind IN ('r','p','v','m') AND n.nspname NOT IN ('pg_catalog','information_schema')
 UNION ALL SELECT 'I|' || pg_get_indexdef(i.indexrelid) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')
 UNION ALL SELECT 'K|' || n.nspname || '|' || c.relname || '|' || pg_get_constraintdef(k.oid) FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')
 UNION ALL SELECT 'V|' || n.nspname || '|' || c.relname || '|' || pg_get_viewdef(c.oid,true) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('v','m') AND n.nspname NOT IN ('pg_catalog','information_schema')
 UNION ALL SELECT 'F|' || n.nspname || '|' || p.proname || '|' || pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema')
 UNION ALL SELECT 'T|' || n.nspname || '|' || c.relname || '|' || pg_get_triggerdef(t.oid,true) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE NOT t.tgisinternal AND n.nspname NOT IN ('pg_catalog','information_schema')
) SELECT COALESCE(string_agg(entry, E'\n' ORDER BY entry), '') FROM objects`

// Runner applies and verifies the one shared schema catalog. It intentionally has no dependency on either
// service, so the validator and proofs service can use identical history and checksum rules.
type Runner struct {
	DB               *sql.DB
	LockTimeout      time.Duration
	StatementTimeout time.Duration
}

// Fingerprint hashes the complete live public catalog deterministically. It intentionally contains schema
// definitions only—never table rows or credentials—and is used by adopt and deployment verification.
func (r Runner) Fingerprint(ctx context.Context) (string, error) {
	if r.DB == nil {
		return "", errors.New("schema runner requires a database")
	}
	var catalog string
	if err := r.DB.QueryRowContext(ctx, catalogFingerprintQuery).Scan(&catalog); err != nil {
		return "", fmt.Errorf("read schema catalog: %w", err)
	}
	sum := sha256.Sum256([]byte(catalog))
	return hex.EncodeToString(sum[:]), nil
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
		known := make(map[string]Migration, len(migrations))
		for _, migration := range migrations {
			known[migration.Version] = migration
		}
		latest := migrations[len(migrations)-1].Version
		for version := range history {
			if _, ok := known[version]; !ok && version <= latest {
				return fmt.Errorf("unknown schema history version %s at or below catalog version %s", version, latest)
			}
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

// Adopt records an already-existing catalog as the baseline without executing any migration SQL. The caller
// must supply a fingerprint captured from the approved production-schema copy; an empty value is rejected
// so adoption can never silently bless an unknown schema.
func (r Runner) Adopt(ctx context.Context, fingerprint, approvedFingerprint, appliedBy string) error {
	if fingerprint == "" || approvedFingerprint == "" {
		return errors.New("adoption requires both observed and approved schema fingerprints")
	}
	if fingerprint != approvedFingerprint {
		return fmt.Errorf("schema fingerprint mismatch: observed %s, expected %s", fingerprint, approvedFingerprint)
	}
	return r.withLock(ctx, func() error {
		if err := r.ensureHistory(ctx); err != nil {
			return err
		}
		var count int
		if err := r.DB.QueryRowContext(ctx, "SELECT count(*) FROM certen_schema_history").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("schema history is not empty; refusing adoption")
		}
		var legacy bool
		if err := r.DB.QueryRowContext(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&legacy); err != nil {
			return err
		}
		if !legacy {
			return errors.New("legacy schema_migrations table is absent; refusing adoption")
		}
		migrations, err := Migrations()
		if err != nil {
			return err
		}
		baseline := migrations[0]
		_, err = r.DB.ExecContext(ctx, "INSERT INTO certen_schema_history(version,name,sha256,applied_by,duration_ms) VALUES($1,$2,$3,$4,0)", baseline.Version, baseline.Name, hex.EncodeToString(baseline.SHA256[:]), appliedBy)
		return err
	})
}
