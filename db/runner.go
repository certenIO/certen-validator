package schema

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const advisoryLockID int64 = 0x4352544E5343484D // "CRTNSCHM"

const noTransactionMarker = "-- schema: no-transaction"

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

func ensureHistory(ctx context.Context, db sqlExecutor) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS public.certen_schema_history (
version varchar(16) PRIMARY KEY, name text NOT NULL, sha256 char(64) NOT NULL,
applied_at timestamptz NOT NULL DEFAULT now(), applied_by text NOT NULL, duration_ms bigint NOT NULL)`)
	return err
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (r Runner) withLock(ctx context.Context, fn func(*sql.Conn) error) error {
	conn, err := r.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline := time.Now().Add(r.LockTimeout)
	for {
		var locked bool
		if err = conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", advisoryLockID).Scan(&locked); err != nil {
			return fmt.Errorf("acquire schema advisory lock: %w", err)
		}
		if locked {
			break
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("schema advisory lock timed out after %s", r.LockTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockID)
	return fn(conn)
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
	return r.withLock(ctx, func(conn *sql.Conn) error {
		if err := ensureHistory(ctx, conn); err != nil {
			return fmt.Errorf("create schema history: %w", err)
		}
		history := map[string]string{}
		rows, err := conn.QueryContext(ctx, "SELECT version, sha256 FROM public.certen_schema_history")
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
		if err := validateHistory(migrations, history, migrations[len(migrations)-1].Version, false); err != nil {
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
			if isNoTransaction(m) {
				if err := applyWithoutTransaction(ctx, conn, m, sum, appliedBy, r); err != nil {
					return err
				}
			} else if err := applyInTransaction(ctx, conn, m, sum, appliedBy, r); err != nil {
				return err
			}
		}
		return nil
	})
}

// Verify checks that all migrations through requiredVersion have been applied with their expected checksum.
// Newer rows are permitted to support rolling deployments.
func (r Runner) Verify(ctx context.Context, requiredVersion string) error {
	if r.DB == nil {
		return errors.New("schema runner requires a database")
	}
	migrations, err := Migrations()
	if err != nil {
		return err
	}
	rows, err := r.DB.QueryContext(ctx, "SELECT version, sha256 FROM public.certen_schema_history")
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
	if requiredVersion == "" {
		requiredVersion = migrations[len(migrations)-1].Version
	}
	return validateHistory(migrations, history, requiredVersion, true)
}

// Data runs a named, out-of-band data migration. Data migrations are intentionally not part of Up:
// schema deployment must remain bounded and startup must never backfill application rows. No data
// migration is currently registered because the legacy backfill is represented in the production baseline.
func (r Runner) Data(ctx context.Context, name, appliedBy string) error {
	if r.DB == nil {
		return errors.New("schema runner requires a database")
	}
	if name == "" {
		return errors.New("data migration name is required")
	}
	return fmt.Errorf("data migration %q is not registered", name)
}

// Adopt records an already-existing catalog as the baseline without executing any migration SQL. The caller
// must supply a fingerprint captured from the approved production-schema copy; an empty value is rejected
// so adoption can never silently bless an unknown schema.
func (r Runner) Adopt(ctx context.Context, fingerprint, approvedFingerprint, appliedBy string) error {
	r = r.defaults()
	if r.DB == nil {
		return errors.New("schema runner requires a database")
	}
	if err := r.AdoptionPreflight(ctx, fingerprint, approvedFingerprint); err != nil {
		return err
	}
	return r.withLock(ctx, func(conn *sql.Conn) error {
		var exists bool
		if err := conn.QueryRowContext(ctx, "SELECT to_regclass('public.certen_schema_history') IS NOT NULL").Scan(&exists); err != nil {
			return err
		}
		if exists {
			var count int
			if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM public.certen_schema_history").Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				return errors.New("schema history is not empty; refusing adoption")
			}
		}
		var legacy bool
		if err := conn.QueryRowContext(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&legacy); err != nil {
			return err
		}
		if !legacy {
			return errors.New("legacy schema_migrations table is absent; refusing adoption")
		}
		var catalog string
		err := conn.QueryRowContext(ctx, catalogFingerprintQuery).Scan(&catalog)
		if err != nil {
			return fmt.Errorf("read schema catalog: %w", err)
		}
		sum := sha256.Sum256([]byte(catalog))
		observed := hex.EncodeToString(sum[:])
		if observed != fingerprint {
			return fmt.Errorf("schema changed during adoption preflight: observed %s, now %s", fingerprint, observed)
		}
		if err := ensureHistory(ctx, conn); err != nil {
			return fmt.Errorf("create schema history: %w", err)
		}
		migrations, err := Migrations()
		if err != nil {
			return err
		}
		baseline := migrations[0]
		_, err = conn.ExecContext(ctx, "INSERT INTO public.certen_schema_history(version,name,sha256,applied_by,duration_ms) VALUES($1,$2,$3,$4,0)", baseline.Version, baseline.Name, hex.EncodeToString(baseline.SHA256[:]), appliedBy)
		return err
	})
}

// AdoptionPreflight performs every non-mutating adoption check. It is safe to run in deployment
// automation before a change window; Adopt repeats the checks while holding the schema lock before writing.
func (r Runner) AdoptionPreflight(ctx context.Context, fingerprint, approvedFingerprint string) error {
	if r.DB == nil {
		return errors.New("schema runner requires a database")
	}
	if fingerprint == "" || approvedFingerprint == "" {
		return errors.New("adoption requires both observed and approved schema fingerprints")
	}
	if fingerprint != approvedFingerprint {
		return fmt.Errorf("schema fingerprint mismatch: observed %s, expected %s", fingerprint, approvedFingerprint)
	}
	var exists bool
	if err := r.DB.QueryRowContext(ctx, "SELECT to_regclass('public.certen_schema_history') IS NOT NULL").Scan(&exists); err != nil {
		return err
	}
	if exists {
		var count int
		if err := r.DB.QueryRowContext(ctx, "SELECT count(*) FROM public.certen_schema_history").Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("schema history is not empty; refusing adoption")
		}
	}
	var legacy bool
	if err := r.DB.QueryRowContext(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&legacy); err != nil {
		return err
	}
	if !legacy {
		return errors.New("legacy schema_migrations table is absent; refusing adoption")
	}
	return nil
}

func isNoTransaction(m Migration) bool {
	for _, line := range strings.Split(string(m.SQL), "\n") {
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if trimmed == "" {
			continue
		}
		return trimmed == noTransactionMarker
	}
	return false
}

func validateHistory(migrations []Migration, history map[string]string, requiredVersion string, requireAll bool) error {
	known := make(map[string]Migration, len(migrations))
	for _, migration := range migrations {
		known[migration.Version] = migration
	}
	for version := range history {
		if _, ok := known[version]; !ok && version <= requiredVersion {
			return fmt.Errorf("unknown schema history version %s at or below required catalog version %s", version, requiredVersion)
		}
	}
	seenGap := false
	for _, m := range migrations {
		if m.Version > requiredVersion {
			break
		}
		actual, ok := history[m.Version]
		if !ok {
			seenGap = true
			if requireAll {
				return fmt.Errorf("schema is older than required migration %s", m.Version)
			}
			continue
		}
		if seenGap {
			return fmt.Errorf("schema history has a gap before migration %s", m.Version)
		}
		if actual != hex.EncodeToString(m.SHA256[:]) {
			return fmt.Errorf("migration %s checksum mismatch", m.Name)
		}
	}
	return nil
}

func applyInTransaction(ctx context.Context, conn *sql.Conn, m Migration, sum, appliedBy string, r Runner) error {
	started := time.Now()
	tx, err := conn.BeginTx(ctx, nil)
	if err == nil {
		_, err = tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'; SET LOCAL statement_timeout = '%dms'", r.LockTimeout.Milliseconds(), r.StatementTimeout.Milliseconds()))
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, string(m.SQL))
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, "INSERT INTO public.certen_schema_history(version,name,sha256,applied_by,duration_ms) VALUES($1,$2,$3,$4,$5)", m.Version, m.Name, sum, appliedBy, time.Since(started).Milliseconds())
	}
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("apply migration %s: %w", m.Name, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.Name, err)
	}
	// The production baseline is a pg_dump, whose standard preamble changes search_path and
	// other session settings. This connection returns to the pool in development/test runs, so
	// it must be restored before repository code can reuse it.
	if _, err = conn.ExecContext(ctx, "RESET ALL"); err != nil {
		return fmt.Errorf("reset session after migration %s: %w", m.Name, err)
	}
	return nil
}

func applyWithoutTransaction(ctx context.Context, conn *sql.Conn, m Migration, sum, appliedBy string, r Runner) error {
	started := time.Now()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("SET lock_timeout = '%dms'; SET statement_timeout = '%dms'", r.LockTimeout.Milliseconds(), r.StatementTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("configure migration %s timeouts: %w", m.Name, err)
	}
	defer conn.ExecContext(context.Background(), "RESET ALL")
	if _, err := conn.ExecContext(ctx, string(m.SQL)); err != nil {
		return fmt.Errorf("apply non-transactional migration %s: %w", m.Name, err)
	}
	if _, err := conn.ExecContext(ctx, "INSERT INTO public.certen_schema_history(version,name,sha256,applied_by,duration_ms) VALUES($1,$2,$3,$4,$5)", m.Version, m.Name, sum, appliedBy, time.Since(started).Milliseconds()); err != nil {
		return fmt.Errorf("record non-transactional migration %s: %w", m.Name, err)
	}
	return nil
}
