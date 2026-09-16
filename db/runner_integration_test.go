package schema

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

// TestRunnerDatabaseGates exercises the stateful migration guarantees against PostgreSQL. It creates
// throwaway databases rather than truncating CERTEN_TEST_DB, so it can coexist with the repository suites.
// CI must provide a database URL; local unit-test runs remain usable without Docker.
func TestRunnerDatabaseGates(t *testing.T) {
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CERTEN_TEST_DB is required in CI")
		}
		t.Skip("CERTEN_TEST_DB not configured")
	}

	t.Run("fresh install", func(t *testing.T) {
		withThrowawayDatabase(t, conn, func(db *sql.DB) {
			runner := Runner{DB: db}
			if err := runner.Up(context.Background(), "test-suite"); err != nil {
				t.Fatalf("migrate up: %v", err)
			}
			if err := runner.Verify(context.Background(), ""); err != nil {
				t.Fatalf("verify fresh schema: %v", err)
			}
			want, err := ApprovedFingerprint()
			if err != nil {
				t.Fatal(err)
			}
			got, err := runner.Fingerprint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("fresh fingerprint = %s, want %s", got, want)
			}
			assertHistoryRows(t, db, migrationCount(t))
		})
	})

	t.Run("adoption", func(t *testing.T) {
		withThrowawayDatabase(t, conn, func(db *sql.DB) {
			runner := Runner{DB: db}
			if err := runner.Up(context.Background(), "fixture"); err != nil {
				t.Fatalf("build adoption fixture: %v", err)
			}
			if _, err := db.Exec("DROP TABLE public.certen_schema_history"); err != nil {
				t.Fatalf("remove fixture-only history: %v", err)
			}
			before, err := runner.Fingerprint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// The production baseline is restored from pg_dump by psql and is verified
			// independently in the production-copy gate. This fixture exercises the
			// runner's non-destructive adoption protocol using the exact catalog built
			// by the runner, rather than replaying a pg_dump through a database driver.
			if err := runner.AdoptionPreflight(context.Background(), before, before); err != nil {
				t.Fatalf("adoption dry run: %v", err)
			}
			if err := runner.Adopt(context.Background(), before, before, "test-suite"); err != nil {
				t.Fatalf("adopt: %v", err)
			}
			assertHistoryRows(t, db, 1)
			if err := runner.Verify(context.Background(), "00000"); err != nil {
				t.Fatalf("verify adopted baseline: %v", err)
			}
			after, err := runner.Fingerprint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("adoption changed catalog fingerprint from %s to %s", before, after)
			}
		})
	})

	t.Run("seven concurrent migrators", func(t *testing.T) {
		withThrowawayDatabase(t, conn, func(db *sql.DB) {
			var wg sync.WaitGroup
			errs := make(chan error, 7)
			for range 7 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs <- (Runner{DB: db}).Up(context.Background(), "test-suite")
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent migrate up: %v", err)
				}
			}
			assertHistoryRows(t, db, migrationCount(t))
			if err := (Runner{DB: db}).Verify(context.Background(), ""); err != nil {
				t.Fatalf("verify concurrent schema: %v", err)
			}
		})
	})

	t.Run("advisory lock timeout leaves no partial schema", func(t *testing.T) {
		withThrowawayDatabase(t, conn, func(db *sql.DB) {
			ctx := context.Background()
			lock, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if _, err := lock.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
				t.Fatal(err)
			}
			defer lock.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockID)

			err = (Runner{DB: db, LockTimeout: 150 * time.Millisecond}).Up(ctx, "test-suite")
			if err == nil || !strings.Contains(err.Error(), "advisory lock timed out") {
				t.Fatalf("locked migrate up error = %v, want advisory lock timeout", err)
			}
			var exists bool
			if err := db.QueryRow("SELECT to_regclass('public.certen_schema_history') IS NOT NULL").Scan(&exists); err != nil {
				t.Fatal(err)
			}
			if exists {
				t.Fatal("timed-out migration created schema history")
			}
		})
	})
}

func withThrowawayDatabase(t *testing.T, conn string, test func(*sql.DB)) {
	t.Helper()
	ctx := context.Background()
	admin, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	dbName := fmt.Sprintf("certen_schema_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pq.QuoteIdentifier(dbName)); err != nil {
		t.Fatalf("create throwaway database: %v", err)
	}
	defer func() {
		if _, err := admin.ExecContext(ctx, "DROP DATABASE "+pq.QuoteIdentifier(dbName)); err != nil {
			t.Errorf("drop throwaway database %s: %v", dbName, err)
		}
	}()

	target, err := databaseURLForName(conn, dbName)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", target)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close throwaway database: %v", err)
		}
	}()
	test(db)
}

func databaseURLForName(conn, dbName string) (string, error) {
	u, err := url.Parse(conn)
	if err != nil {
		return "", err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", fmt.Errorf("CERTEN_TEST_DB must be a PostgreSQL URL")
	}
	u.Path = "/" + dbName
	u.RawPath = ""
	return u.String(), nil
}

func assertHistoryRows(t *testing.T, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow("SELECT count(*) FROM public.certen_schema_history").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("schema history rows = %d, want %d", got, want)
	}
}

func migrationCount(t *testing.T) int {
	t.Helper()
	migrations, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	return len(migrations)
}
