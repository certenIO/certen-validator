package execution

import (
	"context"
	"database/sql"
	"testing"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
	_ "github.com/lib/pq"
)

// openMigratedTestDB connects to CERTEN_TEST_DB and brings it to this binary's catalog through the
// production runner, so a test never depends on which package happened to migrate the database first.
// Without a database the test skips locally but fails in CI: a skipped gate is not a green gate.
func openMigratedTestDB(t *testing.T, gate string) *sql.DB {
	t.Helper()
	conn, err := testdb.PackageURL("execution")
	if err != nil {
		t.Fatalf("%s needs PostgreSQL: %v", gate, err)
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	if err := (schema.Runner{DB: db}).Up(context.Background(), "execution-test-suite"); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return db
}
