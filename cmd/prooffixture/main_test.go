package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	schema "github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/internal/testdb"
)

// The extractor reads production storage, so it refuses any session that is not forced read-only, before it reads
// anything, and writes no file.
//
// It runs in its own migrated database (RB5-F42): it read the shared base database unmigrated, so it passed only when
// another package had migrated that database first, and failed on a fresh server with "relation proof_artifacts
// does not exist".
func TestTheExtractorRefusesASessionThatCanWrite(t *testing.T) {
	dsn, err := testdb.PackageURL("prooffixture")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := (schema.Runner{DB: db}).Up(context.Background(), "prooffixture-test-suite"); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "fixture.json")
	err = run(dsn, "00000000", out)
	if err == nil || !strings.Contains(err.Error(), "not read-only") {
		t.Fatalf("a read-write session: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("a refused run wrote a file")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	if err := run(dsn+sep+"options=-c%20default_transaction_read_only%3Don", "00000000-no-such", out); err == nil ||
		!strings.Contains(err.Error(), "names 0 proofs") {
		t.Fatalf("a read-only session and a prefix of no proof: %v", err)
	}
}
