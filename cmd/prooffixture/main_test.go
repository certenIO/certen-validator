package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The extractor reads production storage, so it refuses any session that is not forced read-only, before it reads
// anything, and writes no file.
func TestTheExtractorRefusesASessionThatCanWrite(t *testing.T) {
	dsn := os.Getenv("CERTEN_TEST_DB")
	if dsn == "" {
		t.Fatal("CERTEN_TEST_DB is required: this test runs against PostgreSQL (a skipped gate is not a green gate)")
	}
	out := filepath.Join(t.TempDir(), "fixture.json")
	err := run(dsn, "00000000", out)
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
