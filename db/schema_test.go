package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCatalogIsOrderedAndLintClean(t *testing.T) {
	migrations, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) == 0 || migrations[0].Version != "00000" {
		t.Fatalf("catalog begins with %#v, want baseline 00000", migrations)
	}
	for i, migration := range migrations {
		if err := Lint(migration); err != nil {
			t.Fatal(err)
		}
		if i > 0 && migrations[i-1].Version >= migration.Version {
			t.Fatalf("catalog order %s then %s", migrations[i-1].Version, migration.Version)
		}
	}
}

func TestApprovedFingerprintIsValid(t *testing.T) {
	fingerprint, err := ApprovedFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("fingerprint length = %d", len(fingerprint))
	}
}

func TestLintRejectsUnsafeMigrationControl(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		ok   bool
	}{
		{"transaction", "BEGIN;\nCREATE TABLE x();", false},
		{"destructive", "DROP TABLE x;", false},
		{"approved destructive", "-- schema: destructive-approved\nDROP TABLE x;", true},
		{"session setting", "SET statement_timeout = '1s';", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Lint(Migration{Name: tc.name + ".sql", SQL: []byte(tc.sql)})
			if (err == nil) != tc.ok {
				t.Fatalf("Lint() error = %v, want success=%v", err, tc.ok)
			}
		})
	}
}

func TestValidateHistoryRejectsChecksumUnknownAndGap(t *testing.T) {
	checksum := func(sql string) string {
		sum := sha256.Sum256([]byte(sql))
		return hex.EncodeToString(sum[:])
	}
	migrations := []Migration{
		{Version: "00000", Name: "00000_baseline.sql", SQL: []byte("baseline"), SHA256: sha256.Sum256([]byte("baseline"))},
		{Version: "00001", Name: "00001_add_table.sql", SQL: []byte("next"), SHA256: sha256.Sum256([]byte("next"))},
	}
	valid := map[string]string{"00000": checksum("baseline"), "00001": checksum("next")}
	for name, history := range map[string]map[string]string{
		"checksum": {"00000": "wrong", "00001": checksum("next")},
		"unknown":  {"00000": checksum("baseline"), "00001": checksum("next"), "00000a": checksum("other")},
		"gap":      {"00001": checksum("next")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateHistory(migrations, history, "00001", true); err == nil {
				t.Fatal("validateHistory unexpectedly accepted invalid history")
			}
		})
	}
	if err := validateHistory(migrations, valid, "00001", true); err != nil {
		t.Fatalf("validateHistory valid history: %v", err)
	}
	if err := validateHistory(migrations, map[string]string{"00000": checksum("baseline"), "00001": checksum("next"), "00002": checksum("future")}, "00001", true); err != nil {
		t.Fatalf("future history should be permitted for rolling deployment: %v", err)
	}
}

func TestNoTransactionMarkerMustBeFirstNonEmptyLine(t *testing.T) {
	if !isNoTransaction(Migration{SQL: []byte("\n-- schema: no-transaction\nCREATE INDEX CONCURRENTLY x")}) {
		t.Fatal("first migration comment should opt out of transactions")
	}
	if isNoTransaction(Migration{SQL: []byte("CREATE TABLE x();\n-- schema: no-transaction")}) {
		t.Fatal("marker after SQL must not opt out of transactions")
	}
}

func TestNormalizeCatalogEntryIgnoresDumpWhitespaceOnly(t *testing.T) {
	windows := "F|public|f|CREATE FUNCTION f()\r\nRETURNS void\r\n\r\nAS $$\r\nBEGIN\r\n  NULL;  \r\nEND;\r\n$$"
	unix := "F|public|f|CREATE FUNCTION f()\nRETURNS void\nAS $$\nBEGIN\n  NULL;\nEND;\n$$"
	if got := normalizeCatalogEntry(windows); got != unix {
		t.Fatalf("normalized catalog entry = %q, want %q", got, unix)
	}
	changed := "F|public|f|CREATE FUNCTION f()\nRETURNS void\nAS $$\nBEGIN\n  PERFORM 1;\nEND;\n$$"
	if normalizeCatalogEntry(changed) == normalizeCatalogEntry(unix) {
		t.Fatal("normalization hid a non-whitespace function body change")
	}
}

func TestCatalogUsesStableCollationIdentity(t *testing.T) {
	if !strings.Contains(catalogEntriesQuery, "coll_ns.nspname || '.' || coll.collname") {
		t.Fatal("catalog query does not use a stable schema-qualified collation identity")
	}
}

func TestNormalizeCatalogExpressionIgnoresDumpArrayCoercion(t *testing.T) {
	live := "I|CREATE INDEX i ON public.t USING btree (state) WHERE ((state)::text = ANY (ARRAY[('pending'::character varying)::text, ('ready'::character varying)::text]))"
	restored := "I|CREATE INDEX i ON public.t USING btree (state) WHERE ((state)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying])::text[]))"
	if got, want := normalizeCatalogExpression(live), normalizeCatalogExpression(restored); got != want {
		t.Fatalf("normalized index expressions differ:\n%s\n!=\n%s", got, want)
	}
	changed := "I|CREATE INDEX i ON public.t USING btree (state) WHERE ((state)::text = ANY (ARRAY[('pending'::character varying)::text, ('failed'::character varying)::text]))"
	if normalizeCatalogExpression(changed) == normalizeCatalogExpression(live) {
		t.Fatal("normalization hid a changed array member")
	}
	outsideArrayCast := "I|CREATE INDEX i ON public.t USING btree ((state)::text) WHERE state::text = 'pending'::text"
	if got := normalizeCatalogExpression(outsideArrayCast); got != outsideArrayCast {
		t.Fatalf("normalization changed a non-array cast: %s", got)
	}
}
