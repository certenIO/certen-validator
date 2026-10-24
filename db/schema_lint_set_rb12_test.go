package schema

import (
	"regexp"
	"strings"
	"testing"
)

// RB12-OPS-A1 item 5 (ledger F16): the lint rejected any LINE that began with SET, so a function attribute written on a line of its own
// (CREATE FUNCTION ... \n SET search_path = pg_catalog, pg_temp, which migrations must write: defect class 4) was refused as a session
// setting, and migration 00029 passes only because its attribute happens to sit at the end of the LANGUAGE line. A statement-level SET or
// RESET is still refused, wherever it stands.

func migration00029(t *testing.T) Migration {
	t.Helper()
	all, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.Version == "00029" {
			return m
		}
	}
	t.Fatal("migration 00029 is not in the catalog")
	return Migration{}
}

func lintOf(m Migration, sql string) error {
	return Lint(Migration{Version: m.Version, Name: m.Name, SQL: []byte(sql)})
}

var attributeSet = regexp.MustCompile(` SET search_path = pg_catalog, pg_temp`)

func TestFunctionAttributeSetIsAcceptedWhereverItIsWritten(t *testing.T) {
	m := migration00029(t)
	if err := Lint(m); err != nil {
		t.Fatalf("migration 00029 as shipped: %v", err)
	}
	// the same migration with each attribute on a line of its own, and then on the line of the function name
	own := attributeSet.ReplaceAllString(string(m.SQL), "\n    SET search_path = pg_catalog, pg_temp")
	if n := strings.Count(own, "\n    SET search_path = pg_catalog, pg_temp"); n != 3 {
		t.Fatalf("expected 3 function attributes in 00029, found %d", n)
	}
	if err := lintOf(m, own); err != nil {
		t.Fatalf("function attributes on their own lines: %v", err)
	}
	for _, sql := range []string{
		"CREATE FUNCTION f() RETURNS int\nSET search_path = pg_catalog, pg_temp\nLANGUAGE sql AS $$ SELECT 1 $$;",
		"CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql\nSET search_path TO pg_catalog, pg_temp\n AS $$ SELECT 1 $$;",
		"CREATE FUNCTION f() RETURNS int LANGUAGE sql\n  SET search_path FROM CURRENT\n  SET statement_timeout = 0\n AS $$ SELECT 1 $$;",
		"CREATE PROCEDURE p() LANGUAGE sql\nSET search_path = pg_catalog\nAS $$ SELECT 1 $$;",
		"ALTER FUNCTION f()\n  SET search_path = pg_catalog, pg_temp;",
	} {
		if err := lintOf(m, sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

// The SET clause of a data statement is not a session setting either.
func TestSetClausesOfDataStatementsAreAccepted(t *testing.T) {
	m := migration00029(t)
	for _, sql := range []string{
		"UPDATE t\n  SET a = 1\n WHERE b = 2;",
		"INSERT INTO t (a) VALUES (1)\nON CONFLICT (a) DO UPDATE\n  SET b = excluded.b;",
		"ALTER TABLE t\n  SET (fillfactor = 70);",
		"ALTER TABLE t\n  ALTER COLUMN c\n  SET DEFAULT 0;",
		"CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$\nBEGIN\n  UPDATE t\n    SET a = 1;\nEND\n$$;",
		"-- SET statement_timeout = 0 is only said here\nSELECT 'SET statement_timeout = 0' /* SET lock_timeout = 0 */;",
		"SELECT $q$\nSET statement_timeout = 0\n$q$ AS text;",
	} {
		if err := lintOf(m, sql); err != nil {
			t.Errorf("%q: %v", sql, err)
		}
	}
}

// A statement-level SET or RESET is refused: at the start of the file, on a line of its own, after another statement on the same line,
// inside a function body, in a DO block, and as a default of a role or database (ALTER ROLE ... SET reaches the runner's own session).
func TestStatementLevelSetStaysRejected(t *testing.T) {
	m := migration00029(t)
	shipped := string(m.SQL)
	bodyBegin := "BEGIN\n    well_formed := false;"
	if !strings.Contains(shipped, bodyBegin) {
		t.Fatal("00029 has no PL/pgSQL body to put a statement into")
	}
	cases := map[string]string{
		"first statement":             "SET statement_timeout = 0;\n" + shipped,
		"appended":                    shipped + "\nSET search_path = pg_catalog, pg_temp;\n",
		"SET LOCAL":                   shipped + "\nSET LOCAL lock_timeout = '1s';\n",
		"SET SESSION":                 shipped + "\nSET SESSION statement_timeout = 0;\n",
		"RESET":                       shipped + "\nRESET ALL;\n",
		"lower case":                  shipped + "\nset statement_timeout = 0;\n",
		"indented":                    shipped + "\n      \tSET statement_timeout = 0;\n",
		"same line as a statement":    shipped + "\nSELECT 1; SET statement_timeout = 0;\n",
		"function attribute then SET": "CREATE FUNCTION f() RETURNS int LANGUAGE sql\nSET search_path = pg_catalog\nAS $$ SELECT 1 $$;\nSET statement_timeout = 0;",
		"inside a function body":      strings.Replace(shipped, bodyBegin, "BEGIN\n  SET LOCAL statement_timeout = 0;\n    well_formed := false;", 1),
		"DO block":                    "DO $$ BEGIN SET LOCAL statement_timeout = 0; END $$;",
		"after THEN":                  "DO $$ BEGIN IF true THEN SET lock_timeout = 0; END IF; END $$;",
		"tagged dollar quote":         "DO $body$\nBEGIN\n  RESET statement_timeout;\nEND\n$body$;",
		"ALTER ROLE":                  "ALTER ROLE certen SET statement_timeout = 0;",
		"ALTER DATABASE":              "ALTER DATABASE certen_proofs\n  SET lock_timeout = 0;",
		"ALTER SYSTEM":                "ALTER SYSTEM SET statement_timeout = 0;",
		"ALTER ROLE RESET":            "ALTER ROLE certen RESET ALL;",
	}
	for name, sql := range cases {
		if err := lintOf(m, sql); err == nil || !strings.Contains(err.Error(), "changes session settings") {
			t.Errorf("%s: Lint() = %v, want the session-settings refusal", name, err)
		}
	}
	// the baseline is an immutable pg_dump and keeps its session SET commands
	if err := Lint(Migration{Version: "00000", Name: "00000_baseline.sql", SQL: []byte("SET statement_timeout = 0;\nSET lock_timeout = 0;")}); err != nil {
		t.Errorf("baseline: %v", err)
	}
}
