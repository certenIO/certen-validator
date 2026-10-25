// Copyright 2026 Certen Protocol

package schema

import "testing"

// RB12 OPS-A2 item 14: what Lint enforces about dynamic SQL, and what it does not (class 4 depends on this being written down).
// Enforced: an EXECUTE of a LITERAL SET, RESET or transaction-control text, and set_config of a runner-owned setting, at any depth.
// Not enforced: an EXECUTE of a text built at run time, set_config of a name built at run time, a custom (non-runner) setting.

func TestDynamicSessionSettingsAndTransactionControlAreRefused(t *testing.T) {
	m := Migration{Version: "00099", Name: "00099_dynamic.sql"}
	for name, sql := range map[string]string{
		"execute a literal SET":               "DO $$ BEGIN EXECUTE 'SET statement_timeout = 0'; END $$;",
		"execute a literal SET LOCAL":         "DO $$ BEGIN EXECUTE 'set local lock_timeout = 0'; END $$;",
		"execute a format of a SET":           "DO $$ BEGIN EXECUTE format('SET lock_timeout = %L', '5s'); END $$;",
		"execute a dollar-quoted RESET":       "DO $$ BEGIN EXECUTE $q$RESET ALL$q$; END $$;",
		"execute a COMMIT":                    "DO $$ BEGIN EXECUTE 'COMMIT'; END $$;",
		"execute a ROLLBACK":                  "DO $$ BEGIN EXECUTE 'ROLLBACK'; END $$;",
		"execute a START TRANSACTION":         "DO $$ BEGIN EXECUTE 'START TRANSACTION'; END $$;",
		"in a single-quoted function body":    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS 'BEGIN EXECUTE ''COMMIT''; END';",
		"in a dollar-quoted function body":    "CREATE FUNCTION f() RETURNS void LANGUAGE plpgsql AS $$ BEGIN EXECUTE 'SET role = x'; END $$;",
		"set_config of a timeout, session":    "SELECT set_config('statement_timeout', '0', false);",
		"set_config of a timeout, local":      "DO $$ BEGIN PERFORM set_config('Lock_Timeout', '0', true); END $$;",
		"set_config of the idle timeout":      "SELECT set_config('idle_in_transaction_session_timeout', '0', true);",
		"set_config of role":                  "SELECT set_config('role', 'postgres', true);",
		"set_config of session_authorization": "SELECT set_config('session_authorization', 'postgres', false);",
	} {
		if err := Lint(Migration{Version: m.Version, Name: m.Name, SQL: []byte(sql)}); err == nil {
			t.Errorf("%s: Lint accepted %q", name, sql)
		}
	}
}

// What is NOT judged, stated as a test so the limit is a decision and not an accident: a static scan cannot know the text of an EXECUTE
// built at run time, so those rest on the review of the migration.
func TestDynamicSqlTheLintCannotJudgeIsAcceptedAndSaidSo(t *testing.T) {
	m := Migration{Version: "00099", Name: "00099_dynamic.sql"}
	for name, sql := range map[string]string{
		"execute a plain DDL literal":                   "DO $$ BEGIN EXECUTE 'CREATE INDEX IF NOT EXISTS i ON t (a)'; END $$;",
		"execute a text built at run time (variable)":   "DO $$ DECLARE v text := 'x'; BEGIN EXECUTE v; END $$;",
		"execute a text built at run time (concat)":     "DO $$ BEGIN EXECUTE 'SE' || 'T statement_timeout = 0'; END $$;",
		"execute a format whose template is a variable": "DO $$ DECLARE t text := 'x'; BEGIN EXECUTE format(t, 1); END $$;",
		"set_config of a custom setting":                "SELECT set_config('certen.example', 'x', true);",
		"set_config of a name built at run time":        "DO $$ DECLARE n text := 'x'; BEGIN PERFORM set_config(n, '0', true); END $$;",
		"a data string that says SET":                   "INSERT INTO t (a) VALUES ('SET statement_timeout = 0');",
		"the function attribute SET stays accepted":     "CREATE FUNCTION f() RETURNS void LANGUAGE sql\n SET search_path = pg_catalog, pg_temp\n AS $$ SELECT 1 $$;",
	} {
		if err := Lint(Migration{Version: m.Version, Name: m.Name, SQL: []byte(sql)}); err != nil {
			t.Errorf("%s: Lint refused %q: %v", name, sql, err)
		}
	}
}
