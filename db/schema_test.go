package schema

import "testing"

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

func TestLintRejectsUnsafeMigrationControl(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		ok   bool
	}{
		{"transaction", "BEGIN;\nCREATE TABLE x();", false},
		{"destructive", "DROP TABLE x;", false},
		{"approved destructive", "-- schema: destructive-approved\nDROP TABLE x;", true},
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
