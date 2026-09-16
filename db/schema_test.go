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
