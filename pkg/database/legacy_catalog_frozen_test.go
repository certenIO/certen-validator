// Copyright 2025 Certen Protocol
//
// The legacy migration directory is frozen. This test is the guard.

package database

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pkg/database/migrations is FROZEN at 020. Nothing applies it.
//
// The application binary no longer embeds these files: main.go migrates through db.Runner over
// db/migrations, and Client has no MigrateUp. The files remain only because the migration 019 and 020
// tests replay them to prove *why* specific layer-5 rows were withdrawn — regression evidence, not a
// deployment path.
//
// That distinction is invisible from inside the directory, and getting it wrong is expensive. On
// 2026-09-18 a migration was written here, reviewed, merged and deployed, and did nothing at all; the
// only reason anyone noticed was that a constraint was checked by hand. The fleet then crash-looped when
// the real migration finally landed, because its catalog had moved ahead of the database.
//
// So: a new file here is almost certainly a mistake, and this test says so at the moment it is added
// rather than after a silent deploy.
const lastFrozenLegacyVersion = "020"

func TestLegacyMigrationCatalogIsFrozen(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		// The directory may be deleted outright once the 019/020 regression tests are ported. That is a
		// valid end state, not a failure.
		if os.IsNotExist(err) {
			t.Skip("legacy migration directory has been removed entirely")
		}
		t.Fatalf("read legacy migration directory: %v", err)
	}

	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, _, ok := strings.Cut(name, "_")
		if !ok {
			offenders = append(offenders, fmt.Sprintf("%s (no version prefix)", name))
			continue
		}
		if version > lastFrozenLegacyVersion {
			offenders = append(offenders, name)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf(`pkg/database/migrations is frozen at %s, but these files are newer: %v

Nothing applies this directory. A migration placed here is never run: the binary migrates through
db.Runner over db/migrations, and refuses to start when its catalog is ahead of the database.

Put the change in db/migrations/000NN_name.sql instead, then:
  - no BEGIN/COMMIT (the runner owns the transaction) and no session SET/RESET
  - "-- schema: destructive-approved" on any DROP, or ALTER TABLE ... DROP / RENAME / SET NOT NULL
  - regenerate db/schema.fingerprint from the fresh-install gate; leave db/baseline.fingerprint alone
  - deploy the schema BEFORE the binary (cmd/schemamigrate, or MIGRATE_ON_START=true)

See docs/runbooks/schema-and-evidence-hardening.md.`, lastFrozenLegacyVersion, offenders)
	}
}

// The other half of the guard: nothing in the application may read this directory back into a deployment
// path. The 019/020 tests read it from disk, which is fine — a test file cannot migrate production.
func TestLegacyMigrationsAreNotEmbeddedInTheBinary(t *testing.T) {
	root := ".."
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(body)
		if strings.Contains(text, "embed migrations/*") || strings.Contains(text, "embed migrations/") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning for embeds: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("non-test files embed the legacy migration directory, which would resurrect a second "+
			"deployment path: %v", offenders)
	}
}
