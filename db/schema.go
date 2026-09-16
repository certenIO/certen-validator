// Package schema owns Certen's shared PostgreSQL schema catalog.
package schema

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/*.sql
var files embed.FS

// Migration is an immutable, ordered schema change.
type Migration struct {
	Version string
	Name    string
	SQL     []byte
	SHA256  [sha256.Size]byte
}

// Migrations returns the complete catalog in strict numeric order. The baseline is version 00000.
func Migrations() ([]Migration, error) {
	entries, err := fs.ReadDir(files, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migration catalog: %w", err)
	}
	result := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		version, _, ok := strings.Cut(strings.TrimSuffix(name, ".sql"), "_")
		if !ok || len(version) != 5 {
			return nil, fmt.Errorf("migration %q must begin with a five-digit version", name)
		}
		sql, err := files.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", name, err)
		}
		result = append(result, Migration{Version: version, Name: name, SQL: sql, SHA256: sha256.Sum256(sql)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	for i := range result {
		if i > 0 && result[i-1].Version == result[i].Version {
			return nil, fmt.Errorf("duplicate migration version %s", result[i].Version)
		}
	}
	return result, nil
}

// Lint rejects transaction control in SQL files. The runner owns transaction boundaries, which prevents
// the legacy nested-BEGIN/COMMIT failure mode. PL/pgSQL function bodies are intentionally not matched.
func Lint(m Migration) error {
	for _, line := range strings.Split(string(m.SQL), "\n") {
		switch strings.ToUpper(strings.TrimSpace(line)) {
		case "BEGIN;", "COMMIT;", "ROLLBACK;":
			return fmt.Errorf("%s contains runner-owned transaction control", m.Name)
		}
	}
	return nil
}
