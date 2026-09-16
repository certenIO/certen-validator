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

//go:embed schema.fingerprint
var approvedFingerprint string

//go:embed baseline.fingerprint
var baselineFingerprint string

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

// LatestVersion is the minimum schema version required by this binary.
func LatestVersion() (string, error) {
	migrations, err := Migrations()
	if err != nil {
		return "", err
	}
	if len(migrations) == 0 {
		return "", fmt.Errorf("migration catalog is empty")
	}
	return migrations[len(migrations)-1].Version, nil
}

// ApprovedFingerprint is the reviewed catalog fingerprint after every migration known to this binary.
// It changes when a new migration changes the catalog and is used to prove fresh-install equivalence.
func ApprovedFingerprint() (string, error) {
	return parseFingerprint("approved", approvedFingerprint)
}

// BaselineFingerprint is the immutable production catalog captured for version 00000. Adoption must
// compare against this value rather than the current catalog, so future migrations remain deployable
// without making an already-existing production schema ineligible for adoption.
func BaselineFingerprint() (string, error) {
	return parseFingerprint("baseline", baselineFingerprint)
}

func parseFingerprint(name, source string) (string, error) {
	fingerprint := strings.TrimSpace(source)
	if len(fingerprint) != 64 {
		return "", fmt.Errorf("%s schema fingerprint must be a SHA-256 hex digest", name)
	}
	for _, c := range fingerprint {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return "", fmt.Errorf("approved schema fingerprint is not lowercase hexadecimal")
		}
	}
	return fingerprint, nil
}

// Lint rejects transaction control in SQL files. The runner owns transaction boundaries, which prevents
// the legacy nested-BEGIN/COMMIT failure mode. PL/pgSQL function bodies are intentionally not matched.
func Lint(m Migration) error {
	destructive, approved := false, false
	for _, line := range strings.Split(string(m.SQL), "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		switch upper {
		case "BEGIN;", "COMMIT;", "ROLLBACK;":
			return fmt.Errorf("%s contains runner-owned transaction control", m.Name)
		}
		// The production-derived baseline is intentionally an immutable pg_dump and contains
		// pg_dump's session SET commands. New migrations must never alter runner timeouts.
		if m.Version != "00000" && (strings.HasPrefix(upper, "SET ") || strings.HasPrefix(upper, "RESET ")) {
			return fmt.Errorf("%s changes session settings; configure timeouts in the runner instead", m.Name)
		}
		if strings.HasPrefix(upper, "DROP ") || strings.HasPrefix(upper, "ALTER TABLE ") && (strings.Contains(upper, " DROP ") || strings.Contains(upper, " RENAME ") || strings.Contains(upper, " SET NOT NULL")) {
			destructive = true
		}
		if strings.Contains(trimmed, "schema: destructive-approved") {
			approved = true
		}
	}
	if destructive && !approved {
		return fmt.Errorf("%s contains destructive DDL without -- schema: destructive-approved", m.Name)
	}
	return nil
}
