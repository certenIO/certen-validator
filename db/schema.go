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

// Lint rejects transaction control and statement-level session settings in SQL files. The runner owns transaction boundaries, which
// prevents the legacy nested-BEGIN/COMMIT failure mode, and owns the session settings (the timeouts). A function ATTRIBUTE
// (CREATE FUNCTION ... SET search_path = pg_catalog, pg_temp, which migrations must write to pin name resolution) and the SET clause of an
// UPDATE are not session settings and are accepted wherever they are written; a SET or RESET that begins a statement is not.
//
// Dynamic SQL (RB12 OPS-A2 item 14). ENFORCED: an EXECUTE whose text is a literal (single-quoted, dollar-quoted, or the first argument of
// format) that begins with SET, RESET, BEGIN, COMMIT, END, ABORT, ROLLBACK or START, and a set_config call that names a runner-owned setting
// (the timeouts, role, session_authorization), wherever they stand, function and DO bodies included. NOT ENFORCED, because a static scan cannot
// judge it: an EXECUTE of a text built at run time (a variable, a concatenation, a format template that is not a literal), a set_config of a
// setting whose name is built at run time, and anything a function does when it is CALLED rather than when the migration runs. Those rest on
// review of the migration. See schema_lint_dynamic_rb12_test.go.
func Lint(m Migration) error {
	approved := false
	if m.Version != "00000" && hasSessionSetting(string(m.SQL)) {
		return fmt.Errorf("%s changes session settings; configure timeouts in the runner instead", m.Name)
	}
	if m.Version != "00000" && hasDynamicSessionSetting(string(m.SQL)) {
		return fmt.Errorf("%s changes session settings or controls the transaction through dynamic SQL (EXECUTE of a SET, RESET or transaction-control string, or set_config of a runner-owned setting); configure timeouts in the runner instead", m.Name)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(m.SQL), "\n") {
		trimmed := strings.TrimSpace(line)
		upper := strings.ToUpper(trimmed)
		switch upper {
		case "BEGIN;", "COMMIT;", "ROLLBACK;":
			return fmt.Errorf("%s contains runner-owned transaction control", m.Name)
		}
		// The production-derived baseline is intentionally an immutable pg_dump and contains
		// pg_dump's session SET commands. New migrations must never alter runner timeouts (hasSessionSetting, above).
		if strings.Contains(trimmed, "schema: destructive-approved") {
			approved = true
		}
		if comment := strings.Index(upper, "--"); comment >= 0 {
			upper = upper[:comment]
		}
		code.WriteString(upper)
		code.WriteString(" ")
	}
	// Destructive DDL is judged per statement, not per line: "ALTER TABLE t" on one line and
	// "ALTER COLUMN c SET NOT NULL" on the next is the same statement.
	for _, statement := range strings.Split(code.String(), ";") {
		if isDestructive(strings.Join(strings.Fields(statement), " ")) && !approved {
			return fmt.Errorf("%s contains destructive DDL without -- schema: destructive-approved", m.Name)
		}
	}
	return nil
}

func isDestructive(statement string) bool {
	if strings.HasPrefix(statement, "DROP ") || strings.HasPrefix(statement, "TRUNCATE ") {
		return true
	}
	if !strings.HasPrefix(statement, "ALTER TABLE ") && !strings.HasPrefix(statement, "ALTER TYPE ") {
		return false
	}
	padded := statement + " "
	for _, clause := range []string{" DROP ", " RENAME ", " SET NOT NULL ", " TYPE "} {
		if strings.Contains(padded, clause) {
			return true
		}
	}
	return false
}

// sqlToken is one lexical unit of a migration: a word (upper-cased), a semicolon, or the text between a pair of dollar quotes or single quotes
// (which hasSessionSetting judges as SQL of its own where it is the body of a routine). Comments and quoted identifiers are dropped.
type sqlToken struct {
	word     string // upper-cased word, ";" or ""
	body     string // the text inside $tag$ ... $tag$, or inside '...'
	isBody   bool
	isString bool // the body is a single-quoted string
}

func lexSQL(sql string) []sqlToken {
	var out []sqlToken
	i := 0
	for i < len(sql) {
		c := sql[i]
		switch {
		case c == '-' && strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' && sql[i] != '\r' { // PostgreSQL ends a -- comment at a bare carriage return too
				i++
			}
		case c == '/' && strings.HasPrefix(sql[i:], "/*"):
			depth := 0 // PostgreSQL block comments nest
			for i < len(sql) {
				if strings.HasPrefix(sql[i:], "/*") {
					depth++
					i += 2
				} else if strings.HasPrefix(sql[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
				} else {
					i++
				}
			}
		case c == '\'':
			escapes := i > 0 && (sql[i-1] == 'e' || sql[i-1] == 'E') && (i == 1 || !isWordByte(sql[i-2]))
			i++
			var text strings.Builder // the content, a doubled quote read as one: a function body may be written as a string
			for i < len(sql) {
				if escapes && sql[i] == '\\' && i+1 < len(sql) {
					text.WriteString(sql[i : i+2])
					i += 2
					continue
				}
				if sql[i] == '\'' {
					if i+1 < len(sql) && sql[i+1] == '\'' {
						text.WriteByte('\'')
						i += 2
						continue
					}
					i++
					break
				}
				text.WriteByte(sql[i])
				i++
			}
			out = append(out, sqlToken{isBody: true, isString: true, body: text.String()})
		case c == '"':
			i++
			for i < len(sql) {
				if sql[i] == '"' {
					if i+1 < len(sql) && sql[i+1] == '"' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case c == '$':
			if i > 0 && isWordByte(sql[i-1]) { // PostgreSQL reads a $ after an identifier character as part of the identifier (foo$bar$)
				i++
				continue
			}
			if end := dollarTagEnd(sql, i); end > 0 {
				tag := sql[i:end]
				close := strings.Index(sql[end:], tag)
				if close < 0 { // unterminated: PostgreSQL refuses it, the rest is judged as the body
					out = append(out, sqlToken{isBody: true, body: sql[end:]})
					return out
				}
				out = append(out, sqlToken{isBody: true, body: sql[end : end+close]})
				i = end + close + len(tag)
				continue
			}
			i++
		case c == ';':
			out = append(out, sqlToken{word: ";"})
			i++
		case isWordByte(c):
			j := i
			for j < len(sql) && isWordByte(sql[j]) {
				j++
			}
			out = append(out, sqlToken{word: strings.ToUpper(sql[i:j])})
			i = j
		default:
			i++
		}
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// dollarTagEnd is the index just past the opening dollar quote ($$ or $tag$) that starts at sql[i], or 0 when sql[i] is not one.
func dollarTagEnd(sql string, i int) int {
	j := i + 1
	for j < len(sql) && (sql[j] == '_' || sql[j] >= 'a' && sql[j] <= 'z' || sql[j] >= 'A' && sql[j] <= 'Z' || j > i+1 && sql[j] >= '0' && sql[j] <= '9' || sql[j] >= 0x80) {
		j++
	}
	if j < len(sql) && sql[j] == '$' {
		return j + 1
	}
	return 0
}

// runnerSettings are the settings the runner owns: a migration must not change them, by SET or by set_config.
var runnerSettings = map[string]bool{
	"STATEMENT_TIMEOUT": true, "LOCK_TIMEOUT": true, "IDLE_IN_TRANSACTION_SESSION_TIMEOUT": true, "TRANSACTION_TIMEOUT": true,
	"ROLE": true, "SESSION_AUTHORIZATION": true,
}

// startsSessionStatement reports whether a text handed to EXECUTE begins with a statement the runner owns.
func startsSessionStatement(text string) bool {
	f := strings.Fields(strings.ToUpper(text))
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "SET", "RESET", "BEGIN", "COMMIT", "END", "ABORT", "ROLLBACK", "START":
		return true
	}
	return false
}

// hasDynamicSessionSetting reports whether sql holds an EXECUTE of a literal SET, RESET or transaction-control string, or a set_config of a
// runner-owned setting, at any depth: every quoted body is read as SQL of its own, so a function, a DO block, or an EXECUTE text written as
// $$...$$ is judged too. A text built at run time is not judged (see Lint).
func hasDynamicSessionSetting(sql string) bool {
	toks := lexSQL(sql)
	for i, tok := range toks {
		if tok.isBody {
			if hasDynamicSessionSetting(tok.body) {
				return true
			}
			continue
		}
		switch tok.word {
		case "EXECUTE":
			j := i + 1
			if j < len(toks) && toks[j].word == "FORMAT" {
				j++
			}
			if j < len(toks) && toks[j].isBody && startsSessionStatement(toks[j].body) {
				return true
			}
		case "SET_CONFIG":
			if i+1 < len(toks) && toks[i+1].isBody && toks[i+1].isString && runnerSettings[strings.ToUpper(strings.TrimSpace(toks[i+1].body))] {
				return true
			}
		}
	}
	return false
}

// hasSessionSetting reports whether sql holds a statement that changes a session or role setting: a statement that BEGINS with SET or
// RESET (SET LOCAL and SET SESSION included), or an ALTER ROLE / USER / DATABASE / SYSTEM that carries one. A statement begins at the start
// of the text, after a semicolon, and, inside a function body, after BEGIN, THEN, ELSE or LOOP. The SET that follows other words of a
// statement is a clause of it (UPDATE ... SET, ON CONFLICT DO UPDATE SET, ALTER TABLE ... SET, the SET attribute of CREATE FUNCTION) and
// is not judged. The body of CREATE FUNCTION and CREATE PROCEDURE (the dollar-quoted text, or the single-quoted string after AS) and of DO
// is judged as SQL of its own; any other quoted text is a string.
func hasSessionSetting(sql string) bool {
	atStart := true
	var first, second, head, prev string
	alter, routine := false, false
	for _, tok := range lexSQL(sql) {
		if tok.isBody {
			if routine && (!tok.isString || head == "DO" || prev == "AS") && hasSessionSetting(tok.body) {
				return true
			}
			atStart, prev = false, ""
			continue
		}
		prev = tok.word
		switch tok.word {
		case ";":
			atStart, first, second, head, alter, routine = true, "", "", "", false, false
			continue
		case "SET", "RESET":
			if atStart || alter {
				return true
			}
		}
		if head == "" {
			head = tok.word
		}
		routine = routine || head == "DO" || head == "CREATE" && (tok.word == "FUNCTION" || tok.word == "PROCEDURE")
		switch {
		case first == "":
			first = tok.word
		case second == "":
			second = tok.word
			alter = first == "ALTER" && (second == "ROLE" || second == "USER" || second == "DATABASE" || second == "SYSTEM")
		}
		atStart = tok.word == "BEGIN" || tok.word == "THEN" || tok.word == "ELSE" || tok.word == "LOOP"
		if atStart {
			first, second, alter = "", "", false
		}
	}
	return false
}
