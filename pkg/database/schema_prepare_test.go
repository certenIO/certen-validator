package database

import (
	"context"
	"database/sql"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	schema "github.com/certen/independant-validator/db"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// TestStaticRepositorySQLPreparesAgainstSharedSchema is the schema/code compatibility gate for every
// repository statement represented as a complete static SQL literal. Dynamic builders have dedicated
// executable tests because a string fragment cannot be prepared safely in isolation. A missing relation
// or column therefore fails CI before it can reach a production request path.
func TestStaticRepositorySQLPreparesAgainstSharedSchema(t *testing.T) {
	statements, err := repositorySQLStatements(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(statements) == 0 {
		t.Fatal("no repository SQL statements discovered")
	}
	packages := map[string]int{}
	for _, statement := range statements {
		packages[filepath.Dir(statement.Source)]++
	}
	t.Logf("preparing %d distinct statements from %v", len(statements), packages)

	ctx := context.Background()
	prepareDB := freshPreparedSchema(t, ctx)
	for _, statement := range statements {
		prepared, err := prepareDB.PrepareContext(ctx, statement.SQL)
		if err != nil {
			t.Errorf("prepare %s: %v\n%s", statement.Source, err, statement.SQL)
			continue
		}
		if err := prepared.Close(); err != nil {
			t.Errorf("close prepared statement %s: %v", statement.Source, err)
		}
	}
}

// TestDynamicRepositoryQueriesExecuteAgainstSharedSchema covers every query builder that cannot be
// checked as an isolated literal. Representative filters enable each optional branch, so a renamed
// column, malformed placeholder sequence, or status-specific lifecycle update fails in CI.
func TestDynamicRepositoryQueriesExecuteAgainstSharedSchema(t *testing.T) {
	ctx := context.Background()
	db := freshPreparedSchema(t, ctx)
	repo := NewProofArtifactRepository(db)

	accumTxHash, accountURL, anchorTxHash := "dynamic-tx", "acc://dynamic.acme", "anchor-tx"
	batchID := uuid.New()
	proofType := ProofTypeCertenAnchor
	govLevel := GovLevelG1
	proofClass := ProofClassOnDemand
	status := ProofStatusPending
	validatorID, anchorChain := "validator-dynamic", "ethereum"
	now := time.Now().UTC()
	filter := &ProofArtifactFilter{
		AccumTxHash:      &accumTxHash,
		AccountURL:       &accountURL,
		BatchID:          &batchID,
		AnchorTxHash:     &anchorTxHash,
		ProofType:        &proofType,
		GovLevel:         &govLevel,
		ProofClass:       &proofClass,
		Status:           &status,
		ValidatorID:      &validatorID,
		AnchorChain:      &anchorChain,
		CreatedAfter:     &now,
		CreatedBefore:    &now,
		Limit:            1,
		AccountURLs:      []string{accountURL, "acc://dynamic-2.acme"},
		Statuses:         []string{string(status), "anchored"},
		GovernanceLevels: []string{string(govLevel), "G2"},
		GovernanceLevel:  ptr(string(govLevel)),
	}
	if _, err := repo.QueryProofs(ctx, filter); err != nil {
		t.Fatalf("QueryProofs dynamic query: %v", err)
	}
	if _, err := repo.GetProofsForBulkExport(ctx, filter.AccountURLs, now.Add(-time.Hour), now.Add(time.Hour), 1); err != nil {
		t.Fatalf("GetProofsForBulkExport dynamic query: %v", err)
	}
	if _, err := repo.CountProofs(ctx, filter); err != nil {
		t.Fatalf("CountProofs dynamic query: %v", err)
	}
	if _, err := repo.QueryProofsForExport(ctx, filter); err != nil {
		t.Fatalf("QueryProofsForExport dynamic query: %v", err)
	}

	lifecycle := &IntentLifecycleRepository{client: &Client{db: db}}
	if err := lifecycle.UpsertOnDiscovery(ctx, "dynamic-intent", "dynamic-lifecycle-tx", 1, "", "", ""); err != nil {
		t.Fatalf("create lifecycle fixture: %v", err)
	}
	if err := lifecycle.UpdateStatus(ctx, "dynamic-intent", IntentLifecyclePendingSignatures); err != nil {
		t.Fatalf("UpdateStatus without timestamp column: %v", err)
	}
	if err := lifecycle.UpdateStatus(ctx, "dynamic-intent", IntentLifecycleSettling); err != nil {
		t.Fatalf("UpdateStatus with timestamp column: %v", err)
	}
	if _, err := lifecycle.ListRecentEnriched(ctx, 1); err != nil {
		t.Fatalf("ListRecentEnriched wrapped query: %v", err)
	}
	if _, err := lifecycle.ListByUserEnriched(ctx, "dynamic-user", 1); err != nil {
		t.Fatalf("ListByUserEnriched wrapped query: %v", err)
	}
	validOnly := true
	if _, err := repo.CountAttestations(ctx, &validOnly); err != nil {
		t.Fatalf("CountAttestations with the valid-only clause: %v", err)
	}
}

func ptr[T any](value T) *T { return &value }

// freshPreparedSchema keeps the prepare gate independent of mutable repository test fixtures. It uses
// the same shared runner as production, but in a unique database which is dropped after the test.
func freshPreparedSchema(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Fatal("CERTEN_TEST_DB is required for repository SQL preparation")
	}
	u, err := url.Parse(conn)
	if err != nil {
		t.Fatalf("parse CERTEN_TEST_DB: %v", err)
	}
	dbName := fmt.Sprintf("certen_prepare_%d", time.Now().UnixNano())
	adminURL := *u
	adminURL.Path = "/postgres"
	adminURL.RawPath = ""
	admin, err := sql.Open("postgres", adminURL.String())
	if err != nil {
		t.Fatalf("open postgres admin database: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pq.QuoteIdentifier(dbName)); err != nil {
		admin.Close()
		t.Fatalf("create prepare database: %v", err)
	}
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "DROP DATABASE "+pq.QuoteIdentifier(dbName))
		admin.Close()
	})

	testURL := *u
	testURL.Path = "/" + dbName
	testURL.RawPath = ""
	db, err := sql.Open("postgres", testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := (schema.Runner{DB: db}).Up(ctx, "schema-prepare-test"); err != nil {
		t.Fatalf("migrate prepare database: %v", err)
	}
	return db
}

type repositorySQL struct {
	Source string
	SQL    string
}

// repositorySQLStatements collects every complete SQL statement in the module's non-test Go files, not
// just this package's: a statement added anywhere else would otherwise reach production unchecked.
//
// A statement is a string literal, or a concatenation of string literals and package-level string
// constants (a shared column list, say), folded into the text the database receives. A concatenation
// with a runtime operand cannot be folded; its literal fragments are still checked on their own, and the
// statement as a whole is covered by the repository's integration tests.
func repositorySQLStatements(root string) ([]repositorySQL, error) {
	seen := make(map[string]repositorySQL)
	fileSet := token.NewFileSet()
	packages := map[string][]*ast.File{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() {
			if path == root {
				return nil
			}
			// A nested go.mod is another module with its own storage (the lite client's SQLite schema).
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		packages[filepath.Dir(path)] = append(packages[filepath.Dir(path)], file)
		return nil
	})
	if err != nil {
		return nil, err
	}

	record := func(value string, pos token.Pos) {
		value = normalizeRepositorySQLTemplate(value)
		if _, exists := seen[value]; exists {
			return
		}
		position := fileSet.Position(pos)
		source, _ := filepath.Rel(root, position.Filename)
		seen[value] = repositorySQL{Source: fmt.Sprintf("%s:%d", filepath.ToSlash(source), position.Line), SQL: value}
	}
	for _, files := range packages {
		constants := stringConstants(files)
		for _, file := range files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.BinaryExpr:
					if n.Op != token.ADD {
						return true
					}
					folded, ok := foldString(n, constants)
					if !ok {
						return true
					}
					if looksLikeRepositorySQL(folded) {
						record(folded, n.Pos())
					}
					return false
				case *ast.BasicLit:
					if n.Kind != token.STRING {
						return true
					}
					if value, err := strconv.Unquote(n.Value); err == nil && looksLikeRepositorySQL(value) {
						record(value, n.Pos())
					}
				}
				return true
			})
		}
	}

	result := make([]repositorySQL, 0, len(seen))
	for _, statement := range seen {
		result = append(result, statement)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Source < result[j].Source })
	return result, nil
}

// stringConstants returns the package-level string constants of one package, folding constants defined
// in terms of other constants.
func stringConstants(files []*ast.File) map[string]string {
	pending := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				for i, name := range value.Names {
					if i < len(value.Values) {
						pending[name.Name] = value.Values[i]
					}
				}
			}
		}
	}
	constants := map[string]string{}
	for progress := true; progress; {
		progress = false
		for name, expr := range pending {
			if folded, ok := foldString(expr, constants); ok {
				constants[name] = folded
				delete(pending, name)
				progress = true
			}
		}
	}
	return constants
}

// foldString evaluates a concatenation of string literals and known string constants.
func foldString(expr ast.Expr, constants map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(e.Value)
		return value, err == nil
	case *ast.Ident:
		value, ok := constants[e.Name]
		return value, ok
	case *ast.ParenExpr:
		return foldString(e.X, constants)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, ok := foldString(e.X, constants)
		if !ok {
			return "", false
		}
		right, ok := foldString(e.Y, constants)
		return left + right, ok
	}
	return "", false
}

func looksLikeRepositorySQL(value string) bool {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "%") {
		return false
	}
	for _, prefix := range []string{"SELECT ", "INSERT ", "UPDATE ", "DELETE ", "WITH "} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func normalizeRepositorySQLTemplate(value string) string { return value }
