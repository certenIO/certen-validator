// Copyright 2026 Certen Protocol

package finality

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Activation freeze (RB11-B-MERGE): the finality framework may sit in the validator binary and in main.go, but it must not be
// reachable from anything that decides a hashed input, an ABCI verdict, a stored-proof verdict or govRoot. These tests pin
// that structurally, so a later edit that wires the framework into one of those surfaces fails here by name.

const modulePath = "github.com/certen/independant-validator"

// The consensus-reachable and hashed surfaces named by the freeze.
var frozenDirs = []string{
	"pkg/consensus", "pkg/proof", "pkg/attestation", "pkg/commitment", "pkg/intentcert", "pkg/proofv2shadow",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the repository root is not two levels above the package: %v", err)
	}
	return root
}

// No file under a frozen surface imports pkg/finality or names the addendum repository: nothing there can call the framework.
func TestNoFrozenSurfaceReachesTheFinalityFramework(t *testing.T) {
	root := repoRoot(t)
	files := 0
	for _, dir := range frozenDirs {
		abs := filepath.Join(root, filepath.FromSlash(dir))
		if st, err := os.Stat(abs); err != nil || !st.IsDir() {
			t.Fatalf("frozen surface %s is not a directory here (%v): a rename would silently weaken this guard", dir, err)
		}
		err := filepath.WalkDir(abs, func(path string, d os.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			files++
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				t.Errorf("parse %s: %v", path, perr)
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if p == modulePath+"/pkg/finality" || strings.HasPrefix(p, modulePath+"/pkg/finality/") {
					t.Errorf("%s imports %s: a frozen surface must not reach the finality framework", filepath.ToSlash(rel), p)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && strings.Contains(id.Name, "FinalityAddenda") {
					t.Errorf("%s names %s: a frozen surface must not reach the addendum repository", filepath.ToSlash(rel), id.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 50 {
		t.Fatalf("only %d Go files were scanned under the frozen surfaces: the walk is not seeing the tree", files)
	}
}

// A SQL statement that writes: the literal starts with the verb (comments and error texts never do).
var sqlWrite = regexp.MustCompile(`(?is)^\s*(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM|TRUNCATE(?:\s+TABLE)?)\s+(?:ONLY\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?`)

// The addendum repository writes one table, the new one. Every other table it touches it only reads.
func TestAddendumRepositoryWritesOnlyItsOwnTable(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "pkg", "database", "finality_addenda.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	writes := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil {
				if m := sqlWrite.FindStringSubmatch(v); m != nil {
					writes[strings.ToLower(m[1])] = true
				}
			}
		}
		return true
	})
	for w := range writes {
		if w != "proof_finality_addenda" {
			t.Errorf("pkg/database/finality_addenda.go writes %q: the finality repository may write only proof_finality_addenda", w)
		}
	}
	if !writes["proof_finality_addenda"] {
		t.Fatal("the repository's INSERT into proof_finality_addenda was not found: the scan is not seeing the SQL")
	}

	mig, err := os.ReadFile(filepath.Join(root, "db", "migrations", "00027_proof_finality_addenda.sql"))
	if err != nil {
		t.Fatal(err)
	}
	ddl := regexp.MustCompile(`(?i)\b(CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE|CREATE\s+(?:UNIQUE\s+)?INDEX\s+\S+\s+ON|CREATE\s+TRIGGER\s+\S+[\s\S]*?\bON)\s+(?:ONLY\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?`)
	seen := 0
	for _, m := range ddl.FindAllStringSubmatch(string(mig), -1) {
		seen++
		if !strings.EqualFold(m[2], "proof_finality_addenda") {
			t.Errorf("migration 00027 changes %q: it may create and guard only proof_finality_addenda", m[2])
		}
	}
	if seen < 3 {
		t.Fatalf("only %d DDL statements recognised in migration 00027: the scan is not seeing the SQL", seen)
	}
}

// main.go wires the upgrader in exactly one place and hands it nothing but the addendum repository, the switch and the
// framework's own registry and pins: it is never given an attestor, a validator, a consensus object or a hook, and nothing else
// in main.go names the framework.
func TestMainWiresTheUpgraderAloneAndGivesItNoConsensusObject(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "main.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"Enabled": true, "Launch": true, "Default": true, "EmbeddedPins": true, "UpgraderConfig": true}
	var launches []*ast.CallExpr
	var repoCtors int
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name {
			case "finality":
				if fn.Name.Name != "startValidator" {
					t.Errorf("main.go: finality.%s is used in %s; the upgrader is wired in startValidator only", sel.Sel.Name, fn.Name.Name)
				}
				if !allowed[sel.Sel.Name] {
					t.Errorf("main.go: finality.%s is not one of the upgrader wiring symbols", sel.Sel.Name)
				}
			case "database":
				if strings.Contains(sel.Sel.Name, "FinalityAddenda") {
					repoCtors++
				}
			}
			return true
		})
		ast.Inspect(fn, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if p, ok := sel.X.(*ast.Ident); ok && p.Name == "finality" && sel.Sel.Name == "Launch" {
						launches = append(launches, call)
					}
				}
			}
			return true
		})
	}
	if len(launches) != 1 || repoCtors != 1 {
		t.Fatalf("main.go has %d finality.Launch calls and %d addendum repository constructors; want exactly one of each", len(launches), repoCtors)
	}
	for i, arg := range launches[0].Args {
		switch a := arg.(type) {
		case *ast.Ident:
			if a.Name != "finalityOn" && a.Name != "finalityRepo" && a.Name != "finalityPins" {
				t.Errorf("main.go: finality.Launch argument %d is %q; only the switch and the addendum repository may be passed", i, a.Name)
			}
		case *ast.CallExpr, *ast.SelectorExpr, *ast.CompositeLit:
			ast.Inspect(a, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					switch id.Name {
					case "attestor", "validator", "bftValidator", "consensus", "shadow", "executor", "bridge":
						t.Errorf("main.go: finality.Launch argument %d mentions %q, a consensus-side object", i, id.Name)
					}
				}
				return true
			})
		default:
			t.Errorf("main.go: finality.Launch argument %d has unexpected form %T", i, arg)
		}
	}
}
