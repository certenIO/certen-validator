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

// The upgrader is wired in exactly one place - startFinality in finality_start.go, which main.go's startValidator calls exactly once
// with nothing but a context, the database client and the logger - and it is handed nothing but the addendum repository, the switch
// and the framework's own registry and pins: it is never given an attestor, a validator, a consensus object or a hook, and nothing
// else in main.go names the framework (main.go does not even import it).
func TestMainWiresTheUpgraderAloneAndGivesItNoConsensusObject(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()

	// main.go: no use of the framework or its runtime wiring at all; exactly one call of startFinality, inside startValidator, whose
	// arguments name no consensus-side object
	mainFile, err := parser.ParseFile(fset, filepath.Join(root, "main.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	startCalls := 0
	for _, decl := range mainFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := x.X.(*ast.Ident); ok && (pkg.Name == "finality" || pkg.Name == "finruntime") {
					t.Errorf("main.go: %s.%s is used in %s; main.go must not name the finality framework (the wiring is startFinality)", pkg.Name, x.Sel.Name, fn.Name.Name)
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "startFinality" {
					startCalls++
					if fn.Name.Name != "startValidator" {
						t.Errorf("main.go: startFinality is called in %s; the upgrader is started from startValidator only", fn.Name.Name)
					}
					for i, arg := range x.Args {
						ast.Inspect(arg, func(m ast.Node) bool {
							if id, ok := m.(*ast.Ident); ok {
								switch id.Name {
								case "attestor", "validator", "bftValidator", "consensus", "shadow", "executor", "bridge", "accClient", "cfg":
									t.Errorf("main.go: startFinality argument %d mentions %q, a consensus-side object", i, id.Name)
								}
							}
							return true
						})
					}
				}
			}
			return true
		})
	}
	if startCalls != 1 {
		t.Fatalf("main.go calls startFinality %d times; want exactly one", startCalls)
	}

	f, err := parser.ParseFile(fset, filepath.Join(root, "finality_start.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	// RB12-DBFIX-FIX: AnnounceUpgraderDisabled and ConfigInvalidState announce a refused provider entry as the named state
	allowed := map[string]bool{"Enabled": true, "Launch": true, "Default": true, "EmbeddedPins": true, "UpgraderConfig": true, "AnnounceUpgraderDisabled": true, "ConfigInvalidState": true}
	// RB11-B2B2b: the production wiring (pkg/finality/runtime, imported as finruntime) is reached through exactly these symbols:
	// the configuration read, the wiring call and its collaborator struct. Everything else it builds stays inside that package.
	// RB12-GO-INT F14: no failure of the start ends the validator. The runtime classifies a failure into the named state
	// (StartFailure, StartPanic) and marks the two failures that are raised in startFinality itself (GenesisLinkFailed, LaunchFailed); they
	// are classifiers, they hand the upgrader nothing.
	runtimeAllowed := map[string]bool{"ConfigFromEnv": true, "Wire": true, "Deps": true, "ConfigError": true, "CheckProviderEnvironment": true,
		"StartFailure": true, "StartPanic": true, "GenesisLinkFailed": true, "LaunchFailed": true}
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
				if fn.Name.Name != "startFinality" {
					t.Errorf("finality_start.go: finality.%s is used in %s; the upgrader is wired in startFinality only", sel.Sel.Name, fn.Name.Name)
				}
				if !allowed[sel.Sel.Name] {
					t.Errorf("finality_start.go: finality.%s is not one of the upgrader wiring symbols", sel.Sel.Name)
				}
			case "finruntime":
				if fn.Name.Name != "startFinality" {
					t.Errorf("finality_start.go: finruntime.%s is used in %s; the finality wiring is built in startFinality only", sel.Sel.Name, fn.Name.Name)
				}
				if !runtimeAllowed[sel.Sel.Name] {
					t.Errorf("finality_start.go: finruntime.%s is not one of the finality runtime wiring symbols", sel.Sel.Name)
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
				// RB12-GO-INT F14: the one launch is made through launchFinality, a package variable initialised with finality.Launch (checked
				// below) so a test can make the launch fail; it is the same call with the same arguments, still exactly one.
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "launchFinality" {
					launches = append(launches, call)
				}
			}
			return true
		})
	}
	seamIsLaunch := false
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "launchFinality" || len(vs.Values) != 1 {
				continue
			}
			if sel, ok := vs.Values[0].(*ast.SelectorExpr); ok {
				if p, ok := sel.X.(*ast.Ident); ok && p.Name == "finality" && sel.Sel.Name == "Launch" {
					seamIsLaunch = true
				}
			}
		}
	}
	for _, l := range launches {
		if id, ok := l.Fun.(*ast.Ident); ok && id.Name == "launchFinality" && !seamIsLaunch {
			t.Errorf("finality_start.go: launchFinality must be initialised with finality.Launch and nothing else")
		}
	}
	if len(launches) != 1 || repoCtors != 1 {
		t.Fatalf("finality_start.go has %d finality.Launch calls and %d addendum repository constructors; want exactly one of each", len(launches), repoCtors)
	}
	for i, arg := range launches[0].Args {
		switch a := arg.(type) {
		case *ast.Ident:
			if a.Name != "ctx" && a.Name != "on" && a.Name != "repo" {
				t.Errorf("finality_start.go: finality.Launch argument %d is %q; only the context, the switch and the addendum repository may be passed", i, a.Name)
			}
		case *ast.CallExpr, *ast.SelectorExpr, *ast.CompositeLit:
			ast.Inspect(a, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok {
					switch id.Name {
					case "attestor", "validator", "bftValidator", "consensus", "shadow", "executor", "bridge":
						t.Errorf("finality_start.go: finality.Launch argument %d mentions %q, a consensus-side object", i, id.Name)
					}
				}
				return true
			})
		default:
			t.Errorf("finality_start.go: finality.Launch argument %d has unexpected form %T", i, arg)
		}
	}
}

// namedNewRequirements are the only requirement lines that may appear beyond the framework base: RB11-D2 adds the Brotli
// channel decoder (a module that had no line at all). Promotions of an already present indirect requirement to a direct one
// add no line; they are named in allowedDirectRequirements below.
var namedNewRequirements = map[string]string{
	"github.com/andybalholm/brotli": "v1.1.1",
}

// RB11-F1 promotes lukechampine.com/blake3 (already an indirect requirement) to a direct one for the Adiri record digest. The
// freeze rule is therefore: no requirement that existed at the framework base (9941b83) changes its version, every one of
// them is still present, and the only difference in the direct/indirect marking is that promotion. The snapshot of the base
// requirements is testdata/finality/gomod_requirements_9941b83.txt.
func TestGoModKeepsEveryRequirementVersionOfTheFrameworkBase(t *testing.T) {
	root := repoRoot(t)
	snap, err := os.ReadFile(filepath.Join("testdata", "finality", "gomod_requirements_9941b83.txt"))
	if err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	direct := map[string]bool{}
	inReq := false
	for _, l := range strings.Split(string(mod), "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "require ("):
			inReq = true
			continue
		case inReq && l == ")":
			inReq = false
			continue
		}
		if !inReq {
			continue
		}
		f := strings.Fields(l)
		if len(f) >= 2 {
			have[f[0]] = f[1]
			direct[f[0]] = !strings.Contains(l, "// indirect")
		}
	}
	n := 0
	base := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(snap)), "\n") {
		f := strings.Fields(l)
		n++
		base[f[0]] = true
		if v, ok := have[f[0]]; !ok || v != f[1] {
			t.Errorf("go.mod requirement %s was %s at the base and is now %q", f[0], f[1], v)
		}
	}
	if n < 300 {
		t.Fatalf("the base snapshot lists only %d requirements", n)
	}
	if !direct["lukechampine.com/blake3"] || have["lukechampine.com/blake3"] != "v1.2.1" {
		t.Errorf("lukechampine.com/blake3 must be a direct requirement at v1.2.1, got %q direct=%v", have["lukechampine.com/blake3"], direct["lukechampine.com/blake3"])
	}
	for k, v := range have {
		if base[k] {
			continue
		}
		if want, ok := namedNewRequirements[k]; ok && want == v {
			continue
		}
		t.Errorf("go.mod gained the requirement %s %s that the framework base did not have and that no work package was allowed to add", k, v)
	}
}

// go.mod rule (RB11-D2): no existing requirement version changes; the additions are limited to the named modules of the
// work packages that were allowed one. The direct requirements of the module are exactly this set.
var allowedDirectRequirements = map[string]string{
	"cloud.google.com/go/firestore": "v1.21.0", "firebase.google.com/go/v4": "v4.19.0",
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient": "v0.0.0-00010101000000-000000000000",
	"github.com/cometbft/cometbft": "v0.38.21", "github.com/cometbft/cometbft-db": "v0.14.1",
	"github.com/consensys/gnark": "v0.14.0", "github.com/consensys/gnark-crypto": "v0.19.2",
	"github.com/ethereum/go-ethereum": "v1.17.7", "github.com/google/uuid": "v1.6.0", "github.com/lib/pq": "v1.10.9",
	"github.com/mr-tron/base58": "v1.2.0", "github.com/prometheus/client_golang": "v1.21.0", "github.com/xssnick/tonutils-go": "v1.15.5",
	"gitlab.com/accumulatenetwork/accumulate": "v1.4.7-0.20260926030013-e1d1db9ebb7c", "go.etcd.io/bbolt": "v1.4.3",
	"golang.org/x/crypto": "v0.55.0", "google.golang.org/api": "v0.278.0", "gopkg.in/yaml.v3": "v3.0.1",
	// RB11-D2: the Brotli channel decoder and the KZG blob-proof verifier (go-eth-kzg, the pure-Go backend of go-ethereum's
	// crypto/kzg4844, promoted from indirect so the hash-checked ceremony setup can be loaded)
	"github.com/andybalholm/brotli": "v1.1.1", "github.com/crate-crypto/go-eth-kzg": "v1.5.0",
	// RB11-F1: the Adiri record digest (BLAKE3), promoted from indirect without a version change (see
	// TestGoModKeepsEveryRequirementVersionOfTheFrameworkBase)
	"lukechampine.com/blake3": "v1.2.1",
}

func TestGoModDirectRequirementsAreTheBaseSetPlusTheNamedAdditions(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	in := false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			in = true
		case line == ")":
			in = false
		case in && line != "" && !strings.HasSuffix(line, "// indirect"):
			f := strings.Fields(line)
			got[f[0]] = f[1]
		}
	}
	for m, v := range allowedDirectRequirements {
		if got[m] != v {
			t.Errorf("direct requirement %s is %q, want %q", m, got[m], v)
		}
	}
	for m, v := range got {
		if _, ok := allowedDirectRequirements[m]; !ok {
			t.Errorf("direct requirement %s %s is not one of the named additions", m, v)
		}
	}
}
