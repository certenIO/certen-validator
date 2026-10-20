// Copyright 2026 Certen Protocol

// Package conformance scans the sources of pkg/finality/arbposted against the state registry (testdata/finality/states.json): the
// framework's own scan reaches pkg/finality, pkg/database and cmd/* only, so a chain package carries its own. Every state the
// package raises is registered with exactly the fields the registry lists, and the typed reason sets of the package are exactly
// the registry's closed sets.
package conformance

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type regState struct {
	Required []string            `json:"required"`
	Optional []string            `json:"optional"`
	Enums    map[string][]string `json:"enums"`
}

func loadRegistry(t *testing.T) map[string]regState {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		States map[string]regState `json:"states"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.States
}

func parsePackage(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join("..", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) < 6 {
		t.Fatalf("only %d source files scanned", len(files))
	}
	return fset, files
}

// consts returns every string constant of the package (typed or not) and the typed ones grouped by type name.
func consts(files []*ast.File) (map[string]string, map[string][]string) {
	all := map[string]string{}
	typed := map[string][]string{}
	for _, f := range files {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						v, _ := strconv.Unquote(lit.Value)
						all[n.Name] = v
						if id, ok := vs.Type.(*ast.Ident); ok {
							typed[id.Name] = append(typed[id.Name], v)
						}
					}
				}
			}
		}
	}
	return all, typed
}

func sorted(s []string) string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return strings.Join(c, "|")
}

var frameworkCodes = map[string]string{
	"CodePinUnknown": "finality_pin_unknown", "CodeLevelAlreadyPresent": "level_already_present",
}

func TestTheTypedReasonSetsAreExactlyTheRegistrysClosedSets(t *testing.T) {
	reg := loadRegistry(t)
	_, files := parsePackage(t)
	_, typed := consts(files)
	for typ, code := range map[string]string{"ContentReason": "l1_posted_content_not_found", "L1FinalityReason": "l1_finality_unproven"} {
		if got, want := sorted(typed[typ]), sorted(reg[code].Enums["reason"]); got != want || got == "" {
			t.Errorf("%s: constants %q, registry enums.reason of %s %q", typ, got, code, want)
		}
	}
}

// Every NewState call (and every call of a constructor of this package) with a literal code names a registered state, carries
// only registered fields, and carries every required one; every reason is a member of its closed set.
func TestEveryStateTheKindRaisesIsRegisteredWithExactlyItsFields(t *testing.T) {
	reg := loadRegistry(t)
	fset, files := parsePackage(t)
	cs, _ := consts(files)
	for k, v := range frameworkCodes {
		cs[k] = v
	}
	seen := 0
	check := func(pos, code string, keys []string, reason string) {
		st, ok := reg[code]
		if !ok {
			t.Errorf("%s: %q is not in the registry", pos, code)
			return
		}
		allowed := map[string]bool{}
		for _, f := range append(append([]string(nil), st.Required...), st.Optional...) {
			allowed[f] = true
		}
		have := map[string]bool{}
		for _, k := range keys {
			have[k] = true
			if !allowed[k] {
				t.Errorf("%s: %s carries unregistered field %q", pos, code, k)
			}
		}
		for _, r := range st.Required {
			if !have[r] {
				t.Errorf("%s: %s lacks required field %q", pos, code, r)
			}
		}
		if reason != "" {
			set := st.Enums["reason"]
			found := false
			for _, m := range set {
				found = found || m == reason
			}
			if !found && len(set) > 0 {
				t.Errorf("%s: %s reason %q is not in its closed set %v", pos, code, reason, set)
			}
		}
		seen++
	}
	lit := func(e ast.Expr) (string, bool) {
		switch a := e.(type) {
		case *ast.BasicLit:
			v, err := strconv.Unquote(a.Value)
			return v, err == nil
		case *ast.Ident:
			v, ok := cs[a.Name]
			return v, ok
		case *ast.SelectorExpr:
			v, ok := cs[a.Sel.Name]
			return v, ok
		}
		return "", false
	}
	// constructors of this package: name -> (code, fixed keys of the constructor itself)
	ctors := map[string]struct {
		code string
		keys []string
	}{
		"PinMismatch": {"pin_mismatch", []string{"field"}}, "stateProofInvalid": {"l1_state_proof_invalid", []string{"which"}},
		"contractIdentity": {"contract_identity_unproven", []string{"role", "address", "code_hash", "judged_at"}},
		"blobMismatch":     {"blob_commitment_mismatch", nil}, "l1FinalityUnproven": {"l1_finality_unproven", []string{"reason", "inner"}},
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos()).String()
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			switch {
			case name == "NewState" && len(call.Args) >= 1:
				code, ok := lit(call.Args[0])
				if !ok {
					return true
				}
				var keys []string
				reason := ""
				dynamic := false
				for i := 1; i+1 < len(call.Args); i += 2 {
					k, ok := lit(call.Args[i])
					if !ok {
						dynamic = true
						break
					}
					keys = append(keys, k)
					if k == "reason" {
						reason, _ = lit(call.Args[i+1])
					}
				}
				if len(call.Args)%2 == 0 {
					dynamic = true // an odd number of key/value arguments: not a literal list
				}
				if dynamic {
					return true
				}
				check(pos, code, keys, reason)
			case name == "contentNotFound" && len(call.Args) >= 1:
				reason, ok := lit(call.Args[0])
				if !ok {
					return true
				}
				keys := []string{"reason"}
				for i := 1; i+1 < len(call.Args); i += 2 {
					if k, ok := lit(call.Args[i]); ok {
						keys = append(keys, k)
					}
				}
				check(pos, "l1_posted_content_not_found", keys, reason)
			default:
				if c, ok := ctors[name]; ok {
					reason := ""
					if name == "l1FinalityUnproven" && len(call.Args) > 0 {
						reason, _ = lit(call.Args[0])
					}
					check(pos, c.code, c.keys, reason)
				}
			}
			return true
		})
	}
	if seen < 20 {
		t.Fatalf("only %d state constructions were scanned: the scan is not seeing the sources", seen)
	}
}
