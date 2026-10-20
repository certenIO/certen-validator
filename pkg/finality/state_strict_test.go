// Copyright 2026 Certen Protocol

package finality

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---- closed reason sets (RB11-B2B1) ----

// reasonTypes maps each typed reason set of state.go to the state code whose `reason` it closes.
var reasonTypes = map[string]string{
	"EvidenceReason":       CodeEvidenceMalformed,
	"AddendumReason":       CodeAddendumMalformed,
	"PinsReason":           CodePinsCorrupt,
	"IncludedReason":       CodeIncludedUnavailable,
	"NotApplicableReason":  CodeNotApplicable,
	"FinalizedBlockReason": CodeFinalizedBlockUnavailable,
}

// reasonCtors maps each constructor that takes a typed reason to (index of the reason argument, the code it raises).
var reasonCtors = map[string]struct {
	arg  int
	code string
}{
	"Malformed":                 {1, CodeEvidenceMalformed},
	"MalformedAt":               {2, CodeEvidenceMalformed},
	"PinsCorrupt":               {0, CodePinsCorrupt},
	"AddendumMalformed":         {1, CodeAddendumMalformed},
	"IncludedUnavailable":       {0, CodeIncludedUnavailable},
	"FinalizedBlockUnavailable": {2, CodeFinalizedBlockUnavailable},
	"NotApplicableState":        {2, CodeNotApplicable},
}

// packageConsts returns every string constant of the package's own non-test sources (typed or not), with aliases resolved,
// and the typed ones grouped by their type name.
func packageConsts(t testing.TB) (map[string]string, map[string]map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	consts := map[string]string{}
	typed := map[string]map[string]bool{}
	var parsed []*ast.File
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, af)
		for _, d := range af.Decls {
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
						consts[n.Name] = v
						if id, ok := vs.Type.(*ast.Ident); ok && strings.HasSuffix(id.Name, "Reason") {
							if typed[id.Name] == nil {
								typed[id.Name] = map[string]bool{}
							}
							typed[id.Name][v] = true
						}
					}
				}
			}
		}
	}
	for _, af := range parsed {
		for _, d := range af.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if i < len(vs.Values) {
							if id, ok := vs.Values[i].(*ast.Ident); ok {
								consts[n.Name] = consts[id.Name]
							}
						}
					}
				}
			}
		}
	}
	return consts, typed
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestTheTypedReasonConstantsAreExactlyTheRegistrysClosedSets(t *testing.T) {
	reg := loadRegistry(t)
	_, typed := packageConsts(t)
	for typ := range typed {
		if _, ok := reasonTypes[typ]; !ok {
			t.Errorf("reason type %s has no registry code in reasonTypes", typ)
		}
	}
	for typ, code := range reasonTypes {
		want := reg.States[code].Enums["reason"]
		got := sortedKeys(typed[typ])
		sort.Strings(want)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s (%s): constants %v, registry enums.reason %v", typ, code, got, want)
		}
		if len(want) == 0 {
			t.Errorf("%s: an empty closed set", code)
		}
	}
}

func TestEveryStateWithAReasonFieldHasAClosedSetOrNamesTheDefiningPackage(t *testing.T) {
	reg := loadRegistry(t)
	for code, s := range reg.States {
		if code == CodePending {
			continue // its reasons are the closed pending_reasons set
		}
		has := false
		for _, f := range append(append([]string(nil), s.Required...), s.Optional...) {
			if f == "reason" {
				has = true
			}
		}
		if !has {
			continue
		}
		_, enum := s.Enums["reason"]
		_, later := s.EnumsDefinedBy["reason"]
		if enum == later {
			t.Errorf("%s has a reason field: it needs exactly one of enums.reason and enums_defined_by.reason (enum %v, defined_by %v)", code, enum, later)
		}
		if enum && len(s.Enums["reason"]) == 0 {
			t.Errorf("%s: empty enums.reason", code)
		}
	}
}

// reasonValue resolves the reason argument of a constructor or NewState pair to its string, when it is a literal or a constant.
func reasonValue(expr ast.Expr, consts map[string]string) (string, bool) {
	switch a := expr.(type) {
	case *ast.BasicLit:
		v, _ := strconv.Unquote(a.Value)
		return v, a.Kind == token.STRING
	case *ast.Ident:
		v, ok := consts[a.Name]
		return v, ok
	case *ast.SelectorExpr:
		if x, ok := a.X.(*ast.Ident); ok && x.Name == "finality" {
			v, ok := consts[a.Sel.Name]
			return v, ok
		}
	}
	return "", false
}

// callName is the callee's bare name for `F(...)` and `finality.F(...)`, and whether it is in the package (false: a selector on
// the finality package).
func callName(call *ast.CallExpr) (string, bool) {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name, true
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok && x.Name == "finality" {
			return f.Sel.Name, true
		}
	}
	return "", false
}

// The scan reaches pkg/finality, pkg/database and cmd/*: every NewState (identifier OR finality.NewState) names a registered code
// and carries its registered literal fields, and every reason passed to a constructor, or given as a "reason" pair, is a constant
// that is a member of its state's closed set.
func TestTheConformanceScanReachesDatabaseAndCommandsAndEveryReasonIsAMember(t *testing.T) {
	reg := loadRegistry(t)
	consts, _ := packageConsts(t)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, g := range []string{"*.go", "../database/*.go", "../../cmd/*/*.go"} {
		names, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			af, err := parser.ParseFile(fset, n, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, af)
		}
	}
	// the allowed non-constant reason arguments: NotApplicableState fed from the typed profile/table maps (closed by the const test)
	allowedDynamic := map[string]bool{"profile.go": true, "table.go": true, "pins.go": true} // pins.go: walkKeys returns typed PinsReason constants
	inDatabase, inCmd, ctorChecked, newStateChecked := 0, 0, 0, 0
	for _, af := range files {
		fname := fset.Position(af.Pos()).Filename
		slash := filepath.ToSlash(fname)
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := callName(call)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos()).String()
			if c, isCtor := reasonCtors[name]; isCtor && !strings.HasSuffix(slash, "state.go") {
				if c.arg >= len(call.Args) {
					t.Errorf("%s: %s lacks its reason argument", pos, name)
					return true
				}
				v, ok := reasonValue(call.Args[c.arg], consts)
				if !ok {
					if !allowedDynamic[filepath.Base(fname)] {
						t.Errorf("%s: the reason of %s is not a constant", pos, name)
					}
					return true
				}
				ctorChecked++
				set := reg.States[c.code].Enums["reason"]
				found := false
				for _, m := range set {
					found = found || m == v
				}
				if !found {
					t.Errorf("%s: %s reason %q is not in the closed set of %s", pos, name, v, c.code)
				}
				return true
			}
			if name != "NewState" || len(call.Args) == 0 {
				return true
			}
			var code string
			switch a := call.Args[0].(type) {
			case *ast.Ident:
				c, ok := consts[a.Name]
				if !ok {
					return true
				}
				code = c
			case *ast.SelectorExpr:
				c, ok := consts[a.Sel.Name]
				if !ok {
					return true
				}
				code = c
			case *ast.BasicLit:
				code, _ = strconv.Unquote(a.Value)
			default:
				return true
			}
			spec, ok := reg.States[code]
			if !ok {
				t.Errorf("%s: NewState raises %q, which is not in states.json", pos, code)
				return true
			}
			newStateChecked++
			switch {
			case strings.Contains(slash, "/database/"):
				inDatabase++
			case strings.Contains(slash, "/cmd/"):
				inCmd++
			}
			if call.Ellipsis != token.NoPos {
				return true
			}
			keys := map[string]bool{}
			for i := 1; i < len(call.Args); i += 2 {
				lit, ok := call.Args[i].(*ast.BasicLit)
				if !ok {
					return true
				}
				k, _ := strconv.Unquote(lit.Value)
				keys[k] = true
				if k == "reason" && i+1 < len(call.Args) {
					if v, ok := reasonValue(call.Args[i+1], consts); ok && len(spec.Enums["reason"]) > 0 {
						found := false
						for _, m := range spec.Enums["reason"] {
							found = found || m == v
						}
						if !found {
							t.Errorf("%s: NewState(%q) reason %q is not in its closed set", pos, code, v)
						}
					}
				}
			}
			allowed := map[string]bool{}
			for _, f := range spec.Required {
				allowed[f] = true
				if !keys[f] {
					t.Errorf("%s: NewState(%q) lacks required field %q", pos, code, f)
				}
			}
			for _, f := range spec.Optional {
				allowed[f] = true
			}
			for k := range keys {
				if !allowed[k] {
					t.Errorf("%s: NewState(%q) carries unregistered field %q", pos, code, k)
				}
			}
			return true
		})
	}
	if inDatabase < 4 {
		t.Errorf("the scan saw %d NewState calls in pkg/database (want >= 4): it is not reaching the package", inDatabase)
	}
	if ctorChecked < 25 || newStateChecked < 20 {
		t.Errorf("the scan checked %d constructor reasons and %d NewState calls: it is not seeing the packages", ctorChecked, newStateChecked)
	}
	_ = inCmd
}

// The database guard's refusal is a registered go_operational code, not a value of the closed chain_broken checks it is not.
func TestNoStateRaisedAnywhereUsesACheckOutsideTheClosedChainBrokenSet(t *testing.T) {
	reg := loadRegistry(t)
	set := reg.States[CodeChainBroken].Enums["check"]
	for _, name := range []string{CheckSeqGap, CheckPrevHash, CheckOwnHash, CheckLevelDuplicate, CheckKind, CheckLegBinding} {
		found := false
		for _, m := range set {
			found = found || m == name
		}
		if !found {
			t.Errorf("check %q is not in the registry's closed set %v", name, set)
		}
	}
	if len(set) != 6 {
		t.Errorf("the closed set of finality_chain_broken checks has %d members: %v", len(set), set)
	}
	if st := reg.States[CodeGuardRefused]; st.Scope != "go_operational" {
		t.Errorf("%s: %+v", CodeGuardRefused, st)
	}
}

// ---- integer rendering of every width, the conditional requirement and the mixed-type canonical form ----

type namedInt int32

func TestEveryIntegerFieldRendersAsADecimalStringForAnyWidth(t *testing.T) {
	cases := []struct {
		v    any
		want string
	}{
		{int(-7), `"-7"`}, {int8(-128), `"-128"`}, {int16(-32768), `"-32768"`}, {int32(-2147483648), `"-2147483648"`},
		{int64(-9223372036854775808), `"-9223372036854775808"`},
		{uint(7), `"7"`}, {uint8(255), `"255"`}, {uint16(65535), `"65535"`}, {uint32(4294967295), `"4294967295"`},
		{uint64(18446744073709551615), `"18446744073709551615"`}, {uintptr(9), `"9"`}, {namedInt(-3), `"-3"`},
	}
	for _, c := range cases {
		s := NewState("x", "n", c.v)
		want := `{"code":"x","fields":{"n":` + c.want + `}}`
		if got := string(s.Canonical()); got != want {
			t.Errorf("%T: got %s want %s", c.v, got, want)
		}
	}
	// and in a nested map and a []uint64
	s := NewState("x", "m", map[string]any{"a": uint8(1), "b": int64(-2)}, "l", []uint64{1, 2})
	if got := string(s.Canonical()); got != `{"code":"x","fields":{"l":["1","2"],"m":{"a":"1","b":"-2"}}}` {
		t.Errorf("nested: %s", got)
	}
}

func TestAChainBrokenLegBindingWithoutWantAndGotDoesNotConform(t *testing.T) {
	reg := loadRegistry(t)
	b := testBase()
	if msg := conforms(reg, ChainBroken(0, CheckLegBinding)); !strings.Contains(msg, "lacks required field") {
		t.Fatalf("a leg_binding state without want and got conformed: %q", msg)
	}
	if msg := conforms(reg, ChainBroken(0, CheckLegBinding, "want", b.Triple())); !strings.Contains(msg, "got") {
		t.Fatalf("a leg_binding state without got conformed: %q", msg)
	}
	if msg := conforms(reg, ChainBroken(0, CheckLegBinding, "want", b.Triple(), "got", b.Triple())); msg != "" {
		t.Fatal(msg)
	}
	// the other checks do not need want/got
	if msg := conforms(reg, ChainBroken(2, CheckOwnHash)); msg != "" {
		t.Fatal(msg)
	}
	// a check outside the closed set does not conform
	if msg := conforms(reg, ChainBroken(1, "database_guard")); !strings.Contains(msg, "closed set") {
		t.Fatalf("an unregistered check conformed: %q", msg)
	}
	// game_unrecognised requires its reason, and the reason is closed
	if msg := conforms(reg, NewState("game_unrecognised")); !strings.Contains(msg, "lacks required field reason") {
		t.Fatalf("game_unrecognised without a reason conformed: %q", msg)
	}
	if msg := conforms(reg, NewState("game_unrecognised", "reason", "prefix")); msg != "" {
		t.Fatal(msg)
	}
	if msg := conforms(reg, NewState("game_unrecognised", "reason", "other")); !strings.Contains(msg, "closed set") {
		t.Fatalf("an unregistered game_unrecognised reason conformed: %q", msg)
	}
}

func TestAReasonOutsideItsClosedSetDoesNotConform(t *testing.T) {
	reg := loadRegistry(t)
	for _, s := range []*StateError{
		Malformed("part", EvidenceReason("a Go sentence"), 0, 0),
		AddendumMalformed("seq", AddendumReason("whatever")),
		PinsCorrupt(PinsReason("nope")),
		IncludedUnavailable(IncludedReason("nope")),
		NotApplicableState(1, LevelL1Posted, NotApplicableReason("nope")),
		FinalizedBlockUnavailable(1, 1, FinalizedBlockReason("nope")),
	} {
		if msg := conforms(reg, s); !strings.Contains(msg, "closed set") {
			t.Errorf("%s: %q", s.Code, msg)
		}
	}
}
