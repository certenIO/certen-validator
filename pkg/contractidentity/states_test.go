// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

func mustRegistry(t *testing.T) *Registry {
	t.Helper()
	g, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("embedded registry: %v", err)
	}
	return g
}

func TestRegistryEmbedLoads(t *testing.T) {
	g := mustRegistry(t)
	if len(g.Rows) != 72 || len(g.Codes()) != 35 {
		t.Fatalf("registry has %d rows / %d codes, the frozen spec has 72 / 35", len(g.Rows), len(g.Codes()))
	}
	for _, r := range g.Rows {
		if !strings.HasPrefix(r.Code, Prefix) {
			t.Fatalf("code %q without the %s prefix", r.Code, Prefix)
		}
	}
	if got := strings.Join(g.CommonFields, ","); got != "chain,block,block_hash,judged_at_level,manifest_sha256,manifest_source" {
		t.Fatalf("common fields %s", got)
	}
}

// states.go constants (generated) and states.json describe the same registry, both ways.
func TestGeneratedNamesEqualRegistry(t *testing.T) {
	g := mustRegistry(t)
	if got, want := strings.Join(generatedCodes, "\n"), strings.Join(g.Codes(), "\n"); got != want {
		t.Fatalf("code constants differ from states.json\n got %s\nwant %s", got, want)
	}
	var rows []string
	for _, r := range g.Rows {
		rows = append(rows, r.Code+"|"+r.Row)
	}
	if got, want := strings.Join(generatedRows, "\n"), strings.Join(rows, "\n"); got != want {
		t.Fatalf("row list differs from states.json\n got %s\nwant %s", got, want)
	}
	// every named row constant is a row cell of the registry
	if !contains(rows, CodeUnproven+"|"+RowUnprovenStateUnavailable) || !contains(rows, CodeNotChecked+"|"+RowNotCheckedS6LinkS6NotProven) ||
		!contains(rows, CodePending+"|"+RowPendingStateRootNotAuthenticated) || !contains(rows, CodeNotApplicable+"|"+RowNotApplicableCertenInfrastructureCall) {
		t.Fatal("a generated row constant is not a registry row")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

var (
	tagRe     = regexp.MustCompile(`\s*\[r3(?:\.1)?:[A-Za-z0-9-]+\]`)
	item3RowR = regexp.MustCompile(`^\| ([a-z0-9_]+) \| ([^|]+) \| (FR|JR|U|OPEN|PEND|VER|NA|WRAP) \| ([^|]*) \| ([^|]+) \| ([^|]+) \|$`)
)

// The registry file is the Item 3 table of the frozen specification, row by row and cell by cell, re-parsed here independently of the
// lifting script.
func TestRegistryEqualsSpecItem3(t *testing.T) {
	spec := specText(t)
	lines := strings.Split(spec, "\n")
	start, end := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "### Item 3 - named-state registry") {
			start = i
		}
		if strings.HasPrefix(l, "### Item 4 - closed vocabularies") {
			end = i
		}
	}
	if start < 0 || end < start {
		t.Fatal("Item 3 / Item 4 headings not found")
	}
	type srow struct{ code, cell, class, fields, step, effect string }
	var want []srow
	for _, l := range lines[start:end] {
		if m := item3RowR.FindStringSubmatch(l); m != nil {
			c := func(s string) string { return strings.TrimSpace(tagRe.ReplaceAllString(s, "")) }
			want = append(want, srow{m[1], c(m[2]), m[3], c(m[4]), c(m[5]), c(m[6])})
		}
	}
	g := mustRegistry(t)
	if len(want) != len(g.Rows) {
		t.Fatalf("spec Item 3 has %d rows, states.json %d", len(want), len(g.Rows))
	}
	for i, w := range want {
		r := g.Rows[i]
		if r.Code != Prefix+w.code || r.Row != w.cell || r.Class != w.class || r.Step != w.step || r.Effect != w.effect {
			t.Fatalf("row %d differs: json {%s %s %s %s %s} spec {%s %s %s %s %s}", i, r.Code, r.Row, r.Class, r.Step, r.Effect, w.code, w.cell, w.class, w.step, w.effect)
		}
		var wf []string
		if w.fields != "-" {
			for _, f := range strings.Split(w.fields, ",") {
				wf = append(wf, strings.TrimSpace(f))
			}
		}
		plain := w.cell != "-" && w.cell != "(wrapper)" && !strings.Contains(w.cell, " / ")
		if plain && !contains(wf, "reason") {
			wf = append([]string{"reason"}, wf...)
		}
		if strings.Join(r.Fields, ",") != strings.Join(wf, ",") {
			t.Fatalf("row %s|%s fields differ: json %v spec %v", w.code, w.cell, r.Fields, wf)
		}
	}
}

// dummyValue is a value that satisfies the vocabulary binding of (code, field) when there is one.
func dummyValue(t *testing.T, v *Vocabulary, code, field, row string) any {
	t.Helper()
	if id := v.SetFor(code, field, row); id != "" {
		s := v.Sets[id]
		switch {
		case len(s.Values) > 0:
			return s.Values[0]
		case id == "auth_row_field":
			return "A01:0x01"
		case id == "tx_type_text":
			return "0x02"
		default:
			t.Fatalf("no dummy for set %s", id)
		}
	}
	switch field {
	case "missing", "parts", "open", "findings":
		return []string{"a"}
	case "address", "code_hash", "anchorId", "judgedHash":
		return bytes32(0x01)
	}
	return "x"
}

// validFields builds the fields of a valid state of row r (for a family row, of the given reason): every required field with a value that
// satisfies its vocabulary binding. The row-fixed discriminants (part, reason) are left out; New fills them in.
func validFields(t *testing.T, v *Vocabulary, r *Row, reason string) (fields map[string]any, need []string) {
	t.Helper()
	short := strings.TrimPrefix(r.Code, Prefix)
	fields = map[string]any{}
	need = r.Fields
	if r.ReasonSet != "" {
		if r.Variants != nil {
			need = append([]string{"reason"}, r.Variants[reason]...)
		}
		fields["reason"] = reason
	}
	for _, f := range need {
		switch {
		case f == "reason" && r.ReasonSet != "":
			continue
		case f == "reason" && r.Reason != "":
			continue
		case f == "part" && r.Part != "":
			continue
		case r.optSet[f] && r.ReasonSet == "":
			continue
		}
		fields[f] = dummyValue(t, v, short, f, r.Row)
	}
	return fields, need
}

func TestRegistryWalkConstructsEveryRow(t *testing.T) {
	g := mustRegistry(t)
	v, _ := DefaultVocabulary()
	for i := range g.Rows {
		r := &g.Rows[i]
		short := strings.TrimPrefix(r.Code, Prefix)
		reasons := []string{""}
		if r.ReasonSet != "" {
			reasons = v.Values(r.ReasonSet)
			if len(reasons) == 0 {
				t.Fatalf("family row %s has an empty reason set", r.Row)
			}
		}
		for _, reason := range reasons {
			fields, need := validFields(t, v, r, reason)
			st, err := g.New(r.Code, r.Row, fields)
			if err != nil {
				t.Fatalf("row %s|%s reason %q: %v", r.Code, r.Row, reason, err)
			}
			if err := g.Validate(st); err != nil {
				t.Fatalf("row %s|%s reason %q: validate: %v", r.Code, r.Row, reason, err)
			}
			// exactly the fields of the row: the state carries nothing else
			wantKeys := map[string]bool{}
			for _, f := range need {
				if r.optSet[f] && r.ReasonSet == "" {
					continue
				}
				wantKeys[f] = true
			}
			for k := range st.Fields {
				if !wantKeys[k] {
					t.Fatalf("row %s|%s: state carries unexpected field %q", r.Code, r.Row, k)
				}
			}
			for k := range wantKeys {
				if _, ok := st.Fields[k]; !ok {
					t.Fatalf("row %s|%s: state lacks field %q", r.Code, r.Row, k)
				}
			}
			// every required field is required: dropping any one is refused
			for k := range wantKeys {
				if r.Reason != "" && r.ReasonSet == "" && k == "reason" {
					continue // the row fixes it; New fills it in
				}
				if r.Part != "" && k == "part" {
					continue
				}
				without := map[string]any{}
				for kk, vv := range st.Fields {
					if kk != k {
						without[kk] = vv
					}
				}
				if _, err := g.New(r.Code, r.Row, without); err == nil {
					t.Fatalf("row %s|%s reason %q: field %q may be absent but is required", r.Code, r.Row, reason, k)
				}
			}
			// a field the row does not list is refused
			extra := map[string]any{"zz_extra": "1"}
			for kk, vv := range st.Fields {
				extra[kk] = vv
			}
			if _, err := g.New(r.Code, r.Row, extra); err == nil {
				t.Fatalf("row %s|%s: an extra field was accepted", r.Code, r.Row)
			}
			// optional fields may be added
			for _, f := range r.Optional {
				if r.ReasonSet != "" && !contains(r.Variants[reason], f) {
					continue
				}
				with := map[string]any{}
				for kk, vv := range st.Fields {
					with[kk] = vv
				}
				with[f] = dummyValue(t, v, short, f, r.Row)
				if _, err := g.New(r.Code, r.Row, with); err != nil {
					t.Fatalf("row %s|%s: optional field %s refused: %v", r.Code, r.Row, f, err)
				}
			}
		}
	}
}

func TestNewRefusesWhatTheRegistryDoesNotDefine(t *testing.T) {
	g := mustRegistry(t)
	bad := []struct {
		name   string
		code   string
		row    string
		fields map[string]any
	}{
		{"unregistered code", Prefix + "no_such_state", "", map[string]any{}},
		{"unprefixed code", "evidence_malformed", "", map[string]any{}},
		{"unregistered row", CodeUnproven, "no_such_reason", map[string]any{"part": "all"}},
		{"missing field", CodeEvidenceTooLarge, "", map[string]any{"part": PartNodes, "count": uint64(2)}},
		{"extra field", CodeEvidenceTooLarge, "", map[string]any{"part": PartNodes, "count": uint64(2), "limit": uint64(1), "x": 1}},
		{"vocabulary: part", CodeEvidenceTooLarge, "", map[string]any{"part": "bogus", "count": uint64(2), "limit": uint64(1)}},
		{"vocabulary: reason", CodeEvidenceMalformed, "", map[string]any{"part": PartNodes, "index": 0, "reason": "bogus", "got_len": 0, "want_len": 0}},
		{"vocabulary needs a string", CodeBlockMismatch, "", map[string]any{"field": 7, "want": 1, "got": 2}},
		{"row-fixed reason contradicted", CodeUnproven, RowUnprovenStateUnavailable, map[string]any{"reason": "block_too_large", "part": "all", "judgedBlock": 1, "judgedHash": 1, "failures": 1}},
		{"row-fixed part contradicted", CodeNotChecked, RowNotCheckedRegistryKeysPkcSetMismatch, map[string]any{"part": "registry_link", "entry": "0x01"}},
		{"family reason missing", CodeUnproven, RowUnprovenAuthorityLevelUnproven, map[string]any{}},
		{"family reason outside the set", CodeUnproven, RowUnprovenAuthorityLevelUnproven, map[string]any{"reason": "bogus"}},
		{"family variant field missing", CodeUnproven, RowUnprovenAuthorityLevelUnproven, map[string]any{"reason": LevelReasonLevelDiffersFromLogged, "logged": 1}},
		{"family variant extra field", CodeUnproven, RowUnprovenAuthorityLevelUnproven, map[string]any{"reason": LevelReasonLevelLogMissing, "leg": 0}},
		{"no canonical form", CodeBlockMismatch, "", map[string]any{"field": BlockFieldChain, "want": 1.5, "got": struct{}{}}},
	}
	for _, b := range bad {
		if st, err := g.New(b.code, b.row, b.fields); err == nil {
			t.Errorf("%s: accepted %s", b.name, st)
		}
	}
	if _, err := New(CodeManifestCorrupt, "", nil); err != nil {
		t.Errorf("manifest_corrupt with no fields refused: %v", err)
	}
	// Must panics where New refuses
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Must did not panic on an invalid state")
			}
		}()
		Must(CodeEvidenceTooLarge, "", map[string]any{})
	}()
	// Validate refuses a state edited after construction
	st := TooLarge(PartNodes, 2, 1)
	st.Fields["zz"] = 1
	if Validate(st) == nil {
		t.Error("Validate accepted an extra field")
	}
	st = TooLarge(PartNodes, 2, 1)
	delete(st.Fields, "limit")
	if Validate(st) == nil {
		t.Error("Validate accepted a missing field")
	}
	st = TooLarge(PartNodes, 2, 1)
	st.Code = Prefix + "unknown"
	if Validate(st) == nil {
		t.Error("Validate accepted an unregistered code")
	}
	st = Must(CodeUnproven, RowUnprovenStateUnavailable, map[string]any{"part": "settle", "judgedBlock": uint64(1), "judgedHash": bytes32(1), "failures": []string{}})
	st.Reason = "other"
	if Validate(st) == nil {
		t.Error("Validate accepted a Reason that differs from the reason field")
	}
}

func TestTypedHelpersConform(t *testing.T) {
	g := mustRegistry(t)
	for _, st := range []*StateError{
		Malformed(PartNodes, MalformedNodesDuplicate, 2, 0, 0),
		TooLarge(PartCodes, 17, 16),
		Unrecognised("contract-identity/v9"),
		ManifestCorrupt(),
		ManifestUnknown(5),
		ManifestShadow("policy.rules", "MINGOV"),
		BlockMismatch(BlockFieldNumber, uint64(1), uint64(2)),
		BlockMismatch(BlockFieldHash, bytes32(1), bytes32(2)),
		ContextIncomplete([]string{"settlement", "s6"}),
	} {
		if err := g.Validate(st); err != nil {
			t.Errorf("%s: %v", st, err)
		}
	}
	if st := Unrecognised("contract-identity/v9"); st.Fields["version"] != "v9" || st.Fields["kind"] != "contract-identity/v9" {
		t.Errorf("Unrecognised fields %v", st.Fields)
	}
	if st := Unrecognised("nokindslash"); st.Fields["version"] != "" {
		t.Errorf("version of a kind without a slash: %v", st.Fields["version"])
	}
}

func TestStateCanonicalForm(t *testing.T) {
	st := Malformed(PartNodes, MalformedNodesDuplicate, 3, 9, 12)
	want := `{"code":"contract_identity_evidence_malformed","fields":{"got_len":"9","index":"3","part":"nodes","reason":"nodes_duplicate","want_len":"12"}}`
	if got := string(st.Canonical()); got != want {
		t.Fatalf("canonical\n got %s\nwant %s", got, want)
	}
	if got := st.Error(); !strings.HasPrefix(got, CodeEvidenceMalformed+"{") || !strings.Contains(got, `index="3"`) {
		t.Fatalf("Error() = %s", got)
	}
	cx := Context{Chain: 1, Block: 2, BlockHash: bytes32(0xab), JudgedAtLevel: "finalized", ManifestSHA256: bytes32(0xcd), ManifestSource: "embedded"}
	got, err := st.CanonicalWithContext(cx)
	if err != nil {
		t.Fatal(err)
	}
	wantCx := `{"code":"contract_identity_evidence_malformed","context":{"block":"2","block_hash":"0x` + strings.Repeat("ab", 32) + `","chain":"1","judged_at_level":"finalized","manifest_sha256":"0x` + strings.Repeat("cd", 32) + `","manifest_source":"embedded"},"fields":{"got_len":"9","index":"3","part":"nodes","reason":"nodes_duplicate","want_len":"12"}}`
	if string(got) != wantCx {
		t.Fatalf("canonical with context\n got %s\nwant %s", got, wantCx)
	}
	cx.ManifestSource = "somewhere"
	if _, err := st.CanonicalWithContext(cx); err == nil {
		t.Fatal("a manifest_source outside the vocabulary was accepted")
	}
	cx.ManifestSource = "override:" + strings.Repeat("0", 64)
	if _, err := st.CanonicalWithContext(cx); err != nil {
		t.Fatalf("override source refused: %v", err)
	}
}

// The canonical encoder agrees with the pkg/finality (S7 s.6) encoder on every value both define, and refuses what only S7 stringifies.
func TestCanonicalAgreesWithS7(t *testing.T) {
	fields := map[string]any{
		"a_u64": uint64(18446744073709551615), "b_int": -7, "c_u8": uint8(3), "d_bytes": []byte{0xde, 0xad}, "e_empty": []byte{}, "f_arr": [4]byte{1, 2, 3, 4},
		"g_hash": bytes32(0x0f), "h_str": "a\"b\\c<d>&é", "i_bool": true, "j_nil": nil, "k_strs": []string{"x", "y"}, "l_nested": map[string]any{"z": uint32(1), "a": "b"},
	}
	mine := (&StateError{Code: "c", Fields: fields}).Canonical()
	theirs := (&finality.StateError{Code: "c", Fields: fields}).Canonical()
	if !bytes.Equal(mine, theirs) {
		t.Fatalf("encoders differ\n mine   %s\n theirs %s", mine, theirs)
	}
	// lists of objects (open entries, findings, parts): defined here, in the order given
	got, err := Canonical(map[string]any{"open": []any{map[string]any{"part": "p", "n": 1}, map[string]any{"kind": "alert"}}, "big": big.NewInt(-12), "u": []uint64{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"big":"-12","open":[{"n":"1","part":"p"},{"kind":"alert"}],"u":["1","2"]}`; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
	for _, v := range []any{1.5, struct{}{}, make(chan int), func() {}, map[int]string{1: "a"}} {
		if _, err := Canonical(v); err == nil {
			t.Errorf("no canonical form must be an error: %T", v)
		}
	}
	if b, _ := Canonical(([]string)(nil)); string(b) != "[]" {
		t.Errorf("nil list renders %s", b)
	}
	if b, _ := Canonical([]byte(nil)); string(b) != `"0x"` {
		t.Errorf("nil bytes render %s", b)
	}
}

// Every state code mentioned in the frozen specification text is a registry code (the spec says so; the test makes it true of the copy).
func TestEverySpecTokenIsARegistryCode(t *testing.T) {
	spec := specText(t)
	g := mustRegistry(t)
	have := map[string]bool{}
	for _, c := range g.Codes() {
		have[strings.TrimPrefix(c, Prefix)] = true
	}
	var missing []string
	for _, m := range regexp.MustCompile(`contract_identity_([a-z0-9_]+)`).FindAllStringSubmatch(spec, -1) {
		if !have[m[1]] {
			missing = append(missing, m[1])
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("tokens of the spec that are not registry codes: %v", missing)
	}
}
