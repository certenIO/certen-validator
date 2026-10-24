// Copyright 2026 Certen Protocol

package contractidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func loadIndex(t *testing.T) *VectorIndex {
	t.Helper()
	idx, err := LoadVectorIndex(readTestdata(t, "vectors/MANIFEST.json"), mustRegistry(t))
	if err != nil {
		t.Fatalf("vectors/MANIFEST.json: %v", err)
	}
	return idx
}

var (
	item5RowRe = regexp.MustCompile(`^\| (VS8-\d{3}) \| ([^|]+) \| (.*) \| ([^|]*) \|$`)
	stepRe     = regexp.MustCompile(`^(\d+[a-z]?)\. \*\*`)
)

// specSteps returns the ids of the steps of the algorithm section of the frozen specification.
func specSteps(t *testing.T) map[string]bool {
	t.Helper()
	lines := strings.Split(specText(t), "\n")
	a, b := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "## Offline verification algorithm") {
			a = i
		}
		if a >= 0 && b < 0 && i > a && strings.HasPrefix(l, "Interface (Go") {
			b = i
		}
	}
	if a < 0 || b < 0 {
		t.Fatal("algorithm section not found")
	}
	out := map[string]bool{}
	for _, l := range lines[a:b] {
		if m := stepRe.FindStringSubmatch(l); m != nil {
			out[m[1]] = true
		}
	}
	return out
}

// vectors/MANIFEST.json lists every row of Freeze item 5 and nothing else, with the cells of the specification; every expected code is a
// registry code and every step exists.
func TestVectorIndexEqualsSpecItem5(t *testing.T) {
	idx := loadIndex(t)
	lines := strings.Split(specText(t), "\n")
	start, end := -1, -1
	for i, l := range lines {
		if strings.HasPrefix(l, "### Item 5 - vector list") {
			start = i
		}
		if strings.HasPrefix(l, "### Item 6 - CLI mapping") {
			end = i
		}
	}
	var rows [][4]string
	for _, l := range lines[start:end] {
		if m := item5RowRe.FindStringSubmatch(l); m != nil {
			c := func(s string) string { return strings.TrimSpace(tagRe.ReplaceAllString(s, "")) }
			rows = append(rows, [4]string{m[1], c(m[2]), c(m[3]), c(m[4])})
		}
	}
	if len(rows) != 124 || len(idx.Vectors) != 124 {
		t.Fatalf("spec item 5 has %d rows, the index %d, the frozen count is 124", len(rows), len(idx.Vectors))
	}
	steps := specSteps(t)
	letters := map[string]bool{"M": true, "G": true, "N": true, "P": true}
	g := mustRegistry(t)
	for i, r := range rows {
		v := idx.Vectors[i]
		if v.ID != r[0] || v.Step != r[1] || v.Mutation != r[2] || v.ExpectedText != r[3] {
			t.Fatalf("row %s differs between the spec and the index", r[0])
		}
		ok := letters[v.Step] || steps[v.Step] || steps[strings.TrimRight(v.Step, "abcdefgh")] // 3a, 19e, 21c: a clause of a step
		if m := regexp.MustCompile(`^(\d+[a-z]?)-(\d+[a-z]?)$`).FindStringSubmatch(v.Step); m != nil {
			ok = (steps[m[1]] || steps[strings.TrimRight(m[1], "abcdefgh")]) && (steps[m[2]] || steps[strings.TrimRight(m[2], "abcdefgh")])
		}
		if !ok {
			t.Errorf("%s: step %q is not a step of the algorithm", v.ID, v.Step)
		}
		for _, e := range v.Expected {
			if len(g.RowsOf(e.Code)) == 0 {
				t.Errorf("%s expects %s, which is not a registry code", v.ID, e.Code)
			}
		}
		if len(v.Expected) == 0 && len(v.OtherTokens) == 0 && !strings.Contains(v.ExpectedText, "`") && v.ExpectedText == "" {
			t.Errorf("%s has no expectation", v.ID)
		}
	}
	// the vectors the freeze package implements as Go tests now exist in the index
	for _, id := range []string{"VS8-001", "VS8-002", "VS8-003", "VS8-004", "VS8-010", "VS8-011", "VS8-012", "VS8-013", "VS8-014", "VS8-015", "VS8-016", "VS8-017", "VS8-020", "VS8-021", "VS8-024"} {
		found := false
		for _, v := range idx.Vectors {
			found = found || v.ID == id
		}
		if !found {
			t.Errorf("%s missing from the index", id)
		}
	}
}

func TestVectorIndexRefusesWhatIsNotIndexable(t *testing.T) {
	g := mustRegistry(t)
	good := string(readTestdata(t, "vectors/MANIFEST.json"))
	bads := map[string]string{
		"unknown registry code": strings.Replace(good, `"code": "contract_identity_manifest_corrupt"`, `"code": "contract_identity_no_such_state"`, 1),
		"unknown status":        strings.Replace(good, `"status": "spec_only"`, `"status": "done"`, 1),
		"spec_only with a set":  strings.Replace(good, `"set": null`, `"set": "ci1"`, 1),
		"published without set": strings.Replace(good, `"status": "spec_only"`, `"status": "published"`, 1),
		"wrong format":          strings.Replace(good, "certen-contract-identity-vectors/1", "certen-contract-identity-vectors/2", 1),
		"unknown member":        strings.Replace(good, `"format"`, `"extra": 1, "format"`, 1),
		"id out of order":       strings.Replace(good, `"id": "VS8-002"`, `"id": "VS8-000"`, 1),
		"duplicate id":          strings.Replace(good, `"id": "VS8-002"`, `"id": "VS8-001"`, 1),
		"malformed id":          strings.Replace(good, `"id": "VS8-002"`, `"id": "VS8-2"`, 1),
	}
	for name, raw := range bads {
		if raw == good {
			t.Fatalf("%s: fixture did not change the document", name)
		}
		if _, err := LoadVectorIndex([]byte(raw), g); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The mutation vocabulary of the loader equals the table of FORMAT.md (a claim in the document is a claim in the code).
func TestMutationVocabularyEqualsFormatDocument(t *testing.T) {
	doc := string(readTestdata(t, "vectors/FORMAT.md"))
	a := strings.Index(doc, "## Mutation operations")
	b := strings.Index(doc, "The structured JSON form")
	if a < 0 || b < a {
		t.Fatal("FORMAT.md lacks the mutation table")
	}
	var ops, targets []string
	seenT := map[string]bool{}
	for _, l := range strings.Split(doc[a:b], "\n") {
		cells := strings.Split(l, "|")
		if len(cells) < 6 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			continue
		}
		ops = append(ops, strings.Trim(strings.TrimSpace(cells[1]), "`"))
		for _, tg := range strings.Split(cells[2], ",") {
			tg = strings.Trim(strings.TrimSpace(tg), "`")
			if tg != "" && !seenT[tg] {
				seenT[tg] = true
				targets = append(targets, tg)
			}
		}
	}
	sort.Strings(ops)
	want := append([]string(nil), MutationOps...)
	sort.Strings(want)
	if strings.Join(ops, ",") != strings.Join(want, ",") {
		t.Fatalf("FORMAT.md ops %v, code %v", ops, want)
	}
	sort.Strings(targets)
	wt := append([]string(nil), MutationTargets...)
	sort.Strings(wt)
	if strings.Join(targets, ",") != strings.Join(wt, ",") {
		t.Fatalf("FORMAT.md targets %v, code %v", targets, wt)
	}
	for _, l := range reorderLists {
		if !strings.Contains(doc, "`"+l+"`") {
			t.Errorf("FORMAT.md does not name the reorder list %s", l)
		}
	}
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }
func ip(n int) *int                { return &n }

func TestMutationValidation(t *testing.T) {
	good := []Mutation{
		{Op: "set_byte", Target: "container", Offset: ip(3), Value: raw(`"ff"`)},
		{Op: "replace_hex", Target: "container", Offset: ip(0), Old: "43", New: "4344"},
		{Op: "truncate", Target: "container", Length: ip(0)},
		{Op: "append_hex", Target: "container", Value: raw(`"00"`)},
		{Op: "drop_node", Target: "container", Index: ip(0)},
		{Op: "add_node", Target: "container", Value: raw(`"aabb"`)},
		{Op: "reorder", Target: "container", List: "nodes"},
		{Op: "set_field", Target: "context", Path: "adi_url", Value: raw(`"x"`)},
		{Op: "set_field", Target: "manifest", Path: "policy.blsThreshold.numerator", Value: raw(`1`)},
		{Op: "unset_field", Target: "world", Path: "headers.0"},
	}
	for _, m := range good {
		if err := m.Validate(); err != nil {
			t.Errorf("%+v: %v", m, err)
		}
	}
	bad := []Mutation{
		{Op: "delete_everything", Target: "container"},
		{Op: "set_byte", Target: "context", Offset: ip(3), Value: raw(`"ff"`)},
		{Op: "set_byte", Target: "container", Offset: ip(-1), Value: raw(`"ff"`)},
		{Op: "set_byte", Target: "container", Offset: ip(1), Value: raw(`"fff"`)},
		{Op: "set_byte", Target: "container", Offset: ip(1), Value: raw(`"zz"`)},
		{Op: "set_byte", Target: "container", Offset: ip(1), Value: raw(`"ff"`), Index: ip(1)},
		{Op: "replace_hex", Target: "container", Offset: ip(0), Old: "", New: "00"},
		{Op: "truncate", Target: "container"},
		{Op: "truncate", Target: "container", Length: ip(2), Value: raw(`"00"`)},
		{Op: "append_hex", Target: "container", Value: raw(`"0"`)},
		{Op: "drop_node", Target: "container"},
		{Op: "add_node", Target: "container"},
		{Op: "reorder", Target: "container", List: "headers"},
		{Op: "set_field", Target: "chain", Path: "x", Value: raw(`1`)},
		{Op: "set_field", Target: "context", Value: raw(`1`)},
		{Op: "set_field", Target: "context", Path: "x"},
		{Op: "unset_field", Target: "context", Path: "x", Value: raw(`1`)},
		{Op: "unset_field", Target: "context"},
	}
	for _, m := range bad {
		if err := m.Validate(); err == nil {
			t.Errorf("%+v accepted", m)
		}
	}
}

// ---- sets on disk ----

func writeSet(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ci1-test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	sort.Strings(names)
	var m strings.Builder
	for _, n := range names {
		sum := sha256.Sum256([]byte(files[n]))
		m.WriteString(hex.EncodeToString(sum[:]) + "  " + n + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte(m.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const vecRefused = `{"id":"VS8-010","base":"H0","mutations":[{"op":"set_byte","target":"container","offset":3,"value":"32"}],
"expected":{"headline":"refused","states":[{"part":"first","code":"contract_identity_evidence_malformed","fields":{"part":"magic","index":"0","reason":"bad_magic","got_len":"0","want_len":"0"}}]}}`

func goodSet() map[string]string {
	return map[string]string{
		"world.json":                     `{"h0":true}`,
		"VS8-010.json":                   vecRefused,
		"VS8-012.truncate.json":          `{"id":"VS8-012.truncate","base":"H0","mutations":[{"op":"truncate","target":"container","length":5}],"expected":{"headline":"refused"}}`,
		"VS8-012.truncate.container.hex": "4349453100\n",
	}
}

func TestLoadVectorSet(t *testing.T) {
	set, err := LoadVectorSet(writeSet(t, goodSet()))
	if err != nil {
		t.Fatal(err)
	}
	if set.Name != "ci1-test" || len(set.Vectors) != 2 || set.Superseded || string(set.World) != `{"h0":true}` || len(set.Containers) != 1 || len(set.Containers["VS8-012.truncate"]) != 5 {
		t.Fatalf("set %+v", set)
	}
	if set.Vectors[1].SpecID() != "VS8-012" || set.Vectors[0].SpecID() != "VS8-010" {
		t.Fatalf("spec ids %s %s", set.Vectors[0].SpecID(), set.Vectors[1].SpecID())
	}
	files := goodSet()
	files["SUPERSEDED.md"] = "replaced by ci2\n"
	if s, err := LoadVectorSet(writeSet(t, files)); err != nil || !s.Superseded {
		t.Fatalf("superseded set: %v", err)
	}
}

func TestLoadVectorSetRefusesEditedOrMalformedSets(t *testing.T) {
	// edited after publication
	dir := writeSet(t, goodSet())
	if err := os.WriteFile(filepath.Join(dir, "VS8-010.json"), []byte(strings.Replace(vecRefused, `"32"`, `"33"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVectorSet(dir); err == nil || !strings.Contains(err.Error(), "never edited") {
		t.Fatalf("edited vector accepted: %v", err)
	}
	// an unlisted file
	dir = writeSet(t, goodSet())
	if err := os.WriteFile(filepath.Join(dir, "extra.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVectorSet(dir); err == nil {
		t.Fatal("unlisted file accepted")
	}
	// a listed file that is missing
	dir = writeSet(t, goodSet())
	if err := os.Remove(filepath.Join(dir, "VS8-010.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVectorSet(dir); err == nil {
		t.Fatal("missing file accepted")
	}
	// a directory inside
	dir = writeSet(t, goodSet())
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVectorSet(dir); err == nil {
		t.Fatal("directory accepted")
	}
	bad := map[string]map[string]string{
		"no world":          {"VS8-010.json": vecRefused},
		"world not json":    {"world.json": `{`, "VS8-010.json": vecRefused},
		"unknown op":        {"world.json": `{}`, "VS8-010.json": strings.Replace(vecRefused, "set_byte", "poke", 1)},
		"wrong base":        {"world.json": `{}`, "VS8-010.json": strings.Replace(vecRefused, `"H0"`, `"H1"`, 1)},
		"id/file mismatch":  {"world.json": `{}`, "VS8-011.json": vecRefused},
		"bad id":            {"world.json": `{}`, "VS8-10.json": strings.Replace(vecRefused, "VS8-010", "VS8-10", 1)},
		"unknown member":    {"world.json": `{}`, "VS8-010.json": strings.Replace(vecRefused, `"base"`, `"extra":1,"base"`, 1)},
		"headline outside":  {"world.json": `{}`, "VS8-010.json": strings.Replace(vecRefused, `"refused"`, `"fine"`, 1)},
		"unknown part":      {"world.json": `{}`, "VS8-010.json": strings.Replace(vecRefused, `"part":"first"`, `"part":"nowhere"`, 1)},
		"container no json": {"world.json": `{}`, "VS8-010.container.hex": "00"},
		"container not hex": {"world.json": `{}`, "VS8-010.json": vecRefused, "VS8-010.container.hex": "xyz"},
		"unexpected file":   {"world.json": `{}`, "notes.txt": "x"},
	}
	for name, files := range bad {
		if _, err := LoadVectorSet(writeSet(t, files)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// a MANIFEST line out of order or naming itself
	dir = writeSet(t, goodSet())
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte(strings.Repeat("0", 64)+"  b\n"+strings.Repeat("0", 64)+"  a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVectorSet(dir); err == nil {
		t.Fatal("unsorted MANIFEST accepted")
	}
	if _, err := LoadVectorSet(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("absent set accepted")
	}
}

// ---- running ----

type stubWorld struct{ err error }

func (w stubWorld) Build(world json.RawMessage, v Vector, container []byte) (Inputs, error) {
	m, _ := Embedded()
	return Inputs{Container: container, Manifest: m}, w.err
}

// refusedReport is the report a correct verifier gives for vecRefused.
func refusedReport(t *testing.T) Report {
	t.Helper()
	fw := Malformed(PartMagic, MalformedBadMagic, 0, 0, 0)
	h, err := ComputeHeadline(HeadlineInput{Framework: fw})
	if err != nil {
		t.Fatal(err)
	}
	return Report{Headline: h}
}

func TestRunSetNeverPassesWithoutAVerifier(t *testing.T) {
	set, err := LoadVectorSet(writeSet(t, goodSet()))
	if err != nil {
		t.Fatal(err)
	}
	for name, res := range map[string][]VectorResult{
		"no verifier":      RunSet(set, stubWorld{}, nil),
		"no world builder": RunSet(set, nil, VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return refusedReport(t), nil })),
		"neither":          RunSet(set, nil, nil),
	} {
		if len(res) != 2 {
			t.Fatalf("%s: %d results", name, len(res))
		}
		for _, r := range res {
			if r.Outcome != OutcomeNotRun {
				t.Errorf("%s: %s is %s", name, r.ID, r.Outcome)
			}
		}
	}
}

// An empty verifier (it answers with a zero Report, or with an error) makes ZERO vectors pass.
func TestEmptyVerifierPassesNothing(t *testing.T) {
	set, err := LoadVectorSet(writeSet(t, goodSet()))
	if err != nil {
		t.Fatal(err)
	}
	empty := VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return Report{}, nil })
	failing := VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return Report{}, errors.New("boom") })
	for name, ver := range map[string]Verifier{"empty report": empty, "error": failing} {
		for _, r := range RunSet(set, stubWorld{}, ver) {
			if r.Outcome == OutcomePass || r.Outcome != OutcomeFail {
				t.Errorf("%s: %s is %s", name, r.ID, r.Outcome)
			}
		}
	}
	for _, r := range RunSet(set, stubWorld{err: errors.New("no world")}, empty) {
		if r.Outcome != OutcomeFail || !strings.Contains(r.Detail, "world") {
			t.Errorf("world failure: %+v", r)
		}
	}
}

func TestRunSetPassesOnlyAMatchingReport(t *testing.T) {
	set, err := LoadVectorSet(writeSet(t, goodSet()))
	if err != nil {
		t.Fatal(err)
	}
	ok := refusedReport(t)
	right := VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return ok, nil })
	res := RunSet(set, stubWorld{}, right)
	// VS8-010 states the exact first refusal; VS8-012.truncate states only the headline
	for _, r := range res {
		if r.Outcome != OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	// the same report with a different first refusal fails the vector that names it, and only that one
	wrong := refusedReport(t)
	wrong.Headline.First = Malformed(PartMagic, MalformedTruncated, 0, 0, 4)
	res = RunSet(set, stubWorld{}, VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return wrong, nil }))
	if res[0].Outcome != OutcomeFail || res[1].Outcome != OutcomePass {
		t.Errorf("results %+v", res)
	}
	// a different headline kind fails both
	other := Report{Headline: Headline{Kind: HeadlineUnproven}}
	for _, r := range RunSet(set, stubWorld{}, VerifierFunc(func(LegContext, []byte, *Manifest) (Report, error) { return other, nil })) {
		if r.Outcome != OutcomeFail {
			t.Errorf("%s passed with the wrong headline", r.ID)
		}
	}
}

func TestMatchExpectedChecksPartsStatesAndOpenEntries(t *testing.T) {
	in := verifiedInput()
	in.Parts[2] = mkPart(JudgedCodeIdentity, StatusUnproven, false)
	h, err := ComputeHeadline(in)
	if err != nil || h.Kind != HeadlineUnproven {
		t.Fatalf("%+v %v", h, err)
	}
	r := Report{Headline: h, Parts: in.Parts}
	fields := `{"status":"0","reason":"settlement_not_executed"}`
	exp := Expected{Headline: HeadlineUnproven, Parts: map[string]string{"code_identity": "unproven", "pointer": "verified"},
		States: []ExpectedState{{Part: "code_identity", Code: CodeUnproven, Fields: raw(fields)}}}
	if err := MatchExpected(exp, r); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(e *Expected){
		"wrong part status": func(e *Expected) { e.Parts["pointer"] = "refused" },
		"unknown part":      func(e *Expected) { e.Parts = map[string]string{"nowhere": "verified"} },
		"wrong code":        func(e *Expected) { e.States[0].Code = CodeRefused },
		"wrong fields":      func(e *Expected) { e.States[0].Fields = raw(`{"status":"1","reason":"settlement_not_executed"}`) },
		"number for string": func(e *Expected) { e.States[0].Fields = raw(`{"status":0,"reason":"settlement_not_executed"}`) },
		"missing part":      func(e *Expected) { e.States[0].Part = "pointer" },
		"open expected":     func(e *Expected) { e.Open = []ExpectedOpen{{Part: "record", Kind: "alert", Code: CodeAlert}} },
	} {
		e := exp
		e.Parts = map[string]string{"code_identity": "unproven", "pointer": "verified"}
		e.States = append([]ExpectedState(nil), exp.States...)
		mod(&e)
		if err := MatchExpected(e, r); err == nil {
			t.Errorf("%s: matched", name)
		}
	}
	if err := MatchExpected(Expected{Headline: HeadlineUnproven}, Report{}); err == nil {
		t.Error("a report without a headline matched")
	}
	// open entries are compared exactly and in order
	rep := sampleReport(t)
	open := rep.OpenEntries()
	want := make([]ExpectedOpen, len(open))
	for i, o := range open {
		fb, _ := Canonical(o.State.Fields)
		want[i] = ExpectedOpen{Part: o.Part, Kind: o.Kind, Code: o.State.Code, Fields: fb}
	}
	if err := MatchExpected(Expected{Headline: HeadlineVerifiedCore, Open: want}, rep); err != nil {
		t.Fatal(err)
	}
	if err := MatchExpected(Expected{Headline: HeadlineVerifiedCore, Open: want[:1]}, rep); err == nil {
		t.Error("a shorter Open list matched")
	}
	want[0].Kind = "drift"
	if err := MatchExpected(Expected{Headline: HeadlineVerifiedCore, Open: want}, rep); err == nil {
		t.Error("a wrong Open kind matched")
	}
}
