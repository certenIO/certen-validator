// Copyright 2026 Certen Protocol

package contractidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// skWriteSet writes a published set directory: the files plus the MANIFEST of their sha256 lines.
func skWriteSet(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var man strings.Builder
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), files[n], 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(files[n])
		fmt.Fprintf(&man, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	if err := os.WriteFile(filepath.Join(dir, "MANIFEST"), []byte(man.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---- F8: a framework refusal of steps 0-1b has no s6 triple to print ----

func TestF8_FrameworkRefusalOfThePreludeNeedsNoS6(t *testing.T) {
	ctx, raw, m := skInputs(t)
	for name, mod := range map[string]func(c *LegContext){
		"s6 status empty (context_incomplete{s6})": func(c *LegContext) { c.S6Status = "" },
		"s6 status garbage":                        func(c *LegContext) { c.S6Status = "bogus" },
		"s6 silent without its reason":             func(c *LegContext) { c.S6Status, c.S6 = S6Silent, nil },
		"s6 not proven without its state":          func(c *LegContext) { c.S6Status, c.S6, c.S6State = S6NotProven, nil, "" },
	} {
		c := ctx
		mod(&c)
		rep, tr, rec, err := skRun(t, c, raw, m, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Headline.Kind != HeadlineRefused || rep.Headline.First.Code != CodeContextIncomplete || len(rec) != 0 || tr.Halt == nil {
			t.Fatalf("%s: headline %+v", name, rep.Headline)
		}
		if (rep.S6 != S6Report{}) {
			t.Errorf("%s: an invalid s6 triple was printed: %+v", name, rep.S6)
		}
		mp, err := rep.Map()
		if err != nil {
			t.Fatalf("%s: the report is not printable: %v", name, err)
		}
		if _, has := mp["s6"]; has {
			t.Errorf("%s: the s6 key is printed", name)
		}
		if _, err := rep.Canonical(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// a valid triple stays printed, also for a refusal of the prelude
	c := ctx
	c.Chain = 999
	rep, _, _, err := skRun(t, c, raw, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := rep.Map()
	if err != nil || mp["s6"] == nil || rep.S6.Status != S6Proven {
		t.Fatalf("valid triple: %v %v", mp["s6"], err)
	}
}

func TestF8_AbsentS6IsLegalOnlyForAnEarlyFrameworkRefusal(t *testing.T) {
	ctx, raw, m := skInputs(t)
	c := ctx
	c.S6Status = ""
	rep, _, _, err := skRun(t, c, raw, m, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("the early refusal: %v", err)
	}
	for name, mod := range map[string]func(r *Report){
		"with a part table":   func(r *Report) { r.Parts = []PartResult{{Part: JudgedPointer, Status: StatusVerified}} },
		"a judgement refusal": func(r *Report) { r.Headline.First = stRefused() },
		"a verified headline": func(r *Report) {
			r.Headline = Headline{Kind: HeadlineVerified, JudgedAtLevel: "finalized", RegistryLink: "via S9"}
		},
		"an unproven headline":             func(r *Report) { r.Headline = Headline{Kind: HeadlineUnproven, Parts: []string{JudgedPointer}} },
		"a half-filled triple":             func(r *Report) { r.S6 = S6Report{Reason: S6ReasonAbsent} },
		"a status with a foreign reason":   func(r *Report) { r.S6 = S6Report{Status: S6Proven, Reason: S6ReasonAbsent} },
		"silent with no reason (not zero)": func(r *Report) { r.S6 = S6Report{Status: S6Silent} },
	} {
		r := rep
		mod(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: an invalid report validated", name)
		}
	}
}

// ---- F12: set_pin ----

func TestF12_SetPinMutationShape(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	val := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	ok := Mutation{Op: "set_pin", Target: "manifest", Value: val(pin)}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	zero := 0
	for name, m := range map[string]Mutation{
		"container target": {Op: "set_pin", Target: "container", Value: val(pin)},
		"extension target": {Op: "set_pin", Target: "extension", Value: val(pin)},
		"no value":         {Op: "set_pin", Target: "manifest"},
		"short":            {Op: "set_pin", Target: "manifest", Value: val(pin[:62])},
		"upper case":       {Op: "set_pin", Target: "manifest", Value: val(strings.ToUpper(pin))},
		"0x prefix":        {Op: "set_pin", Target: "manifest", Value: val("0x" + pin[2:])},
		"not hex":          {Op: "set_pin", Target: "manifest", Value: val(strings.Repeat("zz", 32))},
		"a number":         {Op: "set_pin", Target: "manifest", Value: json.RawMessage(`7`)},
		"with a path":      {Op: "set_pin", Target: "manifest", Path: "x", Value: val(pin)},
		"with an offset":   {Op: "set_pin", Target: "manifest", Offset: &zero, Value: val(pin)},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// the other operations did not start accepting a value they do not use
	l := 1
	if err := (Mutation{Op: "truncate", Target: "container", Length: &l, Value: val(pin)}).Validate(); err == nil {
		t.Error("truncate with a value was accepted")
	}
}

// ---- F11: the materialised container has its own name ----

func TestF11_ReservedCaseNamesAndTheMaterialisedContainerName(t *testing.T) {
	for _, id := range []string{"VS8-170.inputs", "VS8-170.expected"} {
		if err := (Vector{ID: id, Base: "H0", Expected: Expected{Headline: HeadlineVerified}}).Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: %v", id, err)
		}
	}
	for _, id := range []string{"VS8-170", "VS8-170.input", "VS8-170.inputs2", "VS8-170.container"} {
		if err := (Vector{ID: id, Base: "H0", Expected: Expected{Headline: HeadlineVerified}}).Validate(); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	// Materialise names the container <id>.inputs.container.hex and writes no <id>.container.hex
	ctx, raw, _ := skInputs(t)
	files, err := Materialise("VS8-170", Inputs{Ctx: ctx, Container: raw, ManifestRaw: EmbeddedManifestBytes()}, Expected{Headline: HeadlineVerified})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["VS8-170.inputs.container.hex"]; !ok {
		t.Errorf("materialised files: %d", len(files))
	}
	if _, ok := files["VS8-170.container.hex"]; ok {
		t.Error("a vector-level container file was written for a materialised vector")
	}
	// a loader: an inputs.container.hex without its inputs.json is refused; a vector-level container.hex of the same id is kept apart
	dir := t.TempDir()
	vec, _ := json.Marshal(Vector{ID: "VS8-170", Base: "H0", Mutations: []Mutation{}, Expected: Expected{Headline: HeadlineVerified}})
	d1 := filepath.Join(dir, "orphan")
	skWriteSet(t, d1, map[string][]byte{"world.json": []byte("{}\n"), "VS8-170.json": append(vec, '\n'), "VS8-170.inputs.container.hex": []byte("00\n")})
	if _, err := LoadVectorSet(d1); err == nil || !strings.Contains(err.Error(), "inputs.container.hex has no") {
		t.Fatalf("orphan materialised container: %v", err)
	}
	d2 := filepath.Join(dir, "world-level")
	skWriteSet(t, d2, map[string][]byte{"world.json": []byte("{}\n"), "VS8-170.json": append(vec, '\n'), "VS8-170.container.hex": []byte("00\n")})
	set, err := LoadVectorSet(d2)
	if err != nil || len(set.Containers["VS8-170"]) != 1 || len(set.Inputs) != 0 {
		t.Fatalf("vector-level container: %v", err)
	}
}
