// Copyright 2026 Certen Protocol

package adiri_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

const vectorDir = "testdata/finality_adiri1"

type vEdit struct {
	Offset int    `json:"offset"`
	Delete int    `json:"delete"`
	Insert string `json:"insert"`
}

type vLeg struct {
	Chain     uint64 `json:"chain"`
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	HeaderHex string `json:"header_hex"`
}

type vVec struct {
	Name     string          `json:"name"`
	Group    string          `json:"group"`
	Note     string          `json:"note"`
	Leg      vLeg            `json:"leg"`
	Pins     json.RawMessage `json:"pins"`
	Evidence string          `json:"evidence"`
	Base     string          `json:"base"`
	Edits    []vEdit         `json:"edits"`
	Expect   string          `json:"expect"`
}

type vFile struct {
	Format  string `json:"format"`
	Vectors []vVec `json:"vectors"`
}

func loadVectors(t testing.TB) vFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f vFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// evidenceOf resolves a vector's evidence bytes: its own file, or its base's with the edits applied (highest offset first).
func evidenceOf(t testing.TB, f vFile, v vVec) []byte {
	t.Helper()
	if v.Evidence != "" {
		b, err := os.ReadFile(filepath.Join(vectorDir, "evidence", v.Evidence))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var base *vVec
	for i := range f.Vectors {
		if f.Vectors[i].Name == v.Base {
			base = &f.Vectors[i]
		}
	}
	if base == nil {
		t.Fatalf("%s: base %q not found", v.Name, v.Base)
	}
	out := append([]byte(nil), evidenceOf(t, f, *base)...)
	es := append([]vEdit(nil), v.Edits...)
	sort.Slice(es, func(i, j int) bool { return es[i].Offset > es[j].Offset })
	for _, e := range es {
		ins, err := hex.DecodeString(e.Insert)
		if err != nil {
			t.Fatal(err)
		}
		out = append(append(append([]byte(nil), out[:e.Offset]...), ins...), out[e.Offset+e.Delete:]...)
	}
	return out
}

func pinsOf(t testing.TB, v vVec) *finality.Pins {
	t.Helper()
	var s string
	if json.Unmarshal(v.Pins, &s) == nil && s == "embedded" {
		p, err := finality.EmbeddedPins()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	return &finality.Pins{Format: finality.PinsFormat, PublishedUTC: "2026-10-20T00:00:00Z", Sections: map[string]json.RawMessage{"adiri": v.Pins}}
}

func legOf(t testing.TB, v vVec) finality.BlockRef {
	t.Helper()
	h, err := hex.DecodeString(strings.TrimPrefix(v.Leg.Hash, "0x"))
	if err != nil || len(h) != 32 {
		t.Fatalf("%s: leg hash", v.Name)
	}
	b := finality.BlockRef{Chain: v.Leg.Chain, Number: v.Leg.Number, Hash: [32]byte(h)}
	if v.Leg.HeaderHex != "" {
		if b.HeaderRLP, err = hex.DecodeString(v.Leg.HeaderHex); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// outcome is the canonical {code, fields} text of a verification: a verdict is code "finalized".
func outcome(v finality.Verdict, err error) string {
	if err != nil {
		if s, ok := finality.AsNamed(err); ok {
			return string(s.Canonical())
		}
		return "ERROR: " + err.Error()
	}
	return string(finality.NewState("finalized", flat(v.Fields)...).Canonical())
}

func flat(m map[string]any) []any {
	var kv []any
	for k, v := range m {
		kv = append(kv, k, v)
	}
	return kv
}

func TestManifestHashesEveryVectorFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want, err := os.ReadFile(filepath.Join(vectorDir, "MANIFEST.json.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json hashes to %x, MANIFEST.json.sha256 says %s", sum, want)
	}
	var m struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Files) < 4 {
		t.Fatalf("manifest lists %d files", len(m.Files))
	}
	for p, h := range m.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != h {
			t.Errorf("%s hashes to %x, manifest says %s", p, s, h)
		}
	}
}

// Every vector yields exactly its literal expected verdict, one by one AND batched, and the two modes agree on every vector.
func TestEveryVectorVerdictBothModesIdentical(t *testing.T) {
	f := loadVectors(t)
	if len(f.Vectors) < 30 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	groups := map[string]int{}
	for _, v := range f.Vectors {
		groups[v.Group]++
		ev := evidenceOf(t, f, v)
		pins := pinsOf(t, v)
		leg := legOf(t, v)
		one := &adiri.Verifier{Mode: adiri.ModeOneByOne}
		bat := &adiri.Verifier{Mode: adiri.ModeBatched}
		v1, e1 := one.Verify(pins, leg, ev)
		v2, e2 := bat.Verify(pins, leg, ev)
		g1, g2 := outcome(v1, e1), outcome(v2, e2)
		if g1 != g2 {
			t.Errorf("%s: one-by-one and batched disagree:\n one: %s\n bat: %s", v.Name, g1, g2)
		}
		if g1 != v.Expect {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, g1, v.Expect)
		}
	}
	for _, g := range []string{"live", "adversarial"} {
		if groups[g] == 0 {
			t.Errorf("no %s vectors", g)
		}
	}
}

// The live vectors' pins are the embedded adiri section byte for byte, and their evidence is a registered-kind container.
func TestLiveVectorsUseTheEmbeddedPinsAndTheRegistry(t *testing.T) {
	f := loadVectors(t)
	reg := finality.NewRegistry()
	if err := adiri.Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := adiri.Register(reg); err == nil {
		t.Fatal("a second registration of the kind must be refused")
	}
	seen := 0
	for _, v := range f.Vectors {
		if v.Group != "live" {
			continue
		}
		seen++
		ev := evidenceOf(t, f, v)
		leg := legOf(t, v)
		a := finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainAdiri, Kind: adiri.Name, Evidence: ev}
		got, err := reg.JudgeAddendum(leg, a, pinsOf(t, v))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got.Level != finality.LevelFinalized || got.Kind != adiri.Name {
			t.Fatalf("%s: %+v", v.Name, got)
		}
	}
	if seen < 3 {
		t.Fatalf("%d live vectors", seen)
	}
}
