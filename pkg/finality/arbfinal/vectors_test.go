// Copyright 2026 Certen Protocol

package arbfinal_test

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
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// vectorDir is the published set. It is never edited: a change is a new set (finality_arb_final2) with a SUPERSEDED note.
const vectorDir = "testdata/finality_arb_final1"

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
	Name     string  `json:"name"`
	Group    string  `json:"group"`
	Note     string  `json:"note"`
	Leg      vLeg    `json:"leg"`
	Pins     string  `json:"pins"`
	Evidence string  `json:"evidence"`
	Base     string  `json:"base"`
	Edits    []vEdit `json:"edits"`
	Expect   string  `json:"expect"`
}

type vFile struct {
	dir     string
	Format  string `json:"format"`
	Vectors []vVec `json:"vectors"`
}

func loadSet(t testing.TB, dir string) vFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f vFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.dir = dir
	return f
}

// evidenceOf resolves a vector's evidence bytes: its own file, or its base's with the edits applied (highest offset first).
func evidenceOf(t testing.TB, f vFile, v vVec) []byte {
	t.Helper()
	if v.Evidence != "" {
		b, err := os.ReadFile(filepath.Join(f.dir, "evidence", v.Evidence))
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

// pinsOf resolves a vector's pins: "embedded", or the name of a full pins file of the set's pins/ directory.
func pinsOf(t testing.TB, f vFile, v vVec) *finality.Pins {
	t.Helper()
	if v.Pins == "embedded" {
		p, err := finality.EmbeddedPins()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	raw, err := os.ReadFile(filepath.Join(f.dir, "pins", v.Pins))
	if err != nil {
		t.Fatal(err)
	}
	p, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatalf("%s: pins %s: %v", v.Name, v.Pins, err)
	}
	return p
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
	var kv []any
	for k, val := range v.Fields {
		kv = append(kv, k, val)
	}
	return string(finality.NewState("finalized", kv...).Canonical())
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

// Every vector yields exactly its literal expected verdict.
func TestEveryVectorVerdict(t *testing.T) {
	f := loadSet(t, vectorDir)
	groups := map[string]int{}
	for _, v := range f.Vectors {
		groups[v.Group]++
		got := outcome(arbfinal.New().Verify(pinsOf(t, f, v), legOf(t, v), evidenceOf(t, f, v)))
		if got != v.Expect {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, got, v.Expect)
		}
	}
	if len(f.Vectors) < 80 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	for _, g := range []string{"synthetic", "adversarial"} {
		if groups[g] == 0 {
			t.Errorf("no %s vectors", g)
		}
	}
}

// The valid vectors go through the registry exactly as the dispatcher does, and a second registration is refused.
func TestValidVectorsThroughTheRegistry(t *testing.T) {
	f := loadSet(t, vectorDir)
	reg := finality.NewRegistry()
	if err := arbfinal.Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := arbfinal.Register(reg); err == nil {
		t.Fatal("a second registration of the kind must be refused")
	}
	seen := 0
	for _, v := range f.Vectors {
		if !strings.Contains(v.Expect, `"code":"finalized"`) {
			continue
		}
		seen++
		a := finality.Addendum{Level: finality.LevelFinalized, Chain: finality.ChainArbitrumSepolia, Kind: arbfinal.KindName, Evidence: evidenceOf(t, f, v)}
		got, err := reg.JudgeAddendum(legOf(t, v), a, pinsOf(t, f, v))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if got.Level != finality.LevelFinalized || got.Kind != arbfinal.KindName {
			t.Fatalf("%s: %+v", v.Name, got)
		}
	}
	if seen < 8 {
		t.Fatalf("%d valid vectors", seen)
	}
}
