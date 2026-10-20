// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// vectorDir2 is the second published set (RB11-E1-FIX): the three review findings L1-L3. Set 1 and the force set are untouched.
const vectorDir2 = "testdata/finality_arb_final2"

// The manifest hashes every vector file of the set; the README is deliberately outside it (it only describes).
func TestSet2ManifestHashesEveryVectorFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir2, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want, err := os.ReadFile(filepath.Join(vectorDir2, "MANIFEST.json.sha256"))
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
	if _, ok := m.Files["vectors.json"]; !ok || len(m.Files) < 4 {
		t.Fatalf("manifest lists %d files: %v", len(m.Files), m.Files)
	}
	if _, ok := m.Files["README.md"]; ok {
		t.Fatal("README.md must stay outside the manifest")
	}
	for p, h := range m.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir2, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != h {
			t.Errorf("%s hashes to %x, manifest says %s", p, s, h)
		}
	}
}

// Every vector of set 2 yields exactly its literal expected verdict.
func TestSet2EveryVectorVerdict(t *testing.T) {
	f := loadSet(t, vectorDir2)
	groups := map[string]int{}
	for _, v := range f.Vectors {
		groups[v.Group]++
		got := outcome(arbfinal.New().Verify(pinsOf(t, f, v), legOf(t, v), evidenceOf(t, f, v)))
		if got != v.Expect {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, got, v.Expect)
		}
	}
	if len(f.Vectors) < 12 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	for _, g := range []string{"synthetic", "adversarial"} {
		if groups[g] == 0 {
			t.Errorf("no %s vectors", g)
		}
	}
}

// The valid vectors of set 2 go through the registry as the dispatcher does.
func TestSet2ValidVectorsThroughTheRegistry(t *testing.T) {
	f := loadSet(t, vectorDir2)
	reg := finality.NewRegistry()
	if err := arbfinal.Register(reg); err != nil {
		t.Fatal(err)
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
	if seen < 5 {
		t.Fatalf("%d valid vectors", seen)
	}
}
