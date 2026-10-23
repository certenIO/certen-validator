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

// vectorDir3 is the third published set (RB12-E1RAISE): the wallet route proven. Sets 1 and 2 and the force set are untouched.
const vectorDir3 = "testdata/finality_arb_final3"

// The manifest hashes every vector file of the set; the README is deliberately outside it (it only describes).
func TestSet3ManifestHashesEveryVectorFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir3, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want, err := os.ReadFile(filepath.Join(vectorDir3, "MANIFEST.json.sha256"))
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
		t.Fatalf("manifest lists %d files", len(m.Files))
	}
	if _, ok := m.Files["README.md"]; ok {
		t.Fatal("README.md must stay outside the manifest")
	}
	for p, h := range m.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir3, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != h {
			t.Errorf("%s hashes to %x, manifest says %s", p, s, h)
		}
	}
}

// Every vector of set 3 yields exactly its literal expected verdict.
func TestSet3EveryVectorVerdict(t *testing.T) {
	f := loadSet(t, vectorDir3)
	groups := map[string]int{}
	var wallet, indirect, pinsMismatch int
	for _, v := range f.Vectors {
		groups[v.Group]++
		got := outcome(arbfinal.New().Verify(pinsOf(t, f, v), legOf(t, v), evidenceOf(t, f, v)))
		if got != v.Expect {
			t.Errorf("%s (%s):\n got:  %s\n want: %s", v.Name, v.Note, got, v.Expect)
		}
		switch {
		case strings.Contains(v.Expect, `"confirmation_route":"wallet"`):
			wallet++
		case strings.Contains(v.Expect, `"reason":"indirect"`):
			indirect++
		case strings.Contains(v.Expect, `"code":"pin_mismatch"`):
			pinsMismatch++
		}
	}
	if len(f.Vectors) < 80 {
		t.Fatalf("only %d vectors", len(f.Vectors))
	}
	for _, g := range []string{"synthetic", "adversarial", "live"} {
		if groups[g] == 0 {
			t.Errorf("no %s vectors", g)
		}
	}
	if wallet < 6 || indirect < 30 || pinsMismatch < 10 {
		t.Errorf("wallet-accepted %d (want >= 6), indirect %d (want >= 30), pin_mismatch %d (want >= 10)", wallet, indirect, pinsMismatch)
	}
}

// The valid vectors of set 3 go through the registry as the dispatcher does.
func TestSet3ValidVectorsThroughTheRegistry(t *testing.T) {
	f := loadSet(t, vectorDir3)
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
	if seen < 8 {
		t.Fatalf("%d valid vectors", seen)
	}
}
