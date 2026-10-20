// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

var setDir = filepath.Join("testdata", SetName)

type manifest struct {
	Format string            `json:"format"`
	Set    string            `json:"set"`
	Cases  []string          `json:"cases"`
	Files  map[string]string `json:"files"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	raw, err := ReadFile(setDir, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir, "MANIFEST.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != FileSHA256(raw) {
		t.Fatalf("MANIFEST.sha256 %s, manifest hashes to %s", strings.TrimSpace(string(want)), FileSHA256(raw))
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestVectorSetManifestPinsEveryFileAndNothingElse(t *testing.T) {
	m := loadManifest(t)
	if m.Set != SetName || len(m.Cases) < 12 {
		t.Fatalf("set %q with %d cases", m.Set, len(m.Cases))
	}
	for name, h := range m.Files {
		b, err := ReadFile(setDir, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
	}
	onDisk := map[string]bool{}
	_ = filepath.WalkDir(setDir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(setDir, p)
			rel = filepath.ToSlash(rel)
			if rel != "manifest.json" && rel != "MANIFEST.sha256" && rel != ".gitattributes" {
				onDisk[rel] = true
			}
		}
		return nil
	})
	for n := range onDisk {
		if _, ok := m.Files[n]; !ok {
			t.Errorf("%s is in the set directory but not in the manifest", n)
		}
	}
	for n := range m.Files {
		if !onDisk[n] {
			t.Errorf("%s is in the manifest but not on disk", n)
		}
	}
}

type regState struct {
	Required []string            `json:"required"`
	Optional []string            `json:"optional"`
	Enums    map[string][]string `json:"enums"`
}

func loadRegistry(t *testing.T) map[string]regState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		States map[string]regState `json:"states"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r.States
}

func TestEveryVectorVerdictIsTheHandWrittenOneAndEveryStateIsRegistered(t *testing.T) {
	m := loadManifest(t)
	reg := loadRegistry(t)
	ids := append([]string(nil), m.Cases...)
	sort.Strings(ids)
	okCases := 0
	for _, id := range ids {
		raw, err := ReadFile(setDir, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		got, err := c.Run(setDir)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := ExpectBytes(e); !bytes.Equal(got, want) {
			t.Errorf("%s:\n want %s\n got  %s", id, want, got)
		}
		if e.Result == "ok" {
			okCases++
			continue
		}
		rs, ok := reg[e.Code]
		if !ok {
			t.Errorf("%s: code %s is not in the registry", id, e.Code)
			continue
		}
		var fields map[string]string
		_ = json.Unmarshal(e.Fields, &fields)
		allowed := map[string]bool{}
		for _, f := range append(append([]string(nil), rs.Required...), rs.Optional...) {
			allowed[f] = true
		}
		for _, f := range rs.Required {
			if _, ok := fields[f]; !ok {
				t.Errorf("%s: %s lacks required field %s", id, e.Code, f)
			}
		}
		for f, v := range fields {
			if !allowed[f] {
				t.Errorf("%s: %s carries unregistered field %s", id, e.Code, f)
			}
			if set, ok := rs.Enums[f]; ok {
				found := false
				for _, x := range set {
					found = found || x == v
				}
				if !found {
					t.Errorf("%s: %s.%s = %q is outside the closed set %v", id, e.Code, f, v, set)
				}
			}
		}
	}
	if okCases < 2 {
		t.Fatalf("%d accepting cases", okCases)
	}
}

// The kind is reached the way the framework reaches it: through the registry's JudgeAddendum, which first checks the container
// header against the addendum and the leg.
func TestTheRegisteredKindJudgesTheLiveEvidenceThroughTheFramework(t *testing.T) {
	reg := finality.NewRegistry()
	if err := Register(reg); err != nil {
		t.Fatal(err)
	}
	if err := Register(reg); err == nil {
		t.Fatal("a second verifier for the same kind must be refused")
	}
	m := loadManifest(t)
	var judged int
	for _, id := range m.Cases {
		raw, err := ReadFile(setDir, "cases/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c Case
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		if e.Result != "ok" || c.Splice != nil {
			continue
		}
		pinsRaw, _ := ReadFile(setDir, c.Pins)
		pins, err := finality.ParsePinsOverride(pinsRaw)
		if err != nil {
			t.Fatal(err)
		}
		legRaw, _ := ReadFile(setDir, c.Leg)
		var leg Leg
		_ = json.Unmarshal(legRaw, &leg)
		b := leg.BlockRef(t)
		ev, _ := ReadFile(setDir, c.Base)
		v, err := reg.JudgeAddendum(b, finality.Addendum{Seq: 1, Level: finality.LevelFinalized, Chain: uint64(Chain), Kind: KindName, Evidence: ev}, pins)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if v.Level != finality.LevelFinalized || v.Kind != KindName {
			t.Fatalf("%s: %+v", id, v)
		}
		judged++
	}
	if judged == 0 {
		t.Fatal("no accepting case was judged")
	}
}
