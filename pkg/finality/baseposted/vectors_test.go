// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	if m.Set != SetName || len(m.Cases) < 20 {
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
	if okCases < 3 {
		t.Fatalf("%d accepting cases", okCases)
	}
	_ = finality.CodePending
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
	if err := RegisterProver(reg, &Builder{}); err != nil {
		t.Fatal(err)
	}
	if got := reg.Provers(uint64(Chain)); len(got) != 1 || got[0].(finality.Ceilinged).Ceiling() != finality.LevelL1Posted {
		t.Fatalf("provers %v", got)
	}
	pinsRaw, _ := ReadFile(setDir, "pins/main.json")
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(setDir, "legs/a.json")
	var leg Leg
	_ = json.Unmarshal(legRaw, &leg)
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	hdr, _ := hex.DecodeString(strings.TrimPrefix(leg.Header, "0x"))
	hb, _ := hex.DecodeString(strings.TrimPrefix(leg.Hash, "0x"))
	var hash [32]byte
	copy(hash[:], hb)
	ev, _ := ReadFile(setDir, "evidence/valid_a.bin")
	ref := finality.BlockRef{Chain: uint64(Chain), Number: num, Hash: hash, HeaderRLP: hdr}
	v, err := reg.JudgeAddendum(ref, finality.Addendum{Level: finality.LevelL1Posted, Chain: uint64(Chain), Kind: KindName, Evidence: ev}, pins)
	if err != nil || v.Level != finality.LevelL1Posted || v.Fields["batch_type"] != uint64(0) {
		t.Fatalf("%+v %v", v, err)
	}
	// the same evidence stored at the finalized level is refused by the framework before the kind is asked
	_, err = reg.JudgeAddendum(ref, finality.Addendum{Level: finality.LevelFinalized, Chain: uint64(Chain), Kind: KindName, Evidence: ev}, pins)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "header.level"})
}
