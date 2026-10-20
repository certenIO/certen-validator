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
)

// finality_base_final2 is the second published vector set: the judge cases of the checks the independent review found absent (a zero
// output-root claim against a header without withdrawals root, an output-root header of another block, an ASR the pinned game build
// is not made for) and the respected-type-switched case of R11 Q5. Set 1 is never edited.
var setDir2 = filepath.Join("testdata", "finality_base_final2")

func TestVectorSetTwoManifestPinsEveryFileAndNothingElse(t *testing.T) {
	raw, err := ReadFile(setDir2, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ReadFile(setDir2, "MANIFEST.sha256")
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
	if m.Set != "finality_base_final2" || len(m.Cases) != 4 {
		t.Fatalf("set %q with %d cases", m.Set, len(m.Cases))
	}
	for name, h := range m.Files {
		b, err := ReadFile(setDir2, name)
		if err != nil {
			t.Fatal(err)
		}
		if FileSHA256(b) != h {
			t.Errorf("%s: manifest says %s, file hashes to %s", name, h, FileSHA256(b))
		}
	}
	onDisk := map[string]bool{}
	_ = filepath.WalkDir(setDir2, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(setDir2, p)
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

func TestEveryJudgeVectorOfSetTwoIsTheWrittenVerdict(t *testing.T) {
	raw, _ := ReadFile(setDir2, "manifest.json")
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	ids := append([]string(nil), m.Cases...)
	sort.Strings(ids)
	refused, accepted := 0, 0
	for _, id := range ids {
		b, err := ReadFile(setDir2, "judge/"+id+".json")
		if err != nil {
			t.Fatal(err)
		}
		var c JudgeCase
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		var e Expect
		if err := json.Unmarshal(c.Expect, &e); err != nil {
			t.Fatal(err)
		}
		got, err := c.Run(setDir2)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := ExpectBytes(e); !bytes.Equal(got, want) {
			t.Errorf("%s:\n want %s\n got  %s", id, want, got)
		}
		if e.Result == "ok" {
			accepted++
		} else {
			refused++
		}
	}
	if refused != 3 || accepted != 1 {
		t.Fatalf("%d refusals and %d accepted cases", refused, accepted)
	}
}
