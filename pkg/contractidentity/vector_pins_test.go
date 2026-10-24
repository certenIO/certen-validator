// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// PINS.json pins every file of every published vector set (the directories of testdata/contractidentity/vectors) by the plain sha256 of the file bytes
// (no domain-tag prefix; the file's domain field only labels the pin file with the contract-identity namespace). A published set is never edited: any changed, missing or extra file, and any set directory without a pin,
// fails the test. The per-set MANIFEST file is a pin inside the set and moves with it; PINS.json is the second, independent copy.

const pinsDomain = "certen:contract-identity:v1"

type vectorPins struct {
	Domain string                       `json:"domain"`
	Sets   map[string]map[string]string `json:"sets"`
}

func vectorsRoot() string { return filepath.Join("testdata", "contractidentity", "vectors") }

// publishedSetFiles reads every file of every set directory: set name -> slash path inside the set -> bytes.
func publishedSetFiles(t *testing.T, root string) map[string]map[string][]byte {
	t.Helper()
	out := map[string]map[string][]byte{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files := map[string][]byte{}
		base := filepath.Join(root, e.Name())
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil || d.IsDir() {
				return werr
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(base, p)
			files[filepath.ToSlash(rel)] = b
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = files
	}
	return out
}

// pinProblems compares the files with the pins and returns one line per difference (empty when they agree exactly).
func pinProblems(pins vectorPins, files map[string]map[string][]byte) []string {
	var out []string
	for set, fl := range files {
		pf, ok := pins.Sets[set]
		if !ok {
			out = append(out, "set "+set+" is published but not pinned")
			continue
		}
		for name, b := range fl {
			sum := sha256.Sum256(b)
			want, ok := pf[name]
			switch {
			case !ok:
				out = append(out, set+"/"+name+" is not pinned")
			case want != hex.EncodeToString(sum[:]):
				out = append(out, set+"/"+name+" differs from its pin")
			}
		}
		for name := range pf {
			if _, ok := fl[name]; !ok {
				out = append(out, set+"/"+name+" is pinned but missing")
			}
		}
	}
	for set := range pins.Sets {
		if _, ok := files[set]; !ok {
			out = append(out, "pinned set "+set+" is absent")
		}
	}
	sort.Strings(out)
	return out
}

func loadPins(t *testing.T) vectorPins {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsRoot(), "PINS.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins vectorPins
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pins); err != nil {
		t.Fatalf("PINS.json: %v", err)
	}
	if pins.Domain != pinsDomain || len(pins.Sets) == 0 {
		t.Fatalf("PINS.json domain %q with %d sets, want %q and at least one set", pins.Domain, len(pins.Sets), pinsDomain)
	}
	return pins
}

func TestPublishedVectorSetsMatchTheirPins(t *testing.T) {
	if p := pinProblems(loadPins(t), publishedSetFiles(t, vectorsRoot())); len(p) != 0 {
		t.Fatalf("the published vector sets differ from PINS.json (a published set is never edited):\n%s", strings.Join(p, "\n"))
	}
}

func TestPinCheckRejectsAFlippedByteAMissingFileAnExtraFileAndAnUnpinnedSet(t *testing.T) {
	pins := loadPins(t)
	clone := func() map[string]map[string][]byte {
		out := map[string]map[string][]byte{}
		for s, fl := range publishedSetFiles(t, vectorsRoot()) {
			out[s] = map[string][]byte{}
			for n, b := range fl {
				out[s][n] = append([]byte(nil), b...)
			}
		}
		return out
	}
	sets := make([]string, 0, len(pins.Sets))
	for s := range pins.Sets {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	for _, set := range sets {
		names := make([]string, 0, len(pins.Sets[set]))
		for n := range pins.Sets[set] {
			names = append(names, n)
		}
		sort.Strings(names)
		victim := names[len(names)/2]
		cases := []struct {
			name, want string
			mutate     func(map[string]map[string][]byte)
		}{
			{"flipped byte", victim + " differs from its pin", func(m map[string]map[string][]byte) { m[set][victim][len(m[set][victim])/2] ^= 1 }},
			{"missing file", victim + " is pinned but missing", func(m map[string]map[string][]byte) { delete(m[set], victim) }},
			{"extra file", "zz-extra.json is not pinned", func(m map[string]map[string][]byte) { m[set]["zz-extra.json"] = []byte("{}") }},
			{"absent set", "pinned set " + set + " is absent", func(m map[string]map[string][]byte) { delete(m, set) }},
		}
		for _, c := range cases {
			m := clone()
			c.mutate(m)
			p := strings.Join(pinProblems(pins, m), "\n")
			if !strings.Contains(p, c.want) {
				t.Errorf("%s: %s: problems %q do not contain %q", set, c.name, p, c.want)
			}
		}
	}
	m := clone()
	m["s8_unpinned_9"] = map[string][]byte{"MANIFEST": []byte("x")}
	if p := strings.Join(pinProblems(pins, m), "\n"); !strings.Contains(p, "set s8_unpinned_9 is published but not pinned") {
		t.Errorf("an unpinned set was not reported: %q", p)
	}
}
