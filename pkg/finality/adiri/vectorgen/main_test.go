// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The 34 adversarial vectors are mutations of the committed real evidence of block 513643: regenerating them offline from that
// file reproduces the committed vectors.json entries byte for byte (expected verdicts are literals written in adversarial.go).
// The synthetic vectors need the private test-key seed (gitignored keys/) and are not regenerated here.
func TestAdversarialSetRegeneratesOfflineFromTheCommittedBase(t *testing.T) {
	dir := filepath.Join("..", "testdata", "finality_adiri3")
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	committed := map[string]json.RawMessage{}
	var base vec
	for _, r := range file.Vectors {
		var v vec
		if err := json.Unmarshal(r, &v); err != nil {
			t.Fatal(err)
		}
		committed[v.Name] = r
		if v.Name == "live-513643-epoch651" {
			base = v
		}
	}
	ev, err := os.ReadFile(filepath.Join(dir, "evidence", "live-513643-epoch651.bin"))
	if err != nil {
		t.Fatal(err)
	}
	got := adversarial(base, ev, factsFromEvidence(ev))
	if len(got) != 34 {
		t.Fatalf("%d adversarial vectors", len(got))
	}
	for _, v := range got {
		want, ok := committed[v.Name]
		if !ok {
			t.Errorf("%s is not committed", v.Name)
			continue
		}
		have, _ := json.Marshal(v)
		var a, b any
		_ = json.Unmarshal(have, &a)
		_ = json.Unmarshal(want, &b)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if string(ja) != string(jb) {
			t.Errorf("%s: regenerated differs from the committed vector", v.Name)
		}
	}
}
