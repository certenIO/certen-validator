// Copyright 2026 Certen Protocol

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// finality_adiri5 is hand-built from one test-key seed: building it twice from the same seed gives the same MANIFEST (BLS
// signatures, headers and state roots are deterministic), and it has exactly the vectors the README lists. The committed set is
// written by running this test with ADIRI5_OUT (the output directory) and ADIRI5_KEYS (the gitignored directory holding the seed):
// the vectors are specification, so a build from another seed is a different set.
func TestAdiri5BuildsDeterministicallyFromOneSeed(t *testing.T) {
	base := filepath.Join("..", "testdata", "finality_adiri3")
	keys := t.TempDir()
	a, b := t.TempDir(), t.TempDir()
	if err := writeAdiri5(a, keys, base); err != nil {
		t.Fatal(err)
	}
	if err := writeAdiri5(b, keys, base); err != nil {
		t.Fatal(err)
	}
	ma, err := os.ReadFile(filepath.Join(a, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(filepath.Join(b, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ma) != string(mb) {
		t.Fatal("two builds from one seed differ")
	}
	if got := len(slotCases()); got != 10 {
		t.Fatalf("%d slot vectors", got)
	}
	if out := os.Getenv("ADIRI5_OUT"); out != "" {
		if err := writeAdiri5(out, os.Getenv("ADIRI5_KEYS"), base); err != nil {
			t.Fatal(err)
		}
	}
}
