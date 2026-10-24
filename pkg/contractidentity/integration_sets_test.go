// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// Every published vector set is run through the REAL composed verifier (verify_default.go: steps of 2a, 2b-1, 2b-2, 2c; no stand-ins) from
// its materialised inputs, without the world builder. Whatever a package test accepted over a stand-in is judged here by the real steps.
func TestEveryPublishedSetRunsThroughTheComposedVerifier(t *testing.T) {
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join("testdata", "contractidentity", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "s8_") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) < 7 {
		t.Fatalf("expected the seven published sets, found %v", names)
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			set, err := ci.LoadVectorSet(setDir(name))
			if err != nil {
				t.Fatal(err)
			}
			pass := 0
			for _, r := range ci.RunSet(set, nil, ver) {
				if r.Outcome != ci.OutcomePass {
					t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
					continue
				}
				pass++
			}
			t.Logf("%s: %d of %d vectors pass", name, pass, len(set.Vectors))
		})
	}
}
