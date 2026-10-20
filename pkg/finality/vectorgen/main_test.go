// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed finality_chain1 set is reproducible byte for byte from this generator: a vector is specification and is never
// edited by hand or re-baselined (a changed behaviour is a new set, finality_chain2).
func TestTheGeneratorReproducesTheCommittedSetByteForByte(t *testing.T) {
	tmp := t.TempDir()
	if err := generate(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "testdata", "finality_chain1")
	names, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 7 {
		t.Fatalf("the generator wrote %d files", len(names))
	}
	for _, e := range names {
		want, err := os.ReadFile(filepath.Join(committed, e.Name()))
		if err != nil {
			t.Fatalf("%s is generated but not committed: %v", e.Name(), err)
		}
		got, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the committed copy: the set is specification, never re-baselined", e.Name())
		}
	}
}

// finality_chain2 is reproducible byte for byte from the generator, chain1 and the registry.
func TestTheGeneratorReproducesTheCommittedChain2SetByteForByte(t *testing.T) {
	tmp := t.TempDir()
	if err := generate2(tmp, filepath.Join("..", "testdata", "finality_chain1"), filepath.Join("..", "testdata", "finality", "states.json")); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "testdata", "finality_chain2")
	names, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 11 {
		t.Fatalf("the generator wrote %d files", len(names))
	}
	for _, e := range names {
		want, err := os.ReadFile(filepath.Join(committed, e.Name()))
		if err != nil {
			t.Fatalf("%s is generated but not committed: %v", e.Name(), err)
		}
		got, _ := os.ReadFile(filepath.Join(tmp, e.Name()))
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the committed copy: the set is specification, never re-baselined", e.Name())
		}
	}
}
