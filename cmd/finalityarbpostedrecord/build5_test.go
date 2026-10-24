// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const set5Dir = "../../pkg/finality/arbposted/testdata/finality_arb_posted5"

// build5 is deterministic: it writes the committed vector set finality_arb_posted5 byte for byte. With PV2_BUILD5_OUT set the test
// writes the set into that directory (the way the set is regenerated where `go run` is not used); without it the set is built into a
// temporary directory and every file is compared with the committed one. build5 itself refuses a case whose verdict differs from the
// canonical literal written in synth5.go.
func TestBuild5WritesTheCommittedSetByteForByte(t *testing.T) {
	if out := os.Getenv("PV2_BUILD5_OUT"); out != "" {
		if err := build5(rawSet1, out); err != nil {
			t.Fatal(err)
		}
		return
	}
	tmp := t.TempDir()
	if err := build5(rawSet1, tmp); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		got, _ := os.ReadFile(p)
		want, err := os.ReadFile(filepath.Join(set5Dir, rel))
		if err != nil {
			t.Errorf("%s: not in the committed set: %v", rel, err)
			return nil
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the generator's bytes differ from the committed file", rel)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("only %d files generated", n)
	}
}
