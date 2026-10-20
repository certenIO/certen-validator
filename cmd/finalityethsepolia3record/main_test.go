// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const (
	set1Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia1"
	set3Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia3"
)

// The committed set regenerates byte-identically from set 1 and the embedded pins (the generator refuses any case whose production
// verdict differs from its hand-written one). With PV2_SET3_WRITE=<dir> the test writes the set there instead (how the set is made).
func TestSet3RegeneratesByteIdentically(t *testing.T) {
	if dir := os.Getenv("PV2_SET3_WRITE"); dir != "" {
		if err := run(set1Dir, dir); err != nil {
			t.Fatal(err)
		}
		return
	}
	tmp := t.TempDir()
	if err := run(set1Dir, tmp); err != nil {
		t.Fatal(err)
	}
	n := 0
	err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(tmp, p)
		want, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(set3Dir, rel))
		if err != nil {
			t.Errorf("%s: %v", rel, err)
		} else if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what the generator writes", rel)
		}
		n++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Fatalf("%d files regenerated", n)
	}
}
