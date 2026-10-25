// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

const (
	set1Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia1"
	set3Dir = "../../pkg/finality/ethsepolia/testdata/finality_eth_sepolia3"
)

// committedPins is the pins/embedded.json the set was published with: the set is reproduced from its own committed input, so growing the
// live embedded pins never turns this test red (RB12 OPS-A2 item 19).
func committedPins(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(set3Dir, "pins", "embedded.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The committed set regenerates byte-identically from set 1 and the embedded pins (the generator refuses any case whose production
// verdict differs from its hand-written one). With PV2_SET3_WRITE=<dir> the test writes the set there instead (how the set is made).
func TestSet3RegeneratesByteIdentically(t *testing.T) {
	if dir := os.Getenv("PV2_SET3_WRITE"); dir != "" {
		if err := run(set1Dir, dir, finality.EmbeddedPinsBytes()); err != nil {
			t.Fatal(err)
		}
		return
	}
	tmp := t.TempDir()
	if err := run(set1Dir, tmp, committedPins(t)); err != nil {
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
