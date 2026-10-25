// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A published set reproduces from its own committed inputs (RB12 OPS-A2 item 19): build2 and build3 write the committed sets
// finality_arb_posted2 and finality_arb_posted3 byte for byte, from the raw capture of set 1 and the pins the sets were published with
// (pins_input.go), however far the live embedded pins have grown since.
func TestBuild2And3WriteTheCommittedSetsByteForByte(t *testing.T) {
	for _, c := range []struct {
		name  string
		build func(rawDir, out string) error
		dir   string
	}{
		{"finality_arb_posted2", build2, "../../pkg/finality/arbposted/testdata/finality_arb_posted2"},
		{"finality_arb_posted3", build3, "../../pkg/finality/arbposted/testdata/finality_arb_posted3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			if err := c.build(rawSet1, tmp); err != nil {
				t.Fatal(err)
			}
			n := 0
			err := filepath.Walk(tmp, func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				rel, _ := filepath.Rel(tmp, p)
				got, _ := os.ReadFile(p)
				want, err := os.ReadFile(filepath.Join(c.dir, rel))
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
			if n < 10 {
				t.Fatalf("only %d files generated", n)
			}
		})
	}
}
