package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed vectors of the two-voter UpdateAccountAuth suite are exactly what the generator writes (every file, the manifest and its
// hash), nothing committed is left over, and no earlier suite's file is among them.
func TestXPartition6VectorsAreReproducible(t *testing.T) {
	tmp := t.TempDir()
	if err := writeXPartition6(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "xpartition6")
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 17+2 {
		t.Fatalf("%d files written, want 17 vectors, the manifest and its hash", len(files))
	}
	written := map[string]bool{}
	for _, f := range files {
		written[f.Name()] = true
		a, _ := os.ReadFile(filepath.Join(tmp, f.Name()))
		b, err := os.ReadFile(filepath.Join(committed, f.Name()))
		if err != nil {
			t.Fatalf("%s is not committed: %v", f.Name(), err)
		}
		if !bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))) {
			t.Fatalf("%s differs from the committed vector", f.Name())
		}
	}
	kept, err := os.ReadDir(committed)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range kept {
		if f.Name() != ".gitattributes" && !written[f.Name()] {
			t.Fatalf("%s is committed but the generator does not write it", f.Name())
		}
	}
	for _, earlier := range []string{"valid-mixed-partition.json", "timeline-valid.json", "update-account-auth-add-op-authority-did-not-vote.json"} {
		if _, err := os.Stat(filepath.Join(tmp, earlier)); err == nil {
			t.Fatalf("an earlier suite's document %s was written", earlier)
		}
	}
}
