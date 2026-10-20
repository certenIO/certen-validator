package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed vectors of the robustness suite (RB9-L) are exactly what the generator writes, byte for byte, with their manifest, its
// hash and the attributes that keep the bytes as they are; and no file of an earlier suite is among them.
func TestRobust1VectorsAreReproducible(t *testing.T) {
	tmp := t.TempDir()
	if err := writeRobust1(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "robust1")
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 9 {
		t.Fatalf("only %d files", len(files))
	}
	for _, f := range files {
		a, err := os.ReadFile(filepath.Join(tmp, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(committed, f.Name()))
		if err != nil {
			t.Fatalf("%s is not committed: %v", f.Name(), err)
		}
		// Byte for byte: .gitattributes (* -text) keeps a checkout from rewriting line ends, and the manifest hashes the exact bytes.
		if !bytes.Equal(a, b) {
			t.Fatalf("%s differs from the committed vector", f.Name())
		}
	}
	committedFiles, err := os.ReadDir(committed)
	if err != nil {
		t.Fatal(err)
	}
	if len(committedFiles) != len(files) {
		t.Fatalf("the generator writes %d files, %d are committed", len(files), len(committedFiles))
	}
	for _, earlier := range []string{"valid-mixed-partition.json", "timeline-valid.json"} {
		if _, err := os.Stat(filepath.Join(tmp, earlier)); err == nil {
			t.Fatalf("an earlier suite's document %s was written", earlier)
		}
	}
}
