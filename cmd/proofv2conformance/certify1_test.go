package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed vectors of the anchored-certify suite (RB9-F5) are exactly what the generator writes, byte for byte, with their manifest, its
// hash and the attributes that keep the bytes as they are; and the generator refuses to write a vector the Go verifier does not judge as the
// suite says (so a drifting verifier fails here, not silently in a regenerated file).
func TestCertify1VectorsAreReproducible(t *testing.T) {
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "certify1")
	names, err := os.ReadFile(filepath.Join(committed, "names.json"))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "names.json"), names, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeCertify1(tmp); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 25 {
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
}
