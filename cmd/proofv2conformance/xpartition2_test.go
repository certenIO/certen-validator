package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed evidence 2.1 vectors are exactly what the generator writes: fixed seeds, deterministic encoding, so the files the
// TypeScript verifier copies are reproducible from this repository.
func TestXPartition2VectorsAreReproducible(t *testing.T) {
	tmp := t.TempDir()
	if err := writeXPartition2(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "xpartition2")
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 20 {
		t.Fatalf("only %d files", len(files))
	}
	for _, f := range files {
		a, _ := os.ReadFile(filepath.Join(tmp, f.Name()))
		b, err := os.ReadFile(filepath.Join(committed, f.Name()))
		if err != nil {
			t.Fatalf("%s is not committed: %v", f.Name(), err)
		}
		if !bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))) {
			t.Fatalf("%s differs from the committed vector", f.Name())
		}
	}
	// The 2.0 suite is not written by this mode.
	if _, err := os.Stat(filepath.Join(tmp, "valid.json.gz")); err == nil {
		t.Fatal("the 2.0 suite was written")
	}
}
