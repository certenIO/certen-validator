package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed certified-timeline vectors are exactly what the generator writes, and the first suite's files are not among them.
func TestXPartition2bVectorsAreReproducible(t *testing.T) {
	tmp := t.TempDir()
	if err := writeXPartition2b(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "xpartition2b")
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
	// None of the first suite's documents is rewritten by this mode.
	if _, err := os.Stat(filepath.Join(tmp, "valid-mixed-partition.json")); err == nil {
		t.Fatal("the first suite was written")
	}
}
