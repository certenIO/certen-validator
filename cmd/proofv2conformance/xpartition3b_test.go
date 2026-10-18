package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed vectors of the roles / executor-version / budget suite are exactly what the generator writes, and no earlier suite's
// file is among them.
func TestXPartition3bVectorsAreReproducible(t *testing.T) {
	tmp := t.TempDir()
	if err := writeXPartition3b(tmp); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "pkg", "proof", "v2", "testdata", "xpartition3b")
	files, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
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
	for _, earlier := range []string{"valid-mixed-partition.json", "timeline-valid.json"} {
		if _, err := os.Stat(filepath.Join(tmp, earlier)); err == nil {
			t.Fatalf("an earlier suite's document %s was written", earlier)
		}
	}
}
