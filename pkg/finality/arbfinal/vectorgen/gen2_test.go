// Copyright 2026 Certen Protocol

package main

import (
	"os"
	"testing"
)

// TestGenerateSet2 builds the second set. With ARBFINAL_OUT2 set it writes the set there; without it the set is built into a
// temporary directory, which fails if any expected literal differs from the verifier.
func TestGenerateSet2(t *testing.T) {
	out := os.Getenv("ARBFINAL_OUT2")
	if out == "" {
		out = t.TempDir()
	}
	if err := generate2(out); err != nil {
		t.Fatal(err)
	}
}
