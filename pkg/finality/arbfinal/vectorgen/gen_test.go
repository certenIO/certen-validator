// Copyright 2026 Certen Protocol

package main

import (
	"os"
	"testing"
)

// TestGenerate builds the whole set. With ARBFINAL_OUT set it writes the set there (and ARBFINAL_LIVE adds the real vectors);
// without it the set is built into a temporary directory, which fails if any expected literal differs from the verifier.
func TestGenerate(t *testing.T) {
	out := os.Getenv("ARBFINAL_OUT")
	if out == "" {
		out = t.TempDir()
	}
	if err := generate(out, os.Getenv("ARBFINAL_LIVE")); err != nil {
		t.Fatal(err)
	}
}
