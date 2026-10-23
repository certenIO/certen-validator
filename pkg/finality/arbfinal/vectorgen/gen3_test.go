// Copyright 2026 Certen Protocol

package main

import (
	"os"
	"testing"
)

// TestGenerateSet3 builds the third set. With ARBFINAL_OUT3 set it writes the set there; without it the set is built into a temporary
// directory, which fails if any expected literal differs from the verifier.
func TestGenerateSet3(t *testing.T) {
	out := os.Getenv("ARBFINAL_OUT3")
	if out == "" {
		out = t.TempDir()
	}
	if err := generate3(out); err != nil {
		t.Fatal(err)
	}
}
