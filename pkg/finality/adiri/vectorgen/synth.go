// Copyright 2026 Certen Protocol

package main

// synthetic returns the synthetic evidence files and vectors (filled in synth_chains.go).
func synthetic(keysDir string) (map[string][]byte, []vec) { return syntheticChains(keysDir) }
