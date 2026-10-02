package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// RB5-F28: a validator does not start without the tools every intent's governance proof needs.
func TestTheGovernanceToolsAreRequired(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "govproof")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := requireExecutable("GOV_PROOF_CLI_PATH", tool); err != nil {
		t.Fatalf("an executable tool: %v", err)
	}
	for name, path := range map[string]string{"unset": "", "missing": filepath.Join(dir, "nope"), "a directory": dir} {
		if err := requireExecutable("GOV_PROOF_CLI_PATH", path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		plain := filepath.Join(dir, "plain")
		if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := requireExecutable("TXHASH_CLI_PATH", plain); err == nil {
			t.Error("a file that is not executable: accepted")
		}
	}
}
