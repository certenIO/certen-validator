// Copyright 2026 Certen Protocol

package execution

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// RB3-F36: the BLS ZK prover runs only on the keys whose verification key is deployed. Missing keys are an
// error naming the file - never freshly generated keys, whose proofs verify locally and revert on chain.
func TestTheProverNeverGeneratesKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BLS_ZK_KEYS_DIR", dir)
	reset := func() { blsZKProverOnce, blsZKProver, blsZKProverErr = sync.Once{}, nil, nil }
	reset()
	t.Cleanup(reset)

	if _, err := GetBLSZKProver(); err == nil || !strings.Contains(err.Error(), "proving_key.bin") {
		t.Fatalf("no key files: %v", err)
	}
	// Present but unloadable: an error, not a generated key.
	for _, f := range []string{"proving_key.bin", "verification_key.bin", "constraint_system.bin"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("not a key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	if _, err := GetBLSZKProver(); err == nil || !strings.Contains(err.Error(), "could not be loaded") {
		t.Fatalf("unloadable key files: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 3 {
		t.Fatalf("the key directory was written to: %d entries", len(entries))
	}
}
