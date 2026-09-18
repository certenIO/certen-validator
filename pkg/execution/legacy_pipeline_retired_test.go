// Copyright 2026 Certen Protocol
//
// The shadow batch pipeline is retired by default. This test is the guard.

package execution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The legacy pipeline writes one anchor_batches row PER VALIDATOR per intent, with a merkle_root computed
// locally over pending blobs — a root published nowhere. Seven rows per intent, each disagreeing with the
// anchor actually on chain. Reading one produced the live claim that root d2d24ab3… was in transaction
// 0x9e4ff6ab…, which settled a different root.
//
// The canonical path replaced it, and every reader already filters bundle_id IS NOT NULL. What remained
// was that the rows kept being manufactured on every transaction.
//
// It is now off unless LEGACY_BATCH_PIPELINE=on. That default is the whole change, so it is worth a test:
// a wiring edit that restored the unconditional call would otherwise be invisible until someone counted
// rows in production, which is exactly how the original defect survived for months.
func TestLegacyBatchPipelineIsOffByDefault(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	text := string(src)

	const call = "intentDiscovery.SetBatchSystem("
	idx := strings.Index(text, call)
	if idx < 0 {
		// Deleting the call outright is the intended end state once the soak completes.
		t.Skip("SetBatchSystem is gone entirely; the legacy pipeline has been removed")
	}
	if strings.Count(text, call) != 1 {
		t.Fatalf("SetBatchSystem is called %d times; the legacy pipeline must have exactly one gated "+
			"call site", strings.Count(text, call))
	}

	// The gate must be the environment flag, and it must be an opt-IN. Looking only at the 400 bytes
	// before the call keeps this from passing because the flag is mentioned somewhere else in the file.
	from := idx - 400
	if from < 0 {
		from = 0
	}
	preceding := text[from:idx]

	if !strings.Contains(preceding, `os.Getenv("LEGACY_BATCH_PIPELINE")`) {
		t.Fatal("SetBatchSystem is not gated on LEGACY_BATCH_PIPELINE; every intent would resume writing " +
			"per-validator shadow anchor rows whose root is never published")
	}
	if !strings.Contains(preceding, `== "on"`) {
		t.Fatal(`the gate must be opt-in (== "on"). Any other comparison risks defaulting the retired ` +
			`pipeline back on.`)
	}
}
