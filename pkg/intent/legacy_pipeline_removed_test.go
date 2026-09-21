// Copyright 2026 Certen Protocol

package intent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The retired shadow batch pipeline wrote one anchor_batches row per validator per intent, over a merkle
// root published nowhere, and its HTTP entry point could still anchor on chain after the discovery routing
// was switched off. It is deleted; these guards keep it from coming back through the wiring.
func TestLegacyBatchPipelineIsGone(t *testing.T) {
	main := readSource(t, filepath.Join("..", "..", "main.go"))
	for _, gone := range []string{
		`"github.com/certen/independant-validator/pkg/batch"`,
		"intentDiscovery.SetBatchSystem(",
		"LEGACY_BATCH_PIPELINE",
		"/api/anchors/on-demand",
		"/api/attestations",
	} {
		if strings.Contains(main, gone) {
			t.Errorf("main.go still references %q", gone)
		}
	}
}

// With the legacy handlers unset, the multi-leg routing returned an error before consensus, so every
// multi-leg intent failed without entering the proof phases. A multi-leg intent must build its L1-L3
// chained proof and then run through consensus, exactly as a single-leg intent does.
func TestMultiLegIntentRunsThroughConsensus(t *testing.T) {
	src := readSource(t, "discovery.go")
	start := strings.Index(src, "func (id *IntentDiscovery) processMultiLegIntent(")
	if start < 0 {
		t.Fatal("processMultiLegIntent not found")
	}
	end := strings.Index(src[start:], "\n}\n")
	body := src[start : start+end]

	proofAt := strings.Index(body, "id.buildChainedCertenProof(")
	consensusAt := strings.Index(body, "id.executeCanonical(")
	if proofAt < 0 || consensusAt < 0 || proofAt > consensusAt {
		t.Fatal("a multi-leg intent must build its chained proof and then run through consensus")
	}
	for _, gone := range []string{"route", "batchCollector", "onDemandHandler", "GenerateG0"} {
		if strings.Contains(body, "id."+gone) {
			t.Errorf("processMultiLegIntent still calls id.%s...", gone)
		}
	}
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}
