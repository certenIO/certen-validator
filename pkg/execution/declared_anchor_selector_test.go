// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB4-F9: consensus admits a leg only if it declares the call the batch path makes on its anchor.
// That call is packed here, from the batch ABI; the two must be the same selector.
func TestConsensusNamesTheCallTheBatchPathMakes(t *testing.T) {
	if !bytes.Equal(consensus.BatchAnchorCreateSelector[:], contracts.CreateBatchAnchorV8_2Selector[:]) {
		t.Fatalf("consensus admits 0x%x, the batch path calls 0x%x", consensus.BatchAnchorCreateSelector, contracts.CreateBatchAnchorV8_2Selector)
	}
	// The V8.2 seven-argument createBatchAnchor (RB5): the one the batch path packs (contracts.CertenAnchorV8_2Batch).
	if batchAnchorCreateSelector != "5d22872b" {
		t.Fatalf("the write-back names step 1 as %s, not createBatchAnchor", batchAnchorCreateSelector)
	}
}
