// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

// RB4-F9: consensus admits a leg only if it declares the call the batch path makes on its anchor.
// That call is packed here, from the batch ABI; the two must be the same selector.
func TestConsensusNamesTheCallTheBatchPathMakes(t *testing.T) {
	if !bytes.Equal(consensus.BatchAnchorCreateSelector[:], createBatchAnchorMethod.ID) {
		t.Fatalf("consensus admits 0x%x, the batch path calls 0x%x", consensus.BatchAnchorCreateSelector, createBatchAnchorMethod.ID)
	}
	if batchAnchorCreateSelector != "34597e5a" {
		t.Fatalf("the write-back names step 1 as %s, not createBatchAnchor", batchAnchorCreateSelector)
	}
}
