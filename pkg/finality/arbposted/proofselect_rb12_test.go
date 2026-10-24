// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// The proof the build uses is the first one at or after the batch's own block: one the capturer took BELOW it (it tries the head and the two
// blocks under it) shows the slot still empty. Fail-before: the build used the lowest proof block and was refused.
func TestRB12ArbBuildSkipsAProofTakenBelowTheBatchBlock(t *testing.T) {
	f := bLoad(t)
	low := f.batch.L1Block - 1
	bad := capture.ProofRecord{Kind: capture.ProofBatchAcc, Index: f.ev.BatchSeq, ProofBlock: low, ProofBlockHash: common.Hash{0xbb}, Nodes: f.ev.Nodes[:1]}
	if err := f.store.Put(context.Background(), capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: low, L1Hash: bad.ProofBlockHash, Item: capture.ItemProof(f.ev.BatchSeq)}, bad.Encode()); err != nil {
		t.Fatal(err)
	}
	add, p, err := f.bBuilder().BuildFor(context.Background(), f.ref)
	if err != nil || p != nil {
		t.Fatalf("a proof below the batch's block was used: %v %s", err, bPend(p))
	}
	if !bytes.Equal(add.Evidence, f.evBytes) {
		t.Fatal("the build is not the recorded evidence")
	}
}
