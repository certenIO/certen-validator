//go:build live

// Copyright 2026 Certen Protocol

// Behind the live build tag rather than a skip (00_STANDARD §2): without the tag it is not compiled;
// with it, the network is required.

package execution

import (
	"context"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
)

// RB3-F90: the L3 consensus time is the DN block's own time at the proof's consensus height, read from
// the chain. For intent 47b7e925 (written 2026-09-27 ~10:0xZ) that block is minutes after the write.
func TestLiveL3ConsensusTimeIsTheDNBlocksOwn(t *testing.T) {
	const endpoint = "https://kermit.accumulatenetwork.io/v3"
	cp, err := chained_proof.NewProofBuilder(jsonrpc.NewClient(endpoint), false).BuildProof(context.Background(),
		chained_proof.ProofInput{
			Account: "acc://certen-seq-1790497115.acme/data",
			TxHash:  "1578ff3372e0e17e2c726b5d98c4022cf44857d8df874fc4cb59cc195991c8d2",
			BVN:     "bvn1",
		})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	h := cp.Layer3.DNConsensusHeight
	ts, err := dnBlockTime(context.Background(), endpoint, h)
	if err != nil {
		t.Fatalf("DN block %d: %v", h, err)
	}
	t.Logf("DN block %d time %s", h, ts.Format(time.RFC3339Nano))
	lo := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	hi := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if ts.Before(lo) || ts.After(hi) {
		t.Fatalf("DN block %d time %s is not the time of the block that committed this proof's root", h, ts)
	}
	again, err := dnBlockTime(context.Background(), endpoint, h)
	if err != nil || !again.Equal(*ts) {
		t.Fatalf("the same block read twice gave %v then %v (%v)", ts, again, err)
	}
}
