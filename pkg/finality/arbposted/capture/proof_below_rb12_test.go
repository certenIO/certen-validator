// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

func proofBlocks(t *testing.T, s CaptureStore, n uint64) []uint64 {
	t.Helper()
	keys, err := s.ListByRange(context.Background(), ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, ItemProof(n))
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, k := range keys {
		if k.Item == ItemProof(n) {
			out = append(out, k.L1Block)
		}
	}
	return out
}

// V-INDEX-B B2: a batch whose event is in the head block can only be proven at that block or later (the slot is empty in the state below it). The capturer
// tries the head and the two blocks under it; a proof taken BELOW the batch's block must neither be stored as the batch's proof nor clear its job nor count
// as present after a restart, or the batch is never proven again. Fail-before @d313b708: the head try fails, the proof is taken at head-1 and stored,
// the job is cleared, and a restart counts it as present.
func TestRB12AProofTakenBelowTheBatchBlockIsNotAProofAndTheJobStays(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.l1.head = 995 // the batch event is in the head block
	sc.l1.failAt = map[uint64]bool{995: true}
	c := newCapturer(sc, store)
	rep, err := c.Tick(ctx)
	if err != nil || len(rep.Proofs) != 0 {
		t.Fatalf("the head state is not served yet, yet a proof was stored: %+v %v", rep, err)
	}
	if got := proofBlocks(t, store, 77); len(got) != 0 {
		t.Fatalf("a proof row exists below the batch's block %d: %v", sc.rec.L1Block, got)
	}
	// the process restarts in between: the job is rebuilt from the rows, and the batch is still without a proof
	sc.l1.head, sc.l1.failAt = 997, nil
	c2 := newCapturer(sc, store)
	rep, err = c2.Tick(ctx)
	if err != nil || len(rep.Proofs) != 1 || rep.ProofBlock != 997 {
		t.Fatalf("after the restart the batch is proven at the new head: %+v %v", rep, err)
	}
	got := proofBlocks(t, store, 77)
	if len(got) != 1 || got[0] < sc.rec.L1Block {
		t.Fatalf("proof rows %v, want one at or after the batch's block %d", got, sc.rec.L1Block)
	}
}

// The live row shape (shape check J9): a proof row of N stored below the batch's block by the earlier code. A restart must not count it as a proof.
func TestRB12ARestartDoesNotCountAProofRowBelowTheBatchBlock(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.l1.head = 995
	sc.l1.failAt = map[uint64]bool{995: true, 994: true, 993: true}
	c := newCapturer(sc, store)
	if _, err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	// the earlier code's row: a proof of batch 77 taken at block 994
	h := sc.l1.headers[994]
	pr := ProofRecord{Kind: ProofBatchAcc, Index: 77, ProofBlock: 994, ProofBlockHash: h.Hash, Bridge: BridgeAddr, Nodes: [][]byte{{0xc0}}}
	if err := store.Put(ctx, Key{Chain: ChainArbitrumSepolia, L1Block: 994, L1Hash: h.Hash, Item: ItemProof(77)}, pr.Encode()); err != nil {
		t.Fatal(err)
	}
	sc.l1.head, sc.l1.failAt = 998, nil
	rep, err := newCapturer(sc, store).Tick(ctx)
	if err != nil || len(rep.Proofs) != 1 {
		t.Fatalf("a batch whose only proof row lies below its block is proven again after a restart: %+v %v", rep, err)
	}
	if got := proofBlocks(t, store, 77); len(got) != 2 || got[1] < sc.rec.L1Block {
		t.Fatalf("proof rows %v: the old row below the batch and a new one at or after it", got)
	}
}
