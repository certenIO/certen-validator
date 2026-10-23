// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP, the Arbitrum capturer against the same policy. It never skips a batch EVENT (the cursor stops at a batch it could not
// capture), but a batch captured without its blobs or its accumulator proof was only re-examined after a restart if it lay within
// RebuildBlocks (7,200 L1 blocks, a day) of the head: after a longer outage the batch row stayed in the store with no blob rows and no
// proof row, nothing retried it and nothing recorded that it was incomplete. Now every batch is re-examined, an incomplete old batch is a
// durable capture gap (the framework's gap rows, at the batch's L1 block), retried at a bounded cadence, and closed by a fill row.

func TestRB12ArbBatchLeftIncompleteBeforeALongOutageIsRetriedAndRecordedAsAGapUntilItIsComplete(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
	sc.l1.proofErr = errors.New("down")
	c := newCapturer(sc, store)
	if _, err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if rows, _ := store.ListByRange(ctx, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "batch/"); len(rows) != 1 {
		t.Fatalf("the first run captured the batch event: %v", rows)
	}

	// the validator is down for days: the head is 50,000 blocks on (far beyond RebuildBlocks), and the providers work again
	const newHead = 995 + 50_000
	sc.l1.head = newHead
	for n := uint64(newHead - 5); n <= newHead; n++ {
		sc.l1.headers[n] = synthHeader(n, 1700000000+n*12, sc.l1.state.root, "")
	}
	sc.beacon.err, sc.l1.proofErr = nil, nil

	c2 := newCapturer(sc, store) // a new process over the same store
	rep, err := c2.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.BlobsStored != 1 || len(rep.Proofs) != 1 {
		t.Fatalf("the old batch was never re-examined after the restart: blobs stored %d, proofs %v (%+v)", rep.BlobsStored, rep.Proofs, rep.Errors)
	}
	// the incompleteness was recorded durably, at the batch's L1 block, and the completion closed it
	gaps, _ := store.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapItemPrefix)
	if len(gaps) != 2 {
		t.Fatalf("a gap row per missing part (blobs, proof) at the batch's L1 block: %v", gaps)
	}
	if open, err := finality.GapsIn(ctx, store, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock); err != nil || len(open) != 0 {
		t.Fatalf("complete again: no open gap, got %v %v", open, err)
	}
	if fills, _ := store.ListByRange(ctx, ChainArbitrumSepolia, 995, 995, finality.GapFillPrefix); len(fills) != 1 {
		t.Fatalf("the completion is a fill row: %v", fills)
	}
}

// While the old batch stays incomplete it is an OPEN gap and is retried at a bounded cadence, not every tick.
func TestRB12ArbOldIncompleteBatchStaysAnOpenGapAndIsRetriedAtABoundedCadence(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	sc := newScenario(t, LocBlob, 1)
	sc.beacon.err = &BeaconError{Slot: 1, Status: 404, Err: "not served"}
	sc.l1.proofErr = errors.New("down")
	if _, err := newCapturer(sc, store).Tick(ctx); err != nil {
		t.Fatal(err)
	}
	const newHead = 995 + 50_000
	sc.l1.head = newHead
	for n := uint64(newHead - 5); n <= newHead; n++ {
		sc.l1.headers[n] = synthHeader(n, 1700000000+n*12, sc.l1.state.root, "")
	}
	c2 := newCapturer(sc, store)
	calls0 := sc.beacon.calls
	for i := 0; i < 40; i++ {
		if _, err := c2.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	open, _ := finality.GapsIn(ctx, store, ChainArbitrumSepolia, 0, finality.MaxCaptureBlock)
	if len(open) != 1 || open[0].From != 995 || open[0].State != finality.GapOpen {
		t.Fatalf("the incomplete old batch is an open gap while the providers fail: %v", open)
	}
	if asks := sc.beacon.calls - calls0; asks == 0 || asks > 8 {
		t.Fatalf("the beacon was asked %d times in 40 ticks for one old incomplete batch: want a bounded cadence (more than once, far fewer than 40)", asks)
	}
}
