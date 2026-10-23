// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"
)

// A block filled FAR below the cursor by the backfill (a hint from the loop that filled it) is indexed by the next step, whichever end of the
// channel the hole was, with no walk of the table.
func TestRB12BackfilledBlockBelowTheCursorCompletesItsChannelByHint(t *testing.T) {
	_, bp := idxPins(t)
	for _, c := range []struct {
		name         string
		holeFirst    bool // the hole holds the FIRST frame (the channel closes in a captured block); else the hole holds the closing frame
		holeBlock    uint64
		closingBlock uint64
	}{
		{"hole holds the closing frame", false, 1012, 1012},
		{"hole holds the first frame", true, 1010, 1012},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := NewMemStore()
			A := channelFrames("A", 1_790_300_000, 30, 1000, 2)
			if c.holeFirst {
				vPutBlock(t, st, bp, 1012, []Frame{A[1]})
			} else {
				vPutBlock(t, st, bp, 1010, []Frame{A[0]})
			}
			ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1 << 30, ReconcileSpan: 16})
			stepAll(t, ix, 30_000) // the cursor is 29,000 blocks past the hole
			if entryClosingAt(t, st, c.closingBlock, chanLabelID("A")) {
				t.Fatal("the channel is not complete yet")
			}
			if c.holeFirst {
				vPutBlock(t, st, bp, 1010, []Frame{A[0]})
			} else {
				vPutBlock(t, st, bp, 1012, []Frame{A[1]})
			}
			// control: with no hint and no scheduled reconcile nothing notices the filled block (the rotation is what the hint short-circuits)
			stepAll(t, ix, 30_000)
			if hasDigest(t, st, c.holeBlock) {
				t.Fatal("control: the walk is not scheduled, so the block must still be unindexed here")
			}
			ix.NoteLate(c.holeBlock)
			ix.NoteLate(60_000) // a hint above the cursor is the forward step's business and is harmless
			stepAll(t, ix, 30_000)
			if !hasDigest(t, st, c.holeBlock) || !entryClosingAt(t, st, c.closingBlock, chanLabelID("A")) {
				t.Fatalf("the filled block must have its digest (%v) and its channel's entry at the closing block %d", hasDigest(t, st, c.holeBlock), c.closingBlock)
			}
			// and the leg is served from the index
			ts := uint64(1_790_300_000 + 4)
			hit, _, err := NewIndexReader(st, bp, 0).Find(context.Background(), ts, 1000, 1000+bp.SeqWindowSize, &ioCount{})
			if err != nil || hit == nil || hit.entry.ID != chanLabelID("A") {
				t.Fatalf("the completed channel serves its leg: %v %v", hit, err)
			}
		})
	}
}
