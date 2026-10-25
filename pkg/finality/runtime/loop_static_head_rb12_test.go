// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"
)

// RB12 OPS-A2 item 3 (ledger CG-3): Tick returned before retryFailed when the head had not moved, so a block that failed was never retried
// while no new block arrived. The retry is due by tick, not by head movement.
func TestRB12LoopRetriesAHeldBlockOnItsCadenceWhileTheHeadDoesNotMove(t *testing.T) {
	l1 := newRtProvingL1(t, 100)
	l1.failProofFor = map[uint64]int{99: 1} // the first proof of block 99 fails, the second works
	loop, mem := rtProvingLoop(t, l1)
	ctx := context.Background()
	if err := loop.Tick(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if fills := gapKeys(t, mem, "gapfill/"); len(fills) != 0 {
		t.Fatalf("block 99 is still open after its first attempt: %v", fills)
	}
	// the head stays at 100: the cursor is at the head, so nothing new is scanned, and the retry that is due at tick 2 must still run
	if err := loop.Tick(ctx, 2); err != nil {
		t.Fatal(err)
	}
	fills := gapKeys(t, mem, "gapfill/")
	if len(fills) != 1 || fills[0].L1Block != 99 || fills[0].L1Hash != l1.hashes[99] {
		t.Fatalf("the retry did not run while the head was static: %v", fills)
	}
}
