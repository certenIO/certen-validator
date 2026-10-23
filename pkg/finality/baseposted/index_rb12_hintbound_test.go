// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-FIX N1 (V-INDEX-2): the notes of late blocks are bounded by the SAME limits as every other work of a step (BlocksPerStep,
// StepBudget). The reviewer's probe put 60 noted blocks into one step whose limits allowed one and all 60 were processed (4,080 Gets).

func pendingHints(ix *Indexer) int {
	ix.hintMu.Lock()
	defer ix.hintMu.Unlock()
	return len(ix.hints)
}

func TestRB12ManyHintsInOneStepAreBounded(t *testing.T) {
	_, bp := idxPins(t)
	N := 60
	st := NewMemStore()
	meter := &meterStore{CaptureStore: st}
	ix := NewIndexer(meter, bp, 0, IndexConfig{StepBudget: time.Nanosecond, BlocksPerStep: 1, ReconcileEvery: 1 << 30})
	anchor := channelFrames("anchor", 1_790_000_000, 4, 1000, 1)
	vPutBlock(t, st, bp, 1005, []Frame{anchor[0]})
	for i := 0; i < 10; i++ {
		if _, err := ix.Step(context.Background(), 40_000); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < N; i++ {
		f := channelFrames(fmt.Sprintf("late%d", i), 1_790_100_000+uint64(i)*1000, 4, 1000, 1)
		vPutBlock(t, st, bp, 10_000+uint64(i)*7, []Frame{f[0]})
		ix.NoteLate(10_000 + uint64(i)*7)
	}
	meter.reset()
	rep, err := ix.Step(context.Background(), 40_000)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Late > 4 {
		t.Errorf("STEP BOUND VIOLATED: %d late blocks were processed in one step whose limits allow 1 (%d Gets)", rep.Late, meter.gets.Load())
	}
	if pendingHints(ix) == 0 {
		t.Error("the notes the step ran out of limits for stay noted for the next step")
	}
	// nothing is lost: the next steps drain the rest, each inside the same bound, and every noted block ends up indexed
	for i := 0; i < N+5 && pendingHints(ix) > 0; i++ {
		rep, err = ix.Step(context.Background(), 40_000)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Late > 4 {
			t.Fatalf("step %d processed %d late blocks", i, rep.Late)
		}
	}
	for i := 0; i < N; i++ {
		if !hasDigest(t, st, 10_000+uint64(i)*7) {
			t.Fatalf("noted block %d was never indexed", 10_000+uint64(i)*7)
		}
	}
}

// A hole of 687 blocks (the live holes: 229, 73 and 385) filled by the backfill and noted block by block is flushed over several steps; no
// step does more than its limits allow, and none holds the capture goroutine longer than the stated bound: the step budget plus the one
// block (and the one repair) it may finish after the budget ends.
func TestRB12HoleFlushOf687BlocksNeverBlocksTheCaptureLongerThanTheStatedBound(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	meter := &meterStore{CaptureStore: st}
	const perStep = 32
	budget := 200 * time.Millisecond
	ix := NewIndexer(meter, bp, 0, IndexConfig{StepBudget: budget, BlocksPerStep: perStep, ReconcileEvery: 1 << 30})
	anchor := channelFrames("anchor", 1_790_000_000, 4, 1000, 1)
	vPutBlock(t, st, bp, 1005, []Frame{anchor[0]})
	for i := 0; i < 3; i++ {
		if _, err := ix.Step(context.Background(), 30_000); err != nil {
			t.Fatal(err)
		}
	}
	// the hole 11976373..11976446 style: 687 consecutive blocks, a channel (two frames in two blocks) every third block
	first := uint64(20_000)
	for i := uint64(0); i < 687; i++ {
		b := first + i
		switch i % 3 {
		case 0:
			f := channelFrames(fmt.Sprintf("hole%d", i), 1_790_200_000+i*100, 4, first-5, 2)
			vPutBlock(t, st, bp, b, []Frame{f[0]})
			vPutBlock(t, st, bp, b+1, []Frame{f[1]})
		}
	}
	for i := uint64(0); i < 687; i++ {
		ix.NoteLate(first + i) // the backfill notes every block it fills, empty ones included
	}
	bound := budget + 2*time.Second
	steps, maxLate := 0, 0
	for ; pendingHints(ix) > 0 && steps < 200; steps++ {
		meter.reset()
		at := time.Now()
		rep, err := ix.Step(context.Background(), 30_000)
		if err != nil {
			t.Fatal(err)
		}
		if wall := time.Since(at); wall > bound {
			t.Fatalf("step %d held the capture goroutine for %s, bound %s", steps, wall, bound)
		}
		if rep.Late > perStep+2 {
			t.Fatalf("step %d processed %d late blocks, its limit is %d", steps, rep.Late, perStep)
		}
		if rep.Late > maxLate {
			maxLate = rep.Late
		}
	}
	if pendingHints(ix) != 0 {
		t.Fatalf("the flush did not finish in %d steps", steps)
	}
	if steps < 2 {
		t.Fatalf("687 notes cannot be one step of %d: %d steps", perStep, steps)
	}
	// every block of the hole that holds frames has its digest and every channel its entry
	for i := uint64(0); i < 687; i += 3 {
		if !hasDigest(t, st, first+i) || !hasDigest(t, st, first+i+1) || !entryClosingAt(t, st, first+i+1, chanLabelID(fmt.Sprintf("hole%d", i))) {
			t.Fatalf("hole block %d: the digests and the entry of its channel must exist after the flush", first+i)
		}
	}
	t.Logf("687 notes flushed in %d steps, at most %d late blocks per step", steps, maxLate)
}

// A note for a block that holds no captured inbox row costs one key listing and is dropped: nothing is digested and no repair is run for it.
func TestRB12NoteOfAnEmptyBlockIsDroppedWithoutAnIndexScan(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	meter := &meterStore{CaptureStore: st}
	ix := NewIndexer(meter, bp, 0, IndexConfig{ReconcileEvery: 1 << 30})
	anchor := channelFrames("anchor", 1_790_000_000, 4, 1000, 1)
	vPutBlock(t, st, bp, 1005, []Frame{anchor[0]})
	stepAll(t, ix, 30_000)
	for b := uint64(20_000); b < 20_050; b++ {
		ix.NoteLate(b)
	}
	meter.reset()
	rep, err := ix.Step(context.Background(), 30_000)
	if err != nil || rep.Late != 0 {
		t.Fatalf("an empty block is not a late block: %+v %v", rep, err)
	}
	if pendingHints(ix) != 0 {
		t.Fatalf("the 50 notes of empty blocks are dropped: %d left", pendingHints(ix))
	}
	if g := meter.gets.Load(); g > 5 {
		t.Fatalf("empty blocks must not cost digest or repair reads: %d Gets", g)
	}
}

// N3: a note the full set cannot take is counted (the rotation still covers the block).
func TestRB12ANoteDroppedAtTheCapIsCounted(t *testing.T) {
	metrics.RegisterMetrics()
	_, bp := idxPins(t)
	ix := NewIndexer(NewMemStore(), bp, 0, IndexConfig{})
	before, _ := vGather(t, "certen_finality_index_notes_dropped_total")
	for i := uint64(0); i < maxHints+25; i++ {
		ix.NoteLate(i)
	}
	after, ok := vGather(t, "certen_finality_index_notes_dropped_total")
	if !ok || after-before != 25 {
		t.Fatalf("25 notes past the cap are counted: %v -> %v (present %v)", before, after, ok)
	}
	if pendingHints(ix) != maxHints {
		t.Fatalf("the set holds %d notes, the cap is %d", pendingHints(ix), maxHints)
	}
}

// The backfill notes only blocks that hold inbox rows: a filled block with nothing to capture has no digest to make.
func TestRB12BackfillReportsOnlyTheBlocksItCaptured(t *testing.T) {
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blk, blob := blobBlock(t, kz, 1000, []byte("frame data"))
	ctx := context.Background()
	bf := NewMemStore()
	if err := finality.RecordGap(ctx, bf, uint64(Chain), 998, 1002, finality.GapStateProofUnavailable); err != nil {
		t.Fatal(err)
	}
	now, _ := bfClock()
	cap2 := &Capturer{Chain: uint64(Chain), Pins: newPins(), L1: &fakeL1{blk: blk}, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: bf, GenesisTime: 1655733600, SlotSeconds: 12}
	w := &Backfiller{Chain: uint64(Chain), Store: bf, Capturer: CapturerOf(cap2), Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	rep, err := w.Step(ctx, 10)
	if err != nil || rep.Filled != 5 {
		t.Fatalf("five blocks are filled: %+v %v", rep, err)
	}
	if len(rep.FilledBlocks) != 1 || rep.FilledBlocks[0] != 1000 {
		t.Fatalf("only block 1000 held inbox transactions, so only it is reported for the index: %v", rep.FilledBlocks)
	}
}
