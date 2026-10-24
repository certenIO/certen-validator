// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// RB12-INDEX-FIX (V-INDEX-3 L1-L3): the late work of a step is bounded by the SAME block limit as the forward work (one count), the repair of
// the entries around the noted blocks costs the cluster of notes and never the distance between them, and the time bound is checked against
// a clock that can fail it.

func uniqueFrame(label string, ts uint64) []Frame {
	return channelFrames(label, ts, 2, 1000, 1)
}

// L1: 5 new forward blocks and 40 noted late blocks in a step whose limit is 8 blocks: the step works on at most 8 (plus the one free pass),
// not 8 forward plus 8 late.
func TestRB12ForwardAndLateWorkShareOneBlockLimit(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	ix := NewIndexer(st, bp, 0, IndexConfig{BlocksPerStep: 8, StepBudget: time.Hour, ReconcileEvery: 1 << 30})
	vPutBlock(t, st, bp, 1005, uniqueFrame("anchor", 1_790_000_000))
	stepAll(t, ix, 40_000)
	for i := 0; i < 40; i++ {
		b := 10_000 + uint64(i)*7
		vPutBlock(t, st, bp, b, uniqueFrame(fmt.Sprintf("late%d", i), 1_790_100_000+uint64(i)*100))
		ix.NoteLate(b)
	}
	for i := 0; i < 5; i++ {
		vPutBlock(t, st, bp, 40_010+uint64(i)*10, uniqueFrame(fmt.Sprintf("fwd%d", i), 1_790_900_000+uint64(i)*100))
	}
	rep, err := ix.Step(context.Background(), 41_000)
	if err != nil {
		t.Fatal(err)
	}
	// rep.Blocks counts every digest the step wrote, forward or late; 5 are forward, so at most 3 (+1 free pass) may be late
	if rep.Late == 0 || rep.Blocks > 8+1 {
		t.Fatalf("STEP BOUND VIOLATED: %d digests written (%d of them late) in a step whose limit is 8 (+1 free pass)", rep.Blocks, rep.Late)
	}
	for i := 0; i < 60 && pendingHints(ix) > 0; i++ { // nothing is lost, and no later step exceeds the limit either
		rep, err = ix.Step(context.Background(), 41_000)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Blocks > 8+1 {
			t.Fatalf("step %d: %d digests written", i, rep.Blocks)
		}
	}
	if pendingHints(ix) != 0 {
		t.Fatalf("%d notes never drained", pendingHints(ix))
	}
}

// L2: the repair after a batch of notes reads the digests within a window of each CLUSTER of notes. Six notes 30,000 blocks apart (the digests
// of the gaps between them are 100 each) cost the six clusters, not the 120,000 blocks in between; 40 notes in 400 blocks are one cluster.
func TestRB12RepairCostsTheClusterAndNeverTheDistanceBetweenNotes(t *testing.T) {
	_, bp := idxPins(t)
	const W = 3600
	run := func(t *testing.T, notes []uint64, fillers []uint64) int64 {
		st := NewMemStore()
		meter := &meterStore{CaptureStore: st}
		ix := NewIndexer(meter, bp, 0, IndexConfig{BlocksPerStep: 1000, StepBudget: time.Hour, ReconcileEvery: 1 << 30})
		for i, b := range fillers {
			vPutBlock(t, st, bp, b, uniqueFrame(fmt.Sprintf("fill%d", i), 1_790_000_000+uint64(i)*100))
		}
		stepAll(t, ix, 300_000)
		for i, b := range notes {
			vPutBlock(t, st, bp, b, uniqueFrame(fmt.Sprintf("note%d", i), 1_791_000_000+uint64(i)*100))
			ix.NoteLate(b)
		}
		meter.reset()
		if _, err := ix.Step(context.Background(), 300_000); err != nil {
			t.Fatal(err)
		}
		if pendingHints(ix) != 0 {
			t.Fatalf("%d notes left", pendingHints(ix))
		}
		for _, b := range notes {
			if !hasDigest(t, st, b) {
				t.Fatalf("noted block %d was not indexed", b)
			}
		}
		return meter.gets.Load()
	}
	// six clusters, each with 20 digests near it, and 100 digests in each of the five gaps (more than W away from any note)
	var spread, fillers []uint64
	for k := uint64(0); k < 6; k++ {
		h := 10_000 + k*30_000
		spread = append(spread, h)
		for j := uint64(1); j <= 20; j++ {
			fillers = append(fillers, h+j*10)
		}
		if k < 5 {
			for j := uint64(0); j < 100; j++ {
				fillers = append(fillers, h+15_000+j*10)
			}
		}
	}
	gSpread := run(t, spread, fillers)
	t.Logf("6 notes 30,000 blocks apart, 620 digests in the span: %d Gets", gSpread)
	if gSpread > 6*90 {
		t.Fatalf("the repair read the digests BETWEEN the notes: %d Gets for 6 clusters of 20 digests (bound %d)", gSpread, 6*90)
	}
	// forty notes inside 400 blocks: one cluster, one repair
	var close, closeFillers []uint64
	for j := uint64(0); j < 40; j++ {
		close = append(close, 10_000+j*10)
	}
	for j := uint64(1); j <= 60; j++ {
		closeFillers = append(closeFillers, 10_500+j*10)
	}
	gClose := run(t, close, closeFillers)
	t.Logf("40 notes in 400 blocks, 60 digests near them: %d Gets", gClose)
	if bound := int64(40*10 + 4*60); gClose > bound {
		t.Fatalf("a cluster is repaired once: %d Gets (bound %d)", gClose, bound)
	}
	_ = W
}
