// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
)

// RB12 OPS-A2 F18: a gap fill is keyed by the hash of the block the capture verified; once a builder has learned from the finalized chain that
// the block is an orphan, a fill of that hash closes nothing and the height stays open until the canonical block is filled.
func TestGapOrphanMarkMakesAFillOfThatHashCloseNothingUntilTheCanonicalBlockIsFilled(t *testing.T) {
	ctx := context.Background()
	st := NewMemCaptureStore()
	const chain = ChainBaseSepolia
	orphan, canon := [32]byte{0xaa}, [32]byte{0xbb}
	if err := RecordGap(ctx, st, chain, 100, 109, GapOperatorDeclared); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapFill(ctx, st, chain, 105, orphan, true); err != nil {
		t.Fatal(err)
	}
	open := func() []GapRange {
		ps, err := GapsIn(ctx, st, chain, 100, 109)
		if err != nil {
			t.Fatal(err)
		}
		return ps
	}
	if ps := open(); len(ps) != 2 || ps[0].To != 104 || ps[1].From != 106 {
		t.Fatalf("before the mark the fill of 105 closes it: %+v", ps)
	}
	if err := RecordGapOrphan(ctx, st, chain, 105, orphan); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapOrphan(ctx, st, chain, 105, orphan); err != nil { // insert-only: a repeat is a no-op
		t.Fatal(err)
	}
	if ps := open(); len(ps) != 1 || ps[0].From != 100 || ps[0].To != 109 {
		t.Fatalf("a fill of an orphan block closes nothing: %+v", ps)
	}
	if err := RecordGapFill(ctx, st, chain, 105, canon, true); err != nil {
		t.Fatal(err)
	}
	if ps := open(); len(ps) != 2 || ps[0].To != 104 || ps[1].From != 106 {
		t.Fatalf("the canonical block's fill closes the height: %+v", ps)
	}
	// the mark is of one hash at one height: another height's fill by the same hash is not touched
	if err := RecordGapFill(ctx, st, chain, 107, orphan, true); err != nil {
		t.Fatal(err)
	}
	if ps := open(); len(ps) != 3 {
		t.Fatalf("a fill of the same hash at another height still closes it: %+v", ps)
	}
	if err := RecordGapOrphan(ctx, st, chain, 105, [32]byte{}); err == nil {
		t.Fatal("an orphan mark without a hash was accepted")
	}
}
