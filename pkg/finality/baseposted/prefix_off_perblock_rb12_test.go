// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2: with the prefix off the backfill decides PER BLOCK. GapsIn merges overlapping and abutting rows into one piece with the union
// of their classes (V-INT3c D2: hole 500-509 + window 505-520 + abutting 521-530 are the one piece 500-530), which let the window-only blocks
// 510-530 stay in reach of a validator whose prefix feature was off. GapsInWithout leaves the prefix rows out of the union.
func TestRB12BackfillerWithThePrefixOffTakesOnlyTheBlocksARowOfAnotherClassCovers(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	build := func(off bool) (*Backfiller, *orderCap) {
		st := NewMemStore()
		_ = finality.RecordGap(ctx, st, c, 500, 509, finality.GapOutageUnscanned)
		_ = finality.RecordGap(ctx, st, c, 505, 520, finality.GapCapturePrefix) // overlaps the hole
		_ = finality.RecordGap(ctx, st, c, 521, 530, finality.GapCapturePrefix) // abuts the window
		oc := &orderCap{}
		now, _ := bfClock()
		return &Backfiller{Chain: c, Store: st, Capturer: oc, Providers: []string{"a", "b", "c"}, Policy: bfPolicy(), Now: now,
			Pick: func(int) int { return 0 }, NoPrefix: off}, oc
	}
	run := func(b *Backfiller) {
		for i := 0; i < 60; i++ {
			rep, err := b.Step(ctx, 8)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Attempted == 0 {
				return
			}
		}
	}
	on, onCap := build(false)
	run(on)
	sawWindowOnly := false
	for _, n := range onCap.order {
		if n >= 510 {
			sawWindowOnly = true
		}
	}
	if !sawWindowOnly {
		t.Fatalf("control: with the prefix on the window-only blocks are taken: %v", onCap.order)
	}
	off, offCap := build(true)
	run(off)
	if fmt.Sprint(offCap.order) != fmt.Sprint(rangeOf(500, 509)) {
		t.Fatalf("with the prefix off only the blocks of the hole are taken, each once: %v", offCap.order)
	}
}
