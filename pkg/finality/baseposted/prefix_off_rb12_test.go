// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT, V-INT3b LOW (b): a Backfiller whose prefix feature is OFF (a bad prefix setting, named finality_prefix_disabled) takes no
// block of any prefix window, reopens no block a prefix window holds, and goes on closing the holes of the live range exactly as before.
func TestRB12BackfillerWithThePrefixOffTakesNoPrefixBlockAndStillClosesTheHoles(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	build := func(off bool) (*Backfiller, *orderCap, finality.CaptureStore) {
		st := NewMemStore()
		_ = finality.RecordGap(ctx, st, c, 1000, 1019, finality.GapCapturePrefix) // a live window
		_ = finality.RecordGap(ctx, st, c, 2000, 2019, finality.GapCapturePrefix) // a window holding a block no provider has
		_ = finality.RecordGapEnd(ctx, st, c, 2005, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}})
		_ = finality.RecordGap(ctx, st, c, 500, 509, finality.GapOutageUnscanned) // a hole of the live range
		oc := &orderCap{}
		now, _ := bfClock()
		// the providers have changed since block 2005 was proven gone: the unrestricted backfill reopens it
		return &Backfiller{Chain: c, Store: st, Capturer: oc, Providers: []string{"a", "b", "c"}, Policy: bfPolicy(), Now: now,
			Pick: func(int) int { return 0 }, NoPrefix: off}, oc, st
	}
	run := func(b *Backfiller) {
		for i := 0; i < 40; i++ {
			rep, err := b.Step(ctx, 8)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Attempted == 0 {
				return
			}
		}
	}
	on, onCap, _ := build(false)
	run(on)
	var sawPrefix bool
	for _, n := range onCap.order {
		if n >= 1000 {
			sawPrefix = true
		}
	}
	if !sawPrefix {
		t.Fatalf("control: with the prefix on the windows are taken: %v", onCap.order)
	}
	off, offCap, st := build(true)
	run(off)
	for _, n := range offCap.order {
		if n < 500 || n > 509 {
			t.Fatalf("block %d is outside the live-range hole: the prefix feature is off, yet %v", n, offCap.order)
		}
	}
	if fmt.Sprint(offCap.order) != fmt.Sprint(rangeOf(500, 509)) {
		t.Fatalf("every block of the hole is closed, once: %v", offCap.order)
	}
	// the windows stay as recorded (insert-only): still open, still waiting for a validator whose prefix feature is on
	wins, err := finality.PrefixWindowsOf(ctx, st, c)
	if err != nil || len(wins) != 2 {
		t.Fatalf("%v %v", wins, err)
	}
	if tot, _ := finality.GapTotalsOf(ctx, st, c); tot.Open != 39 || tot.UnavailableProven != 1 {
		t.Fatalf("the prefix blocks are untouched: %+v", tot)
	}
}
