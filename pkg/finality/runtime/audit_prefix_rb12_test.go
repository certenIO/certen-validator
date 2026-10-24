// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted"
)

// Captured prefix blocks lie below the loop's own start with unrequested stretches between and around them. The spacing audit must not
// read those stretches as outages (it would record them as gaps and the backfill would then capture the whole history between the windows);
// it still finds a real outage inside the scanned region.
func TestRB12PrefixTheSpacingAuditNeverReachesBelowTheCaptureStartAndStillFindsRealOutages(t *testing.T) {
	ctx := context.Background()
	mem := finality.NewMemCaptureStore()
	c := finality.ChainBaseSepolia
	put := func(block uint64, item string, b []byte) {
		var h [32]byte
		h[0], h[1] = 0x42, byte(block)
		if err := mem.Put(ctx, finality.CaptureKey{Chain: c, L1Block: block, L1Hash: h, Item: item}, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, blk := range []uint64{1_000_100, 1_000_900} { // the loop's cursor: it scanned from 1,000,100 on
		var v [8]byte
		v[7], v[6], v[5], v[4], v[3] = byte(blk), byte(blk>>8), byte(blk>>16), byte(blk>>24), byte(blk>>32)
		if err := mem.Put(ctx, finality.CaptureKey{Chain: c, L1Block: blk, Item: finality.CaptureCursorItem}, v[:]); err != nil {
			t.Fatal(err)
		}
	}
	for _, blk := range []uint64{500, 510, 90_000, 1_000_110, 1_000_120, 1_000_500} { // two prefix windows, then the live range with a 380-block outage
		put(blk, baseposted.ItemInbox, []byte{0})
	}
	l, _ := newGapLoop(t, mem, &bfFakeCap{})
	l.audit(ctx)
	ps, err := finality.GapsIn(ctx, mem, c, 0, finality.MaxCaptureBlock)
	if err != nil || len(ps) != 1 || ps[0].From != 1_000_121 || ps[0].To != 1_000_499 {
		t.Fatalf("only the outage inside the scanned region is recorded, not the stretches below it: %v %v", ps, err)
	}
}
