// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, review fixes (V-ARCHIVE D2, D3, D4b, D5).

// ---- D2: the window of a prefix request is never derived from an unauthenticated provider word ----

func TestRB12PrefixALyingL2AnswerWritesNoPrefixRowAndIsNamed(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	realOrigin := uint64(rbFirstBlock - 20_000)
	s, _ := rbLeg(t, realOrigin)
	for _, bogus := range []uint64{5, 50_000, 500_000} {
		_, liar := rbLeg(t, bogus) // an L2 answer whose first transaction names another origin: its root is not the header's
		b := rbBuilder(t, st, liar)
		b.Prefix = finality.PrefixPolicy{MaxBlocks: 10_000}
		_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
		se, _ := finality.AsNamed(err)
		if pend != nil || se == nil || se.Code != "l2_block_content_mismatch" || se.Fields["block"] != uint64(48333406) {
			t.Fatalf("origin %d: want the named l2_block_content_mismatch, got pend=%v err=%v", bogus, pend, err)
		}
	}
	if rows := prefixRows(t, st); len(rows) != 0 {
		t.Fatalf("a lying answer writes nothing durable: %v", rows)
	}
	// the real leg, answered truthfully, is then requested and covered as usual (the budget was not touched)
	_, truth := rbLeg(t, realOrigin)
	b := rbBuilder(t, st, truth)
	b.Prefix = finality.PrefixPolicy{MaxBlocks: 3601}
	_, _, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, _ := finality.AsNamed(err); se == nil || se.Code != "l1_capture_gap" {
		t.Fatalf("%v", err)
	}
}

// ---- D3: the holes keep a share of every tick ----

func TestRB12PrefixTheHolesKeepAQuarterOfEveryTickWhilePrefixBlocksFailForEver(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, c, 100_000, 100_999, finality.GapCapturePrefix) // 1000 live prefix blocks, none will ever succeed
	_ = finality.RecordGap(ctx, st, c, 5000, 5009, finality.GapOutageUnscanned)     // a hole of the live range
	oc := &orderCap{failAll: true}
	now, _ := bfClock()
	b := &Backfiller{Chain: c, Store: st, Capturer: oc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	rep, err := b.Step(ctx, 8)
	if err != nil || rep.Attempted != 8 || rep.PrefixAttempted != 6 {
		t.Fatalf("prefix at most max - ceil(max/4) = 6 of 8: %+v %v", rep, err)
	}
	holes := 0
	for _, n := range oc.order {
		if n >= 5000 && n <= 5009 {
			holes++
		}
	}
	if holes != 2 {
		t.Fatalf("the holes get the other 2: %v", oc.order)
	}
	// every hole block is attempted within five steps, however many prefix blocks fail
	for i := 0; i < 4; i++ {
		_, _ = b.Step(ctx, 8)
	}
	seen := map[uint64]bool{}
	for _, n := range oc.order {
		seen[n] = true
	}
	for n := uint64(5000); n <= 5009; n++ {
		if !seen[n] {
			t.Fatalf("hole block %d not attempted in 5 steps: %v", n, oc.order)
		}
	}
	// holes that are all backing off leave the whole tick to the prefix (nothing is wasted)
	rep, _ = b.Step(ctx, 8)
	if rep.Attempted != 8 || rep.PrefixAttempted != 8 {
		t.Fatalf("no hole is due: the prefix takes all 8: %+v", rep)
	}
	// a single due hole block: it takes one, the prefix the other seven
	st2 := NewMemStore()
	_ = finality.RecordGap(ctx, st2, c, 100_000, 100_999, finality.GapCapturePrefix)
	_ = finality.RecordGap(ctx, st2, c, 5000, 5000, finality.GapOutageUnscanned)
	b2 := &Backfiller{Chain: c, Store: st2, Capturer: &orderCap{failAll: true}, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	if rep, _ = b2.Step(ctx, 8); rep.Attempted != 8 || rep.PrefixAttempted != 7 {
		t.Fatalf("%+v", rep)
	}
	// max 1: the hole has it while one is due; no hole: the prefix has it
	st3 := NewMemStore()
	_ = finality.RecordGap(ctx, st3, c, 100_000, 100_009, finality.GapCapturePrefix)
	_ = finality.RecordGap(ctx, st3, c, 5000, 5001, finality.GapOutageUnscanned)
	oc3 := &orderCap{}
	b3 := &Backfiller{Chain: c, Store: st3, Capturer: oc3, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	_, _ = b3.Step(ctx, 1)
	_, _ = b3.Step(ctx, 1)
	_, _ = b3.Step(ctx, 1)
	if fmt.Sprint(oc3.order) != "[5000 5001 100000]" {
		t.Fatalf("%v", oc3.order)
	}
}

// ---- D4b: the daily re-ask covers a block past retention too ----

func TestRB12PrefixBlocksPastRetentionAreAskedAgainOncePerDayLikeThoseProvenUnavailable(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, c, 70, 71, finality.GapBlobUnavailable)
	_ = finality.RecordGap(ctx, st, c, 90, 91, finality.GapBlobUnavailable)
	for _, n := range []uint64{70, 71} {
		_ = finality.RecordGapSlot(ctx, st, c, n, 100)
		_ = finality.RecordGapEnd(ctx, st, c, n, finality.GapEnd{Kind: finality.GapRetentionExpired, Reason: "blob_retention_elapsed", Providers: []string{"a", "b"}})
	}
	for _, n := range []uint64{90, 91} {
		_ = finality.RecordGapSlot(ctx, st, c, n, 100)
		_ = finality.RecordGapEnd(ctx, st, c, n, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}})
	}
	now, adv := bfClock()
	gone := true
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		if gone {
			return [32]byte{}, false, blobFailure(n, 100, true)
		}
		return okCap(n, call)
	}}
	w := &Backfiller{Chain: c, Store: st, Capturer: sc, Providers: []string{"a", "b"}, Policy: bfPolicy(), Now: now}
	_, _ = w.Step(ctx, 8)
	adv(24 * time.Hour)
	_, _ = w.Step(ctx, 8)
	if len(sc.calls) != 2 || sc.calls[71] != 1 || sc.calls[91] != 1 {
		t.Fatalf("the newest block of each run, expired or proven, is asked: %v", sc.calls)
	}
	adv(24 * time.Hour)
	gone = false
	for i := 0; i < 8; i++ {
		_, _ = w.Step(ctx, 8)
		adv(time.Minute)
	}
	if open, _ := finality.GapsIn(ctx, st, c, 0, 1000); len(open) != 0 {
		t.Fatalf("a served probe re-opens both kinds, which then fill: %v", open)
	}
}

// ---- D5: a complete historical window without a channel is a determinate named state ----

func TestRB12PrefixACompleteWindowWithoutAChannelIsNamedNotPendingAndARecentOneStaysPending(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	ask()
	for n := origin; n <= origin+3600; n++ {
		rawFillRow(t, st, n)
	}
	se, _ := ask()
	last := uint64(rbFirstBlock + 5*299) // the capture cursor
	if se == nil || se.Code != "l1_posted_not_found" || se.Fields["from"] != origin || se.Fields["to"] != origin+3600 || se.Fields["covered_to"] != last {
		t.Fatalf("a window fully captured below the cursor holds no channel: %v", se)
	}
	for _, f := range []string{"chain", "kind", "from", "to", "covered_to"} {
		if _, ok := se.Fields[f]; !ok {
			t.Errorf("missing %s: %v", f, se)
		}
	}
	// one open block keeps it a gap leg
	st2 := rbStore(t, rbFirstBlock, 300, true)
	_, ask2 := pxBuilder(t, st2, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	ask2()
	for n := origin + 1; n <= origin+3600; n++ {
		rawFillRow(t, st2, n)
	}
	if se2, _ := ask2(); se2 == nil || se2.Code != "l1_capture_gap" {
		t.Fatalf("%v", se2)
	}
	// exact margin: the window must end 96 blocks before the cursor; one block later it is still the plain pending
	last = uint64(rbFirstBlock + 5*999)
	edge := last - 96 - 3600
	for _, c := range []struct {
		origin uint64
		named  bool
	}{{edge, true}, {edge + 1, false}} {
		s4 := rbStore(t, rbFirstBlock, 1000, true)
		_, a := pxBuilder(t, s4, c.origin, finality.PrefixPolicy{})
		se4, err4 := a()
		if c.named != (se4 != nil && se4.Code == "l1_posted_not_found") {
			t.Fatalf("origin %d (window end %d, cursor %d): named=%v want %v (%v %v)", c.origin, c.origin+3600, last, !c.named, c.named, se4, err4)
		}
		if !c.named && (err4 == nil || err4.Error() != "pending l1_posted_unproven") {
			t.Fatalf("a window not yet 96 blocks behind the cursor is the plain pending: %v", err4)
		}
	}
}

// V-ARCHIVE-2 V2-1: the determinate verdict of a window INSIDE the scanned region is derived from the same origin, so it needs the same
// authentication as the verdicts below it.
func TestRB12PrefixALyingL2AnswerCannotMakeAWindowInsideTheScannedRegionDeterminate(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 1000, true)
	last := uint64(rbFirstBlock + 5*999)
	edge := last - 96 - 3600 // a window starting here is complete; one starting 500 blocks later is not
	s, truth := rbLeg(t, edge+500)
	_, liar := rbLeg(t, edge)
	_, pend, err := rbBuilder(t, st, liar).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, _ := finality.AsNamed(err); pend != nil || se == nil || se.Code != "l2_block_content_mismatch" {
		t.Fatalf("a lying answer must not yield l1_posted_not_found: pend=%v err=%v", pend, err)
	}
	_, pend, err = rbBuilder(t, st, truth).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("the truthful answer is the plain pending: pend=%v err=%v", pend, err)
	}
}
