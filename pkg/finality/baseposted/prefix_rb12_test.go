// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, the prefix extension (production 2026-10-23: 31 Base legs posted before the capture started were all
// l1_capture_not_covering). The production table is modelled by rbStore: its capture loop scanned from rbFirstBlock+31-64 on (the
// first cursor row minus the slack), so a leg whose window lies below that is a prefix leg.

const pxLower = rbFirstBlock + 31 - 64 // the first block the capture loop may have scanned

func pxBuilder(t *testing.T, st finality.CaptureStore, origin uint64, pol finality.PrefixPolicy) (*Builder, func() (*finality.StateError, error)) {
	t.Helper()
	s, l2 := rbLeg(t, origin)
	b := rbBuilder(t, st, l2)
	b.Prefix = pol
	return b, func() (*finality.StateError, error) {
		_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
		se, _ := finality.AsNamed(err)
		if pend != nil {
			return nil, fmt.Errorf("pending %s", pend.Reason)
		}
		return se, err
	}
}

func prefixRows(t *testing.T, st finality.CaptureStore) []finality.CaptureKey {
	t.Helper()
	ks, err := st.ListByRange(context.Background(), uint64(Chain), 0, finality.MaxCaptureBlock, "gap/")
	if err != nil {
		t.Fatal(err)
	}
	var out []finality.CaptureKey
	for _, k := range ks {
		if len(k.Item) > 15 && k.Item[len(k.Item)-15:] == "/capture_prefix" {
			out = append(out, k)
		}
	}
	return out
}

func TestRB12PrefixALegBeforeTheCaptureRequestsItsWindowAndIsNamedOpenNotNotCovering(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000) // window [origin, origin+3600], wholly below the scanned region
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	se, err := ask()
	if se == nil || se.Code != "l1_capture_gap" {
		t.Fatalf("want l1_capture_gap, got %v %v", se, err)
	}
	if se.Fields["gap_state"] != "open" || se.Fields["from"] != origin || se.Fields["to"] != origin+3600 || se.Fields["blocks"] != uint64(3601) || se.Fields["ranges"] != uint64(1) {
		t.Errorf("the open prefix is the whole window: %v", se)
	}
	rows := prefixRows(t, st)
	if len(rows) != 1 || rows[0].L1Block != origin || rows[0].Item != fmt.Sprintf("gap/%d/capture_prefix", origin+3600) {
		t.Fatalf("exactly one request row for the window: %v", rows)
	}
	gets := st.gets.Load()
	se2, _ := ask()
	if se2 == nil || se2.Code != "l1_capture_gap" || len(prefixRows(t, st)) != 1 {
		t.Fatalf("asking again changes nothing: %v", se2)
	}
	if st.gets.Load() != gets {
		t.Fatalf("a window with no captured block reads no row")
	}
}

func TestRB12PrefixAStraddlingLegRequestsOnlyTheBlocksBelowTheScannedRegion(t *testing.T) {
	for _, c := range []struct {
		name   string
		origin uint64
		to     uint64
		prefix bool
	}{
		{"origin one block below", pxLower - 1, pxLower - 1, true},
		{"origin 100 below", pxLower - 100, pxLower - 1, true},
		{"origin at the scanned region", pxLower, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rbStore(t, rbFirstBlock, 300, true)
			_, ask := pxBuilder(t, st, c.origin, finality.PrefixPolicy{MaxBlocks: 10_000})
			se, err := ask()
			rows := prefixRows(t, st)
			if !c.prefix {
				if len(rows) != 0 || (se != nil && se.Code == "l1_capture_not_covering") {
					t.Fatalf("a window that starts in the scanned region needs no prefix: %v rows=%v", se, rows)
				}
				return
			}
			if len(rows) != 1 || rows[0].L1Block != c.origin || rows[0].Item != fmt.Sprintf("gap/%d/capture_prefix", c.to) {
				t.Fatalf("the request ends at the block before the scanned region (%d): %v", c.to, rows)
			}
			if se == nil || se.Code != "l1_capture_gap" || se.Fields["from"] != c.origin || se.Fields["to"] != c.to {
				t.Fatalf("%v %v", se, err)
			}
		})
	}
}

func TestRB12PrefixOffByDefaultKeepsNotCoveringAndWritesNothing(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	n := len(prefixRows(t, st))
	_, ask := pxBuilder(t, st, rbFirstBlock-20_000, finality.PrefixPolicy{})
	se, _ := ask()
	if se == nil || se.Code != "l1_capture_not_covering" || se.Fields["prefix_state"] != "off" {
		t.Fatalf("an off extension names itself: %v", se)
	}
	if len(prefixRows(t, st)) != n {
		t.Fatalf("nothing is written when the extension is off")
	}
	if st.gets.Load() != 0 {
		t.Fatalf("no row read: %d", st.gets.Load())
	}
}

func TestRB12PrefixRefusalsAreNamedWithTheirReason(t *testing.T) {
	origin := uint64(rbFirstBlock - 20_000)
	for _, c := range []struct {
		name string
		pol  finality.PrefixPolicy
		want string
	}{
		{"floor above the window", finality.PrefixPolicy{MaxBlocks: 10_000, Floor: origin + 1}, "below_floor"},
		{"budget one block short", finality.PrefixPolicy{MaxBlocks: 3600}, "over_budget"},
	} {
		t.Run(c.name, func(t *testing.T) {
			st := rbStore(t, rbFirstBlock, 300, true)
			_, ask := pxBuilder(t, st, origin, c.pol)
			se, _ := ask()
			if se == nil || se.Code != "l1_capture_not_covering" || se.Fields["prefix_state"] != c.want {
				t.Fatalf("want not_covering/%s got %v", c.want, se)
			}
			if len(prefixRows(t, st)) != 0 {
				t.Fatalf("a refused request writes nothing")
			}
		})
	}
	// the exact boundaries: floor == origin and budget == 3601 are granted
	st := rbStore(t, rbFirstBlock, 300, true)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 3601, Floor: origin})
	if se, _ := ask(); se == nil || se.Code != "l1_capture_gap" {
		t.Fatalf("floor == origin and budget == blocks are granted: %v", se)
	}
}

func TestRB12PrefixAnotherValidatorsRequestCoversEvenWhenThisOneIsOff(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	rawGapRow(t, st, origin, origin+3600, "capture_prefix")
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{})
	se, _ := ask()
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" {
		t.Fatalf("a window another validator asked for is covered: %v", se)
	}
}

func TestRB12PrefixAPartlyCoveredWindowAsksForTheRest(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	rawGapRow(t, st, origin+1000, origin+3600, "capture_prefix") // another leg's window
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	se, _ := ask()
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["from"] != origin || se.Fields["blocks"] != uint64(3601) {
		t.Fatalf("%v", se)
	}
	if len(prefixRows(t, st)) != 2 {
		t.Fatalf("the missing part [%d,%d] was requested: %v", origin, origin+3600, prefixRows(t, st))
	}
	// with a budget that cannot take the union, the leg is not covered and says why
	st2 := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st2, origin+1000, origin+3600, "capture_prefix")
	_, ask2 := pxBuilder(t, st2, origin, finality.PrefixPolicy{MaxBlocks: 3600})
	if se, _ := ask2(); se == nil || se.Code != "l1_capture_not_covering" || se.Fields["prefix_state"] != "over_budget" ||
		se.Fields["prefix_lowest_l1_block"] != origin+1000 || se.Fields["prefix_blocks"] != uint64(2601) {
		t.Fatalf("%v", se)
	}
}

func TestRB12PrefixTheWindowIsOpenUntilTheLastBlockIsFilledThenThePendingStands(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	if se, _ := ask(); se == nil || se.Code != "l1_capture_gap" {
		t.Fatal("request")
	}
	for n := origin; n <= origin+3600; n++ {
		if n == origin+3600 {
			se, _ := ask() // everything but the last block filled
			if se == nil || se.Code != "l1_capture_gap" || se.Fields["from"] != n || se.Fields["to"] != n || se.Fields["blocks"] != uint64(1) {
				t.Fatalf("one open block keeps the leg a gap leg, named at that block: %v", se)
			}
		}
		rawFillRow(t, st, n)
	}
	se, err := ask()
	if se != nil || err == nil || err.Error() != "pending l1_posted_unproven" {
		t.Fatalf("a fully captured window with no channel is the plain pending, never a gap and never accepted: %v %v", se, err)
	}
}

// ---- the Backfiller: order and the cross-validator claim ----

type orderCap struct {
	mu      sync.Mutex
	order   []uint64
	fail    map[uint64]bool
	failAll bool
}

func (o *orderCap) CaptureBlockHash(_ context.Context, n uint64) ([32]byte, bool, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.order = append(o.order, n)
	if o.failAll || o.fail[n] {
		return [32]byte{}, false, errors.New("provider down")
	}
	return [32]byte{0xcc, byte(n), byte(n >> 8)}, false, nil
}

func rangeOf(from, to uint64) []uint64 {
	var out []uint64
	for n := from; n <= to; n++ {
		out = append(out, n)
	}
	return out
}

func TestRB12PrefixBackfillTakesLiveWindowsOldestFirstThenHolesThenWindowsWithAProvenGoneBlock(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	c := uint64(Chain)
	_ = finality.RecordGap(ctx, st, c, 2000, 2019, finality.GapCapturePrefix) // the newer window: holds a proven-unavailable block
	_ = finality.RecordGap(ctx, st, c, 1000, 1019, finality.GapCapturePrefix) // the older window: live
	_ = finality.RecordGap(ctx, st, c, 500, 509, finality.GapOutageUnscanned) // a hole of the live range
	_ = finality.RecordGapEnd(ctx, st, c, 2005, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}})
	oc := &orderCap{}
	now, _ := bfClock()
	b := &Backfiller{Chain: c, Store: st, Capturer: oc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	for i := 0; i < 20; i++ {
		rep, err := b.Step(ctx, 8)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Attempted == 0 {
			break
		}
	}
	var want []uint64
	want = append(want, rangeOf(1000, 1019)...) // oldest live window first
	want = append(want, rangeOf(500, 509)...)   // then the holes of the live range
	want = append(want, rangeOf(2000, 2004)...) // last: the window that cannot complete without an archive
	want = append(want, rangeOf(2006, 2019)...)
	if fmt.Sprint(oc.order) != fmt.Sprint(want) {
		t.Fatalf("capture order\n got %v\nwant %v", oc.order, want)
	}
	if tot, _ := finality.GapTotalsOf(ctx, st, c); tot.Open != 0 || tot.UnavailableProven != 1 {
		t.Fatalf("%+v", tot)
	}
}

func TestRB12PrefixBackfillIsBoundedPerStepAndSkipsBlocksAnotherValidatorFilled(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	c := uint64(Chain)
	_ = finality.RecordGap(ctx, st, c, 100, 139, finality.GapCapturePrefix)
	_ = finality.RecordGapFill(ctx, st, c, 101, [32]byte{1}, false)
	oc := &orderCap{}
	now, _ := bfClock()
	b := &Backfiller{Chain: c, Store: st, Capturer: oc, Policy: bfPolicy(), Now: now}
	rep, err := b.Step(ctx, 3)
	if err != nil || rep.Attempted != 3 || rep.Filled != 3 || rep.PrefixAttempted != 3 || rep.Open != 36 {
		t.Fatalf("%+v %v", rep, err)
	}
	if fmt.Sprint(oc.order) != "[100 102 103]" {
		t.Fatalf("%v", oc.order)
	}
}

func lease(st finality.CaptureStore, holder byte) *Lease {
	l := &Lease{Store: st, Chain: uint64(Chain), Span: 10 * time.Minute, Chunk: 8}
	l.Holder[0] = holder
	return l
}

func TestRB12PrefixSevenValidatorsSharingOneStoreNeverFetchTheSameBlock(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	c := uint64(Chain)
	_ = finality.RecordGap(ctx, st, c, 1000, 1055, finality.GapCapturePrefix) // 56 blocks = 7 chunks of 8
	now, _ := bfClock()
	// every capture fails, so no fill is ever recorded: all seven validators see the same 56 open blocks, and only the claims keep them apart
	var caps []*orderCap
	var bs []*Backfiller
	for v := 0; v < 7; v++ {
		oc := &orderCap{failAll: true}
		caps = append(caps, oc)
		bs = append(bs, &Backfiller{Chain: c, Store: st, Capturer: oc, Policy: bfPolicy(), Now: now, Lease: lease(st, byte(v+1))})
	}
	var lost int
	for v := 0; v < 7; v++ {
		rep, err := bs[v].Step(ctx, 8)
		if err != nil {
			t.Fatal(err)
		}
		lost += rep.LeaseLost
		if rep.Attempted != 8 || rep.PrefixAttempted != 8 || rep.LeaseLost != v {
			t.Fatalf("validator %d: %+v", v, rep)
		}
	}
	seen := map[uint64]int{}
	for _, oc := range caps {
		for _, n := range oc.order {
			seen[n]++
		}
	}
	if len(seen) != 56 {
		t.Fatalf("seven steps of 8 cover all 56 blocks once: %d", len(seen))
	}
	for n, k := range seen {
		if k != 1 {
			t.Fatalf("block %d was fetched %d times", n, k)
		}
	}
	if lost != 21 {
		t.Fatalf("validator v meets v claims: %d", lost)
	}
	if tot, _ := finality.GapTotalsOf(ctx, st, c); tot.Open != 56 || tot.Filled != 0 {
		t.Fatalf("claim rows are not gap bookkeeping: %+v", tot)
	}
}

func TestRB12PrefixAClaimExpiresAndALostChunkIsRetakenByAnotherValidator(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	c := uint64(Chain)
	_ = finality.RecordGap(ctx, st, c, 1000, 1007, finality.GapCapturePrefix) // one chunk
	now, advance := bfClock()
	a := &orderCap{fail: map[uint64]bool{1004: true}}
	ba := &Backfiller{Chain: c, Store: st, Capturer: a, Policy: bfPolicy(), Now: now, Lease: lease(st, 1)}
	if rep, _ := ba.Step(ctx, 8); rep.Filled != 7 || rep.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	bo := &orderCap{}
	bb := &Backfiller{Chain: c, Store: st, Capturer: bo, Policy: bfPolicy(), Now: now, Lease: lease(st, 2)}
	rep, _ := bb.Step(ctx, 8)
	if rep.Attempted != 0 || rep.LeaseLost != 1 {
		t.Fatalf("inside the lease B does not touch A's chunk: %+v", rep)
	}
	advance(10 * time.Minute) // the next lease bucket
	rep, _ = bb.Step(ctx, 8)
	if rep.Attempted != 1 || rep.Filled != 1 || fmt.Sprint(bo.order) != "[1004]" {
		t.Fatalf("after the lease B takes the one open block: %+v %v", rep, bo.order)
	}
}

func TestRB12PrefixLeaseIsIdempotentForTheHolderAndNamesALoss(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	now := bfEpoch
	a, b := lease(st, 1), lease(st, 2)
	for i := 0; i < 3; i++ {
		if won, err := a.Claim(ctx, now, 1000); !won || err != nil {
			t.Fatalf("the holder claims its own chunk again: %v %v", won, err)
		}
	}
	if won, err := b.Claim(ctx, now, 1000); won || err != nil {
		t.Fatalf("a loss is an answer, not an error: %v %v", won, err)
	}
	if won, err := b.Claim(ctx, now, 1008); !won || err != nil {
		t.Fatalf("another chunk is free: %v %v", won, err)
	}
	if won, err := b.Claim(ctx, now.Add(10*time.Minute), 1000); !won || err != nil {
		t.Fatalf("the next bucket is free: %v %v", won, err)
	}
	if won, _ := a.Claim(ctx, now.Add(10*time.Minute-time.Second), 1000); !won {
		t.Fatalf("one second before the bucket ends the holder still holds it")
	}
}

type failingPutStore struct{ finality.CaptureStore }

func (failingPutStore) Put(context.Context, finality.CaptureKey, []byte) error {
	return errors.New("store down")
}

func TestRB12PrefixAStoreThatCannotClaimTakesNoPrefixBlockAndSaysSo(t *testing.T) {
	ctx := context.Background()
	mem := NewMemStore()
	c := uint64(Chain)
	_ = finality.RecordGap(ctx, mem, c, 1000, 1007, finality.GapCapturePrefix)
	oc := &orderCap{}
	now, _ := bfClock()
	b := &Backfiller{Chain: c, Store: mem, Capturer: oc, Policy: bfPolicy(), Now: now, Lease: lease(failingPutStore{mem}, 1)}
	rep, err := b.Step(ctx, 8)
	if err != nil || rep.Attempted != 0 || rep.LeaseErrors != 1 || len(oc.order) != 0 {
		t.Fatalf("no claim, no fetch: %+v %v %v", rep, err, oc.order)
	}
}
