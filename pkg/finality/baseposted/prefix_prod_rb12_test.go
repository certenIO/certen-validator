// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, replay and production shape.

// prefixCursorStore holds only what the Base builder reads to decide coverage: the capture loop's cursor rows. The loop is taken to have
// started so that the first block it may have scanned (first cursor row minus the slack of 64) is lower.
func prefixCursorStore(t testing.TB, lower uint64, last uint64) CaptureStore {
	t.Helper()
	st := NewMemStore()
	for _, blk := range []uint64{lower + 64, last} {
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], blk)
		if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: blk, Item: "runtime/cursor"}, v[:]); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// The recorded blocks of the second Sepolia hole are the prefix of a validator whose capture started right after it: the leg posted in it
// is named, the backfill captures the recorded block with the production decoders and KZG (its rows verify against its own header, tx
// trie proof, SystemConfig state proof and batcher), and the rest stays open under its name until it is served.
func TestRB12ReplayAPrefixWindowOfRecordedBlocksIsRequestedNamedBackfilledAndAuthenticated(t *testing.T) {
	rs := loadReplay(t)
	ctx := context.Background()
	hole := rs.Holes[1] // 11976374-11976445 holds the recorded block rs.Featured[1]
	first, last := hole.After+1, hole.Before-1
	if first != 11976374 || last != 11976445 || rs.Featured[1] < first || rs.Featured[1] > last {
		t.Fatalf("the recorded hole is not where the test thinks: %d-%d featured %v", first, last, rs.Featured)
	}
	st := prefixCursorStore(t, last+1, 11977356)
	s, l2 := rbLeg(t, first) // the leg's L1 origin is the first block of the hole; its window runs on to first+3600

	// 1. the extension is off: the leg predates the capture and says so
	b := rbBuilder(t, st, l2)
	_, _, err := b.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if se, _ := finality.AsNamed(err); se == nil || se.Code != "l1_capture_not_covering" || se.Fields["prefix_state"] != "off" {
		t.Fatalf("%v", err)
	}
	// 2. on: the window is requested (the part below the first scanned block: exactly the 72 blocks of the hole) and the leg is the open gap
	b.Prefix = finality.PrefixPolicy{MaxBlocks: 1000}
	_, _, err = b.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	se, _ := finality.AsNamed(err)
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" || se.Fields["from"] != first || se.Fields["to"] != last || se.Fields["blocks"] != uint64(72) {
		t.Fatalf("%v", err)
	}
	// 3. the backfill, with the recorded provider answers
	srv := rs.server(t)
	hc := &replayHoleCapturer{rs: rs, real: CapturerOf(rs.capturer(t, srv, st)), byNum: map[uint64]replayScanBlock{}}
	var unrecorded []uint64
	for _, blk := range hole.Blocks {
		hc.byNum[blk.N] = blk
		if blk.Inbox > 0 && blk.N != rs.Featured[1] {
			unrecorded = append(unrecorded, blk.N)
		}
	}
	sort.Slice(unrecorded, func(i, j int) bool { return unrecorded[i] < unrecorded[j] })
	now, _ := bfClock()
	bf := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: hc, Policy: bfPolicy(), Now: now, Lease: lease(st, 1)}
	for i := 0; i < 40; i++ {
		rep, err := bf.Step(ctx, 8)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Attempted == 0 {
			break
		}
	}
	open, _ := finality.GapsIn(ctx, st, uint64(Chain), first, last)
	var openBlocks []uint64
	for _, g := range open {
		for n := g.From; n <= g.To; n++ {
			openBlocks = append(openBlocks, n)
		}
	}
	if fmt.Sprint(openBlocks) != fmt.Sprint(unrecorded) {
		t.Fatalf("exactly the inbox blocks the recording lacks stay open\n got %v\nwant %v", openBlocks, unrecorded)
	}
	var h [32]byte
	for _, blk := range hole.Blocks {
		if blk.N == rs.Featured[1] {
			copy(h[:], common.FromHex(blk.Hash))
		}
	}
	verifyCapturedBlock(t, st, replayPins(t), rs.Featured[1], h)
	// 4. the leg now names the blocks that are still to come
	_, _, err = b.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if se, _ := finality.AsNamed(err); se == nil || se.Code != "l1_capture_gap" || se.Fields["blocks"] != uint64(len(unrecorded)) || se.Fields["from"] != unrecorded[0] {
		t.Fatalf("%v", err)
	}
}

// The 31 Base legs that were l1_capture_not_covering on production on 2026-10-23 (epoch L1 blocks read from the status table), the capture
// starting at 11958003: 26 distinct windows, 7 merged segments, 41,316 blocks. Every leg is requested, named as the open gap, and the
// whole prefix is backfilled oldest window first; the budget bound is exact.
var prodBaseEpochs = []uint64{11842420, 11843396, 11845545, 11845545, 11847992, 11849261, 11851293, 11854921, 11858982, 11861923, 11862277, 11878684,
	11928128, 11928204, 11937576, 11939986, 11939986, 11939986, 11939989, 11939989, 11939991, 11939993, 11939996, 11939999, 11940009, 11940928,
	11940928, 11940930, 11949455, 11949903, 11949966}

func TestRB12ProductionShapeThirtyOneLegsBeforeTheCaptureAreRequestedMergedAndBackfilledOldestWindowFirst(t *testing.T) {
	ctx := context.Background()
	if len(prodBaseEpochs) != 31 {
		t.Fatal("31 legs")
	}
	lower := uint64(11958003)
	// a budget one block short of the union refuses exactly the leg that does not fit, by name, and writes nothing for it
	short := prefixCursorStore(t, lower, 11979000)
	var refused int
	for _, e := range prodBaseEpochs {
		s, l2 := rbLeg(t, e)
		b := rbBuilder(t, short, l2)
		b.Prefix = finality.PrefixPolicy{MaxBlocks: 41_315}
		if _, _, err := b.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted); err != nil {
			if se, _ := finality.AsNamed(err); se != nil && se.Code == "l1_capture_not_covering" && se.Fields["prefix_state"] == "over_budget" {
				refused++
			}
		}
	}
	if refused == 0 {
		t.Fatalf("a budget one block under the union must refuse at least one leg by name")
	}
	// the budget of the union takes all 31
	st := prefixCursorStore(t, lower, 11979000)
	for _, e := range prodBaseEpochs {
		s, l2 := rbLeg(t, e)
		b := rbBuilder(t, st, l2)
		b.Prefix = finality.PrefixPolicy{MaxBlocks: 41_316}
		_, _, err := b.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
		if se, _ := finality.AsNamed(err); se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" {
			t.Fatalf("leg %d: %v", e, err)
		}
	}
	wins, err := finality.PrefixWindowsOf(ctx, st, uint64(Chain))
	if err != nil {
		t.Fatal(err)
	}
	merged := finality.MergePrefixWindows(wins)
	if len(wins) != 26 || len(merged) != 7 || finality.PrefixBlocks(merged) != 41_316 {
		t.Fatalf("26 windows, 7 segments, 41,316 blocks: %d %d %d", len(wins), len(merged), finality.PrefixBlocks(merged))
	}
	// the backfill takes the oldest window's first block first and, run to the end, closes every window
	oc := &orderCap{}
	now, _ := bfClock()
	bf := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: oc, Policy: bfPolicy(), Now: now}
	if _, err := bf.Step(ctx, 8); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(oc.order) != fmt.Sprint(rangeOf(11842420, 11842427)) {
		t.Fatalf("oldest block of the oldest window first: %v", oc.order)
	}
	// the order holds on: the next steps continue upward through the oldest window without a repeat
	for i := 0; i < 3; i++ {
		if _, err := bf.Step(ctx, 100); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[uint64]bool{}
	for i, n := range oc.order {
		if seen[n] || n != 11842420+uint64(i) {
			t.Fatalf("fetch %d was block %d: the oldest window is walked in order, once each", i, n)
		}
		seen[n] = true
	}
	// one window to the end: the newest leg of the 31, alone in a store, is requested, backfilled and then covered
	one := prefixCursorStore(t, lower, 11979000)
	s, l2 := rbLeg(t, 11949966)
	b1 := rbBuilder(t, one, l2)
	b1.Prefix = finality.PrefixPolicy{MaxBlocks: 41_316}
	if _, _, err := b1.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted); err == nil {
		t.Fatal("requested")
	}
	oc1 := &orderCap{}
	bf1 := &Backfiller{Chain: uint64(Chain), Store: one, Capturer: oc1, Policy: bfPolicy(), Now: now}
	for i := 0; i < 10; i++ {
		rep, err := bf1.Step(ctx, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Attempted == 0 {
			break
		}
	}
	if len(oc1.order) != 3601 || oc1.order[0] != 11949966 || oc1.order[3600] != 11953566 {
		t.Fatalf("the 3,601 blocks of the window, oldest first: %d", len(oc1.order))
	}
	_, pend, err := b1.Build(ctx, s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("a covered window is the plain pending, never a gap: pend=%v err=%v", pend, err)
	}
	if states := PrefixWindowStates(wins, nil); states[PrefixWindowComplete] != 26 {
		t.Fatalf("%v", states)
	}
}
