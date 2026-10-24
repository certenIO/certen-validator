// Copyright 2026 Certen Protocol

package finality

import (
	"strings"
	"testing"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum: a chain whose captured items are sparse events (one SequencerInbox batch every ~7 L1 blocks) cannot close
// its prefix with a fill per block (a block without an event has no hash to fill under). A SCAN row says "the logs of [from, to] were read
// completely and every event in them is captured": gap/<to>/... rows are closed over that range by it, exactly as by fills.

func TestRB12GapScanClosesTheBlocksOfItsRangeAndOnlyThose(t *testing.T) {
	s := NewMemCaptureStore()
	if _, err := RequestPrefix(pxCtx(), s, pxChain, 100, 199, PrefixPolicy{MaxBlocks: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapScan(pxCtx(), s, pxChain, 100, 149); err != nil {
		t.Fatal(err)
	}
	ps, err := GapsIn(pxCtx(), s, pxChain, 0, MaxCaptureBlock)
	if err != nil || len(ps) != 1 || ps[0].From != 150 || ps[0].To != 199 {
		t.Fatalf("%v %v", ps, err)
	}
	// a scan that overhangs the window on both sides closes what it overlaps and nothing outside the window appears
	if err := RecordGapScan(pxCtx(), s, pxChain, 140, 400); err != nil {
		t.Fatal(err)
	}
	if ps, _ = GapsIn(pxCtx(), s, pxChain, 0, MaxCaptureBlock); len(ps) != 0 {
		t.Fatalf("every block of the window is scanned: %v", ps)
	}
	// another chain's scan closes nothing here
	s2 := NewMemCaptureStore()
	_, _ = RequestPrefix(pxCtx(), s2, pxChain, 100, 199, PrefixPolicy{MaxBlocks: 1000})
	_ = RecordGapScan(pxCtx(), s2, pxChain+1, 100, 199)
	if ps, _ = GapsIn(pxCtx(), s2, pxChain, 0, MaxCaptureBlock); len(ps) != 1 {
		t.Fatalf("%v", ps)
	}
	// exact edges: a scan ending one block short leaves that block
	s3 := NewMemCaptureStore()
	_, _ = RequestPrefix(pxCtx(), s3, pxChain, 100, 199, PrefixPolicy{MaxBlocks: 1000})
	_ = RecordGapScan(pxCtx(), s3, pxChain, 100, 198)
	if ps, _ = GapsIn(pxCtx(), s3, pxChain, 0, MaxCaptureBlock); len(ps) != 1 || ps[0].From != 199 || ps[0].To != 199 {
		t.Fatalf("%v", ps)
	}
	_ = RecordGapScan(pxCtx(), s3, pxChain, 199, 199)
	if ps, _ = GapsIn(pxCtx(), s3, pxChain, 0, MaxCaptureBlock); len(ps) != 0 {
		t.Fatalf("%v", ps)
	}
}

func TestRB12GapScanRowIsAFunctionOfItsRangeAndMalformedOnesAreRefused(t *testing.T) {
	s := NewMemCaptureStore()
	for i := 0; i < 3; i++ {
		if err := RecordGapScan(pxCtx(), s, pxChain, 500, 899); err != nil {
			t.Fatalf("recording the same scan again is a no-op: %v", err)
		}
	}
	ks, _ := s.ListByRange(pxCtx(), pxChain, 0, MaxCaptureBlock, GapScanPrefix)
	if len(ks) != 1 || ks[0].L1Block != 500 || ks[0].Item != "gapscan/899" || ks[0].L1Hash != ([32]byte{}) {
		t.Fatalf("%v", ks)
	}
	if err := RecordGapScan(pxCtx(), s, pxChain, 900, 899); err == nil {
		t.Fatal("to < from is refused")
	}
	_ = RecordGap(pxCtx(), s, pxChain, 1, 100, GapCapturePrefix)
	_ = s.Put(pxCtx(), CaptureKey{Chain: pxChain, L1Block: 50, Item: "gapscan/10"}, []byte("x")) // ends before it starts
	if _, err := GapsIn(pxCtx(), s, pxChain, 0, MaxCaptureBlock); err == nil || !strings.Contains(err.Error(), "scan") {
		t.Fatalf("a scan row that ends before it starts is an error, never ignored: %v", err)
	}
}
