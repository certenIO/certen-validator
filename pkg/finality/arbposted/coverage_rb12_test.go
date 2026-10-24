// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-ARCHIVE-BACKFILL, Arbitrum: a leg whose batch was posted before the capture started was 'awaiting_batch_post' for ever (12 legs in
// production, 2026-10-23). The window in which its batch can lie comes from its own authenticated header.

func synthL2Header(l1 uint64, short bool) []byte {
	items := []any{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 20), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32),
		bytes.Repeat([]byte{6}, 32), make([]byte, 256), uint64(1), uint64(7), uint64(8), uint64(9), uint64(10), []byte("x")}
	mix := make([]byte, 32)
	binary.BigEndian.PutUint64(mix[0:], 99)  // sendCount
	binary.BigEndian.PutUint64(mix[8:], l1)  // l1BlockNumber
	binary.BigEndian.PutUint64(mix[16:], 32) // arbOSVersion
	if !short {
		items = append(items, mix, make([]byte, 8))
	}
	raw, _ := rlp.EncodeToBytes(items)
	return raw
}

func TestRB12ArbTheL1BlockNumberIsReadFromTheMixHashOfTheHeader(t *testing.T) {
	if n, ok := l1BlockNumberOf(synthL2Header(11_842_545, false)); !ok || n != 11_842_545 {
		t.Fatalf("%d %v", n, ok)
	}
	if _, ok := l1BlockNumberOf(synthL2Header(1, true)); ok {
		t.Fatal("a header without a mixHash has no L1 block number")
	}
	if _, ok := l1BlockNumberOf([]byte{0xc0}); ok {
		t.Fatal("an empty list")
	}
	if _, ok := l1BlockNumberOf([]byte("garbage")); ok {
		t.Fatal("garbage")
	}
}

func putCursor(t *testing.T, st capture.CaptureStore, blocks ...uint64) {
	t.Helper()
	for _, b := range blocks {
		var h [32]byte
		binary.BigEndian.PutUint64(h[24:], b)
		if err := st.Put(context.Background(), capture.Key{Chain: finality.ChainArbitrumSepolia, L1Block: b, L1Hash: h, Item: capture.ItemCursor}, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
}

func gapRows(t *testing.T, st capture.CaptureStore) int {
	t.Helper()
	ks, _ := st.ListByRange(context.Background(), finality.ChainArbitrumSepolia, 0, finality.MaxCaptureBlock, "gap/")
	return len(ks)
}

func TestRB12ArbALegPostedBeforeTheCaptureIsRequestedNamedThenScannedThenDeterminate(t *testing.T) {
	ctx := context.Background()
	g := bLoad(t)
	g.store = capture.NewMemStore()
	l1, ok := l1BlockNumberOf(g.ref.HeaderRLP)
	if !ok {
		t.Fatal("the recorded Arbitrum header carries its L1 block number")
	}
	start, end := l1-MaxFutureBlocks, l1+MaxDelayBlocks
	first := l1 + 30_000 // the capture started 30,000 blocks after the leg's block was sequenced
	putCursor(t, g.store, first, first+1000)
	b := g.bBuilder()
	ask := func() *finality.StateError {
		_, p, err := b.BuildFor(ctx, g.ref)
		se, _ := finality.AsNamed(err)
		if se == nil && p != nil && p.Reason != PendingAwaitingBatchPost {
			t.Fatalf("pending %s", p.Reason)
		}
		return se
	}
	// 1. the extension is off: the leg is named, and nothing is written
	se := ask()
	if se == nil || se.Code != "l1_capture_not_covering" || se.Fields["prefix_state"] != "off" || se.Fields["epoch_l1_block"] != start || se.Fields["window_end_l1_block"] != end ||
		se.Fields["capture_first_l1_block"] != first || se.Fields["kind"] != KindName {
		t.Fatalf("%v", se)
	}
	if gapRows(t, g.store) != 0 {
		t.Fatal("nothing is written when the extension is off")
	}
	// 2. on: the window is requested once and the leg is the open gap over all of it
	b.Prefix = finality.PrefixPolicy{MaxBlocks: 10_000}
	se = ask()
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" || se.Fields["from"] != start || se.Fields["to"] != end ||
		se.Fields["blocks"] != end-start+1 || se.Fields["archive_provider"] != "n/a" {
		t.Fatalf("%v", se)
	}
	if ask(); gapRows(t, g.store) != 1 {
		t.Fatalf("one request row: %d", gapRows(t, g.store))
	}
	// 3. the scan covers all but its last block: still open at that block; then complete
	if err := finality.RecordGapScan(ctx, g.store, finality.ChainArbitrumSepolia, start, end-1); err != nil {
		t.Fatal(err)
	}
	if se = ask(); se == nil || se.Code != "l1_capture_gap" || se.Fields["from"] != end || se.Fields["to"] != end {
		t.Fatalf("%v", se)
	}
	if err := finality.RecordGapScan(ctx, g.store, finality.ChainArbitrumSepolia, end, end); err != nil {
		t.Fatal(err)
	}
	se = ask()
	if se == nil || se.Code != "l1_posted_not_found" || se.Fields["from"] != start || se.Fields["to"] != end || se.Fields["covered_to"] != first+1000 {
		t.Fatalf("a window scanned completely with no batch holding the block is determinate: %v", se)
	}
}

func TestRB12ArbALegWhoseWindowIsInTheScannedRegionIsPendingUntilTheCursorIsPastItsEnd(t *testing.T) {
	ctx := context.Background()
	g := bLoad(t)
	g.store = capture.NewMemStore()
	l1, _ := l1BlockNumberOf(g.ref.HeaderRLP)
	end := l1 + MaxDelayBlocks
	b := g.bBuilder()
	b.Prefix = finality.PrefixPolicy{MaxBlocks: 10_000}
	// the capture started before the window and has not reached its end: the batch may simply not be posted yet
	putCursor(t, g.store, l1-1000, end-100)
	_, p, err := b.BuildFor(ctx, g.ref)
	if err != nil || p == nil || p.Reason != PendingAwaitingBatchPost || gapRows(t, g.store) != 0 {
		t.Fatalf("pend=%v err=%v rows=%d", p, err, gapRows(t, g.store))
	}
	// exact margin: the window is complete only when its end is 96 blocks behind the cursor
	g2 := bLoad(t)
	g2.store = capture.NewMemStore()
	putCursor(t, g2.store, l1-1000, end+windowCompleteMargin)
	b2 := g2.bBuilder()
	if _, p, err = b2.BuildFor(ctx, g2.ref); p != nil {
		t.Fatalf("pend=%v", p)
	} else if se, _ := finality.AsNamed(err); se == nil || se.Code != "l1_posted_not_found" {
		t.Fatalf("a window ending exactly 96 blocks behind the cursor is complete: %v", err)
	}
	g3 := bLoad(t)
	g3.store = capture.NewMemStore()
	putCursor(t, g3.store, l1-1000, end+windowCompleteMargin-1)
	if _, p, err = g3.bBuilder().BuildFor(ctx, g3.ref); err != nil || p == nil || p.Reason != PendingAwaitingBatchPost {
		t.Fatalf("one block short of the margin it is still pending: pend=%v err=%v", p, err)
	}
}

func TestRB12ArbAHeaderThatIsNotTheReferencesIsNeverReadAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	g := bLoad(t)
	g.store = capture.NewMemStore()
	l1, _ := l1BlockNumberOf(g.ref.HeaderRLP)
	putCursor(t, g.store, l1+30_000, l1+31_000)
	b := g.bBuilder()
	b.Prefix = finality.PrefixPolicy{MaxBlocks: 10_000}
	forged := g.ref
	forged.Hash[0] ^= 0xff // the reference does not name this header
	if _, p, err := b.BuildFor(ctx, forged); err != nil || p == nil || gapRows(t, g.store) != 0 {
		t.Fatalf("an unauthenticated header writes nothing: pend=%v err=%v rows=%d", p, err, gapRows(t, g.store))
	}
}
