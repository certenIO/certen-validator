// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT duty (a): the blocks the archive PREFIX backfill closes arrive out of order and far BELOW the index cursor. They reach the
// indexer through the same fill path as every other backfilled block (Backfiller.attempt: the fill row, then OnFill and the report's
// FilledBlocks), and the indexer gives them their digest and completes their channels at its next step, with no walk of the table.

// rowCap is a BlockCapturer that stores the rows of the blocks it is given (as the capturer does) and reports whether the block holds inbox
// transactions.
type rowCap struct {
	t      testing.TB
	st     finality.CaptureStore
	bp     *Pins
	frames map[uint64][][]Frame // block -> the inbox transactions' frames
}

func (c rowCap) CaptureBlockHash(_ context.Context, n uint64) ([32]byte, bool, error) {
	txs, ok := c.frames[n]
	if !ok {
		return [32]byte{0xcc, byte(n), byte(n >> 8)}, false, nil // a block with no inbox transactions (the fill names a hash all the same)
	}
	var sts []shapeTx
	for _, fr := range txs {
		sts = append(sts, shapeTx{datas: [][]byte{payloadOf(fr...)}})
	}
	shapeBlock{number: n, hash: shapeHash(n, 0), txs: sts}.put(c.t, c.st, c.bp)
	return shapeHash(n, 0), true, nil
}

func TestRB12PrefixFilledBlocksBelowTheIndexCursorAreIndexedAtTheNextStep(t *testing.T) {
	ctx := context.Background()
	_, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("prefix-A", 1_790_300_000, 30, 990, 1)
	B := channelFrames("prefix-B", 1_790_400_000, 30, 990, 1)
	vPutBlock(t, st, bp, 5000, channelFrames("anchor", 1_790_900_000, 4, 4900, 1))
	ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1 << 30, ReconcileSpan: 16})
	stepAll(t, ix, 40_000) // the cursor is 35,000 blocks above the prefix window

	// a prefix window (blocks 1000..1007) below everything the loop scanned, closed out of order by the archive backfill
	if err := finality.RecordGap(ctx, st, uint64(Chain), 1000, 1007, finality.GapCapturePrefix); err != nil {
		t.Fatal(err)
	}
	now, _ := bfClock()
	var told []uint64
	w := &Backfiller{Chain: uint64(Chain), Store: st, Policy: bfPolicy(), Now: now, Pick: func(n int) int { return n - 1 }, // highest block first: out of order
		Capturer: rowCap{t: t, st: st, bp: bp, frames: map[uint64][][]Frame{1003: {{A[0]}}, 1005: {{B[0]}}}},
		OnFill: func(n uint64, hasInbox bool) {
			if hasInbox {
				told = append(told, n)
				ix.NoteLate(n)
			}
		}}
	rep, err := w.Step(ctx, 16)
	if err != nil || rep.Filled != 8 {
		t.Fatalf("the window is closed: %+v %v", rep, err)
	}
	if len(told) != 2 || len(rep.FilledBlocks) != 2 {
		t.Fatalf("only the blocks with inbox transactions are told to the index: told %v reported %v", told, rep.FilledBlocks)
	}
	// nothing but the note makes the indexer look below its cursor: one ordinary step digests both blocks and completes their channels
	if hasDigest(t, st, 1003) || hasDigest(t, st, 1005) {
		t.Fatal("control: the blocks are not indexed before the step")
	}
	stepAll(t, ix, 40_000)
	for _, c := range []struct {
		block uint64
		id    [16]byte
		ts    uint64
	}{{1003, chanLabelID("prefix-A"), 1_790_300_004}, {1005, chanLabelID("prefix-B"), 1_790_400_004}} {
		if !hasDigest(t, st, c.block) || !entryClosingAt(t, st, c.block, c.id) {
			t.Fatalf("prefix-filled block %d: digest %v, entry of its channel %v", c.block, hasDigest(t, st, c.block), entryClosingAt(t, st, c.block, c.id))
		}
		hit, _, err := NewIndexReader(st, bp, 0).Find(ctx, c.ts, 990, 990+bp.SeqWindowSize, &ioCount{})
		if err != nil || hit == nil || hit.entry.ID != c.id {
			t.Fatalf("the leg of block %d is served from the index: %v %v", c.block, hit, err)
		}
	}
}
