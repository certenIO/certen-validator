// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// canonL1 names the canonical block at every height: variant 0 of the shape world; variant 1 is the orphan twin of the reorged height.
type canonL1 struct{ w *shapeWorld }

func (c canonL1) Head(context.Context) (uint64, error) { return c.w.numberOf(c.w.N-1) + 200, nil }
func (c canonL1) Block(_ context.Context, n uint64) (L1BlockData, error) {
	return L1BlockData{Number: n, Hash: shapeHash(n, 0)}, nil
}
func (c canonL1) Proof(context.Context, [20]byte, [][32]byte, uint64) (StateProof, error) {
	return StateProof{}, errors.New("not used")
}

// RB12 OPS-A2 F18: a channel with a frame at a reorged height is served from the CANONICAL twin's rows by the window reader and by the index
// path alike. Before, the twin's duplicate frames made it unassemblable for both (TestRB12IndexSearchEqualsTheWindowReaderOnProductionShapedStores
// documents that shape without a provider, where nothing changes).
func TestF18AChannelWithAFrameAtAReorgedHeightIsServedFromTheCanonicalTwinByBothReaders(t *testing.T) {
	_, bp := idxPins(t)
	pins, _ := idxPins(t)
	w := newShapeWorld(t, bp, 120, 10)
	w.ForkAt = 40
	upTo := w.numberOf(w.N-1) + 200
	stepAll(t, newIdx(w, bp, IndexConfig{BlocksPerStep: 1 << 20}), upTo)
	for _, tc := range []struct {
		name string
		c, k int
	}{{"inside the reorged channel", 40, 3}, {"its first batch", 40, 0}, {"the channel before", 39, 2}, {"the channel after", 41, 2}} {
		ts, origin := w.legAt(tc.c, tc.k)
		l2 := fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}
		win := &Builder{Pins: pins, Store: w, L2: l2, L1: canonL1{w}}
		idx := &Builder{Pins: pins, Store: w, L2: l2, L1: canonL1{w}, Index: NewIndexReader(w, bp, 0)}
		hdr := finality.HeaderFields{Number: 5, Timestamp: ts}
		sw, errW := win.search(context.Background(), bp, hdr, nil)
		si, errI := idx.search(context.Background(), bp, hdr, nil)
		if errW != nil || errI != nil || sw.ch == nil || si.ch == nil {
			t.Fatalf("%s: window %v %v index %v %v", tc.name, sw.ch, errW, si.ch, errI)
		}
		if sw.ch.ID != si.ch.ID || len(sw.frameTxs) != len(si.frameTxs) || sw.bt.Timestamp != si.bt.Timestamp {
			t.Fatalf("%s: the readers differ: window %+v index %+v", tc.name, sw.ch, si.ch)
		}
		for i, f := range sw.frameTxs {
			if f.key != si.frameTxs[i].key {
				t.Fatalf("%s: frame %d: window %v index %v", tc.name, i, f.key, si.frameTxs[i].key)
			}
			if f.key.L1Hash != shapeHash(f.key.L1Block, 0) {
				t.Fatalf("%s: frame %d is of the orphan twin %v", tc.name, i, f.key)
			}
		}
	}
}

// With no provider the twins cannot be told apart and the answer is what it was: neither reader serves the reorged channel.
func TestF18WithoutAProviderTheReorgedChannelIsStillNotServed(t *testing.T) {
	_, bp := idxPins(t)
	pins, _ := idxPins(t)
	w := newShapeWorld(t, bp, 120, 10)
	w.ForkAt = 40
	ts, origin := w.legAt(40, 3)
	win := &Builder{Pins: pins, Store: w, L2: fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}}
	sw, err := win.search(context.Background(), bp, finality.HeaderFields{Number: 5, Timestamp: ts}, nil)
	if err != nil || sw.ch != nil {
		t.Fatalf("window %v %v", sw.ch, err)
	}
}

func TestF18TwinHeightsAreTheHeightsWithMoreThanOneCapturedHeader(t *testing.T) {
	_, bp := idxPins(t)
	pins, _ := idxPins(t)
	w := newShapeWorld(t, bp, 120, 10)
	w.ForkAt = 40
	b := &Builder{Pins: pins, Store: w}
	twins, err := b.twinHeights(context.Background(), 0, finality.MaxCaptureBlock)
	if err != nil || len(twins) != 1 || !twins[w.numberOf(40)] {
		t.Fatalf("twins %v %v, want only the height of channel 40 (%d)", twins, err, w.numberOf(40))
	}
	none, err := b.twinHeights(context.Background(), w.numberOf(41), w.numberOf(60))
	if err != nil || len(none) != 0 {
		t.Fatalf("a window without the twin: %v %v", none, err)
	}
}

// A frame the verified spine shows to sit in an orphan block is marked: a fill of that block then closes nothing, so the backfill fills the
// canonical block. A frame in a canonical block is not touched.
func TestF18BuildMarksTheOrphanFramesItFindsOnTheVerifiedSpine(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	c := uint64(Chain)
	orphan, canon := [32]byte{0xaa}, [32]byte{0xbb}
	if err := finality.RecordGap(ctx, st, c, 700, 709, finality.GapOperatorDeclared); err != nil {
		t.Fatal(err)
	}
	for _, h := range [][32]byte{orphan, canon} { // the orphan was filled at 705, the canonical block at 707
		blk := uint64(705)
		if h == canon {
			blk = 707
		}
		if err := finality.RecordGapFill(ctx, st, c, blk, h, true); err != nil {
			t.Fatal(err)
		}
	}
	b := &Builder{Store: st}
	frames := []capturedTx{{key: CaptureKey{Chain: c, L1Block: 705, L1Hash: orphan}}, {key: CaptureKey{Chain: c, L1Block: 707, L1Hash: canon}}}
	b.markOrphanFrames(ctx, frames, map[uint64][32]byte{705: canon, 707: canon})
	ps, err := finality.GapsIn(ctx, st, c, 700, 709)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].From != 700 || ps[0].To != 706 || ps[1].From != 708 {
		t.Fatalf("705 is open again (its fill was the orphan's) and 707 stays closed: %+v", ps)
	}
}
