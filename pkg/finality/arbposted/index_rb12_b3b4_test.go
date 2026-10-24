// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

func (w *ixWorld) hasEntryFor(n uint64) bool {
	ks, err := w.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, ixItem(1, ixEntry)+"/")
	if err != nil {
		w.t.Fatal(err)
	}
	for _, k := range ks {
		if nm, ok := parseEntryName(1, k); ok && nm.N == n {
			return true
		}
	}
	return false
}

// V-INDEX-B B3(b): a note is never lost. With the set of single-block notes full (notes above the cursor stay pending until the forward step takes
// them) a further note for a batch stored BELOW the capture's first block used to be dropped, and nothing else reaches that region: it was not
// indexed after 200 further steps. Fail-before @d313b708 (existing API only): the batch is not indexed after the steps a note needs.
func TestRB12ArbIndexNoteIsNeverLostWhenTheNoteSetIsFull(t *testing.T) {
	w := newIxWorld(t)
	for i := uint64(0); i < 5; i++ {
		w.add(ixBatch{N: 200 + i, Block: 5000 + 8*i, T: ixT0 + 96*i, Msgs: [][][]byte{ixMsg(ixTx(int(70000 + i)))}})
	}
	ix := w.index(IndexConfig{RecentSpan: 4})
	for b := uint64(0); b < maxHints; b++ {
		ix.NoteLate(7000 + b) // above the cursor: they stay pending
	}
	w.add(ixBatch{N: 150, Block: 900, T: ixT0 - 5000, Msgs: [][][]byte{ixMsg(ixTx(70150))}}) // stored after the cursor passed, below the capture's first block
	ix.NoteLate(900)
	for i := 0; i < 8 && !w.hasEntryFor(150); i++ {
		if _, err := ix.Step(context.Background(), w.top+1); err != nil {
			t.Fatal(err)
		}
	}
	if !w.hasEntryFor(150) {
		t.Fatal("the note was dropped with the set full and the batch below the capture start is not indexed after the steps a note needs")
	}
}

// V-INDEX-B B3(b)/(c): the rotating walk reaches below the capture's first cursor row down to the floor, with no note at all, within a stated bound: it
// is a cycle over [floor, cursor] in chunks of ReconcileSpan blocks, one chunk per ReconcileEvery steps, so a block is reached within
// ceil((cursor - floor + 1) / ReconcileSpan) x ReconcileEvery steps.
func TestRB12ArbIndexRotationReachesBelowTheCaptureStartDownToTheFloor(t *testing.T) {
	setup := func(floor func(context.Context) (uint64, bool, error)) (*ixWorld, *Indexer) {
		w := newIxWorld(t)
		for i := uint64(0); i < 3; i++ {
			w.add(ixBatch{N: 200 + i, Block: 5000 + 8*i, T: ixT0 + 96*i, Msgs: [][][]byte{ixMsg(ixTx(int(71000 + i)))}})
		}
		ix := w.index(IndexConfig{RecentSpan: 4, ReconcileSpan: 128, ReconcileEvery: 1, Floor: floor})
		w.add(ixBatch{N: 150, Block: 900, T: ixT0 - 5000, Msgs: [][][]byte{ixMsg(ixTx(71150))}}) // stored later, no note
		return w, ix
	}
	// without a floor the region below the first cursor row is never walked
	w0, ix0 := setup(nil)
	for i := 0; i < 60; i++ {
		if _, err := ix0.Step(context.Background(), w0.top+1); err != nil {
			t.Fatal(err)
		}
	}
	if w0.hasEntryFor(150) {
		t.Fatal("without a floor the walk indexed a block below the capture start")
	}
	// with the floor at 800 the whole cycle is (6100 - 800 + 1) / 128 chunks, and the batch at 900 is reached within it
	w1, ix1 := setup(func(context.Context) (uint64, bool, error) { return 800, true, nil })
	rounds := int((w1.top + 1 - 800 + 1 + 127) / 128)
	for i := 0; i < rounds+1; i++ {
		if _, err := ix1.Step(context.Background(), w1.top+1); err != nil {
			t.Fatal(err)
		}
	}
	if !w1.hasEntryFor(150) {
		t.Fatalf("the walk did not reach block 900 from the floor 800 within %d rounds", rounds+1)
	}
	// a floor far lower is a longer cycle, and the same bound holds
	w2, ix2 := setup(func(context.Context) (uint64, bool, error) { return 100, true, nil })
	w2.add(ixBatch{N: 100, Block: 640, T: ixT0 - 9000, Msgs: [][][]byte{ixMsg(ixTx(71100))}})
	bound := int((w2.top + 1 - 100 + 1 + 127) / 128)
	for i := 0; i < bound+1; i++ {
		if _, err := ix2.Step(context.Background(), w2.top+1); err != nil {
			t.Fatal(err)
		}
	}
	if !w2.hasEntryFor(100) || !w2.hasEntryFor(150) {
		t.Fatalf("the walk did not reach block 640 from the floor 100 within %d rounds", bound+1)
	}
}

// A RANGE note (the prefix scan stores a window, not blocks one by one) is worked off in chunks under the step limits and then forgotten; the notes
// are bounded in number and only ever widen.
func TestRB12ArbIndexRangeNoteIsWorkedOffInBoundedChunksAndTheNotesAreBounded(t *testing.T) {
	w := newIxWorld(t)
	for i := uint64(0); i < 3; i++ {
		w.add(ixBatch{N: 200 + i, Block: 5000 + 8*i, T: ixT0 + 96*i, Msgs: [][][]byte{ixMsg(ixTx(int(72000 + i)))}})
	}
	ix := w.index(IndexConfig{RecentSpan: 4, BlocksPerStep: 2, ReconcileSpan: 64, ReconcileEvery: 1 << 30})
	var late []uint64
	for i := uint64(0); i < 5; i++ {
		b := 700 + 40*i
		w.add(ixBatch{N: 100 + i, Block: b, T: ixT0 - 9000 + 96*i, Msgs: [][][]byte{ixMsg(ixTx(int(72100 + i)))}})
		late = append(late, 100+i)
	}
	var _ finality.LateRangeNoter = ix
	ix.NoteLateRange(1000, 600) // a range may be given either way round
	steps := 0
	for ; steps < 20; steps++ {
		if _, err := ix.Step(context.Background(), w.top+1); err != nil {
			t.Fatal(err)
		}
		all := true
		for _, n := range late {
			all = all && w.hasEntryFor(n)
		}
		if all {
			break
		}
	}
	for _, n := range late {
		if !w.hasEntryFor(n) {
			t.Fatalf("batch %d of the noted range was not indexed within %d steps", n, steps)
		}
	}
	// the bound: 5 batches at 2 per step is 3 steps, plus the chunking of 401 blocks by 64
	if steps > 12 {
		t.Fatalf("%d steps for 5 batches in a range of 401 blocks", steps)
	}
	for i := 0; i < 20; i++ { // the empty rest of the range is worked off too, and the note is forgotten
		if _, err := ix.Step(context.Background(), w.top+1); err != nil {
			t.Fatal(err)
		}
	}
	ix.hintMu.Lock()
	left := len(ix.ranges)
	ix.hintMu.Unlock()
	if left != 0 {
		t.Fatalf("%d range notes are still pending after the range was worked off", left)
	}
	// bounded and only widening: 300 disjoint notes leave at most maxHintRanges, and every noted block is still covered
	ix2 := w.indexer(IndexConfig{})
	for i := uint64(0); i < 300; i++ {
		ix2.NoteLateRange(100+10*i, 100+10*i+2)
	}
	ix2.hintMu.Lock()
	defer ix2.hintMu.Unlock()
	if len(ix2.ranges) > maxHintRanges {
		t.Fatalf("%d range notes", len(ix2.ranges))
	}
	for i := uint64(0); i < 300; i++ {
		covered := false
		for _, r := range ix2.ranges {
			covered = covered || (r[0] <= 100+10*i && 100+10*i+2 <= r[1])
		}
		if !covered {
			t.Fatalf("the note %d..%d was lost when the notes were merged", 100+10*i, 100+10*i+2)
		}
	}
}

// V-INDEX-B B4 (class 7): the edges of the normal lookup window, and the batches beyond it. A batch whose posting is up to 100,000 s after its minTs
// and up to 4,000 s before its maxTs is found by the lookup's normal window; one more second on either side is pointed at by a "w" row and served
// exactly as the reference serves it - no batch the verifier can accept is unservable by the index. Only a window wider than 400 days is named
// index_block_unindexable{window_beyond_cap}. Fail-before @d313b708: delay 100,001 / future 4,001 gave window_beyond_cap where the reference serves the batch.
func TestRB12ArbIndexWindowEdgesAndBatchesBeyondTheNormalWindow(t *testing.T) {
	const T = ixT0 + 600_000
	for _, c := range []struct {
		name       string
		delay, fut uint64
		wide       bool
		legs       []uint64
	}{
		{"delay at the cap", 100_000, 768, false, []uint64{T - 100_000, T - 100_001, T + 768, T + 769}},
		{"delay one beyond the cap", 100_001, 768, true, []uint64{T - 100_001, T - 100_002, T + 768, T + 769}},
		{"future at the cap", 86_400, 4_000, false, []uint64{T - 86_400, T + 4_000, T + 4_001}},
		{"future one beyond the cap", 86_400, 4_001, true, []uint64{T - 86_400, T + 4_001, T + 4_002}},
		{"both far beyond", 3_000_000, 90_000, true, []uint64{T - 3_000_000, T - 1_000_000, T + 90_000, T + 90_001}},
	} {
		w := newIxWorld(t)
		tx := ixTx(73000)
		w.add(ixBatch{N: 800, Block: 1000, T: T, MinTs: T - c.delay, MaxTs: T + c.fut, Msgs: [][][]byte{ixMsg(tx)}})
		// neighbours on either side, inside the normal window, so the history is not one batch
		w.add(ixBatch{N: 799, Block: 992, T: T - 96, Msgs: [][][]byte{ixMsg(ixTx(73001))}})
		w.add(ixBatch{N: 801, Block: 1008, T: T + 96, Msgs: [][][]byte{ixMsg(ixTx(73002))}})
		w.index(IndexConfig{})
		r := w.reader()
		found := 0
		for _, ts := range c.legs {
			ref, idx := w.ref(ts, [][]byte{tx}), w.idx(r, ts, [][]byte{tx})
			if ref != idx {
				t.Errorf("%s ts %d: reference %s, index %s", c.name, ts, ref, idx)
			}
			if ref.N == 800 {
				found++
			}
		}
		if found < 2 {
			t.Errorf("%s: the reference serves the batch for only %d of the legs: the case does not exercise the edges", c.name, found)
		}
		_, wide := w.indexRows()[wideKey(1, T-c.delay, T+c.fut, 800)]
		if wide != c.wide {
			t.Errorf("%s: a pointer row exists: %v, want %v", c.name, wide, c.wide)
		}
	}
	// the hard limit: a window wider than 400 days is no real configuration; it is named, the reference serves it
	w := newIxWorld(t)
	tx := ixTx(73100)
	w.add(ixBatch{N: 810, Block: 1000, T: T, MinTs: T - (windowHardLimit + 1), Msgs: [][][]byte{ixMsg(tx)}})
	w.index(IndexConfig{})
	r := w.reader()
	if ref := w.ref(T-10, [][]byte{tx}); ref.N != 810 {
		t.Fatalf("the reference does not serve the batch: %s", ref)
	}
	got := w.idx(r, T-10, [][]byte{tx})
	if got.N != 0 || !strings.Contains(got.State, `"code":"index_block_unindexable"`) || !strings.Contains(got.State, `"reason":"window_beyond_cap"`) || !strings.Contains(got.State, `"block":"1000"`) {
		t.Fatalf("a window wider than the hard limit is not named: %s", got)
	}
	// exactly at the hard limit the batch is a wide batch and is served
	w2 := newIxWorld(t)
	w2.add(ixBatch{N: 811, Block: 1000, T: T, MinTs: T - windowHardLimit, Msgs: [][][]byte{ixMsg(tx)}})
	w2.index(IndexConfig{})
	if ref, idx := w2.ref(T-10, [][]byte{tx}), w2.idx(w2.reader(), T-10, [][]byte{tx}); ref.N != 811 || ref != idx {
		t.Fatalf("at the hard limit: reference %s, index %s", ref, idx)
	}
}
