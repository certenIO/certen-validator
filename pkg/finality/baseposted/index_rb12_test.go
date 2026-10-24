// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// ---- helpers shared by the index tests ----

func smallWorld(t testing.TB, bp *Pins, channels int) *shapeWorld {
	t.Helper()
	return newShapeWorld(t, bp, channels, 10)
}

func newIdx(st finality.CaptureStore, bp *Pins, cfg IndexConfig) *Indexer {
	return NewIndexer(st, bp, 0, cfg)
}

func stepAll(t testing.TB, ix *Indexer, upTo uint64) finality.StepReport {
	t.Helper()
	var total finality.StepReport
	for i := 0; i < 1000; i++ {
		rep, err := ix.Step(context.Background(), upTo)
		if err != nil {
			t.Fatalf("step: %v", err)
		}
		total.Blocks += rep.Blocks
		total.Entries += rep.Entries
		total.Late += rep.Late
		total.Through = rep.Through
		total.Open = rep.Open
		if rep.StoppedByCap == "" {
			return total
		}
	}
	t.Fatal("the indexer never caught up")
	return total
}

// indexRows returns every idx/ row of a store, by key.
func indexRows(t testing.TB, st finality.CaptureStore) map[finality.CaptureKey][]byte {
	t.Helper()
	ks, err := st.ListByRange(context.Background(), uint64(Chain), 0, finality.MaxCaptureBlock, "idx/")
	if err != nil {
		t.Fatal(err)
	}
	out := map[finality.CaptureKey][]byte{}
	for _, k := range ks {
		b, ok, err := st.Get(context.Background(), k)
		if err != nil || !ok {
			t.Fatalf("row %s: %v %v", k, ok, err)
		}
		out[k] = b
	}
	return out
}

func sameRows(a, b map[finality.CaptureKey][]byte) string {
	for k, v := range a {
		w, ok := b[k]
		if !ok {
			return "only in first: " + k.String()
		}
		if !bytes.Equal(v, w) {
			return "bytes differ: " + k.String()
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			return "only in second: " + k.String()
		}
	}
	return ""
}

func findFor(t testing.TB, st finality.CaptureStore, bp *Pins, ts, origin, end uint64) (*indexHit, []entryName, error) {
	t.Helper()
	return NewIndexReader(st, bp, 0).Find(context.Background(), ts, origin, end, &ioCount{})
}

func ctxBG() context.Context { return context.Background() }

// ---- what the indexer writes ----

func TestRB12IndexStepWritesDigestsEntriesAndTheCursorAndResumes(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 40)
	upTo := w.numberOf(39) + 200
	ix := newIdx(w, bp, IndexConfig{BlocksPerStep: 16})
	rep := stepAll(t, ix, upTo)
	if rep.Blocks != 40 || rep.Entries != 40 || rep.Through != upTo || rep.Open != 0 {
		t.Fatalf("report %+v", rep)
	}
	rows := indexRows(t, w)
	var digests, entries, cursors int
	for k, v := range rows {
		switch {
		case strings.HasPrefix(k.Item, "idx/g1/bi/f"):
			digests++
			d, err := decodeDigest(k, v)
			if err != nil || len(d.Txs) != 2 || len(d.Txs[0].Frames) != 6 || d.Txs[0].Blobs != 6 || d.Txs[1].Frames[0].Number != 6 || !d.Txs[1].Frames[0].Last {
				t.Fatalf("digest %s: %+v %v", k, d, err)
			}
		case strings.HasPrefix(k.Item, "idx/g1/bi/c/"):
			entries++
			n, ok := parseEntryName(1, k)
			if !ok {
				t.Fatalf("entry name %s", k.Item)
			}
			e, err := decodeEntry(v)
			if err != nil || e.Status != entryDecoded || e.NFrames != 7 || len(e.Txs) != 2 || len(e.Runs) != 1 || e.Runs[0].Count != shapePerChan || e.TMin != n.TMin || e.TMax != n.TMax || e.TMax-e.TMin != 2*(shapePerChan-1) {
				t.Fatalf("entry %s: %+v %v", k, e, err)
			}
			if k.L1Block != e.Txs[1].Block {
				t.Fatalf("the entry sits at the closing block: key %d, closing tx %d", k.L1Block, e.Txs[1].Block)
			}
		case strings.HasPrefix(k.Item, "idx/g1/bi/cursor"):
			cursors++
		}
	}
	if digests != 40 || entries != 40 || cursors < 1 {
		t.Fatalf("digests %d entries %d cursors %d", digests, entries, cursors)
	}
	// a restarted indexer resumes from the cursor and writes nothing
	again := newIdx(w, bp, IndexConfig{BlocksPerStep: 16})
	rep2 := stepAll(t, again, upTo)
	if rep2.Blocks != 0 || rep2.Entries != 0 || rep2.Through != upTo {
		t.Fatalf("a restart must find nothing to do: %+v", rep2)
	}
	if d := sameRows(rows, indexRows(t, w)); d != "" {
		t.Fatalf("a restart changed the index: %s", d)
	}
}

func TestRB12IndexFindsTheChannelOfATimestampAndOnlyThatOne(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 40)
	stepAll(t, newIdx(w, bp, IndexConfig{}), w.numberOf(39)+200)
	meter := &meterStore{CaptureStore: w}
	r := NewIndexReader(meter, bp, 0)
	for _, c := range []int{0, 7, 39} {
		ts, origin := w.legAt(c, 33)
		io := &ioCount{}
		hit, names, err := r.Find(ctxBG(), ts, origin, origin+bp.SeqWindowSize, io)
		if err != nil || hit == nil {
			t.Fatalf("channel %d: %v %v", c, hit, err)
		}
		if hit.entry.ID != chanLabelID("shape/"+strconv.Itoa(c)) || hit.run.Epoch != w.Epoch(c) || hit.run.Type != 0 {
			t.Fatalf("channel %d: wrong hit %+v", c, hit.run)
		}
		if io.n > 4<<10 {
			t.Fatalf("a lookup must read the entry (a few hundred bytes), read %d", io.n)
		}
		if len(names) > 12 {
			t.Fatalf("channel %d: %d names listed for a hit in the first part of the window", c, len(names))
		}
		txs, err := r.Assemble(ctxBG(), hit, nil, io)
		if err != nil || len(txs) != 2 || len(txs[0].blobs) != 6 || len(txs[1].blobs) != 1 {
			t.Fatalf("assemble: %v %d", err, len(txs))
		}
	}
	// a timestamp no channel covers is a miss, not a guess
	ts, origin := w.legAt(40, 0)
	if hit, _, err := findFor(t, w, bp, ts, origin, origin+bp.SeqWindowSize); hit != nil || err != nil {
		t.Fatalf("a timestamp past the last channel is a miss: %v %v", hit, err)
	}
}

// The frame table orders and assembles exactly as the window reader's findChannel does: interleaved channels, a channel over several
// blocks and transactions, and a transaction that carries frames of two channels.
func TestRB12IndexAssemblesInterleavedAndMultiBlockChannelsLikeFindChannel(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, 1000, 4)
	B := channelFrames("B", 1_790_200_000, 30, 1000, 3)
	// block 1010: tx0 = A0, B0 (one tx, two channels); tx1 = A1. block 1015: A2, then B1. block 1030: A3(last), B2(last) in two txs
	blocks := []shapeBlock{
		{number: 1010, hash: shapeHash(1010, 0), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(A[0], B[0])}}, {blob: false, datas: [][]byte{payloadOf(A[1])}}}},
		{number: 1015, hash: shapeHash(1015, 0), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(A[2])}}, {blob: false, datas: [][]byte{payloadOf(B[1])}}}},
		{number: 1030, hash: shapeHash(1030, 0), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(A[3])}}, {blob: false, datas: [][]byte{payloadOf(B[2])}}}},
	}
	for _, b := range blocks {
		b.put(t, st, bp)
	}
	ix := newIdx(st, bp, IndexConfig{})
	stepAll(t, ix, 1100)
	// the reference: the window reader's grouping over the same rows
	b := &Builder{Store: st}
	all, err := b.loadRange(ctxBG(), bp, 0, 2000, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		label string
		ts    uint64
		txs   int
		first uint64
	}{{"A", 1_790_100_000 + 20, 4, 1010}, {"B", 1_790_200_000 + 40, 3, 1010}} {
		ch, frameTxs, _, _ := findChannel(all, bp, c.ts)
		if ch == nil {
			t.Fatalf("%s: the reference finds no channel", c.label)
		}
		hit, _, err := findFor(t, st, bp, c.ts, 1000, 1000+bp.SeqWindowSize)
		if err != nil || hit == nil || hit.entry.ID != ch.ID {
			t.Fatalf("%s: index %v %v, reference %x", c.label, hit, err, ch.ID[:4])
		}
		txs, err := NewIndexReader(st, bp, 0).Assemble(ctxBG(), hit, nil, &ioCount{})
		if err != nil || len(txs) != len(frameTxs) {
			t.Fatalf("%s: %d txs, reference %d (%v)", c.label, len(txs), len(frameTxs), err)
		}
		for i := range txs {
			if txs[i].key != frameTxs[i].key || txs[i].index != frameTxs[i].index || !bytes.Equal(txs[i].raw, frameTxs[i].raw) || len(txs[i].blobs) != len(frameTxs[i].blobs) {
				t.Fatalf("%s: tx %d differs from the reference: %v vs %v", c.label, i, txs[i].key, frameTxs[i].key)
			}
		}
	}
}

// ---- determinism and conflicts ----

func TestRB12IndexRowsAreAPureFunctionOfTheCapturedBytes(t *testing.T) {
	_, bp := idxPins(t)
	build := func() *shapeWorld { return smallWorld(t, bp, 30) }
	upTo := smallWorld(t, bp, 30).numberOf(29) + 200
	// one big step, many tiny steps, and two indexers racing on the same store
	w1, w2, w3 := build(), build(), build()
	stepAll(t, newIdx(w1, bp, IndexConfig{BlocksPerStep: 1 << 20}), upTo)
	stepAll(t, newIdx(w2, bp, IndexConfig{BlocksPerStep: 1, ReconcileEvery: 1}), upTo)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ix := newIdx(w3, bp, IndexConfig{BlocksPerStep: 3 + i})
			for j := 0; j < 100; j++ {
				rep, err := ix.Step(ctxBG(), upTo)
				if err != nil {
					errs <- err
					return
				}
				if rep.StoppedByCap == "" {
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("a concurrent indexer of the same store failed: %v", err)
	}
	a, b, c := indexRows(t, w1), indexRows(t, w2), indexRows(t, w3)
	// the cursor rows differ in count (one per step) but every digest and entry is identical
	strip := func(m map[finality.CaptureKey][]byte) map[finality.CaptureKey][]byte {
		out := map[finality.CaptureKey][]byte{}
		for k, v := range m {
			if !strings.Contains(k.Item, "/cursor") {
				out[k] = v
			}
		}
		return out
	}
	if d := sameRows(strip(a), strip(b)); d != "" {
		t.Fatalf("one big step vs one block per step: %s", d)
	}
	if d := sameRows(strip(a), strip(c)); d != "" {
		t.Fatalf("one indexer vs four racing indexers: %s", d)
	}
	if len(strip(a)) != 60 {
		t.Fatalf("expected 30 digests and 30 entries, got %d rows", len(strip(a)))
	}
}

func TestRB12IndexConflictingRowIsTheNamedErrorNeverAnOverwrite(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 10)
	upTo := w.numberOf(9) + 200
	good := smallWorld(t, bp, 10)
	stepAll(t, newIdx(good, bp, IndexConfig{}), upTo)
	var victim finality.CaptureKey
	for k := range indexRows(t, good) {
		if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && k.L1Block == w.numberOf(4) {
			victim = k
		}
	}
	if victim.Item == "" {
		t.Fatal("no entry at block 4")
	}
	if err := w.Put(ctxBG(), victim, []byte("a different row")); err != nil {
		t.Fatal(err)
	}
	// another validator's Put of the entry is not in this one's listing yet (a race): the indexer builds the entry and its Put meets the row
	ix := newIdx(hideKey{CaptureStore: w, hide: victim}, bp, IndexConfig{})
	_, err := ix.Step(ctxBG(), upTo)
	if !errors.Is(err, finality.ErrIndexConflict) || !IsIndexConflict(err) {
		t.Fatalf("a different row under an entry's key must be the named conflict, got %v", err)
	}
	var ce *finality.IndexConflictError
	if !errors.As(err, &ce) || ce.Key != victim {
		t.Fatalf("the error must name the row: %v", err)
	}
	if b, _, _ := w.Get(ctxBG(), victim); string(b) != "a different row" {
		t.Fatal("the stored row was overwritten")
	}
}

// hideKey lists everything but one key.
type hideKey struct {
	finality.CaptureStore
	hide finality.CaptureKey
}

func (h hideKey) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	ks, err := h.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
	out := ks[:0:0]
	for _, k := range ks {
		if k != h.hide {
			out = append(out, k)
		}
	}
	return out, err
}

// ---- late arrivals and capture holes ----

// A block that arrives after the cursor passed it (a retried capture, a hole filled later) completes its channel; the entry is the same
// bytes the in-order index writes.
func TestRB12IndexLateArrivalCompletesAChannelWithIdenticalBytes(t *testing.T) {
	_, bp := idxPins(t)
	ref := smallWorld(t, bp, 30)
	upTo := ref.numberOf(29) + 200
	stepAll(t, newIdx(ref, bp, IndexConfig{}), upTo)
	want := indexRows(t, ref)

	// the same world with channels 12 and 13 missing (a hole), indexed, then filled out of order and indexed again
	w := smallWorld(t, bp, 30)
	w.Holes = [][2]int{{12, 13}}
	ix := newIdx(w, bp, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix, upTo)
	got := indexRows(t, w)
	for k := range got {
		if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && (k.L1Block == w.numberOf(12) || k.L1Block == w.numberOf(13)) {
			t.Fatalf("a hole must not have an entry: %s", k)
		}
	}
	if _, hit := func() (*indexHit, error) {
		ts, origin := w.legAt(12, 4)
		h, _, err := findFor(t, w, bp, ts, origin, origin+bp.SeqWindowSize)
		return h, err
	}(); hit != nil {
		t.Fatal("the channel in the hole is found")
	}
	// the hole is filled (channel 13 first), the indexer is the same process, the cursor is far past
	w.Holes = [][2]int{{12, 12}}
	if rep := stepAll(t, ix, upTo); rep.Late != 1 || rep.Entries != 1 {
		t.Fatalf("filling block 13 must index exactly it: %+v", rep)
	}
	w.Holes = nil
	if rep := stepAll(t, ix, upTo); rep.Late != 1 || rep.Entries != 1 {
		t.Fatalf("filling block 12 must index exactly it: %+v", rep)
	}
	strip := func(m map[finality.CaptureKey][]byte) map[finality.CaptureKey][]byte {
		out := map[finality.CaptureKey][]byte{}
		for k, v := range m {
			if !strings.Contains(k.Item, "/cursor") {
				out[k] = v
			}
		}
		return out
	}
	if d := sameRows(strip(want), strip(indexRows(t, w))); d != "" {
		t.Fatalf("a hole filled later must give the index of a complete capture: %s", d)
	}
}

// A channel with a frame in a hole is incomplete: no entry, counted open, never skipped; the leg that needs it gets the named gap.
func TestRB12IndexChannelWithAMissingFrameIsOpenAndTheLegIsANamedGap(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, 1000, 4) // frames in blocks 1010, 1012, 1014 (missing), 1016
	B := channelFrames("B", 1_790_100_060, 30, 1100, 1) // a later channel, wholly captured, closing far later
	put := func(n uint64, f ...Frame) {
		shapeBlock{number: n, hash: shapeHash(n, 0), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(f...)}}}}.put(t, st, bp)
	}
	put(1010, A[0])
	put(1012, A[1])
	put(1016, A[3])
	put(1100, B[0])
	var v [8]byte
	v[7] = 0xff // cursor: not used by the block bounds fallback below
	for _, c := range []uint64{1031, 1400} {
		var cv [8]byte
		cv[6], cv[7] = byte(c>>8), byte(c)
		if err := st.Put(ctxBG(), finality.CaptureKey{Chain: uint64(Chain), L1Block: c, Item: finality.CaptureCursorItem}, cv[:]); err != nil {
			t.Fatal(err)
		}
	}
	ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1})
	rep := stepAll(t, ix, 1400)
	if rep.Blocks != 4 || rep.Entries != 1 || rep.Open != 1 {
		t.Fatalf("one complete channel and one open: %+v", rep)
	}
	pins, _ := idxPins(t)
	b := &Builder{Pins: pins, Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(1000, [32]byte{9})}}, Index: NewIndexReader(st, bp, 0)}
	hold := finality.NewHold(ctxBG(), uint64(Chain), "t")
	sr, err := b.search(ctxBG(), bp, finality.HeaderFields{Number: 5, Timestamp: 1_790_100_000 + 20}, hold)
	st2, ok := finality.AsNamed(err)
	if !ok || st2.Code != finality.CodeCaptureGap || sr.ch != nil {
		t.Fatalf("want the named gap, got %v", err)
	}
	f := st2.Fields
	if f["l2_timestamp"] != uint64(1_790_100_020) || f["to_l1"] != uint64(1100) || f["partial_frames"] != uint64(3) {
		t.Fatalf("the gap names where it was judged: %v", f)
	}
	// the missing block is captured: the channel completes and the leg is found
	put(1014, A[2])
	if rep := stepAll(t, ix, 1400); rep.Late != 1 || rep.Entries != 1 || rep.Open != 0 {
		t.Fatalf("the late block completes the channel: %+v", rep)
	}
	sr, err = b.search(ctxBG(), bp, finality.HeaderFields{Number: 5, Timestamp: 1_790_100_000 + 20}, finality.NewHold(ctxBG(), uint64(Chain), "t"))
	if err != nil || sr.ch == nil || len(sr.frameTxs) != 4 {
		t.Fatalf("after the fill: %v %v", sr.ch, err)
	}
}

// A late frame that breaks an already closed channel leaves a marker; a build that would use the channel is the named inconsistency.
func TestRB12IndexLateDuplicateFrameMarksTheClosedChannel(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, 1000, 2)
	put := func(n uint64, v int, f ...Frame) {
		shapeBlock{number: n, hash: shapeHash(n, v), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(f...)}}}}.put(t, st, bp)
	}
	put(1010, 0, A[0])
	put(1020, 0, A[1])
	ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix, 1100)
	if hit, _, err := findFor(t, st, bp, 1_790_100_000+10, 1000, 4600); err != nil || hit == nil {
		t.Fatalf("complete channel: %v %v", hit, err)
	}
	put(1015, 0, A[1]) // a second copy of frame 1, captured late
	stepAll(t, ix, 1100)
	_, _, err := findFor(t, st, bp, 1_790_100_000+10, 1000, 4600)
	s, ok := finality.AsNamed(err)
	if !ok || s.Code != finality.CodeIndexInconsistent || s.Fields["reason"] != finality.IndexDuplicateAfterOpen {
		t.Fatalf("want index_inconsistent{duplicate_frame_after_close}, got %v", err)
	}
}

// ---- budget and resumability ----

func TestRB12IndexStepEndsAtItsBlockBoundAndResumesFromTheCursor(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 50)
	upTo := w.numberOf(49) + 200
	ix := newIdx(w, bp, IndexConfig{BlocksPerStep: 8})
	steps := 0
	var last uint64
	for {
		rep, err := ix.Step(ctxBG(), upTo)
		if err != nil {
			t.Fatal(err)
		}
		steps++
		if rep.Blocks > 8 {
			t.Fatalf("a step digested %d blocks above its bound of 8", rep.Blocks)
		}
		if rep.Through < last {
			t.Fatalf("the cursor went back: %d -> %d", last, rep.Through)
		}
		last = rep.Through
		if steps == 3 { // a restart in the middle of the backfill
			ix = newIdx(w, bp, IndexConfig{BlocksPerStep: 8})
		}
		if rep.StoppedByCap == "" {
			break
		}
	}
	if steps != 7 {
		t.Fatalf("50 blocks at 8 per step take 7 steps, took %d", steps)
	}
	if last != upTo {
		t.Fatalf("cursor %d, want %d", last, upTo)
	}
	ref := smallWorld(t, bp, 50)
	stepAll(t, newIdx(ref, bp, IndexConfig{}), upTo)
	strip := func(m map[finality.CaptureKey][]byte) map[finality.CaptureKey][]byte {
		out := map[finality.CaptureKey][]byte{}
		for k, v := range m {
			if !strings.Contains(k.Item, "/cursor") {
				out[k] = v
			}
		}
		return out
	}
	if d := sameRows(strip(indexRows(t, ref)), strip(indexRows(t, w))); d != "" {
		t.Fatalf("a resumed backfill differs: %s", d)
	}
}

func TestRB12IndexStepStopsByNameWhenTheMemoryBudgetRefusesAndFinishesLater(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 12)
	upTo := w.numberOf(11) + 200
	tight := finality.WithMemoryBudget(ctxBG(), finality.NewMemoryBudget(finality.MinMemoryBudget).WithWait(0))
	// the budget is the minimum (64 MB): a block of ~1 MB fits, so shrink it by taking most of it
	b := finality.MemoryBudgetOf(tight)
	if _, err := b.Reserve(uint64(Chain), "other", finality.MinMemoryBudget-(1<<20)); err != nil {
		t.Fatal(err)
	}
	ix := newIdx(w, bp, IndexConfig{})
	rep, err := ix.Step(tight, upTo)
	if err != nil || rep.StoppedByCap != "budget" || rep.Blocks != 0 {
		t.Fatalf("a refused reservation ends the step by name and writes nothing: %+v %v", rep, err)
	}
	roomy := finality.WithMemoryBudget(ctxBG(), finality.NewMemoryBudget(0))
	for i := 0; i < 5; i++ {
		if rep, err = ix.Step(roomy, upTo); err != nil || rep.StoppedByCap == "" {
			break
		}
	}
	if err != nil || rep.Through != upTo {
		t.Fatalf("with room it finishes: %+v %v", rep, err)
	}
}

// ---- self-check ----

func TestRB12IndexSelfCheckRecomputesFromTheCapturedRowsAndNamesAMismatch(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 20)
	upTo := w.numberOf(19) + 200
	var states []*finality.StateError
	ix := newIdx(w, bp, IndexConfig{OnState: func(s *finality.StateError) { states = append(states, s) }, ReconcileSpan: 1 << 20})
	stepAll(t, ix, upTo)
	if err := ix.SelfCheck(ctxBG(), 40); err != nil || len(states) != 0 {
		t.Fatalf("a sound index passes its self-check: %v %v", err, states)
	}
	// a stored entry whose bytes are valid but not what the captured rows say
	var victim finality.CaptureKey
	var good []byte
	for k, v := range indexRows(t, w) {
		if strings.HasPrefix(k.Item, "idx/g1/bi/c/") {
			victim, good = k, v
			break
		}
	}
	e, err := decodeEntry(good)
	if err != nil {
		t.Fatal(err)
	}
	e.Runs[0].Epoch++ // a plausible lie: another origin
	bad := newShapeWorldCopy(t, w)
	bad.extra[victim] = e.encode()
	ix2 := newIdx(bad, bp, IndexConfig{OnState: func(s *finality.StateError) { states = append(states, s) }, ReconcileSpan: 1 << 20})
	if err := ix2.SelfCheck(ctxBG(), 40); err == nil {
		t.Fatal("a lying entry must fail the self-check")
	}
	if len(states) == 0 || states[0].Code != finality.CodeIndexInconsistent || states[0].Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("want index_inconsistent{self_check_mismatch}, got %v", states)
	}
}

func newShapeWorldCopy(t testing.TB, w *shapeWorld) *shapeWorld {
	t.Helper()
	c := newShapeWorld(t, w.bp, w.N, w.Stride)
	c.Holes, c.ForkAt = w.Holes, w.ForkAt
	for k, v := range w.extra {
		c.extra[k] = v
	}
	return c
}

// ---- names ----

func TestRB12IndexItemNamesSatisfyTheCaptureTableConstraintAndAreOrdered(t *testing.T) {
	id := chanLabelID("x")
	for _, it := range []string{finality.IndexItem(7, "bi", "f"), channelItem(1, 1_790_000_000, 1_790_000_118, id), markerItem(1, id), finality.IndexCursorItem(1, "bi"),
		channelItem(1, 0, 0, id)} {
		if err := finality.CheckCaptureItem(it); err != nil {
			t.Fatalf("%s: %v", it, err)
		}
	}
	n, ok := parseEntryName(1, finality.CaptureKey{Item: channelItem(1, 5, 9, id)})
	if !ok || n.TMin != 5 || n.TMax != 9 || n.ID != id {
		t.Fatalf("%+v %v", n, ok)
	}
	for _, bad := range []string{"idx/g1/bi/c/5/9", "idx/g1/bi/c/9/5/" + strings.Repeat("0", 32), "idx/g1/bi/c/5/9/zz", "idx/g2/bi/c/5/9/" + strings.Repeat("0", 32)} {
		if _, ok := parseEntryName(1, finality.CaptureKey{Item: bad}); ok {
			t.Fatalf("%q must not parse", bad)
		}
	}
	// generations do not see each other's rows
	names := []string{finality.IndexItem(1, "bi", "f"), finality.IndexItem(2, "bi", "f")}
	sort.Strings(names)
	if strings.HasPrefix(names[1], finality.IndexPrefix(1, "bi")) {
		t.Fatal("generation prefixes overlap")
	}
	_ = time.Second
}

// While the index has not reached what the capture holds (the backfill after a deploy, a lagging step) a leg beyond it is pending with the
// positions it was judged at; once the index catches up the same leg is found.
func TestRB12IndexBehindIsPendingUnprovenJudgedAtItsPositions(t *testing.T) {
	pins, bp := idxPins(t)
	w := smallWorld(t, bp, 40)
	ix := newIdx(w, bp, IndexConfig{})
	stepAll(t, ix, w.numberOf(19))
	ts, origin := w.legAt(30, 4)
	b := &Builder{Pins: pins, Store: w, L2: fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}, Index: NewIndexReader(w, bp, 0)}
	hdr := finality.HeaderFields{Number: 5, Timestamp: ts}
	sr, err := b.search(ctxBG(), bp, hdr, nil)
	if err != nil || sr.ch != nil || sr.pending != "l1_posted_unproven" || sr.judged["index_behind"] != true || sr.judged["index_through_l1"] != w.numberOf(19) {
		t.Fatalf("want a pending judged at the index position, got ch=%v err=%v pending=%q judged=%v", sr.ch, err, sr.pending, sr.judged)
	}
	stepAll(t, ix, w.numberOf(39)+200)
	if sr, err = b.search(ctxBG(), bp, hdr, nil); err != nil || sr.ch == nil {
		t.Fatalf("after the index caught up the leg is found: %v %v", sr.ch, err)
	}
}

// A digest whose entry is missing (a crash between the two writes of a late block, or a lost row) is repaired by the reconcile walk, with
// the bytes the entry had.
func TestRB12IndexReconcileRepairsAnEntryThatIsMissingBesideItsDigest(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 30)
	upTo := w.numberOf(29) + 200
	ix := newIdx(w, bp, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix, upTo)
	var victim finality.CaptureKey
	var want []byte
	for k, v := range indexRows(t, w) {
		if strings.HasPrefix(k.Item, "idx/g1/bi/c/") && k.L1Block == w.numberOf(11) {
			victim, want = k, v
		}
	}
	if victim.Item == "" {
		t.Fatal("no entry at block 11")
	}
	w.mu.Lock()
	delete(w.extra, victim)
	w.mu.Unlock()
	if hit, _, _ := findFor(t, w, bp, mustTS(w, 11), w.Epoch(11), w.Epoch(11)+bp.SeqWindowSize); hit != nil {
		t.Fatal("the entry is gone, the lookup must not find the channel")
	}
	rep := stepAll(t, ix, upTo)
	if rep.Entries != 1 {
		t.Fatalf("the reconcile walk must write the one missing entry: %+v", rep)
	}
	if got, ok, _ := w.Get(ctxBG(), victim); !ok || !bytes.Equal(got, want) {
		t.Fatal("the repaired entry differs from the original")
	}
}

func mustTS(w *shapeWorld, c int) uint64 { ts, _ := w.legAt(c, 3); return ts }

// A step limit set too low slows the index and never stops it: every step processes at least its first height; a cancelled context
// processes nothing and is not an error.
func TestRB12IndexStepAlwaysProcessesItsFirstHeightAndStopsOnACancelledContext(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 12)
	upTo := w.numberOf(11) + 200
	ix := newIdx(w, bp, IndexConfig{StepBudget: time.Nanosecond, BlocksPerStep: 1})
	steps := 0
	for {
		rep, err := ix.Step(ctxBG(), upTo)
		if err != nil {
			t.Fatal(err)
		}
		steps++
		if steps > 40 {
			t.Fatal("an index with a tiny time budget never finished")
		}
		if rep.StoppedByCap == "" {
			break
		}
		if rep.Blocks != 1 {
			t.Fatalf("each step must digest exactly its first height under a 1 ns budget, digested %d (%+v)", rep.Blocks, rep)
		}
	}
	if steps != 12 || ix.cursor != upTo {
		t.Fatalf("12 heights at one per step: %d steps, cursor %d", steps, ix.cursor)
	}
	w2 := smallWorld(t, bp, 5)
	cctx, cancel := context.WithCancel(ctxBG())
	cancel()
	rep, err := newIdx(w2, bp, IndexConfig{}).Step(cctx, w2.numberOf(4)+200)
	if err != nil || rep.Blocks != 0 || rep.StoppedByCap != "context" {
		t.Fatalf("a cancelled context stops the step by name: %+v %v", rep, err)
	}
}

// A refusal of the memory budget while a channel is being read for its entry ends the step by name; the digest that was written stays, the
// cursor stays below that height, and the next step with room writes the entry.
func TestRB12IndexStepStopsByNameWhenTheBudgetRefusesTheChannelRead(t *testing.T) {
	_, bp := idxPins(t)
	w := smallWorld(t, bp, 6)
	upTo := w.numberOf(5) + 200
	// a budget that fits one block read (about 1.4 MB reserved) but not the channel read of the same rows plus its stream
	budget := finality.NewMemoryBudget(finality.MinMemoryBudget).WithWait(0)
	var blockCost int64
	for item, row := range w.block(0, 0).rows(bp) { // the rows a block read reserves: inbox, transactions, blobs
		if item == ItemInbox || strings.HasPrefix(item, "tx/") || strings.HasPrefix(item, "blob/") {
			blockCost += finality.RowCost(len(row))
		}
	}
	if _, err := budget.Reserve(uint64(Chain), "other", finality.MinMemoryBudget-(blockCost+1000)); err != nil {
		t.Fatal(err)
	}
	ix := newIdx(w, bp, IndexConfig{})
	rep, err := ix.Step(finality.WithMemoryBudget(ctxBG(), budget), upTo)
	if err != nil {
		t.Fatal(err)
	}
	if rep.StoppedByCap != "budget" || rep.Entries != 0 {
		t.Fatalf("the channel read must be refused by name: %+v", rep)
	}
	if rep.Through >= w.numberOf(0) {
		t.Fatalf("the cursor must stay below the unfinished height, got %d", rep.Through)
	}
	rep = stepAll(t, ix, upTo)
	if rep.Through != upTo {
		t.Fatalf("with room the index finishes: %+v", rep)
	}
	ts, origin := w.legAt(0, 3)
	if hit, _, err := findFor(t, w, bp, ts, origin, origin+bp.SeqWindowSize); err != nil || hit == nil {
		t.Fatalf("the entry of the refused height was written later: %v %v", hit, err)
	}
}
