// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// V-B2-1: two wide records of one slot (an equivocated block, or a forged twin from a lying provider) have the same batch number and the same
// bounds, so they must not share one pointer key with two different bodies: each gets its own pointer, the cursor passes the block, the lookup serves
// the one the Bridge holds, and the bytes do not depend on which twin arrived first. Fail-before @00582def: ErrIndexConflict at the first step, the
// cursor never passes the block.
func TestRB12ArbIndexTwoWideTwinsOfOneSlotKeepTheirOwnPointers(t *testing.T) {
	const T = ixT0 + 600_000
	build := func(twinFirst bool) (*ixWorld, finality.CaptureKey, finality.CaptureKey) {
		w := newIxWorld(t)
		msgs := [][][]byte{ixMsg(ixTx(34000))}
		a := ixBatch{N: 400, Block: 1000, T: T, MinTs: T - 3_000_000, MaxTs: T + 90_000, Msgs: msgs}
		b := a
		b.Tag, b.AccTag = 1, 1 // the twin: another block hash at the same height and another beforeAcc, with the same N and the same bounds
		var ka, kb finality.CaptureKey
		if twinFirst {
			kb = w.add(b)
			ka = w.add(a)
		} else {
			ka = w.add(a)
			kb = w.add(b)
		}
		w.add(ixBatch{N: 401, Block: 1008, T: T + 96, Msgs: [][][]byte{ixMsg(ixTx(34001))}})
		w.index(IndexConfig{})
		return w, ka, kb
	}
	w1, _, held1 := build(false)
	w2, _, held2 := build(true)

	for name, w := range map[string]*ixWorld{"first-then-twin": w1, "twin-then-first": w2} {
		if got := w.wideRows(); got != 2 {
			t.Fatalf("%s: %d pointer rows for two wide twins", name, got)
		}
		digests := 0
		for k := range w.indexRows() {
			if strings.Contains(k.Item, "/arb/f/") {
				digests++
			}
		}
		if digests != 3 {
			t.Fatalf("%s: %d block digests, want 3 (the cursor passed both twins)", name, digests)
		}
	}
	equalRows(t, w1.indexRows(), w2.indexRows())

	// the Bridge holds the twin; the other is an orphan
	for name, p := range map[string]struct {
		w    *ixWorld
		held finality.CaptureKey
	}{"first-then-twin": {w1, held1}, "twin-then-first": {w2, held2}} {
		w := p.w
		w.proof(400, w.recs[p.held].AfterAcc, 1005)
		leg := [][]byte{ixTx(34000)}
		ts := uint64(T - 1_000_000)
		ref, idx := w.ref(ts, leg), w.idx(w.reader(), ts, leg)
		if ref != idx || idx.N != 400 {
			t.Fatalf("%s: reference %s, index %s", name, ref, idx)
		}
		b := &Builder{Store: w.store, Pins: w.pins, Index: w.reader()}
		loc, _, err := b.Index.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(leg), w.arb)
		if err != nil || loc == nil || loc.rec.L1Hash != p.held.L1Hash {
			t.Fatalf("%s: the index serves %v %v, not the twin the Bridge holds", name, loc, err)
		}
	}
}

// V-B2-2: the pointer work of a lookup is bounded. A lookup lists the pointers (keys only) and reads only those whose bounds hold its timestamp; more
// than maxWidePointers pointers is the named index_inconsistent{coverage_overflow} for a leg only a wide batch can serve - before any pointer is read -
// while a leg a normal batch serves is still served. The count is a gauge. Fail-before @00582def: 4,097 pointers are all listed and read without a bound.
func TestRB12ArbIndexWidePointerWorkIsBoundedAtTheLimit(t *testing.T) {
	metrics.RegisterMetrics()
	const T = ixT0 + 600_000
	w := newIxWorld(t)
	txWide, txNormal := ixTx(35000), ixTx(35001)
	w.add(ixBatch{N: 799, Block: 992, T: T - 96, Msgs: [][][]byte{ixMsg(txNormal)}})
	w.add(ixBatch{N: 800, Block: 1000, T: T, MinTs: T - 3_000_000, MaxTs: T + 90_000, Msgs: [][][]byte{ixMsg(txWide)}})
	w.add(ixBatch{N: 801, Block: 1008, T: T + 96, Msgs: [][][]byte{ixMsg(ixTx(35002))}})
	w.index(IndexConfig{})
	legWide, legNormal := uint64(T-1_000_000), uint64(T-96+10)

	m := &meter{CaptureStore: w.store}
	r, err := NewIndexReader(m, w.pins, 0)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(ts uint64, tx []byte) (outcome, outcome) {
		m.reset()
		return w.ref(ts, [][]byte{tx}), w.idx(r, ts, [][]byte{tx})
	}
	fill := func(total int) {
		for i := w.wideRows(); i < total; i++ {
			w.putPointer(i)
		}
	}

	// exactly at the limit: served as the reference serves, with the reads of the one pointer that matters
	fill(ixMaxWide)
	if w.wideRows() != ixMaxWide {
		t.Fatalf("%d pointers, want %d", w.wideRows(), ixMaxWide)
	}
	ref, idx := ask(legWide, txWide)
	if ref.N != 800 || ref != idx {
		t.Fatalf("at the limit: reference %s, index %s", ref, idx)
	}
	if g := m.gets.Load(); g > 200 {
		t.Fatalf("%d rows read for a lookup with %d pointers of which one matches", g, ixMaxWide)
	}
	if v, ok := ixMetric(t, "certen_finality_index_wide_pointers"); !ok || v != float64(ixMaxWide) {
		t.Errorf("the pointer gauge is %v (found %v), want %d", v, ok, ixMaxWide)
	}

	// one more: the wide leg is named (nothing is read of the pointers), the normal leg is still served
	fill(ixMaxWide + 1)
	_, idx = ask(legWide, txWide)
	if idx.N != 0 || !strings.Contains(idx.State, `"code":"index_inconsistent"`) || !strings.Contains(idx.State, `"reason":"coverage_overflow"`) {
		t.Fatalf("above the limit the wide leg is %s", idx)
	}
	if g := m.gets.Load(); g > 200 {
		t.Fatalf("%d rows read above the limit: the work is not bounded by it", g)
	}
	ref, idx = ask(legNormal, txNormal)
	if ref.N != 799 || ref != idx {
		t.Fatalf("above the limit a leg a normal batch serves: reference %s, index %s", ref, idx)
	}
	if v, _ := ixMetric(t, "certen_finality_index_wide_pointers"); v != float64(ixMaxWide+1) {
		t.Errorf("the pointer gauge is %v, want %d", v, ixMaxWide+1)
	}
}

// V-B2-2: the self-check samples the pointer rows: a pointer that does not say what the captured rows say (another block, another batch's bounds), and a
// wide entry whose pointer is gone, are named self_check_mismatch; a clean store passes and the check says how many pointers it compared.
func TestRB12ArbIndexSelfCheckSamplesThePointerRows(t *testing.T) {
	const T = ixT0 + 600_000
	build := func() (*ixWorld, finality.CaptureKey) {
		w := newIxWorld(t)
		w.add(ixBatch{N: 799, Block: 992, T: T - 96, Msgs: [][][]byte{ixMsg(ixTx(36001))}})
		kw := w.add(ixBatch{N: 800, Block: 1000, T: T, MinTs: T - 3_000_000, MaxTs: T + 90_000, Msgs: [][][]byte{ixMsg(ixTx(36000))}})
		w.add(ixBatch{N: 801, Block: 1008, T: T + 96, Msgs: [][][]byte{ixMsg(ixTx(36002))}})
		w.index(IndexConfig{})
		return w, kw
	}
	w, kw := build()
	pk := ixWideKeyOf(1, T-3_000_000, T+90_000, 800, kw.L1Hash)
	_, found, err := w.store.Get(context.Background(), pk)
	if err != nil || !found {
		t.Fatalf("the pointer of the wide batch is not stored: %v %v", found, err)
	}
	cfg := IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20}

	res, err := w.indexer(cfg).SelfCheckReport(context.Background(), 100)
	if err != nil || res.Mismatches != 0 || res.Entries == 0 {
		t.Fatalf("a clean store: %v %+v", err, res)
	}
	if ixPointers(res) < 1 {
		t.Errorf("a clean store: the self-check compared %d pointers", ixPointers(res))
	}

	for name, mutate := range map[string]func(o *ixOverlay){
		"the pointer names another block":        func(o *ixOverlay) { o.over[pk] = wideBody(992, kw.L1Hash) },
		"the pointer names another hash":         func(o *ixOverlay) { o.over[pk] = wideBody(1000, [32]byte{9}) },
		"the pointer of a wide entry is missing": func(o *ixOverlay) { o.gone[pk] = true },
	} {
		o := newOverlay(w.store)
		mutate(o)
		ix, err := NewIndexer(o, w.pins, 0, cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := ix.SelfCheckReport(context.Background(), 100)
		if err == nil || res.Mismatches == 0 {
			t.Errorf("%s: the self-check found nothing: %v %+v", name, err, res)
			continue
		}
		if st, ok := finality.AsNamed(err); !ok || st.Code != finality.CodeIndexInconsistent || st.Fields["reason"] != finality.IndexSelfCheckMismatch {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a pointer for a batch that is not wide at all
	w2, _ := build()
	h := w2.keys[799][0].L1Hash
	if err := finality.IndexPut(context.Background(), w2.store, FamilyArb, ixWideKeyOf(1, T-96-86_400, T-96+768, 799, h), wideBody(992, h)); err != nil {
		t.Fatal(err)
	}
	if _, err := w2.indexer(cfg).SelfCheckReport(context.Background(), 100); err == nil {
		t.Error("a pointer for a batch that is inside the normal window is not found by the self-check")
	}
}
