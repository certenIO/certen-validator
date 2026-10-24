// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
)

// RB12-ARCHIVE-BACKFILL: the capture-store PREFIX extension. A leg posted before the capture loop started is covered by a durable,
// insert-only request "the capture store is to be extended over [from, to]" (a gap row of the class capture_prefix: the whole gap
// machinery - fills, ends, hole-aware coverage - then applies unchanged). These tests pin the record bytes, the policy bounds (exact), the
// union arithmetic and the coverage edges.

const pxChain = uint64(84532)

func pxCtx() context.Context { return context.Background() }

func TestRB12PrefixRequestIsAGapRowOfTheDocumentedBytesAndRepeatsAreNoOps(t *testing.T) {
	s := NewMemCaptureStore()
	pol := PrefixPolicy{MaxBlocks: 10_000}
	v, err := RequestPrefix(pxCtx(), s, pxChain, 1000, 1999, pol)
	if err != nil || v != PrefixRecorded {
		t.Fatalf("first request: %v %v", v, err)
	}
	ks, _ := s.ListByRange(pxCtx(), pxChain, 0, MaxCaptureBlock, "")
	if len(ks) != 1 || ks[0].L1Block != 1000 || ks[0].Item != "gap/1999/capture_prefix" || ks[0].L1Hash != ([32]byte{}) {
		t.Fatalf("one row at the window start under the zero hash, item gap/<to>/capture_prefix: %v", ks)
	}
	b, _, _ := s.Get(pxCtx(), ks[0])
	want := append([]byte("CGAP1"), 0, 0, 0, 0, 0, 0, 0x03, 0xe8, 0, 0, 0, 0, 0, 0, 0x07, 0xcf, 0, 0, 0, 14)
	want = append(want, "capture_prefix"...)
	if !bytes.Equal(b, want) {
		t.Fatalf("row bytes %x want %x", b, want)
	}
	for i := 0; i < 3; i++ {
		if v, err := RequestPrefix(pxCtx(), s, pxChain, 1000, 1999, pol); err != nil || v != PrefixKnown {
			t.Fatalf("the same window again is known, not written: %v %v", v, err)
		}
	}
	if v, err := RequestPrefix(pxCtx(), s, pxChain, 1200, 1500, pol); err != nil || v != PrefixKnown {
		t.Fatalf("a window inside a recorded one is known: %v %v", v, err)
	}
	if s.Len() != 1 {
		t.Fatalf("no row was added: %d", s.Len())
	}
}

func TestRB12PrefixSevenValidatorsRequestingTheSameWindowWriteOneRowWithoutConflict(t *testing.T) {
	s := NewMemCaptureStore()
	pol := PrefixPolicy{MaxBlocks: 10_000}
	var wg sync.WaitGroup
	errs := make(chan error, 7)
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := RequestPrefix(pxCtx(), s, pxChain, 5000, 8600, pol)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a duplicate request is not a conflict: %v", err)
		}
	}
	if s.Len() != 1 {
		t.Fatalf("one row: %d", s.Len())
	}
}

func TestRB12PrefixPolicyBoundsAreExact(t *testing.T) {
	// the budget: a window of exactly MaxBlocks passes, one block more is refused by name, and nothing is written for the refusal
	s := NewMemCaptureStore()
	pol := PrefixPolicy{MaxBlocks: 3601}
	if v, err := RequestPrefix(pxCtx(), s, pxChain, 100, 3700, pol); err != nil || v != PrefixRecorded {
		t.Fatalf("3601 blocks with a budget of 3601: %v %v", v, err)
	}
	s2 := NewMemCaptureStore()
	if v, err := RequestPrefix(pxCtx(), s2, pxChain, 100, 3701, pol); err != nil || v != PrefixOverBudget {
		t.Fatalf("3602 blocks with a budget of 3601: %v %v", v, err)
	}
	if s2.Len() != 0 {
		t.Fatalf("a refused request writes nothing")
	}
	// the floor: from == Floor passes, Floor-1 is refused
	s3 := NewMemCaptureStore()
	pol = PrefixPolicy{MaxBlocks: 100_000, Floor: 500}
	if v, err := RequestPrefix(pxCtx(), s3, pxChain, 500, 600, pol); err != nil || v != PrefixRecorded {
		t.Fatalf("from == floor: %v %v", v, err)
	}
	if v, err := RequestPrefix(pxCtx(), s3, pxChain, 499, 600, pol); err != nil || v != PrefixBelowFloor {
		t.Fatalf("from == floor-1: %v %v", v, err)
	}
	// off: MaxBlocks 0 writes nothing and says so
	s4 := NewMemCaptureStore()
	if v, err := RequestPrefix(pxCtx(), s4, pxChain, 10, 20, PrefixPolicy{}); err != nil || v != PrefixOff || s4.Len() != 0 {
		t.Fatalf("off: %v %v rows=%d", v, err, s4.Len())
	}
	// a bad range is an error, not a verdict
	if _, err := RequestPrefix(pxCtx(), s4, pxChain, 20, 10, PrefixPolicy{MaxBlocks: 100}); err == nil {
		t.Fatalf("to < from must be refused")
	}
}

func TestRB12PrefixBudgetCountsTheUnionOfTheWindowsNotTheirSum(t *testing.T) {
	s := NewMemCaptureStore()
	pol := PrefixPolicy{MaxBlocks: 4600}
	if v, _ := RequestPrefix(pxCtx(), s, pxChain, 10_000, 13_600, pol); v != PrefixRecorded { // 3601 blocks
		t.Fatalf("first: %v", v)
	}
	// 1000 blocks further on and overlapping the first by 2601 blocks: the union is 4601 blocks - one over
	if v, _ := RequestPrefix(pxCtx(), s, pxChain, 11_000, 14_600, pol); v != PrefixOverBudget {
		t.Fatalf("union 4601 > 4600: %v", v)
	}
	if v, _ := RequestPrefix(pxCtx(), s, pxChain, 11_000, 14_599, pol); v != PrefixRecorded { // union 4600: exact
		t.Fatalf("union 4600 == 4600: %v", v)
	}
}

func TestRB12PrefixMergeAndCoverageEdges(t *testing.T) {
	ws := []PrefixWindow{{20, 29}, {10, 19}, {40, 50}, {45, 60}, {10, 12}}
	m := MergePrefixWindows(ws)
	want := []PrefixWindow{{10, 29}, {40, 60}}
	if fmt.Sprint(m) != fmt.Sprint(want) {
		t.Fatalf("adjacent and overlapping windows merge, a one-block hole does not: %v want %v", m, want)
	}
	if got := PrefixBlocks(m); got != 20+21 {
		t.Fatalf("blocks %d", got)
	}
	cases := []struct {
		from, to uint64
		ok       bool
		first    uint64
	}{
		{10, 29, true, 0}, {15, 20, true, 0}, {40, 60, true, 0},
		{9, 29, false, 9}, {10, 30, false, 30}, {10, 40, false, 30}, {29, 40, false, 30}, {30, 39, false, 30},
		{61, 70, false, 61}, {0, 5, false, 0}, {60, 60, true, 0}, {61, 61, false, 61},
	}
	for _, c := range cases {
		ok, first := PrefixCovers(m, c.from, c.to)
		if ok != c.ok || (!ok && first != c.first) {
			t.Errorf("PrefixCovers(%d,%d) = %v,%d want %v,%d", c.from, c.to, ok, first, c.ok, c.first)
		}
	}
	if ok, _ := PrefixCovers(nil, 5, 6); ok {
		t.Errorf("no windows cover nothing")
	}
	if ok, _ := PrefixCovers(m, 7, 3); !ok {
		t.Errorf("an empty range has nothing uncovered")
	}
	if lo, ok := PrefixLowest(m); !ok || lo != 10 {
		t.Errorf("lowest %d %v", lo, ok)
	}
	if _, ok := PrefixLowest(nil); ok {
		t.Errorf("no windows, no lowest")
	}
}

func TestRB12PrefixWindowIsAHoleAwareGapUntilEveryBlockIsFilled(t *testing.T) {
	s := NewMemCaptureStore()
	if _, err := RequestPrefix(pxCtx(), s, pxChain, 100, 109, PrefixPolicy{MaxBlocks: 100}); err != nil {
		t.Fatal(err)
	}
	ps, err := GapsIn(pxCtx(), s, pxChain, 95, 120)
	if err != nil || len(ps) != 1 || ps[0].From != 100 || ps[0].To != 109 || ps[0].State != GapOpen || len(ps[0].Classes) != 1 || ps[0].Classes[0] != GapCapturePrefix {
		t.Fatalf("an unfilled prefix is an open gap clipped to the asked window: %v %v", ps, err)
	}
	for n := uint64(100); n <= 109; n++ {
		if n == 105 {
			continue
		}
		if err := RecordGapFill(pxCtx(), s, pxChain, n, [32]byte{byte(n)}, false); err != nil {
			t.Fatal(err)
		}
	}
	ps, _ = GapsIn(pxCtx(), s, pxChain, 100, 109)
	if len(ps) != 1 || ps[0].From != 105 || ps[0].To != 105 {
		t.Fatalf("one unfilled block keeps the window open: %v", ps)
	}
	_ = RecordGapFill(pxCtx(), s, pxChain, 105, [32]byte{105}, true)
	if ps, _ = GapsIn(pxCtx(), s, pxChain, 100, 109); len(ps) != 0 {
		t.Fatalf("every block filled: %v", ps)
	}
	// the request stays on record (insert-only): the windows are still read back
	if ws, _ := PrefixWindowsOf(pxCtx(), s, pxChain); len(ws) != 1 || ws[0] != (PrefixWindow{100, 109}) {
		t.Fatalf("%v", ws)
	}
}

func TestRB12PrefixWindowsOfReadsOnlyThePrefixClassAndNoRowBytes(t *testing.T) {
	s := NewMemCaptureStore()
	_ = RecordGap(pxCtx(), s, pxChain, 50, 60, GapOutageUnscanned)
	_ = RecordGap(pxCtx(), s, pxChain, 70, 80, GapCapturePrefix)
	_ = RecordGap(pxCtx(), s, pxChain+1, 90, 99, GapCapturePrefix) // another chain
	_ = RecordGapFill(pxCtx(), s, pxChain, 70, [32]byte{1}, false)
	g := &getCounting{CaptureStore: s}
	ws, err := PrefixWindowsOf(pxCtx(), g, pxChain)
	if err != nil || len(ws) != 1 || ws[0] != (PrefixWindow{70, 80}) {
		t.Fatalf("%v %v", ws, err)
	}
	if g.gets != 0 {
		t.Fatalf("the windows are in the key names: %d rows were read", g.gets)
	}
}

type getCounting struct {
	CaptureStore
	gets int
}

func (g *getCounting) Get(ctx context.Context, k CaptureKey) ([]byte, bool, error) {
	g.gets++
	return g.CaptureStore.Get(ctx, k)
}

func TestRB12PrefixClassIsInTheClosedSetAndAFailingStoreIsAnError(t *testing.T) {
	if !GapCapturePrefix.Valid() {
		t.Fatalf("capture_prefix must be a member of the closed class set")
	}
	if err := RecordGap(pxCtx(), NewMemCaptureStore(), pxChain, 1, 2, GapClass("capture-prefix")); err == nil {
		t.Fatalf("a spelling outside the set is refused")
	}
	if _, err := RequestPrefix(pxCtx(), failingListStore{NewMemCaptureStore()}, pxChain, 1, 2, PrefixPolicy{MaxBlocks: 9}); err == nil {
		t.Fatalf("a store that cannot be read never answers 'no windows'")
	}
}

type failingListStore struct{ CaptureStore }

func (failingListStore) ListByRange(context.Context, uint64, uint64, uint64, string) ([]CaptureKey, error) {
	return nil, fmt.Errorf("store down")
}
