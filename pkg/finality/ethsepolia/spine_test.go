// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// ---- the pure decision functions ----

func TestPlanSpansPinsTheWindowsAndTheTail(t *testing.T) {
	cases := []struct {
		name        string
		first, last uint64
		want        []Span
	}{
		{"tail then two windows", 1000, 1099, []Span{{1080, 1099, false}, {1040, 1079, true}, {1000, 1039, true}}},
		{"head closes a window: no tail", 1000, 1119, []Span{{1080, 1119, true}, {1040, 1079, true}, {1000, 1039, true}}},
		{"bottom window is cut at the leg", 1010, 1119, []Span{{1080, 1119, true}, {1040, 1079, true}, {1010, 1039, true}}},
		{"the tail is the whole spine", 1085, 1099, []Span{{1085, 1099, false}}},
		{"one header, not closing a window", 1099, 1099, []Span{{1099, 1099, false}}},
		{"one header closing a window", 1119, 1119, []Span{{1119, 1119, true}}},
		{"the finalized head is the leg block", 1100, 1099, nil},
		{"from block zero, one full window", 0, 39, []Span{{0, 39, true}}},
		{"from block zero, short", 0, 3, []Span{{0, 3, false}}},
		{"leg inside the tail's window", 1090, 1099, []Span{{1090, 1099, false}}},
		{"leg at the tail's first block", 1080, 1099, []Span{{1080, 1099, false}}},
		{"leg one below the tail's first block", 1079, 1099, []Span{{1080, 1099, false}, {1079, 1079, true}}},
	}
	for _, c := range cases {
		got := PlanSpans(c.first, c.last)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("%s: PlanSpans(%d,%d) = %v, want %v", c.name, c.first, c.last, got, c.want)
		}
	}
}

func TestPlanSpansCoverEveryBlockOnceWithOnlyTheTopUnkept(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 3000; i++ {
		first := uint64(rng.Intn(6000))
		last := first + uint64(rng.Intn(900))
		spans := PlanSpans(first, last)
		if len(spans) == 0 {
			t.Fatalf("PlanSpans(%d,%d) is empty", first, last)
		}
		next := last
		for j, s := range spans {
			if s.End != next || s.Start > s.End || s.Count() > SpineWindow {
				t.Fatalf("PlanSpans(%d,%d)[%d] = %v does not continue below %d within %d headers", first, last, j, s, next+1, SpineWindow)
			}
			if s.Stored != (s.End%SpineWindow == SpineWindow-1) {
				t.Fatalf("PlanSpans(%d,%d)[%d] = %v: kept iff it ends a window", first, last, j, s)
			}
			if j > 0 && s.Start != first && s.Start%SpineWindow != 0 {
				t.Fatalf("PlanSpans(%d,%d)[%d] = %v: a window that is not cut at the leg starts at a multiple of %d", first, last, j, s, SpineWindow)
			}
			if !s.Stored && j != 0 {
				t.Fatalf("PlanSpans(%d,%d)[%d] = %v: only the top span may be unkept", first, last, j, s)
			}
			next = s.Start - 1
			if s.Start == 0 {
				next = 0
			}
		}
		if spans[len(spans)-1].Start != first {
			t.Fatalf("PlanSpans(%d,%d) stops at %d", first, last, spans[len(spans)-1].Start)
		}
	}
}

func TestSpineProgressCountsTheHeadAndTheSpansDone(t *testing.T) {
	spans := PlanSpans(1000, 1099) // 20, 40, 40 headers
	for _, c := range []struct {
		head       bool
		done       int
		have, need int
	}{
		{false, 0, 0, 101}, {true, 0, 1, 101}, {true, 1, 21, 101}, {true, 2, 61, 101}, {true, 3, 101, 101}, {false, 3, 0, 101},
	} {
		have, need := SpineProgress(spans, c.head, c.done)
		if have != c.have || need != c.need {
			t.Errorf("head=%v done=%d: have %d need %d, want %d %d", c.head, c.done, have, need, c.have, c.need)
		}
	}
	if have, need := SpineProgress(nil, true, 0); have != 1 || need != 1 {
		t.Errorf("a spine that is the head alone: have %d need %d", have, need)
	}
}

func TestBudgetAllowsPinsTheBoundaryExactly(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		spent, longest, budget time.Duration
		want                   bool
	}{
		{0, 0, 0, false}, {0, 0, 1, true}, {10 * s, 5 * s, 15 * s, true}, {10 * s, 5 * s, 15*s - 1, false}, {0, 0, -s, false}, {14 * s, 0, 15 * s, true},
	} {
		if got := BudgetAllows(c.spent, c.longest, c.budget); got != c.want {
			t.Errorf("spent %s longest %s budget %s: %v, want %v", c.spent, c.longest, c.budget, got, c.want)
		}
	}
}

func TestAttemptBudgetIsTheCapOrWhatTheDeadlineLeavesAfterTheReserve(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		name      string
		cap, left time.Duration
		want      time.Duration
	}{
		{"no deadline, default cap", 0, -1, DefaultSpineBudget},
		{"no deadline, own cap", 40 * s, -1, 40 * s},
		{"plenty left", 0, 300 * s, DefaultSpineBudget},
		{"the build timeout of 300 s with a 100 s cap", 100 * s, 300 * s, 100 * s},
		{"deadline binds: a fifth is the reserve", 1000 * s, 100 * s, 80 * s},
		{"short deadline: the reserve is at least 10 s", 1000 * s, 40 * s, 30 * s},
		{"exactly the reserve", 1000 * s, 10 * s, 0},
		{"one nanosecond above the reserve", 1000 * s, 10*s + 1, 1},
		{"nothing left", 0, 0, 0},
	} {
		if got := AttemptBudget(c.cap, c.left); got != c.want {
			t.Errorf("%s: AttemptBudget(%s,%s) = %s, want %s", c.name, c.cap, c.left, got, c.want)
		}
	}
}

func TestPauseAfterByKindAndStalls(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		kind   PauseKind
		ra     time.Duration
		stalls int
		want   time.Duration
	}{
		{PauseBudget, 0, 0, SpineResumeDelay}, {PauseBudget, 99 * s, 9, SpineResumeDelay},
		{PauseThrottled, 90 * s, 0, 90 * s}, {PauseThrottled, s, 0, SpineResumeDelay}, {PauseThrottled, 3 * time.Hour, 0, MaxRetryAfterKept},
		{PauseThrottled, 0, 0, 30 * s}, {PauseThrottled, 0, 2, 120 * s},
		{PauseError, 0, 0, 30 * s}, {PauseError, 0, 1, 60 * s}, {PauseError, 0, 4, 480 * s}, {PauseError, 0, 5, SpineErrorMax}, {PauseError, 0, 500, SpineErrorMax},
	} {
		if got := PauseAfter(c.kind, c.ra, c.stalls); got != c.want {
			t.Errorf("kind %d retry-after %s stalls %d: %s, want %s", c.kind, c.ra, c.stalls, got, c.want)
		}
	}
}

func TestEncodeDecodeSpanRoundTripsDeterministicallyAndRefusesMalformedBytes(t *testing.T) {
	ch := newSynth(5000, 40, 1)
	enc := encodeSpan(ch.hs)
	if !bytes.Equal(enc, encodeSpan(ch.hs)) {
		t.Fatal("the encoding is not deterministic")
	}
	hs, f := decodeSpan(enc)
	if f != nil || len(hs) != 40 {
		t.Fatalf("decode: %v, %d headers", f, len(hs))
	}
	for i := range hs {
		if !bytes.Equal(hs[i], ch.hs[i]) {
			t.Fatalf("header %d differs after the round trip", i)
		}
	}
	for name, bad := range map[string][]byte{
		"empty":              nil,
		"not a list":         {0x83, 1, 2, 3},
		"trailing byte":      append(append([]byte(nil), enc...), 0x00),
		"a string element":   {0xc4, 0x83, 1, 2, 3},
		"truncated":          enc[:len(enc)/2],
		"element not a list": {0xc2, 0x01, 0x02},
	} {
		if _, f := decodeSpan(bad); f == nil || f.Reason != SpineRowMalformed {
			t.Errorf("%s: %v, want %s", name, f, SpineRowMalformed)
		}
	}
}

func TestCheckSpanNamesEachWayAChunkCanBeWrong(t *testing.T) {
	ch := newSynth(1000, 100, 1)
	sp := Span{Start: 1040, End: 1079, Stored: true}
	win := func() [][]byte { return append([][]byte(nil), ch.hs[40:80]...) }
	top := ch.hashOf(1079)
	parent, f := checkSpan(win(), sp, top)
	if f != nil || parent != ch.hashOf(1039) {
		t.Fatalf("a good chunk: fault %v parent %x", f, parent[:4])
	}
	other := newSynth(1000, 100, 2)
	cases := []struct {
		name   string
		hs     [][]byte
		top    [32]byte
		reason string
		at     uint64
	}{
		{"one header short", win()[:39], top, SpineRowMalformed, 0},
		{"one header too many", append(win(), ch.hs[80]), top, SpineRowMalformed, 0},
		{"an unreadable header", func() [][]byte { w := win(); w[5] = []byte{0x01}; return w }(), top, SpineRowMalformed, 1045},
		{"a header with another number", func() [][]byte { w := win(); w[5] = spineSynthHeader(9999, ch.hashOf(1044), 1); return w }(), top, SpineRowNumbers, 1045},
		{"a header whose parent is not the one before", func() [][]byte { w := win(); w[5] = spineSynthHeader(1045, [32]byte{9}, 1); return w }(), top, SpineRowNotChained, 1045},
		{"a header replaced by a sibling: the NEXT one no longer chains", func() [][]byte { w := win(); w[5] = spineSynthHeader(1045, ch.hashOf(1044), 9); return w }(), top, SpineRowNotChained, 1046},
		{"the last header replaced: the top is not the one asked for", func() [][]byte { w := win(); w[39] = spineSynthHeader(1079, ch.hashOf(1078), 9); return w }(), top, SpineRowTopMismatch, 1079},
		{"a chunk of another chain", other.hs[40:80], top, SpineRowTopMismatch, 1079},
	}
	for _, c := range cases {
		_, f := checkSpan(c.hs, sp, c.top)
		if f == nil || f.Reason != c.reason || f.At != c.at {
			t.Errorf("%s: fault %v, want %s at %d", c.name, f, c.reason, c.at)
		}
	}
}

// ---- the walk ----

// completed drives attempts until the spine is complete and returns it with the attempts it took and each pending state on the way.
func completed(t *testing.T, p *Prover, leg finality.BlockRef, c candidate, max int) (spine [][]byte, attempts int, pends []*finality.PendingState) {
	t.Helper()
	for attempts < max {
		attempts++
		sp, pend, err := p.spineFor(context.Background(), leg, c)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempts, err)
		}
		if pend == nil {
			return sp, attempts, pends
		}
		pends = append(pends, pend)
	}
	t.Fatalf("not complete after %d attempts; last pending %v", max, pends[len(pends)-1])
	return nil, 0, nil
}

func expectedSpine(ch *synthChain, leg uint64) [][]byte {
	var out [][]byte
	for n := ch.top(); ; n-- {
		out = append(out, ch.byNum[n])
		if n == leg {
			return out
		}
	}
}

func TestSpineWalkAssemblesTheSpineTheVerifierCoversAndKeepsOneRowPerWindow(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	src := ch.model(clk, 10*time.Millisecond)
	store := finality.NewMemCaptureStore()
	p := spineProver(src, store, clk, 0)
	spine, attempts, _ := completed(t, p, ch.leg(legN), ch.candidate(), 5)
	if attempts != 1 {
		t.Fatalf("%d attempts with the default budget", attempts)
	}
	want := expectedSpine(ch, legN)
	if len(spine) != len(want) {
		t.Fatalf("%d headers, want %d", len(spine), len(want))
	}
	for i := range want {
		if !bytes.Equal(spine[i], want[i]) {
			t.Fatalf("spine[%d] differs", i)
		}
	}
	// the verifier's own coverage check accepts it and finds the leg
	covered, err := ethl1.FinalizedHead{ExecHash: ch.hashOf(ch.top())}.Covers(spine, 16384)
	if err != nil {
		t.Fatal(err)
	}
	if at, err := ethl1.BlockAt(covered, legN); err != nil || at.Hash != ch.hashOf(legN) {
		t.Fatalf("BlockAt: %v %x", err, at.Hash)
	}
	// exactly one row per kept span, addressed by (last block, hash of the last header, item), holding exactly the window
	spans := PlanSpans(legN, ch.top()-1)
	keys := storedSpineKeys(t, store)
	kept := 0
	for _, sp := range spans {
		if sp.Stored {
			kept++
		}
	}
	if len(keys) != kept {
		t.Fatalf("%d rows kept, %d kept spans", len(keys), kept)
	}
	for _, sp := range spans {
		if !sp.Stored {
			continue
		}
		k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: sp.End, L1Hash: ch.hashOf(sp.End), Item: SpineItem(sp.Count())}
		b, ok, _ := store.Get(context.Background(), k)
		if !ok || !bytes.Equal(b, encodeSpan(ch.hs[sp.Start-ch.base:sp.End-ch.base+1])) {
			t.Fatalf("no row (or other bytes) at %s", k)
		}
	}
	// nothing below the leg and nothing at or above the finalized head was asked for
	for n := range src.served {
		if n < legN || n >= ch.top() {
			t.Fatalf("header %d was requested; the walk covers %d..%d", n, legN, ch.top()-1)
		}
	}
	if src.hashCalls != 1 {
		t.Fatalf("%d header-by-hash calls", src.hashCalls)
	}
}

// simulate is the pure plan of an attempt sequence: which spans each attempt fetches when none is kept and each header costs per.
func simulate(spans []Span, per, budget time.Duration, skip func(i int) bool) [][]int {
	var out [][]int
	var cur []int
	var spent, longest time.Duration
	for i, sp := range spans {
		if skip != nil && skip(i) {
			continue
		}
		if !BudgetAllows(spent, longest, budget) {
			out = append(out, cur)
			cur, spent, longest = nil, 0, 0
		}
		c := time.Duration(sp.Count()) * per
		spent += c
		if c > longest {
			longest = c
		}
		cur = append(cur, i)
	}
	return append(out, cur)
}

func TestEachAttemptFetchesFromTheFirstChunkNotKeptAndTheStateSaysHowFarItGot(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	per := time.Second
	src := ch.model(clk, per)
	store := finality.NewMemCaptureStore()
	budget := 150 * time.Second
	p := spineProver(src, store, clk, budget)
	spans := PlanSpans(legN, ch.top()-1)
	plan := simulate(spans, per, budget, nil)
	need := ch.top() - legN + 1

	done := 0
	for a, fetch := range plan {
		_, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil {
			t.Fatalf("attempt %d: %v", a+1, err)
		}
		done += len(fetch)
		if a == len(plan)-1 {
			if pend != nil {
				t.Fatalf("the last planned attempt (%d) is not complete: %v", a+1, pend)
			}
			break
		}
		have, n, next := pendingOf(t, pend)
		wantHave, _ := SpineProgress(spans, true, done)
		if int(have) != wantHave || n != need {
			t.Fatalf("attempt %d: have %d need %d, want %d %d", a+1, have, n, wantHave, need)
		}
		if want := clk.Now().Add(SpineResumeDelay).UTC().Format(time.RFC3339); next != want || !pend.ETA.Equal(clk.Now().Add(SpineResumeDelay)) {
			t.Fatalf("attempt %d: next_attempt_at %s eta %s, want %s", a+1, next, pend.ETA, want)
		}
		if pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelFinalized || pend.Chain != finality.ChainSepolia {
			t.Fatalf("attempt %d: %+v", a+1, pend)
		}
	}
	if len(plan) < 3 {
		t.Fatalf("the plan has %d attempts: the test no longer spans several", len(plan))
	}
	// the calls are the spans in plan order, each once: attempt k+1 starts at the first span attempt k did not reach
	if src.callCount() != len(spans) {
		t.Fatalf("%d calls for %d spans", src.callCount(), len(spans))
	}
	for i, sp := range spans {
		if src.calls[i] != [2]uint64{sp.Start, sp.End} {
			t.Fatalf("call %d = %v, span %v", i, src.calls[i], sp)
		}
	}
	if rep, _ := src.repeated(); rep != 0 {
		t.Fatalf("%d headers fetched twice", rep)
	}
}

func TestANewProcessResumesFromTheKeptRowsAtTheFirstMissingChunk(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	per := time.Second
	budget := 150 * time.Second
	spans := PlanSpans(legN, ch.top()-1)
	plan := simulate(spans, per, budget, nil)
	store := finality.NewMemCaptureStore()

	clk1 := newClock()
	p1 := spineProver(ch.model(clk1, per), store, clk1, budget)
	if _, pend, err := p1.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend == nil {
		t.Fatalf("first attempt: %v %v", pend, err)
	}
	reached := len(plan[0]) // spans 0..reached-1 are in hand; span 0 (the top) is not kept, spans 1..reached-1 are
	if got := len(storedSpineKeys(t, store)); got != reached-1 {
		t.Fatalf("%d rows kept after the first attempt, want %d", got, reached-1)
	}

	// the process restarts: a new prover, an empty cache, the same store
	clk2 := newClock()
	src2 := ch.model(clk2, per)
	p2 := spineProver(src2, store, clk2, budget)
	if _, pend, err := p2.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend == nil {
		t.Fatalf("second attempt: %v %v", pend, err)
	}
	// it fetched the top again (never kept: it moves with the head), read spans 1..reached-1 from the store without fetching, and went on
	// at span `reached`, the first one the store did not have
	if src2.calls[0] != [2]uint64{spans[0].Start, spans[0].End} {
		t.Fatalf("first call %v, want the top %v", src2.calls[0], spans[0])
	}
	if src2.calls[1] != [2]uint64{spans[reached].Start, spans[reached].End} {
		t.Fatalf("second call %v, want the first missing chunk %v", src2.calls[1], spans[reached])
	}
	for _, c := range src2.calls[1:] {
		for i := 1; i < reached; i++ {
			if c[0] == spans[i].Start {
				t.Fatalf("chunk %v was fetched although its row was kept", spans[i])
			}
		}
	}
}

func TestTheAttemptBudgetCountsNewWorkOnlyAndIsExactAtTheBoundary(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	per := time.Second
	spans := PlanSpans(legN, ch.top()-1)
	last, prev := len(spans)-1, len(spans)-2
	fill := func() finality.CaptureStore { // every kept window but the last two is in the store
		st := finality.NewMemCaptureStore()
		for i, sp := range spans {
			if sp.Stored && i < prev {
				k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: sp.End, L1Hash: ch.hashOf(sp.End), Item: SpineItem(sp.Count())}
				if err := st.Put(context.Background(), k, encodeSpan(ch.hs[sp.Start-ch.base:sp.End-ch.base+1])); err != nil {
					t.Fatal(err)
				}
			}
		}
		return st
	}
	cost := func(i int) time.Duration { return time.Duration(spans[i].Count()) * per }
	// new work: the top (always), then the two missing windows. The second fetch needs spent+longest <= budget, the third too: the budget
	// that admits all three is what the third needs, the top and the second window spent plus the longest of them.
	third := cost(0) + cost(prev) + maxDur(cost(0), cost(prev))
	run := func(budget time.Duration) (*finality.PendingState, *modelHeaders) {
		clk := newClock()
		src := ch.model(clk, per)
		p := spineProver(src, fill(), clk, budget)
		_, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil {
			t.Fatal(err)
		}
		return pend, src
	}
	// the budget that exactly admits all three fetches completes with three calls: reading 100+ kept windows cost nothing
	pend, src := run(third)
	if pend != nil || src.callCount() != 3 {
		t.Fatalf("budget %s: pending %v, %d calls; want complete with 3", third, pend, src.callCount())
	}
	// one nanosecond less stops before the last fetch; the state says exactly how far it got
	pend, src = run(third - 1)
	if src.callCount() != 2 {
		t.Fatalf("budget %s: %d calls, want 2", third-1, src.callCount())
	}
	have, n, _ := pendingOf(t, pend)
	wantHave, _ := SpineProgress(spans, true, last)
	if int(have) != wantHave || int(n) != int(ch.top()-legN+1) {
		t.Fatalf("have %d need %d, want %d %d", have, n, wantHave, ch.top()-legN+1)
	}
}

func maxDur(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// ---- a chunk that is not what its address says ----

func filledStore(t *testing.T, ch *synthChain, legN uint64) finality.CaptureStore {
	t.Helper()
	st := finality.NewMemCaptureStore()
	clk := newClock()
	p := spineProver(ch.model(clk, 0), st, clk, 0)
	if _, _, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil {
		t.Fatal(err)
	}
	return st
}

// replaced is st with the row at k holding other bytes: a store that was damaged, or written by something that is not this code.
func replaced(t *testing.T, st finality.CaptureStore, k finality.CaptureKey, bad []byte) finality.CaptureStore {
	t.Helper()
	out := finality.NewMemCaptureStore()
	keys, err := st.ListByRange(context.Background(), k.Chain, 0, finality.MaxCaptureBlock, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, kk := range keys {
		b, _, _ := st.Get(context.Background(), kk)
		if kk == k {
			b = bad
		}
		if err := out.Put(context.Background(), kk, b); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Every kind of wrong kept row is a miss that is reported by name: the chunk is fetched, authenticated, kept in the process, and the leg
// completes with the right headers. Nothing is verified from the row itself.
func TestEveryKindOfWrongKeptRowIsReportedByNameAndReplacedFromTheProvider(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	spans := PlanSpans(legN, ch.top()-1)
	target := spans[2]
	k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: target.End, L1Hash: ch.hashOf(target.End), Item: SpineItem(target.Count())}
	good := filledStore(t, ch, legN)
	win := append([][]byte(nil), ch.hs[target.Start-ch.base:target.End-ch.base+1]...)
	swapped := append([][]byte(nil), win...)
	swapped[3], swapped[4] = swapped[4], swapped[3]
	sib := func(i int, seed byte) [][]byte {
		w := append([][]byte(nil), win...)
		n := target.Start + uint64(i)
		w[i] = spineSynthHeader(n, ch.hashOf(n-1), seed)
		return w
	}
	cases := []struct {
		name   string
		bytes  []byte
		reason string
	}{
		{"the last header is another block", encodeSpan(sib(len(win)-1, 9)), SpineRowTopMismatch},
		{"a middle header is another block", encodeSpan(sib(10, 9)), SpineRowNotChained},
		{"two headers swapped", encodeSpan(swapped), SpineRowNumbers},
		{"a header missing", encodeSpan(win[1:]), SpineRowMalformed},
		{"a byte appended", append(encodeSpan(win), 0x00), SpineRowMalformed},
		{"half of it", encodeSpan(win)[:len(encodeSpan(win))/2], SpineRowMalformed},
		{"empty", nil, SpineRowMalformed},
	}
	want := expectedSpine(ch, legN)
	for _, c := range cases {
		clk := newClock()
		var logs logSink
		p := spineProver(ch.model(clk, 0), replaced(t, good, k, c.bytes), clk, 0)
		p.Logf = logs.Logf
		spine, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil || pend != nil || len(spine) != len(want) {
			t.Fatalf("%s: %d headers, pending %v, err %v", c.name, len(spine), pend, err)
		}
		for i := range want {
			if !bytes.Equal(spine[i], want[i]) {
				t.Fatalf("%s: spine[%d] is not the chain's header", c.name, i)
			}
		}
		st := spineRowInvalid(target, &spineFault{Reason: c.reason})
		if !logs.has(CodeSpineRowInvalid+"{") || !logs.has(`reason="`+c.reason+`"`) || !logs.has(`block="`+fmt.Sprint(target.End)+`"`) || st.Code != CodeSpineRowInvalid {
			t.Fatalf("%s: the wrong row was not reported as %s{reason=%s}: %v", c.name, CodeSpineRowInvalid, c.reason, logs.lines)
		}
	}
}

// ---- a provider that serves what does not chain ----

func TestHeadersThatDoNotChainToTheFinalizedHeadAreNeverKeptAndTheNextAttemptRecovers(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	fork := newSynth(1_000_000, 1000, 2)
	legN := uint64(1_000_100)
	spans := PlanSpans(legN, ch.top()-1)
	bad := spans[3]
	variants := map[string]func(out [][]byte) [][]byte{
		"another chain": func(out [][]byte) [][]byte { return fork.hs[bad.Start-ch.base : bad.End-ch.base+1] },
		"one header replaced": func(out [][]byte) [][]byte {
			o := append([][]byte(nil), out...)
			o[7] = spineSynthHeader(bad.Start+7, ch.hashOf(bad.Start+6), 9)
			return o
		},
		"one header short":     func(out [][]byte) [][]byte { return out[:len(out)-1] },
		"in the wrong order":   func(out [][]byte) [][]byte { o := append([][]byte(nil), out...); o[1], o[2] = o[2], o[1]; return o },
		"a header unreadable":  func(out [][]byte) [][]byte { o := append([][]byte(nil), out...); o[0] = []byte{0x01}; return o },
		"the right ones twice": func(out [][]byte) [][]byte { return append(append([][]byte(nil), out...), out...) },
	}
	for name, mutate := range variants {
		clk := newClock()
		src := ch.model(clk, 0)
		lying := true
		src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
			if lying && from == bad.Start {
				return mutate(out), nil
			}
			return out, nil
		}
		store := finality.NewMemCaptureStore()
		p := spineProver(src, store, clk, 0)
		_, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		have, _, _ := pendingOf(t, pend)
		wantHave, _ := SpineProgress(spans, true, 3)
		if int(have) != wantHave {
			t.Fatalf("%s: have %d, want %d (the three spans above the bad one)", name, have, wantHave)
		}
		if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "do not chain") {
			t.Fatalf("%s: cause %q", name, c)
		}
		if got := len(storedSpineKeys(t, store)); got != 2 { // spans 1 and 2 are kept, 3 is not, and 0 is the unkept top
			t.Fatalf("%s: %d rows kept, want 2", name, got)
		}
		lying = false
		spine, attempts, _ := completed(t, p, ch.leg(legN), ch.candidate(), 3)
		if len(spine) != int(ch.top()-legN+1) || attempts != 1 {
			t.Fatalf("%s: recovery took %d attempts for %d headers", name, attempts, len(spine))
		}
	}
}

// ---- providers that throttle, fail or die ----

func TestAThrottledOrFailedAttemptEndsWithTheProgressStateAndBacksOffWithoutProgress(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	src := ch.model(clk, 0)
	var mode func() error
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		if mode != nil {
			if err := mode(); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	throttled := func(ra time.Duration) error {
		return &SourceError{Failures: []EndpointFailure{{Endpoint: "https://rpc.example", Op: "headers", Reason: "HTTP 429", Throttled: true, RetryAfter: ra}}}
	}
	store := finality.NewMemCaptureStore()
	p := spineProver(src, store, clk, 0)
	attempt := func() *finality.PendingState {
		_, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil {
			t.Fatal(err)
		}
		return pend
	}
	nextIn := func(pend *finality.PendingState) time.Duration {
		_, _, next := pendingOf(t, pend)
		at, err := time.Parse(time.RFC3339, next)
		if err != nil {
			t.Fatal(err)
		}
		if !pend.ETA.Equal(at) {
			t.Fatalf("eta %s and next_attempt_at %s differ", pend.ETA, next)
		}
		return at.Sub(clk.Now())
	}
	// a provider that states Retry-After: come back then
	mode = func() error { return throttled(90 * time.Second) }
	pend := attempt()
	if d := nextIn(pend); d != 90*time.Second {
		t.Fatalf("Retry-After 90s: next attempt in %s", d)
	}
	if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "fetching headers") || !strings.Contains(c, "429") {
		t.Fatalf("cause %q", c)
	}
	if have, _, _ := pendingOf(t, pend); have != 1 {
		t.Fatalf("have %d with nothing fetched: only the finalized head is in hand", have)
	}
	// one that states nothing, or fails some other way: 30 s, doubling per attempt in a row without progress, up to 15 min
	for _, m := range []struct {
		name string
		err  func() error
	}{
		{"429 without Retry-After", func() error { return throttled(0) }},
		{"a plain failure", func() error { return errors.New("connection reset") }},
	} {
		mode = m.err
		for i, want := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 480 * time.Second, 900 * time.Second, 900 * time.Second} {
			p = spineProver(src, store, clk, 0) // a fresh stall count for each provider behaviour
			for j := 0; j < i; j++ {
				attempt()
			}
			if d := nextIn(attempt()); d != want {
				t.Fatalf("%s, %d earlier attempts without progress: next attempt in %s, want %s", m.name, i, d, want)
			}
		}
	}
	// progress resets the count: two failures, then an attempt that fetches something, then a failure waits the base again
	p = spineProver(src, store, clk, 0)
	mode = func() error { return errors.New("down") }
	attempt()
	attempt()
	mode = nil
	p.SpineBudget = 100 * time.Second // the top window (39 s) and one kept window (40 s): the next would end after 100 s
	src.perHdr = time.Second
	if pend := attempt(); pend == nil {
		t.Fatal("a 100 s budget at 1 s a header cannot finish 900 headers")
	}
	mode = func() error { return errors.New("down") }
	if d := nextIn(attempt()); d != SpineErrorBase {
		t.Fatalf("after progress the wait is %s, want the base %s", d, SpineErrorBase)
	}
}

func TestAProviderErrorTextIsRedactedInTheProgressState(t *testing.T) {
	ch := newSynth(1_000_000, 300, 1)
	src := ch.model(newClock(), 0)
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		return nil, fmt.Errorf(`Post "https://eth-sepolia.g.alchemy.com/v2/abc123SECRETkeyabc123SECRETkey": dial tcp: lookup failed`)
	}
	p := spineProver(src, nil, newClock(), 0)
	_, pend, err := p.spineFor(context.Background(), ch.leg(1_000_050), ch.candidate())
	if err != nil {
		t.Fatal(err)
	}
	if text := pend.Error(); strings.Contains(text, "abc123SECRET") {
		t.Fatalf("a credential reached the state: %s", text)
	}
}

type failingStore struct {
	finality.CaptureStore
	getErr, putErr error
	hideGets       bool // Get answers "not found" although the row is there (another validator wrote it in between)
	mu             sync.Mutex
	puts           int
}

func (s *failingStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if s.getErr != nil {
		return nil, false, s.getErr
	}
	if s.hideGets {
		return nil, false, nil
	}
	return s.CaptureStore.Get(ctx, k)
}

func (s *failingStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	s.mu.Lock()
	s.puts++
	s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	return s.CaptureStore.Put(ctx, k, b)
}

func TestAStoreThatFailsPausesTheSpineAndLosesNoProgress(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	src := ch.model(clk, 0)
	st := &failingStore{CaptureStore: finality.NewMemCaptureStore(), getErr: errors.New("database is down")}
	p := spineProver(src, st, clk, 0)
	_, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "reading a kept spine chunk") || !strings.Contains(c, "database is down") {
		t.Fatalf("cause %q", c)
	}
	// reads recover but writes fail: every fetched chunk is kept in the process and the attempt pauses; the next one needs no new fetch
	st.getErr, st.putErr = nil, errors.New("disk full")
	_, pend, err = p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "keeping a spine chunk") {
		t.Fatalf("cause %q", c)
	}
	st.putErr = nil
	calls := src.callCount()
	if _, attempts, _ := completed(t, p, ch.leg(legN), ch.candidate(), 50); attempts > 50 {
		t.Fatal("did not finish")
	}
	if rep, _ := src.repeated(); rep != 0 {
		t.Fatalf("%d headers fetched twice although the process kept them (%d calls before the store came back)", rep, calls)
	}
}

// A row another validator wrote with the same bytes is accepted. (A row with other bytes is TestAPutConflictWithAStoredRowIsReported...)
func TestAnIdenticalRowWrittenByAnotherValidatorIsAccepted(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	good := filledStore(t, ch, legN)
	// the row is there but this validator does not see it (it reads between the other's read and write): Put of the same bytes is a no-op
	seen := &failingStore{CaptureStore: good, hideGets: true}
	clk := newClock()
	var logs logSink
	p := spineProver(ch.model(clk, 0), seen, clk, 0)
	p.Logf = logs.Logf
	if _, _, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil {
		t.Fatalf("identical duplicate rows: %v", err)
	}
	if seen.puts == 0 {
		t.Fatal("the duplicate path was not exercised")
	}
	if logs.has(CodeSpineRowInvalid) {
		t.Fatalf("an identical duplicate was reported as invalid: %v", logs.lines)
	}
}

func TestACancelledOrExpiredAttemptKeepsWhatItFetchedAndEndsWithTheProgressState(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	clk := newClock()
	src := ch.model(clk, 0)
	ctx, cancel := context.WithCancel(context.Background())
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		if call == 4 {
			cancel()
			return nil, ctx.Err()
		}
		return out, nil
	}
	store := finality.NewMemCaptureStore()
	p := spineProver(src, store, clk, 0)
	_, pend, err := p.spineFor(ctx, ch.leg(legN), ch.candidate())
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "context canceled") {
		t.Fatalf("cause %q", c)
	}
	if got := len(storedSpineKeys(t, store)); got != 2 { // calls 1 (top, unkept), 2 and 3 kept, 4 cancelled
		t.Fatalf("%d rows kept", got)
	}
	// a context with no time left allows no new work, and says so; kept chunks are still read
	src.hook = nil
	short, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	before := src.callCount()
	_, pend, err = p.spineFor(short, ch.leg(legN), ch.candidate())
	if err != nil {
		t.Fatal(err)
	}
	if src.callCount() != before {
		t.Fatalf("a context with 5 s left fetched %d more chunks", src.callCount()-before)
	}
	if c, _ := pend.Judged["cause"].(string); !strings.Contains(c, "budget") {
		t.Fatalf("cause %q", c)
	}
}

// ---- legs that share chunks ----

// Four legs asking for the same chunks at once fetch each chunk once: the second waits for the first and finds it. The interleaving is
// gated, not raced: the first fetch is held until the other three are waiting for its lock.
func TestLegsAskingForTheSameChunkAtOnceFetchItOnce(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	clk := newClock()
	src := ch.model(clk, 0)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		once.Do(func() { close(entered); <-release })
		return out, nil
	}
	store := finality.NewMemCaptureStore()
	p := spineProver(src, store, clk, 0)
	legs := []uint64{1_000_120, 1_000_320, 1_000_520, 1_000_720} // multiples of the window: no leg cuts a window short
	spines := make([][][]byte, len(legs))
	errs := make([]error, len(legs))
	var wg sync.WaitGroup
	run := func(i int) {
		defer wg.Done()
		for tries := 0; tries < 20; tries++ {
			sp, pend, err := p.spineFor(context.Background(), ch.leg(legs[i]), ch.candidate())
			if err != nil || pend == nil {
				spines[i], errs[i] = sp, err
				return
			}
		}
	}
	wg.Add(1)
	go run(0)
	<-entered
	for i := 1; i < len(legs); i++ {
		wg.Add(1)
		go run(i)
	}
	// wait until the three others are queued on the lock of the chunk the first one is fetching
	deadline := time.Now().Add(10 * time.Second)
	for {
		p.sc.locks.mu.Lock()
		refs := 0
		for _, e := range p.sc.locks.m {
			if e.refs > refs {
				refs = e.refs
			}
		}
		p.sc.locks.mu.Unlock()
		if refs == len(legs) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the other legs never queued on the first chunk (most waiters %d)", refs)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()
	for i, l := range legs {
		if errs[i] != nil || len(spines[i]) != int(ch.top()-l+1) {
			t.Fatalf("leg %d: %d headers, %v", l, len(spines[i]), errs[i])
		}
	}
	if rep, distinct := src.repeated(); rep != 0 || distinct != int(ch.top()-legs[0]) {
		t.Fatalf("%d headers fetched twice; %d distinct, want %d", rep, distinct, ch.top()-legs[0])
	}
	p.sc.locks.mu.Lock()
	left := len(p.sc.locks.m)
	p.sc.locks.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d chunk locks still registered after every fetch ended", left)
	}
}

func TestALockWaitEndsWithTheContextAndALockIsReleasedOnce(t *testing.T) {
	var l spineLocks
	k := spineKey{End: 1}
	rel, err := l.acquire(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.acquire(ctx, k); err == nil {
		t.Fatal("a held lock was acquired")
	}
	rel()
	rel() // idempotent: a second release must not free someone else's hold
	r2, err := l.acquire(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	r2()
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d lock entries left", n)
	}
}

func TestTheProcessCacheIsBoundedAndKeepsTheNewestChunks(t *testing.T) {
	c := spineCache{cap: 100}
	e := func(n int) *spineEntry { return &spineEntry{enc: make([]byte, n)} }
	for i := 0; i < 10; i++ {
		c.put(spineKey{End: uint64(i)}, e(30))
	}
	if c.bytes > 100 || len(c.m) != 3 {
		t.Fatalf("%d bytes in %d entries", c.bytes, len(c.m))
	}
	if _, ok := c.get(spineKey{End: 0}); ok {
		t.Fatal("the oldest entry survived")
	}
	if _, ok := c.get(spineKey{End: 9}); !ok {
		t.Fatal("the newest entry was dropped")
	}
	c.put(spineKey{End: 77}, e(101)) // larger than the whole bound: not kept, nothing evicted for it
	if _, ok := c.get(spineKey{End: 77}); ok || len(c.m) != 3 {
		t.Fatal("an entry larger than the bound was kept")
	}
	c.put(spineKey{End: 9}, e(30)) // the same key again changes nothing
	if c.bytes != 90 {
		t.Fatalf("%d bytes after a duplicate put", c.bytes)
	}
}

// ---- memory ----

func TestTheSpineIsHeldWithinTheBuildsMemoryReservationAndAnOverBudgetBuildIsNamed(t *testing.T) {
	ch := newSynth(1_000_000, 4700, 1) // the shape of a day-old leg: about 4.6 thousand headers
	legN := uint64(1_000_050)
	payload := 0
	for n := legN; n < ch.top(); n++ {
		payload += len(ch.byNum[n])
	}
	b := finality.NewMemoryBudget(256 << 20)
	ctx := finality.WithMemoryBudget(context.Background(), b)
	hold := finality.NewHold(ctx, finality.ChainSepolia, "build")
	ctx = finality.WithHold(ctx, hold)
	clk := newClock()
	p := spineProver(ch.model(clk, 0), finality.NewMemCaptureStore(), clk, 0)
	if _, pend, err := p.spineFor(ctx, ch.leg(legN), ch.candidate()); err != nil || pend != nil {
		t.Fatalf("%v %v", pend, err)
	}
	used := b.Used()
	if used < int64(payload) || used > 2*int64(payload) {
		t.Fatalf("the build reserved %d bytes for a spine of %d bytes", used, payload)
	}
	hold.Release()
	if b.Used() != 0 {
		t.Fatalf("%d bytes still reserved after the hold was released", b.Used())
	}
	// a budget the spine does not fit is the named memory state, with nothing built
	small := finality.NewMemoryBudget(int64(payload) / 2)
	ctx2 := finality.WithMemoryBudget(context.Background(), small)
	h2 := finality.NewHold(ctx2, finality.ChainSepolia, "build")
	defer h2.Release()
	ctx2 = finality.WithHold(ctx2, h2)
	p2 := spineProver(ch.model(newClock(), 0), finality.NewMemCaptureStore(), newClock(), 0)
	spine, pend, err := p2.spineFor(ctx2, ch.leg(legN), ch.candidate())
	if spine != nil || pend != nil {
		t.Fatal("a spine was built over the budget")
	}
	isNamed(t, err, finality.CodeMemoryBudget, "")
}

func TestPeakHeapOfTheLargestSpineStaysWithinAFewTimesItsSize(t *testing.T) {
	// the verifier's bound is 16384 headers: build that, kept in a store and in the process cache, and sample the heap while it runs
	ch := newSynth(1_000_000, 16384, 1)
	legN := ch.base
	payload := 0
	for n := legN; n < ch.top(); n++ {
		payload += len(ch.byNum[n])
	}
	clk := newClock()
	p := spineProver(ch.model(clk, 0), finality.NewMemCaptureStore(), clk, 0)
	peak := peakHeap(func() {
		if _, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate()); err != nil || pend != nil {
			t.Errorf("%v %v", pend, err)
		}
	})
	t.Logf("spine of %d headers, %d bytes: peak heap growth %d bytes (%.2f x)", ch.top()-legN+1, payload, peak, float64(peak)/float64(payload))
	if peak > uint64(4*payload) {
		t.Fatalf("peak heap grew by %d bytes for a %d byte spine", peak, payload)
	}
}

func TestAttemptReserveIsAFifthOfTheDeadlineAtLeastTenSeconds(t *testing.T) {
	s := time.Second
	for _, c := range []struct{ left, want time.Duration }{
		{-1, 0}, {0, 10 * s}, {40 * s, 10 * s}, {50 * s, 10 * s}, {51 * s, 10*s + 200*time.Millisecond}, {300 * s, 60 * s},
	} {
		if got := AttemptReserve(c.left); got != c.want {
			t.Errorf("AttemptReserve(%s) = %s, want %s", c.left, got, c.want)
		}
	}
}

func TestFetchFitsNeedsTheReserveAndTheLongestFetchLeftOfTheDeadlineExactly(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		left, reserve, longest time.Duration
		want                   bool
	}{
		{-1, 10 * s, 5 * s, true}, {15 * s, 10 * s, 5 * s, true}, {15*s - 1, 10 * s, 5 * s, false}, {0, 10 * s, 0, false}, {10 * s, 10 * s, 0, true}, {0, 0, 0, true},
	} {
		if got := FetchFits(c.left, c.reserve, c.longest); got != c.want {
			t.Errorf("FetchFits(%s,%s,%s) = %v, want %v", c.left, c.reserve, c.longest, got, c.want)
		}
	}
}
