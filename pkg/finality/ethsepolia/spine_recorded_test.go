// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// These tests build REAL proofs: the three recorded finalized legs of finality_eth_sepolia2 (a day-old leg with a 4638-header spine, a
// two-period-old one and a legacy-layout one), through the resumable spine and the registered verifier, against headers served by a model
// provider. Nothing here is synthetic except the provider's latency.

func recordedProver(t testing.TB, l recordedLeg, src HeaderSource, store finality.CaptureStore, clk *fakeClock, budget time.Duration) *Prover {
	t.Helper()
	p := &Prover{Source: l.source, Exec: src, Pins: embeddedPinsT(t), Verifier: New(), ExtraLinks: l.source.links, Store: store, SpineBudget: budget}
	if clk != nil {
		p.Now = clk.Now
	}
	return p
}

func spansOf(l recordedLeg) []Span {
	return PlanSpans(l.ref.Number, l.ref.Number+uint64(len(l.body.Spine))-2)
}

// Through the kept spine a recorded leg's evidence is byte for byte the recorded evidence and the verifier accepts it; a second process
// with the same store builds it again after asking the provider for the top of the spine only (the one span that is never kept).
func TestRecordedLegsBuildByteIdenticalThroughTheKeptSpineAndVerify(t *testing.T) {
	for _, id := range []string{"gloas_latest", "gloas_period", "legacy"} {
		l := loadRecorded(t, id)
		store := finality.NewMemCaptureStore()
		src := recordedModel(l, newClock(), 0, 0)
		add, pend, err := recordedProver(t, l, src, store, nil, 0).BuildLeg(context.Background(), l.ref)
		if err != nil || pend != nil || add == nil {
			t.Fatalf("%s: add %v pend %v err %v", id, add != nil, pend, err)
		}
		if !bytes.Equal(add.Evidence, l.ev) {
			t.Fatalf("%s: the evidence is not the recorded evidence", id)
		}
		if _, err := New().Verify(embeddedPinsT(t), l.ref, add.Evidence); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		spans := spansOf(l)
		kept := 0
		for _, sp := range spans {
			if sp.Stored {
				kept++
			}
		}
		if got := len(storedSpineKeys(t, store)); got != kept {
			t.Fatalf("%s: %d rows kept, %d kept spans", id, got, kept)
		}
		src2 := recordedModel(l, newClock(), 0, 0)
		add2, pend2, err := recordedProver(t, l, src2, store, nil, 0).BuildLeg(context.Background(), l.ref)
		if err != nil || pend2 != nil || add2 == nil || !bytes.Equal(add2.Evidence, l.ev) {
			t.Fatalf("%s after a restart: add %v pend %v err %v", id, add2 != nil, pend2, err)
		}
		if src2.callCount() != 1 || src2.calls[0] != [2]uint64{spans[0].Start, spans[0].End} {
			t.Fatalf("%s after a restart the provider was asked %v; want only the top %v", id, src2.calls, spans[0])
		}
	}
}

// The live defect, end to end: the day-old leg behind a provider that costs half a second a header and an attempt budget that admits seven
// chunks. The attempts are exactly the planned ones, each state says how far the spine got, and the last attempt returns the recorded
// evidence, which the verifier accepts.
func TestADayOldLegCompletesInThePlannedNumberOfAttemptsWithTheProgressStateBetween(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	clk := newClock()
	per := 500 * time.Millisecond
	src := recordedModel(l, clk, per, 300*time.Second)
	budget := 140 * time.Second
	spans := spansOf(l)
	plan := simulate(spans, per, budget, nil)
	p := recordedProver(t, l, src, finality.NewMemCaptureStore(), clk, budget)
	need := uint64(len(l.body.Spine))
	done := 0
	for a, fetch := range plan {
		add, pend, err := p.BuildLeg(context.Background(), l.ref)
		if err != nil {
			t.Fatalf("attempt %d: %v", a+1, err)
		}
		done += len(fetch)
		if a == len(plan)-1 {
			if add == nil || pend != nil || !bytes.Equal(add.Evidence, l.ev) {
				t.Fatalf("attempt %d of %d should complete: add %v pend %v", a+1, len(plan), add != nil, pend)
			}
			if _, err := New().Verify(embeddedPinsT(t), l.ref, add.Evidence); err != nil {
				t.Fatal(err)
			}
			break
		}
		have, n, _ := pendingOf(t, pend)
		wantHave, _ := SpineProgress(spans, true, done)
		if add != nil || int(have) != wantHave || n != need {
			t.Fatalf("attempt %d: have %d need %d (want %d %d)", a+1, have, n, wantHave, need)
		}
	}
	if len(plan) < 10 {
		t.Fatalf("only %d attempts planned", len(plan))
	}
	if rep, distinct := src.repeated(); rep != 0 || distinct != len(l.body.Spine)-1 {
		t.Fatalf("%d headers fetched twice, %d distinct (the spine below the head has %d)", rep, distinct, len(l.body.Spine)-1)
	}
}

// A stored chunk that is not what its address says never reaches the verifier: the build fails by name, no addendum is returned. And the
// verifier is independently the last line: the same corruption put into evidence by hand is refused as a broken header chain.
func TestACorruptedKeptChunkNeverVerifiesAndTheVerifierRefusesTheSameCorruption(t *testing.T) {
	l := loadRecorded(t, "gloas_period")
	store := finality.NewMemCaptureStore()
	if add, pend, err := recordedProver(t, l, recordedModel(l, newClock(), 0, 0), store, nil, 0).BuildLeg(context.Background(), l.ref); err != nil || add == nil || pend != nil {
		t.Fatalf("%v %v %v", add != nil, pend, err)
	}
	spans := spansOf(l)
	target := spans[3]
	// the recorded spine is [head, ..., leg]; index i of it is block head-i
	headN := l.ref.Number + uint64(len(l.body.Spine)) - 1
	idx := func(n uint64) int { return int(headN - n) }
	k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: target.End, L1Hash: rlpFields(t, l.body.Spine[idx(target.End)]).hash, Item: SpineItem(target.Count())}
	if _, ok, _ := store.Get(context.Background(), k); !ok {
		t.Fatalf("no kept row at %s", k)
	}
	mid := target.Start + 9
	sibling := spineSynthHeader(mid, rlpFields(t, l.body.Spine[idx(mid-1)]).hash, 9) // a block of the right number whose parent is right
	win := make([][]byte, 0, target.Count())
	for n := target.Start; n <= target.End; n++ {
		win = append(win, l.body.Spine[idx(n)])
	}
	win[9] = sibling
	bad := replaced(t, store, k, encodeSpan(win))
	add, pend, err := recordedProver(t, l, recordedModel(l, newClock(), 0, 0), bad, nil, 0).BuildLeg(context.Background(), l.ref)
	if add != nil || pend != nil {
		t.Fatal("evidence or a pending state came back from a corrupted chunk")
	}
	isNamed(t, err, CodeSpineRowInvalid, SpineRowNotChained)

	// the same substitution in the evidence itself: the registered verifier refuses it
	body := l.body
	body.Spine = append([][]byte(nil), l.body.Spine...)
	body.Spine[idx(mid)] = sibling
	ev, err := BuildContainer(l.ref, body)
	if err != nil {
		t.Fatal(err)
	}
	_, verr := New().Verify(embeddedPinsT(t), l.ref, ev)
	s, ok := finality.AsNamed(verr)
	if !ok || s.Code != "finality_header_chain_broken" {
		t.Fatalf("the verifier answered %v to a spine with a substituted header", verr)
	}
}

// The first tick after the deploy: eleven legs of one finality update, at eleven depths of the same 4638-header spine, none with a kept
// chunk. Every one of them answers with progress, never a failure; the rounds share the chunks (each header is fetched once for all
// eleven); and every leg ends with evidence the verifier accepts.
func TestElevenLegsOfOneFinalityUpdateDrainOnTheFirstTicksAndShareTheirChunks(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	clk := newClock()
	per := 500 * time.Millisecond
	src := recordedModel(l, clk, per, 300*time.Second)
	store := finality.NewMemCaptureStore()
	p := recordedProver(t, l, src, store, clk, 0) // the default budget: 150 s of new work per attempt
	idxs := []int{4637, 4300, 3900, 3500, 3100, 2700, 2300, 1900, 1400, 800, 300}
	done := make([]bool, len(idxs))
	remaining := len(idxs)
	pins := embeddedPinsT(t)
	rounds := 0
	for remaining > 0 && rounds < 40 {
		rounds++
		for i, idx := range idxs {
			if done[i] {
				continue
			}
			leg := legAt(t, l, idx)
			if idx == 4637 {
				leg = l.ref
			}
			add, pend, err := p.BuildLeg(context.Background(), leg)
			if err != nil {
				t.Fatalf("round %d leg %d: %v", rounds, leg.Number, err)
			}
			if add == nil {
				if pend == nil || pend.Reason != PendingAwaitingSpine {
					t.Fatalf("round %d leg %d: neither evidence nor the progress state: %v", rounds, leg.Number, pend)
				}
				continue
			}
			if _, err := New().Verify(pins, leg, add.Evidence); err != nil {
				t.Fatalf("round %d leg %d: %v", rounds, leg.Number, err)
			}
			done[i] = true
			remaining--
		}
	}
	if remaining != 0 {
		t.Fatalf("%d of %d legs still unfinished after %d rounds", remaining, len(idxs), rounds)
	}
	// every header of the deepest leg is fetched; the only ones fetched twice are at the leg boundaries, where a leg's lowest chunk is cut at
	// the leg block (a row of its own) and a deeper leg needs the whole window: fewer than one window per leg
	rep, distinct := src.repeated()
	if distinct != len(l.body.Spine)-1 || rep >= SpineWindow*len(idxs) {
		t.Fatalf("%d headers fetched twice (bound %d); %d distinct, want the %d of the deepest leg", rep, SpineWindow*len(idxs), distinct, len(l.body.Spine)-1)
	}
	t.Logf("eleven legs drained in %d rounds; %d header fetches in %d calls", rounds, distinct, src.callCount())
}

// Validators that share one store and build the same leg at the same time write byte-identical rows: no conflict, no error, one row per
// kept span.
func TestTwoValidatorsBuildingTheSameLegAtOnceShareOneRowPerChunk(t *testing.T) {
	l := loadRecorded(t, "gloas_period")
	store := finality.NewMemCaptureStore()
	var wg sync.WaitGroup
	results := make([]*finality.Addendum, 2)
	errs := make([]error, 2)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := recordedProver(t, l, recordedModel(l, nil, 0, 0), store, nil, 0)
			results[i], _, errs[i] = p.BuildLeg(context.Background(), l.ref)
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] == nil || !bytes.Equal(results[i].Evidence, l.ev) {
			t.Fatalf("validator %d: %v", i, errs[i])
		}
	}
	kept := 0
	for _, sp := range spansOf(l) {
		if sp.Stored {
			kept++
		}
	}
	if got := len(storedSpineKeys(t, store)); got != kept {
		t.Fatalf("%d rows for %d kept spans", got, kept)
	}
}

// A day-old leg's whole build, memory included: the reservation the upgrader's hold takes for it stays within twice the spine and the
// heap it adds stays within a few times it.
func TestADayOldLegsBuildStaysWithinTheMemoryBudgetItReserves(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	payload := 0
	for _, h := range l.body.Spine {
		payload += len(h)
	}
	b := finality.NewMemoryBudget(256 << 20)
	ctx := finality.WithMemoryBudget(context.Background(), b)
	hold := finality.NewHold(ctx, finality.ChainSepolia, "build")
	defer hold.Release()
	ctx = finality.WithHold(ctx, hold)
	p := recordedProver(t, l, recordedModel(l, nil, 0, 0), finality.NewMemCaptureStore(), nil, 0)
	var add *finality.Addendum
	peak := peakHeap(func() {
		var err error
		if add, _, err = p.BuildLeg(ctx, l.ref); err != nil {
			t.Error(err)
		}
	})
	if add == nil {
		t.Fatal("no evidence")
	}
	used := b.Used()
	t.Logf("spine %d bytes (%d headers), evidence %d bytes: reserved %d bytes, peak heap growth %d bytes", payload, len(l.body.Spine), len(add.Evidence), used, peak)
	if used < int64(payload) || used > 2*int64(payload) {
		t.Fatalf("reserved %d bytes for a %d byte spine", used, payload)
	}
	if peak > uint64(8*payload) {
		t.Fatalf("peak heap growth %d bytes for a %d byte spine (store and process cache included)", peak, payload)
	}
}
