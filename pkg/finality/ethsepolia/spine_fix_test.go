// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// V-SPINE (independent review of RB12-SEPOLIA-SPINE at 6da90e12): the regression tests of its defects. They use only what that commit
// offered, so each fails there and passes after the fix.

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) Logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *logSink) has(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// D1. Several legs that want the same chunks run in lock step behind whichever leg is fetching. The time a leg waits for that fetch is time of
// its own attempt: it is counted against its budget, so every one of them ends in the progress state at its budget, not each a full budget
// after the one before it and the last at the build's deadline (finality_build_timeout, the symptom this package removes). Real goroutines, a
// real clock and a real deadline: with 4 legs the build has 14 s, so the attempt budget is 14 s minus the 10 s reserve = 4 s, and a leg that
// ends after 5 s waited without counting it; with 11 legs (the first tick after the deploy) 12 s and 2 s.
func TestConcurrentLegsEachEndInTheProgressStateAtTheirBudgetNotAtTheBuildsDeadline(t *testing.T) {
	for _, c := range []struct {
		legs               int
		deadline, maxAfter time.Duration
	}{{4, 14 * time.Second, 5 * time.Second}, {11, 12 * time.Second, 3500 * time.Millisecond}} {
		ch := newSynth(1_000_000, 4000, 1)
		src := ch.model(nil, 0)
		src.sleep = 100 * time.Millisecond
		p := spineProver(src, finality.NewMemCaptureStore(), nil, 0)
		legs := make([]uint64, c.legs)
		for i := range legs {
			legs[i] = 1_000_040 + 40*uint64(i)
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.deadline)
		type result struct {
			pend    *finality.PendingState
			err     error
			elapsed time.Duration
		}
		res := make([]result, len(legs))
		var wg sync.WaitGroup
		start := time.Now()
		for i := range legs {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, pend, err := p.spineFor(ctx, ch.leg(legs[i]), ch.candidate())
				res[i] = result{pend, err, time.Since(start)}
			}(i)
		}
		wg.Wait()
		cancel()
		for i, r := range res {
			if r.err != nil || r.pend == nil {
				t.Fatalf("%d legs, leg %d: pending %v err %v", c.legs, legs[i], r.pend, r.err)
			}
			if cause, _ := r.pend.Judged["cause"].(string); !strings.Contains(cause, "budget") {
				t.Fatalf("%d legs, leg %d ended for another reason than its budget: %q (after %s)", c.legs, legs[i], cause, r.elapsed)
			}
			if r.elapsed > c.maxAfter {
				t.Fatalf("%d legs, leg %d ended after %s of a %s build: the time it waited for another leg's fetch was not counted", c.legs, legs[i], r.elapsed, c.deadline)
			}
		}
	}
}

// D2. A kept row that fails its check is a miss: the chunk is fetched, authenticated by the same hash chain and kept in the process only (the
// insert-only table cannot be corrected), the invalid row is reported by name, and the leg completes. Three fresh processes in a row, a healthy
// provider: none of them is blocked by the row.
func TestABadKeptRowIsAMissThatIsReportedAndNeverBlocksALeg(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	spans := PlanSpans(legN, ch.top()-1)
	target := spans[2]
	k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: target.End, L1Hash: ch.hashOf(target.End), Item: SpineItem(target.Count())}
	win := append([][]byte(nil), ch.hs[target.Start-ch.base:target.End-ch.base+1]...)
	win[len(win)-1] = spineSynthHeader(target.End, ch.hashOf(target.End-1), 9)
	badBytes := encodeSpan(win)
	store := replaced(t, filledStore(t, ch, legN), k, badBytes)
	want := expectedSpine(ch, legN)
	for i := 1; i <= 3; i++ {
		clk := newClock()
		src := ch.model(clk, 0)
		var logs logSink
		p := spineProver(src, store, clk, 0)
		p.Logf = logs.Logf
		spine, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
		if err != nil || pend != nil {
			t.Fatalf("process %d: the bad row blocks the leg: pending %v err %v", i, pend, err)
		}
		if len(spine) != len(want) {
			t.Fatalf("process %d: %d headers, want %d", i, len(spine), len(want))
		}
		for j := range want {
			if !bytes.Equal(spine[j], want[j]) {
				t.Fatalf("process %d: spine[%d] differs", i, j)
			}
		}
		asked := false
		for _, c := range src.calls {
			asked = asked || c[0] == target.Start
		}
		if !asked {
			t.Fatalf("process %d: the provider was never asked for the window with the bad row", i)
		}
		if !logs.has(CodeSpineRowInvalid+"{") || !logs.has(SpineRowTopMismatch) {
			t.Fatalf("process %d: the invalid row was not reported by name: %v", i, logs.lines)
		}
	}
	if b, ok, _ := store.Get(context.Background(), k); !ok || !bytes.Equal(b, badBytes) {
		t.Fatal("the stored row was changed: the table is insert-only and nothing may be written over it")
	}
}

// D2, the write side: another validator's row with other bytes appears under the key between this process's read and its write. The chunk in
// hand is authenticated, so the conflict is reported by name and the leg goes on.
func TestAPutConflictWithAStoredRowIsReportedAndTheAuthenticatedChunkIsUsed(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	legN := uint64(1_000_100)
	spans := PlanSpans(legN, ch.top()-1)
	other := newSynth(1_000_000, 1000, 1)
	k := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: spans[1].End, L1Hash: ch.hashOf(spans[1].End), Item: SpineItem(spans[1].Count())}
	bad := replaced(t, filledStore(t, ch, legN), k, encodeSpan(other.hs[10:50]))
	clk := newClock()
	var logs logSink
	p := spineProver(ch.model(clk, 0), &failingStore{CaptureStore: bad, hideGets: true}, clk, 0)
	p.Logf = logs.Logf
	spine, pend, err := p.spineFor(context.Background(), ch.leg(legN), ch.candidate())
	if err != nil || pend != nil || len(spine) != int(ch.top()-legN+1) {
		t.Fatalf("a Put conflict failed the leg: %d headers, pending %v, err %v", len(spine), pend, err)
	}
	if !logs.has(SpineRowConflict) {
		t.Fatalf("the conflict was not reported by name: %v", logs.lines)
	}
}

// D3. The real source never states a Retry-After for a bare 429 and so reports none: the pause then escalates like any failure, 30 s doubling,
// instead of the 12 s backoff the call had reached being taken for the provider's request.
func TestABare429FromTheRealSourceEscalatesTheNextAttemptLikeAnyFailure(t *testing.T) {
	srv, _, _, _, _ := slowDownServer(t, 1000, "")
	clk := newClock()
	p := &Prover{Now: clk.Now}
	leg := finality.BlockRef{Chain: finality.ChainSepolia, Number: 1_000_000}
	c := candidate{execHash: [32]byte{1}, execNumber: 1_000_100}
	for i, want := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second} {
		p.Exec = &RPCHeaders{Endpoints: []string{srv.URL}} // a new source each time: a new pacer
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		_, pend, err := p.spineFor(ctx, leg, c)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		_, _, next := pendingOf(t, pend)
		at, perr := time.Parse(time.RFC3339, next)
		if perr != nil {
			t.Fatal(perr)
		}
		if d := at.Sub(clk.Now()); d != want {
			t.Fatalf("bare 429, attempt %d: next attempt in %s, want %s", i+1, d, want)
		}
	}
}

// D5. An attempt that fetched only the top window, which is never kept and moves with the head, made no progress: the stall count must not be
// reset by it.
func TestAnAttemptThatFetchedOnlyTheUnkeptTopMadeNoProgress(t *testing.T) {
	ch := newSynth(1_000_000, 1000, 1)
	clk := newClock()
	src := ch.model(clk, 0)
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		if call == 1 {
			return out, nil // the top window
		}
		return nil, fmt.Errorf("provider down")
	}
	p := spineProver(src, finality.NewMemCaptureStore(), clk, 0)
	for i, want := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second} {
		_, pend, err := p.spineFor(context.Background(), ch.leg(1_000_100), ch.candidate())
		if err != nil {
			t.Fatal(err)
		}
		_, _, next := pendingOf(t, pend)
		at, _ := time.Parse(time.RFC3339, next)
		if d := at.Sub(clk.Now()); d != want {
			t.Fatalf("attempt %d (only the top window ever fetched): next attempt in %s, want %s", i+1, d, want)
		}
	}
}
