// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// V-SPINE-2 N1. Progress is the leg's own position, not who fetched: a leg that follows another leg and gains headers by REUSING the chunks the
// leader kept is progressing. Counting only the chunks a leg fetched itself made the stalled alert fire in a healthy slow drain (the deploy
// scenario) and made the follower's pause escalate. Only the stored spans in hand count (the top window is never kept).
func TestALegThatOnlyReusesTheChunksOfAnotherLegIsProgressingNotStalled(t *testing.T) {
	metrics.RegisterMetrics()
	ch := newSynth(1_000_000, 2000, 1)
	clk := newClock()
	src := ch.model(clk, time.Second)
	failing := false
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		if failing {
			return nil, errors.New("provider down")
		}
		return out, nil
	}
	p := spineProver(src, finality.NewMemCaptureStore(), clk, 100*time.Second)
	legA, legB := ch.leg(1_000_040), ch.leg(1_000_080)
	var lastHave uint64
	for wave := 1; wave <= 5; wave++ {
		failing = false // the leader gains two kept windows
		if _, pend, err := p.spineFor(context.Background(), legA, ch.candidate()); err != nil || pend == nil {
			t.Fatalf("wave %d, leader: %v %v", wave, pend, err)
		}
		failing = true // the follower reuses them and then meets a failing provider: its pause is the failure back-off
		_, pend, err := p.spineFor(context.Background(), legB, ch.candidate())
		if err != nil || pend == nil {
			t.Fatalf("wave %d, follower: %v %v", wave, pend, err)
		}
		have, _, next := pendingOf(t, pend)
		if have <= lastHave {
			t.Fatalf("wave %d: the follower's have did not grow (%d after %d): the test no longer shows reuse", wave, have, lastHave)
		}
		lastHave = have
		at, _ := time.Parse(time.RFC3339, next)
		if d := at.Sub(clk.Now()); d != SpineErrorBase {
			t.Fatalf("wave %d: the follower gains headers every wave, its pause is %s, want the base %s", wave, d, SpineErrorBase)
		}
		if stalled, _ := scraped(t, "certen_finality_spine_stalled_attempts_max", nil); stalled != 0 {
			t.Fatalf("wave %d: stalled_attempts_max %v although both legs gain headers every wave", wave, stalled)
		}
	}
}

// V-SPINE-2 N1, second path: a leg that was completed by ANOTHER validator is never attempted again by this process, so nothing clears its
// entry. An entry untouched for an hour is forgotten, at the scrape as well as at the next attempt (the alert must not outlive the cause).
func TestAStalledLegIsForgottenAfterAnHourWithoutAnAttempt(t *testing.T) {
	metrics.RegisterMetrics()
	ch := newSynth(1_000_000, 1000, 1)
	clk := newClock()
	src := ch.model(clk, 0)
	src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
		return nil, errors.New("provider down")
	}
	p := spineProver(src, finality.NewMemCaptureStore(), clk, 0)
	for i := 0; i < 2; i++ {
		if _, pend, err := p.spineFor(context.Background(), ch.leg(1_000_100), ch.candidate()); err != nil || pend == nil {
			t.Fatalf("%v %v", pend, err)
		}
	}
	read := func() (stalled, awaiting float64) {
		stalled, _ = scraped(t, "certen_finality_spine_stalled_attempts_max", nil)
		awaiting, _ = scraped(t, "certen_finality_spine_legs_awaiting", nil)
		return
	}
	if s, a := read(); s != 2 || a != 1 {
		t.Fatalf("after two attempts without progress: stalled %v awaiting %v, want 2 and 1", s, a)
	}
	clk.Advance(time.Hour) // exactly an hour is still inside the window
	if s, a := read(); s != 2 || a != 1 {
		t.Fatalf("an hour after the last attempt: stalled %v awaiting %v, want 2 and 1", s, a)
	}
	clk.Advance(time.Nanosecond)
	if s, a := read(); s != 0 || a != 0 {
		t.Fatalf("more than an hour after the last attempt: stalled %v awaiting %v, want 0 and 0: the alert outlives its cause", s, a)
	}
}

// V-SPINE-3 N3. The window under the head moves with the head: whenever the head's parent closes a window it is a stored span, but it never
// carries over to the next attempt and is no progress. A provider that serves that window and then refuses is a stall whatever the head does
// (+1, +32 per epoch, +33, +40): the stall count must reach 3 in three attempts and the pause must climb to its cap.
func TestAProviderThatOnlyServesTheWindowUnderTheHeadIsAStallWhateverTheHeadDoes(t *testing.T) {
	metrics.RegisterMetrics()
	wantPause := []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second, 240 * time.Second, 480 * time.Second, SpineErrorMax, SpineErrorMax, SpineErrorMax}
	for _, step := range []uint64{1, 32, 33, 40} {
		ch := newSynth(1_000_000, 3000, 1)
		clk := newClock()
		src := ch.model(clk, 0)
		var curLast uint64
		src.hook = func(call int, from, to uint64, out [][]byte) ([][]byte, error) {
			if to == curLast {
				return out, nil // the window under the head
			}
			return nil, errors.New("provider refuses")
		}
		p := spineProver(src, finality.NewMemCaptureStore(), clk, 0)
		head := uint64(1_002_000) // its parent, 1_001_999, closes a window: the top span is a stored one
		for k, want := range wantPause {
			curLast = head - 1
			cand := candidate{execHash: ch.hashOf(head), execNumber: head}
			_, pend, err := p.spineFor(context.Background(), ch.leg(1_000_100), cand)
			if err != nil || pend == nil {
				t.Fatalf("step %d, attempt %d: %v %v", step, k+1, pend, err)
			}
			_, _, next := pendingOf(t, pend)
			at, _ := time.Parse(time.RFC3339, next)
			if d := at.Sub(clk.Now()); d != want {
				t.Fatalf("head +%d, attempt %d (head %d): next attempt in %s, want %s", step, k+1, head, d, want)
			}
			if stalled, _ := scraped(t, "certen_finality_spine_stalled_attempts_max", nil); stalled != float64(k+1) {
				t.Fatalf("head +%d, attempt %d (head %d): stalled_attempts_max %v, want %d", step, k+1, head, stalled, k+1)
			}
			head += step
		}
	}
}
