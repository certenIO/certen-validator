// Copyright 2026 Certen Protocol

package ethsepolia

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// RB12-SEPOLIA-SPINE, the live defect (F6): a finalized proof whose spine does not fit one attempt must be finished by several, each
// starting where the last stopped. These two tests use only what the package offered before the fix (a Prover with a source, a header
// source and an injected clock; an RPCHeaders over HTTP), so they run unchanged on the base commit, where they fail.

// A day-old Sepolia leg (the recorded gloas_latest leg: 4638 spine headers, 3.1 MB) behind a provider that takes half a second a header
// and whose calls die at 300 s with nothing delivered, as the build's own timeout used to kill the whole fetch. Fetched in one piece the
// spine takes 2318 s and can never finish; fetched in resumable chunks it finishes in a few attempts, never asking for a header twice.
func TestRB12AFinalizedSpineThatDoesNotFitOneAttemptIsResumedNotRestarted(t *testing.T) {
	l := loadRecorded(t, "gloas_latest")
	clk := newClock()
	src := recordedModel(l, clk, 500*time.Millisecond, 300*time.Second)
	p := &Prover{Source: l.source, Exec: src, Pins: embeddedPinsT(t), Verifier: New(), ExtraLinks: l.source.links, Now: clk.Now}

	attempts, done := 0, false
	for attempts < 60 && !done {
		attempts++
		add, _, err := p.BuildLeg(context.Background(), l.ref)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempts, err)
		}
		if add != nil {
			if !bytes.Equal(add.Evidence, l.ev) {
				t.Fatalf("attempt %d: the evidence is not the recorded evidence", attempts)
			}
			done = true
		}
	}
	rep, distinct := src.repeated()
	if !done {
		t.Fatalf("%d attempts and the spine is still unfinished: %d calls, %d distinct headers served (%d of them more than once); every attempt starts again at the leg block",
			attempts, src.callCount(), distinct, rep)
	}
	if rep != 0 {
		t.Fatalf("%d header numbers were fetched more than once across %d attempts", rep, attempts)
	}
	if distinct != len(l.body.Spine)-1 {
		t.Fatalf("%d distinct headers fetched, the spine below the finalized head has %d", distinct, len(l.body.Spine)-1)
	}
}

// A provider that answers 429 with a Retry-After longer than a call is willing to wait must end the call at once, handing the time to come
// back to the caller; it must not sleep on the attempt's clock and ask again. Before the fix the call slept through its own backoff.
func TestRB12AProviderRetryAfterBeyondTheCallsPatienceEndsTheCallAtOnce(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Retry-After", "120")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	r := &RPCHeaders{Endpoints: []string{srv.URL}, BatchSize: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	t0 := time.Now()
	_, err := r.HeadersByNumber(ctx, 100, 105)
	if err == nil {
		t.Fatal("a provider that only answers 429 cannot have served headers")
	}
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("the call took %s: it waited instead of handing the Retry-After back", d)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("the provider saw %d requests, want exactly 1", n)
	}
}
