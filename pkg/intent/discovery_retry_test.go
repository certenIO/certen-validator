// Copyright 2025 Certen Protocol
//
// Tests for the on_demand consensus-bound proof retry mechanism: bounded exponential
// backoff, retryable-vs-terminal error classification, and non-blocking requeue.

package intent

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestChainedRetryBackoff_Bounded(t *testing.T) {
	base := 10 * time.Second
	maxShift := 5
	capDur := 5 * time.Minute

	cases := []struct {
		step int
		want time.Duration
	}{
		{step: -1, want: 10 * time.Second}, // clamped to step 0
		{step: 0, want: 10 * time.Second},  // 10 * 2^0
		{step: 1, want: 20 * time.Second},  // 10 * 2^1
		{step: 2, want: 40 * time.Second},  // 10 * 2^2
		{step: 3, want: 80 * time.Second},  // 10 * 2^3
		{step: 4, want: 160 * time.Second}, // 10 * 2^4
		{step: 5, want: 5 * time.Minute},   // 10 * 2^5 = 320s -> capped at 300s
		{step: 9, want: 5 * time.Minute},   // shift clamped to 5, then capped
	}
	for _, c := range cases {
		got := chainedRetryBackoff(base, c.step, maxShift, capDur)
		if got != c.want {
			t.Errorf("chainedRetryBackoff(step=%d) = %v, want %v", c.step, got, c.want)
		}
	}
}

func TestChainedRetryBackoff_InlineCapByValue(t *testing.T) {
	// Inline policy: base 2s, exponential, capped at 30s by value (high maxShift).
	base := 2 * time.Second
	for step, want := range map[int]time.Duration{
		0: 2 * time.Second,
		1: 4 * time.Second,
		2: 8 * time.Second,
		3: 16 * time.Second,
		4: 30 * time.Second, // 32s -> capped 30s
		8: 30 * time.Second,
	} {
		if got := chainedRetryBackoff(base, step, 30, 30*time.Second); got != want {
			t.Errorf("inline backoff step=%d = %v, want %v", step, got, want)
		}
	}
}

func TestChainedRetryBackoff_DefaultsOnZeroBase(t *testing.T) {
	if got := chainedRetryBackoff(0, 0, 5, time.Hour); got != time.Second {
		t.Errorf("zero base should default to 1s, got %v", got)
	}
}

// The retryable sentinel must be distinguishable from the terminal one through fmt.Errorf
// wrapping (%w), since the block-worker and retry worker branch on errors.Is.
func TestProofErrorClassification(t *testing.T) {
	retryable := fmt.Errorf("on_demand intent X: %w", errChainedProofUnavailable)
	terminal := fmt.Errorf("on_demand intent X: %w (cfg)", errChainedProofTerminal)

	if !errors.Is(retryable, errChainedProofUnavailable) {
		t.Error("retryable error must satisfy errors.Is(errChainedProofUnavailable)")
	}
	if errors.Is(retryable, errChainedProofTerminal) {
		t.Error("retryable error must NOT be classified as terminal")
	}
	if !errors.Is(terminal, errChainedProofTerminal) {
		t.Error("terminal error must satisfy errors.Is(errChainedProofTerminal)")
	}
	if errors.Is(terminal, errChainedProofUnavailable) {
		t.Error("terminal error must NOT be classified as retryable (no requeue loop)")
	}
	// A generic downstream error is neither -> treated as terminal by the caller.
	generic := errors.New("on_demand handler failed")
	if errors.Is(generic, errChainedProofUnavailable) || errors.Is(generic, errChainedProofTerminal) {
		t.Error("generic error must not match either proof sentinel")
	}
}

func TestEnqueueRetry_NonBlockingAndNilSafe(t *testing.T) {
	id := NewIntentDiscovery(nil, "", nil, nil, nil, "test")

	// Nil channel (before Start): must not panic or block.
	id.retryCh = nil
	id.enqueueRetry(&intentRetryJob{intent: &CertenIntent{IntentID: "nilq"}})

	// Full channel: must drop (default branch), not block.
	id.retryCh = make(chan *intentRetryJob, 1)
	id.retryCh <- &intentRetryJob{intent: &CertenIntent{IntentID: "occupies-slot"}}

	done := make(chan struct{})
	go func() {
		id.enqueueRetry(&intentRetryJob{intent: &CertenIntent{IntentID: "should-be-dropped"}})
		close(done)
	}()
	select {
	case <-done:
		// good: returned without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("enqueueRetry blocked on a full queue (should drop non-blocking)")
	}

	if n := len(id.retryCh); n != 1 {
		t.Errorf("queue should still hold exactly 1 item (the dropped one was not enqueued), got %d", n)
	}
}

// The default config must enable retry (non-zero attempts/backoff) so on_demand intents are
// never left without a retry path.
func TestDefaultConfig_RetryEnabled(t *testing.T) {
	c := DefaultIntentDiscoveryConfig()
	if c.ChainedProofInlineRetries < 1 {
		t.Errorf("ChainedProofInlineRetries must be >= 1, got %d", c.ChainedProofInlineRetries)
	}
	if c.ChainedProofRequeueAttempts < 1 {
		t.Errorf("ChainedProofRequeueAttempts must be >= 1, got %d", c.ChainedProofRequeueAttempts)
	}
	if c.ChainedProofInlineBackoff <= 0 || c.ChainedProofRequeueBackoff <= 0 {
		t.Error("retry backoffs must be positive")
	}
}
