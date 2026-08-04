package execution

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

// A gas-ceiling refusal must be recognised through wrapping — it arrives wrapped from
// evaluateGasPrice, so errors.Is on a sentinel would miss it.
func TestGasCeilingRecognisedThroughWrapping(t *testing.T) {
	inner := &ErrGasCeilingExceeded{ChainID: 11155111, SuggestedGwei: 150, CeilingGwei: 100}
	wrapped := fmt.Errorf("settling member: %w", fmt.Errorf("sending tx: %w", inner))

	var got *ErrGasCeilingExceeded
	if !errors.As(wrapped, &got) {
		t.Fatal("errors.As failed to see the gas refusal through wrapping — the member would be " +
			"permanently failed instead of deferred")
	}
	if got.CeilingGwei != 100 || got.SuggestedGwei != 150 {
		t.Fatalf("unexpected refusal detail: %+v", got)
	}
}

// An ordinary settle failure must NOT be mistaken for a gas refusal, or genuine failures would be
// retried forever instead of being reported.
func TestOrdinaryErrorIsNotTreatedAsGasRefusal(t *testing.T) {
	err := fmt.Errorf("member execution reverted on-chain (leaf still spendable)")
	var got *ErrGasCeilingExceeded
	if errors.As(err, &got) {
		t.Fatal("a revert was classified as a gas refusal")
	}
}

// The deferral is bounded: a member deferred longer than maxGasDeferral is failed rather than
// requeued forever.
func TestGasDeferralIsBounded(t *testing.T) {
	o := &BatchOrchestrator{}

	fresh := &PendingBatchIntent{EnqueuedAt: time.Now()}
	if o.memberPastDeadline(fresh) {
		t.Fatal("a freshly queued member was treated as expired")
	}

	stale := &PendingBatchIntent{EnqueuedAt: time.Now().Add(-maxGasDeferral - time.Minute)}
	if !o.memberPastDeadline(stale) {
		t.Fatal("a member past maxGasDeferral was not failed — it would retry forever")
	}

	// EnqueuedAt is stamped once and survives requeue, so the window must not restart on defer.
	if !o.memberPastDeadline(&PendingBatchIntent{EnqueuedAt: time.Now().Add(-2 * maxGasDeferral)}) {
		t.Fatal("deadline did not hold for a long-deferred member")
	}
}
