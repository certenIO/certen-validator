package consensus

import (
	"errors"
	"strings"
	"testing"
)

// RB7 Task 5 T5-7: a leg that commits a storage slot (expectedState) is proven with eth_getProof at the finalized block.
// On a chain no provider of which serves that deep the intent is refused by name before anything is signed - a condition of
// CERTEN's deployment, retried, never held against the intent - instead of looping as "proven neither present nor absent".

func withExpectedState(chainIndex int) func(map[string]any, []map[string]any) {
	return func(_ map[string]any, legs []map[string]any) {
		p := legs[chainIndex]["executionPayload"].(map[string]any)
		p["expectedState"] = []map[string]any{{
			"account": "0x5FbDB2315678afecb367f032d93F642f64180aa3",
			"slot":    "0x0000000000000000000000000000000000000000000000000000000000000007",
			"value":   "0x000000000000000000000000000000000000000000000000000000000000002a",
		}}
	}
}

func TestAnExpectedStateLegOnAChainThatCannotProveItIsRefusedByNameAndRetried(t *testing.T) {
	f := newFakeEnqueuer()
	f.stateProofErr = map[int64]error{421614: errors.Join(ErrBatchUnavailable, errors.New("STATE_PROOF_WINDOW_UNAVAILABLE: no provider serves it"))}
	ci := declaring(t, []int64{421614}, withExpectedState(0))
	err := enqueue(refusalValidator(f), ci)
	var r *BatchRefusal
	if err == nil || !errors.As(err, &r) || r.Permanent || !errors.Is(err, ErrBatchUnavailable) ||
		!strings.Contains(err.Error(), "STATE_PROOF_WINDOW_UNAVAILABLE") {
		t.Fatalf("want a retryable refusal naming STATE_PROOF_WINDOW_UNAVAILABLE, got %v", err)
	}
	if len(f.queued) != 0 {
		t.Fatalf("a refused intent was queued: %v", f.queued)
	}
}

func TestAnIntentWithNoExpectedStateIsNeverAskedAboutStateProofs(t *testing.T) {
	f := newFakeEnqueuer()
	f.stateProofErr = map[int64]error{421614: errors.Join(ErrBatchUnavailable, errors.New("STATE_PROOF_WINDOW_UNAVAILABLE"))}
	if err := enqueue(refusalValidator(f), batchableIntent(t, "i1", 421614)); err != nil {
		t.Fatalf("an intent committing no slot was refused for a state-proof window: %v", err)
	}
}

func TestAnExpectedStateLegOnAChainThatCanProveItIsAdmitted(t *testing.T) {
	f := newFakeEnqueuer()
	ci := declaring(t, []int64{11155111}, withExpectedState(0))
	if err := enqueue(refusalValidator(f), ci); err != nil {
		t.Fatalf("a servable chain's expectedState leg was refused: %v", err)
	}
}
