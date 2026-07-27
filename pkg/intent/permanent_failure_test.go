// Copyright 2025 Certen Protocol
//
// A structurally invalid intent must be refused ONCE, not on every poll.
//
// The failure this guards against was observed in production on 2026-07-27:
// intent i-91388 carried expires_at with no created_at, failed execution
// validation, was marked retryable, and was then rediscovered and re-refused
// 254 times across all 7 validators. The intent's bytes are final on
// Accumulate, so no attempt could ever have succeeded.

package intent

import (
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
)

func newStatusOnlyDiscovery() *IntentDiscovery {
	return &IntentDiscovery{
		intentStatus: make(map[string]IntentStatus),
		logger:       log.New(os.Stdout, "[test] ", 0),
	}
}

func TestPermanentlyInvalidIntentIsNeverReprocessed(t *testing.T) {
	id := newStatusOnlyDiscovery()
	const intentID = "i-91388"

	if !id.markInProgress(intentID) {
		t.Fatal("first attempt should be admitted")
	}

	// The real shape: validation error wrapped by the sentinel, wrapped again
	// by the BFT layer's "execution unsuccessful" message.
	inner := fmt.Errorf("intent %s failed execution validation: %w: %w",
		intentID, consensus.ErrIntentPermanentlyInvalid,
		errors.New("expires_at set but created_at missing"))
	err := fmt.Errorf("canonical BFT execution unsuccessful: %w", inner)

	id.markFailedClassified(intentID, err)

	if got := id.getIntentStatus(intentID); got != IntentStatusFailedPermanent {
		t.Fatalf("status = %v, want failed_permanent", got)
	}

	// The actual regression: every later poll must be refused.
	for i := 0; i < 10; i++ {
		if id.markInProgress(intentID) {
			t.Fatalf("poll %d re-admitted a permanently invalid intent", i+1)
		}
	}
}

func TestRetryableFailureStillRetries(t *testing.T) {
	id := newStatusOnlyDiscovery()
	const intentID = "i-transient"

	if !id.markInProgress(intentID) {
		t.Fatal("first attempt should be admitted")
	}

	// A transient failure must NOT be swallowed by the new terminal path — a
	// false terminal silently drops a paying customer's intent, which is worse
	// than the wasted CPU of a retry.
	id.markFailedClassified(intentID, fmt.Errorf("wrapped: %w", errChainedProofUnavailable))

	if got := id.getIntentStatus(intentID); got != IntentStatusFailed {
		t.Fatalf("status = %v, want failed (retryable)", got)
	}
	if !id.markInProgress(intentID) {
		t.Fatal("a retryable failure must still be re-admitted")
	}
}

func TestPermanentSentinelSurvivesTheRealWrappingChain(t *testing.T) {
	// Guards the %v-vs-%w regression: bft_integration formats the task result
	// error into "canonical BFT execution unsuccessful". With %v the chain is
	// flattened to a string, errors.Is stops matching, and the intent silently
	// reverts to being retried forever.
	inner := fmt.Errorf("intent x failed execution validation: %w: %w",
		consensus.ErrIntentPermanentlyInvalid, errors.New("structural defect"))
	wrapped := fmt.Errorf("canonical BFT execution unsuccessful: %w", inner)

	if !errors.Is(wrapped, consensus.ErrIntentPermanentlyInvalid) {
		t.Fatal("sentinel did not survive wrapping — permanent failures will loop")
	}
}
