// Copyright 2026 Certen Protocol

package consensus

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// RB3-F98: nothing acts on a ValidatorBlock consensus has not committed. Admitted-but-not-committed used
// to proceed unless REQUIRE_BFT_COMMIT=true, which production did not set.

func TestAnUncommittedValidatorBlockIsARetryableRefusal(t *testing.T) {
	for name, res := range map[string]*BFTExecutionResult{
		"admitted, not committed": {Height: 0, TxHash: []byte{0xab}},
		"no result":               nil,
	} {
		err := requireCommitted(res)
		if !errors.Is(err, ErrValidatorBlockNotCommitted) {
			t.Errorf("%s: got %v, want the retryable not-committed refusal", name, err)
		}
		if errors.Is(err, ErrIntentPermanentlyInvalid) {
			t.Errorf("%s: a late commit was made permanent", name)
		}
	}
	if err := requireCommitted(&BFTExecutionResult{Height: 2187}); err != nil {
		t.Fatalf("a committed block was refused: %v", err)
	}
}

func TestTheWorkflowActsOnlyOnACommittedBlock(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	start := strings.Index(src, "func (bv *BFTValidator) executeCanonicalBFTWorkflow(")
	body := src[start : start+strings.Index(src[start:], "\n}\n")]
	if strings.Contains(body, "REQUIRE_BFT_COMMIT") {
		t.Error("the workflow still lets an environment variable decide whether an uncommitted block is acted on")
	}
	broadcast := strings.Index(body, "bv.engine.BroadcastValidatorBlockCommit(bftCtx, vb)")
	check := strings.Index(body, "requireCommitted(bftRes)")
	enqueue := strings.Index(body, "bv.enqueueForBatch(")
	if broadcast < 0 || check < 0 || enqueue < 0 || !(broadcast < check && check < enqueue) {
		t.Fatalf("broadcast at %d, commit check at %d, batch enqueue at %d: the check must sit between them", broadcast, check, enqueue)
	}
}
