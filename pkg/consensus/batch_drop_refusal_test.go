package consensus

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// capturingOrchestrator keeps the commitment of the last proof cycle it was asked to start.
type capturingOrchestrator struct{ commitment map[string]interface{} }

func (c *capturingOrchestrator) keep(commitment interface{}) {
	if m, ok := commitment.(map[string]interface{}); ok {
		c.commitment = m
	}
}
func (c *capturingOrchestrator) StartProofCycle(_ context.Context, _ string, _ [32]byte, _ common.Hash, commitment interface{}) error {
	c.keep(commitment)
	return nil
}
func (c *capturingOrchestrator) StartProofCycleWithAllTxs(_ context.Context, _ string, _ string, _ [32]byte, _ interface{}, commitment interface{}) error {
	c.keep(commitment)
	return nil
}
func (c *capturingOrchestrator) StartProofCycleWithAccumulateRef(_ context.Context, _ string, _ string, _ [32]byte, _ interface{}, commitment interface{}, _ string, _ string, _ string) error {
	c.keep(commitment)
	return nil
}
func (c *capturingOrchestrator) StartPerChainProofCycles(_ context.Context, _ string, _ string, _ [32]byte, _ map[string][]string, commitment interface{}, _ string, _ interface{}, _ string, _ string, _ string) error {
	c.keep(commitment)
	return nil
}

// RB3-F37: a member dropped from its batch is recorded as FAILED with the cause it was dropped
// for - not with a fixed text that blamed every drop on quorum, and not "reverted" when nothing
// was ever sent.
func TestDroppedMemberIsRecordedFailedWithItsOwnCause(t *testing.T) {
	orch := &capturingOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "x", CertenIntent: liveFailedIntent(t)}
	cause := "its batch anchor 0x1234 on chain 84532 was created but rejects the member leaves: leaf 0 not found"

	bv.RunBatchMemberRefusal(context.Background(), att, 84532, cause, "on_cadence")

	if att.TargetChainOutcome != TargetChainFailed {
		t.Fatalf("outcome = %q, want failed", att.TargetChainOutcome)
	}
	if orch.commitment == nil {
		t.Fatal("the failure was not recorded at all")
	}
	if orch.commitment["outcome"] != "failed" {
		t.Fatalf("recorded outcome = %v", orch.commitment["outcome"])
	}
	reason := fmt.Sprint(orch.commitment["reason"])
	if !strings.Contains(reason, cause) {
		t.Fatalf("recorded reason %q does not carry the cause %q", reason, cause)
	}
	if strings.Contains(reason, "reverted") {
		t.Fatalf("a dropped member never reached the chain, yet the reason says it reverted: %q", reason)
	}
}

// A dropped member with no known cause is still recorded, and says the cause was not recorded -
// rather than inventing one.
func TestDroppedMemberWithoutACauseSaysSo(t *testing.T) {
	orch := &capturingOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "x", CertenIntent: liveFailedIntent(t)}

	bv.RunBatchMemberRefusal(context.Background(), att, 84532, "", "on_cadence")

	reason := fmt.Sprint(orch.commitment["reason"])
	if !strings.Contains(reason, "cause not recorded") {
		t.Fatalf("a drop with no cause must say so, got %q", reason)
	}
}

// A failure with no settlement transaction states only what is known. It used to say "execution
// reverted on the target chain", which is false whenever nothing reached the chain.
func TestFailureWithoutATransactionDoesNotClaimARevert(t *testing.T) {
	orch := &capturingOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "x", CertenIntent: liveFailedIntent(t)}

	bv.RunBatchMemberAttestation(context.Background(), att, "", 84532, false, "on_cadence")

	reason := fmt.Sprint(orch.commitment["reason"])
	if strings.Contains(reason, "reverted") {
		t.Fatalf("no transaction reached the chain, yet the reason says it reverted: %q", reason)
	}
	if !strings.Contains(reason, "no settlement transaction reached the target chain") {
		t.Fatalf("reason = %q", reason)
	}
}
