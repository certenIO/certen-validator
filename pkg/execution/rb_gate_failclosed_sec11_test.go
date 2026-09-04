package execution

import (
	"context"
	"testing"
)

// SEC-11: when a cycle is flagged rbContractCall=true but the committed leg descriptors are
// missing/malformed (parse to zero), the gate must FAIL CLOSED — never no-op. A nil/garbage
// rbContractCallLegs must not be able to neuter the effect gate for a contract-call cycle.
func TestSec11_RBContractCallWithNoLegs_FailsClosed(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "test"}}
	cycle := &activeCycle{
		CycleID: "c1",
		Request: &UnifiedProofCycleRequest{
			CycleID:     "c1",
			TargetChain: "ethereum-sepolia",
			CommitmentData: map[string]interface{}{
				"rbContractCall":     true,
				"rbContractCallLegs": nil, // asserted a call, but no parseable legs
			},
		},
	}
	// chainStrategy is nil, but the fail-closed check returns before any RPC access.
	if _, err := o.verifyContractCallGate(context.Background(), cycle, nil); err == nil {
		t.Error("rbContractCall=true with zero parseable legs must fail closed, not no-op")
	}
}

// A cycle with NO commitment data (native transfer / batch anchoring) legitimately no-ops.
func TestSec11_NoCommitmentData_NoOp(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "test"}}
	cycle := &activeCycle{
		CycleID: "c2",
		Request: &UnifiedProofCycleRequest{CycleID: "c2", TargetChain: "ethereum-sepolia"},
	}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, nil); err != nil {
		t.Errorf("no commitment data must be a no-op (native/anchoring), got %v", err)
	}
}

// rbContractCall=false (native leg) with commitment data present is a no-op.
func TestSec11_RBContractCallFalse_NoOp(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "test"}}
	cycle := &activeCycle{
		CycleID: "c3",
		Request: &UnifiedProofCycleRequest{
			CycleID:        "c3",
			TargetChain:    "ethereum-sepolia",
			CommitmentData: map[string]interface{}{"rbContractCall": false},
		},
	}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, nil); err != nil {
		t.Errorf("rbContractCall=false must be a no-op, got %v", err)
	}
}
