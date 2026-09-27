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

// A cycle with NO contract-call commitment used to pass the gate untouched - a native transfer, or a
// cycle whose commitment simply omitted the flag, was attested on whatever transaction it named. Every
// member is now held to its signed intent (RB3-F77): without it the gate refuses.
func TestSec11_NoCommitmentData_IsStillBound(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "test"}}
	cycle := &activeCycle{
		CycleID: "c2",
		Request: &UnifiedProofCycleRequest{CycleID: "c2", IntentID: "x", TargetChain: "11155111", TxHashes: []string{"0xaa"},
			AccumulateTxHash: "h", AccumulateAccountURL: "a"},
	}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, nil); err == nil {
		t.Error("a cycle with no commitment data passed the gate unbound")
	}
}

// rbContractCall=false (a native leg) is bound like any other member.
func TestSec11_RBContractCallFalse_IsStillBound(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "test"}}
	cycle := &activeCycle{
		CycleID: "c3",
		Request: &UnifiedProofCycleRequest{
			CycleID: "c3", IntentID: "x", TargetChain: "11155111", TxHashes: []string{"0xaa"},
			AccumulateTxHash: "h", AccumulateAccountURL: "a",
			CommitmentData: map[string]interface{}{"rbContractCall": false},
		},
	}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, nil); err == nil {
		t.Error("a native member passed the gate unbound")
	}
}
