package execution

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/strategy"
)

// RB3-F45 on the executor side: a cycle that names no chain was observed on DefaultChainID, and the
// contract-call gate chose legs by free-text chain name - or by any leg whose execTx this cycle
// happened to hold - so another chain's call was checked against this chain's execution.

func TestAdapterRefusesACycleThatNamesNoChain(t *testing.T) {
	a := NewUnifiedOrchestratorAdapter(&UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{Registry: strategy.NewRegistry()}})
	err := a.StartProofCycleWithAccumulateRef(context.Background(), "i1", "", [32]byte{},
		[]string{"0x00000000000000000000000000000000000000000000000000000000000000aa"},
		map[string]interface{}{"intentId": "i1"}, "acc://x.acme/data", "tx", "")
	if err == nil || !strings.Contains(err.Error(), "no target chain") {
		t.Fatalf("a cycle with no chain must be refused by name, got %v", err)
	}
}

func TestOrchestratorRefusesACycleThatNamesNoChain(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{Registry: strategy.NewRegistry()}}
	_, err := o.StartProofCycle(context.Background(), &UnifiedProofCycleRequest{
		IntentID: "i1", CycleID: "c1", TxHashes: []string{"0xaa"}, ProofClass: "on_demand",
	})
	if err == nil || !strings.Contains(err.Error(), "no target chain") {
		t.Fatalf("got %v", err)
	}
}

// The gate checks the call legs whose signed chain is this cycle's, and only those.
func TestContractCallGateSelectsLegsBySignedChain(t *testing.T) {
	legs := []map[string]interface{}{
		{"chainKey": "base-sepolia", "chainId": int64(421614), "execTxHash": "", "expectedEvents": []map[string]interface{}{}},
		{"chainKey": "base-sepolia", "chainId": int64(84532), "execTxHash": "0xaa", "expectedEvents": []map[string]interface{}{}},
	}
	cycle := &activeCycle{Request: &UnifiedProofCycleRequest{
		TargetChain: "84532", TxHashes: []string{"0xaa"},
		CommitmentData: map[string]interface{}{"rbContractCall": true, "rbContractCallLegs": legs},
	}}
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "v"}}
	// Base's call leg committed no events, so selecting it is a named refusal; Arbitrum's must not
	// be selected at all. The error must be about the Base leg's chain, reached with no RPC call.
	_, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "84532", rpc: "http://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "committed no events") {
		t.Fatalf("the Base leg was not the one checked: %v", err)
	}

	// A cycle on Arbitrum whose commitment holds only Base's call selects nothing: a no-op.
	cycle.Request.TargetChain = "421614"
	cycle.Request.CommitmentData["rbContractCallLegs"] = legs[1:]
	if proofs, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "421614", rpc: "http://127.0.0.1:1"}); err != nil || len(proofs) != 0 {
		t.Fatalf("Base's call leg was checked against the Arbitrum cycle: proofs=%v err=%v", proofs, err)
	}

	// A leg with no signed chain cannot be placed - refused, not guessed.
	cycle.Request.CommitmentData["rbContractCallLegs"] = []map[string]interface{}{{"chainKey": "x", "expectedEvents": []map[string]interface{}{}}}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "421614", rpc: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("a call leg with no chain id was accepted")
	}
}
