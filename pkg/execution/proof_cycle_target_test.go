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

// The gate holds the cycle to the signed intent's member on THIS cycle's chain, selected by each leg's
// signed chain id - never by the free-text chain name or the commitment the executor carries.
func TestContractCallGateSelectsLegsBySignedChain(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	// Base's call commits no event: selecting it is a named refusal, reached before any RPC call.
	// Arbitrum's leg is well-formed and must not be what is checked.
	blobs := signedBlobs(t, "x", f77CallLeg(421614, true), f77CallLeg(84532, false))
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "v", AccumulateQueryClient: &mockQueryClient{blobs: blobs}}}
	cycle := &activeCycle{Request: &UnifiedProofCycleRequest{
		IntentID: "x", TargetChain: "84532", TxHashes: []string{"0xaa"}, AccumulateTxHash: "h", AccumulateAccountURL: "a",
	}}
	_, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "84532", rpc: "http://127.0.0.1:1"})
	if err == nil || !strings.Contains(err.Error(), "commits no event") {
		t.Fatalf("the Base leg was not the one checked: %v", err)
	}

	// A cycle on a chain the signed intent has no leg on has no member: refused, not a no-op.
	o.config.AccumulateQueryClient = &mockQueryClient{blobs: signedBlobs(t, "x", f77CallLeg(84532, true))}
	cycle.Request.TargetChain = "421614"
	if _, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "421614", rpc: "http://127.0.0.1:1"}); err == nil ||
		!strings.Contains(err.Error(), "no legs on chain 421614") {
		t.Fatalf("Base's leg was held against the Arbitrum cycle: %v", err)
	}

	// A leg with no signed chain cannot be placed - refused, not guessed.
	noChain := f77CallLeg(0, true)
	o.config.AccumulateQueryClient = &mockQueryClient{blobs: signedBlobs(t, "x", noChain)}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "421614", rpc: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("a leg with no chain id was accepted")
	}
}
