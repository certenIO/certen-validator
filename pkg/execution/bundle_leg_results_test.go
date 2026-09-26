package execution

import (
	"testing"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// RB3-F51: a chain member's write-back listed EVERY leg of its intent, giving the legs on other
// chains this member's transaction hash, block and status - a record claiming another chain's leg
// executed, in a transaction from a different chain, before that chain's member had settled.

func TestBundleListsOnlyTheLegsThisMemberExecuted(t *testing.T) {
	const baseTx = "0x00000000000000000000000000000000000000000000000000000000000000aa"
	cycle := &activeCycle{
		Request: &UnifiedProofCycleRequest{
			IntentID:    "i1",
			TargetChain: "84532",
			CommitmentData: map[string]interface{}{
				"legCount": 2,
				"legs": []map[string]interface{}{
					{"legIndex": 0, "legId": "leg-0", "chain": "base", "chainId": int64(84532), "network": "sepolia"},
					{"legIndex": 1, "legId": "leg-1", "chain": "arbitrum", "chainId": int64(421614), "network": "sepolia"},
				},
			},
		},
		Result: &UnifiedProofCycleResult{
			ChainID: "84532",
			ObservationResults: []*chain.ObservationResult{{
				TxHash: baseTx, BlockNumber: 900, BlockHash: "0xbb", Status: 1, GasUsed: 21000, IsFinalized: true,
			}},
		},
	}
	bundle := &AttestationBundle{}
	(&UnifiedOrchestrator{}).enrichBundleWithLegData(bundle, cycle)

	if len(bundle.LegResults) != 1 {
		t.Fatalf("the Base member recorded %d leg results, want only its own chain's 1: %+v", len(bundle.LegResults), bundle.LegResults)
	}
	lr := bundle.LegResults[0]
	if lr.ChainID != 84532 || lr.LegID != "leg-0" || lr.TxHash != baseTx || lr.Status != 1 || lr.BlockNumber != 900 {
		t.Fatalf("own leg misrecorded: %+v", lr)
	}
}
