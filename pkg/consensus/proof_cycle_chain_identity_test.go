package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// RB3-F45: the proof cycle took its chain from the intent's free-text leg name (commitment
// "targetChain" = legs[0].chain), and the executor's adapter guessed DefaultChainID when that was
// missing - so a member was observed on the chain its intent NAMED rather than the chain it settled on,
// and a recorded failure carried no chain at all. The chain a member settled on is known exactly: it
// is the chain its batch was flushed on.

type routeOrchestrator struct {
	method     string
	commitment map[string]interface{}
}

func (r *routeOrchestrator) keep(method string, c interface{}) {
	r.method = method
	r.commitment, _ = c.(map[string]interface{})
}
func (r *routeOrchestrator) StartProofCycle(_ context.Context, _ string, _ [32]byte, _ common.Hash, c interface{}) error {
	r.keep("StartProofCycle", c)
	return nil
}
func (r *routeOrchestrator) StartProofCycleWithAllTxs(_ context.Context, _ string, _ string, _ [32]byte, _ interface{}, c interface{}) error {
	r.keep("StartProofCycleWithAllTxs", c)
	return nil
}
func (r *routeOrchestrator) StartProofCycleWithAccumulateRef(_ context.Context, _ string, _ string, _ [32]byte, _ interface{}, c interface{}, _ string, _ string, _ string) error {
	r.keep("StartProofCycleWithAccumulateRef", c)
	return nil
}
func (r *routeOrchestrator) StartPerChainProofCycles(_ context.Context, _ string, _ string, _ [32]byte, _ map[string][]string, c interface{}, _ string, _ interface{}, _ string, _ string, _ string) error {
	r.keep("StartPerChainProofCycles", c)
	return nil
}

// memberIntent is a batchable intent whose legs NAME a chain other than the one they execute on - the
// name is free text the user wrote; the chainId is what CheckIntentTargetChains validated.
func memberIntent(t *testing.T, legs ...map[string]interface{}) *CertenIntent {
	t.Helper()
	ci := batchableIntent(t, "i1", 84532)
	env := map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": legs}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	ci.CrossChainData = b
	return ci
}

func leg(name string, id int64, callData string) map[string]interface{} {
	return map[string]interface{}{
		"legId": fmt.Sprintf("leg-%d", id), "chain": name, "chainId": id,
		"from": "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B",
		"executionPayload": map[string]interface{}{
			"target": "0x1111111111111111111111111111111111111111", "value": "0", "chainId": id, "callData": callData,
			"expectedEvents": []interface{}{map[string]interface{}{"contract": "0x1111111111111111111111111111111111111111", "topic0": "0x" + fmt.Sprintf("%064x", 1)}},
		},
	}
}

const settledTx = "0x00000000000000000000000000000000000000000000000000000000000000aa"

func TestProofCycle_ObservesTheChainTheMemberSettledOn(t *testing.T) {
	orch := &routeOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "i1", Replayed: true,
		CertenIntent: memberIntent(t, leg("ethereum-sepolia", 84532, "0x"))}

	bv.RunBatchMemberAttestation(context.Background(), att, settledTx, 84532, true)

	if orch.method != "StartProofCycleWithAccumulateRef" {
		t.Fatalf("member cycle routed to %s", orch.method)
	}
	if got := orch.commitment["targetChain"]; got != "84532" {
		t.Fatalf("Phase 7 target = %v, want the settled chain 84532 (the leg merely NAMES ethereum-sepolia)", got)
	}
}

// A recorded failure says which chain the member failed on.
func TestProofCycle_RecordedFailureNamesItsChain(t *testing.T) {
	orch := &routeOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "i1", Replayed: true,
		CertenIntent: memberIntent(t, leg("base-sepolia", 84532, "0x"))}

	bv.RunBatchMemberAttestation(context.Background(), att, "", 84532, false)

	if orch.commitment == nil || orch.commitment["outcome"] != "failed" {
		t.Fatalf("failure not recorded: %v", orch.commitment)
	}
	if got := orch.commitment["targetChain"]; got != "84532" {
		t.Fatalf("recorded failure carries chain %v, want 84532", got)
	}
}

// Every member is one chain's: a two-chain intent's member closes its own cycle, and its committed
// call legs say which chain each executes on - the member's transaction is the execution only for
// the legs on its own chain.
func TestProofCycle_MemberCallLegsCarryTheirSignedChain(t *testing.T) {
	orch := &routeOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "i1",
		CertenIntent: memberIntent(t, leg("base sepolia", 84532, "0x33d425c411"), leg("base sepolia", 421614, "0x33d425c422"))}

	bv.RunBatchMemberAttestation(context.Background(), att, settledTx, 84532, true)

	if orch.method != "StartProofCycleWithAccumulateRef" {
		t.Fatalf("a chain member was routed to %s", orch.method)
	}
	legs, _ := orch.commitment["rbContractCallLegs"].([]map[string]interface{})
	if len(legs) != 2 {
		t.Fatalf("call legs = %v", orch.commitment["rbContractCallLegs"])
	}
	for _, l := range legs {
		switch l["chainId"] {
		case int64(84532):
			if l["execTxHash"] != settledTx {
				t.Errorf("the member's own leg does not carry its transaction: %v", l["execTxHash"])
			}
		case int64(421614):
			if l["execTxHash"] != "" {
				t.Errorf("the other chain's leg was given this member's transaction %v", l["execTxHash"])
			}
		default:
			t.Errorf("call leg without its signed chain id: %v", l)
		}
	}
}

// RB3-F50: every cycle carries the intent's member set and the member's share of its legs, so the
// intent's status can be derived from all its members. A member carries every leg of the intent on
// its chain - they execute in its one transaction - and none of another chain's.
func TestProofCycle_CommitmentCarriesTheMemberSet(t *testing.T) {
	orch := &routeOrchestrator{}
	bv := failureTestValidator(orch)
	att := &PendingAttestation{IntentID: "i1", CertenIntent: memberIntent(t,
		leg("base", 84532, "0x"), leg("arb", 421614, "0x"), leg("base", 84532, "0x"))}

	bv.RunBatchMemberAttestation(context.Background(), att, settledTx, 84532, true)
	if chains, _ := orch.commitment["memberChains"].([]int64); len(chains) != 2 || chains[0] != 84532 || chains[1] != 421614 {
		t.Fatalf("member set = %v, want [84532 421614]", orch.commitment["memberChains"])
	}
	if legs := orch.commitment["memberLegs"]; legs != 2 {
		t.Fatalf("the Base member carries 2 legs, commitment says %v", legs)
	}

	// A failure record carries it too.
	bv.RunBatchMemberAttestation(context.Background(), att, "", 421614, false)
	if legs := orch.commitment["memberLegs"]; legs != 1 || orch.commitment["outcome"] != "failed" {
		t.Fatalf("failure record: %v", orch.commitment)
	}
}
