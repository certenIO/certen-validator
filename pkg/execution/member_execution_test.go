// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
)

// RB3-F77: a member's settlement is bound to the member. These pin the parts that need no chain;
// member_execution_live_test.go proves the chain side on Base Sepolia.

const (
	f77Account = "0x184aeF98bEAcAF3E73Ca4a77c72e8F11E9B790A7"
	f77Target  = "0xE3b7678231642e4de600C601Ff422654D17203f3"
	f77Payee   = "0x32b4687bE3c02d52e2d94Dc1cFAF03a0E5af0C8B"
)

func f77CallLeg(chainID int64, events bool) map[string]interface{} {
	data := []byte{0x33, 0xd4, 0x25, 0xc4, 0x11}
	ec := consensus.ComputeExecutionCommitment(chainID, common.HexToAddress(f77Target), big.NewInt(0), data)
	ep := map[string]interface{}{"target": f77Target, "value": "0", "callData": "0x33d425c411",
		"dataHash": ethcrypto.Keccak256Hash(data).Hex(), "executionCommitment": common.Hash(ec).Hex()}
	if events {
		ep["expectedEvents"] = []interface{}{map[string]interface{}{"contract": f77Target, "topic0": rbTopic0().Hex()}}
	}
	return map[string]interface{}{"chain": "c", "chainId": chainID, "from": f77Account, "executionPayload": ep}
}

func f77NativeLeg(chainID int64, wei string) map[string]interface{} {
	return map[string]interface{}{"chain": "c", "chainId": chainID, "from": f77Account,
		"executionPayload": map[string]interface{}{"target": f77Payee, "value": wei, "callData": "0x"}}
}

// signedBlobs is a user-signed intent as the four blobs Accumulate holds.
func signedBlobs(t *testing.T, id string, legs ...map[string]interface{}) [][]byte {
	t.Helper()
	ls := make([]interface{}, len(legs))
	for i, l := range legs {
		ls[i] = l
	}
	ccd, err := json.Marshal(map[string]interface{}{"legs": ls})
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{intentBlob(id), ccd, []byte(`{"authority":"acc://a.acme/book"}`), []byte(`{"nonce":"1"}`)}
}

func TestMemberLegsAreTheSignedMemberOnTheChain(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	blobs := signedBlobs(t, "x", f77NativeLeg(84532, "1000"), f77CallLeg(421614, true), f77CallLeg(84532, true))
	legs, account, opID, err := memberLegsFromSignedIntent(blobs, 84532)
	if err != nil {
		t.Fatal(err)
	}
	if account != common.HexToAddress(f77Account) || opID == ([32]byte{}) {
		t.Fatalf("account %s opID %x", account.Hex(), opID)
	}
	// Base's two legs, in signed order: the native transfer first, then the call; Arbitrum's is not here.
	if len(legs) != 2 || legs[0].Call.Target != common.HexToAddress(f77Payee) || legs[0].Call.Value.Cmp(big.NewInt(1000)) != 0 ||
		len(legs[0].Call.Data) != 0 || len(legs[0].Events) != 0 ||
		legs[1].Call.Target != common.HexToAddress(f77Target) || len(legs[1].Call.Data) == 0 || len(legs[1].Events) != 1 {
		t.Fatalf("legs %+v", legs)
	}
	if _, _, _, err := memberLegsFromSignedIntent(blobs, 1); err == nil {
		t.Fatal("a chain the intent does not touch has no member")
	}
	if _, _, _, err := memberLegsFromSignedIntent(blobs[:2], 84532); err == nil {
		t.Fatal("an incomplete signed intent has no operationID and cannot bind a settlement")
	}
	if _, _, _, err := memberLegsFromSignedIntent(signedBlobs(t, "x", f77CallLeg(84532, false)), 84532); err == nil ||
		!strings.Contains(err.Error(), "commits no event") {
		t.Fatalf("a contract call committing no event: %v", err)
	}
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "false")
	if _, _, _, err := memberLegsFromSignedIntent(blobs, 84532); err == nil {
		t.Fatal("a contract call in a deployment that executes none")
	}
	if legs, _, _, err := memberLegsFromSignedIntent(signedBlobs(t, "x", f77NativeLeg(84532, "5")), 84532); err != nil || len(legs) != 1 {
		t.Fatalf("a native member is a member in any deployment: %v", err)
	}
}

func TestSettlementMustExecuteExactlyTheCommittedCalls(t *testing.T) {
	a := CommittedCall{Target: common.HexToAddress(f77Target), Value: big.NewInt(0), Data: []byte{1}}
	b := CommittedCall{Target: common.HexToAddress(f77Payee), Value: big.NewInt(7)}
	if err := matchCommittedCalls([]CommittedCall{a, b}, []CommittedCall{a, b}); err != nil {
		t.Fatal(err)
	}
	unset := a
	unset.Value = nil
	if err := matchCommittedCalls([]CommittedCall{a}, []CommittedCall{unset}); err != nil {
		t.Fatalf("an uncommitted value is zero: %v", err)
	}
	other := b
	other.Value = big.NewInt(8)
	for name, c := range map[string][2][]CommittedCall{
		"an extra executed call": {{a, b}, {a}},
		"a missing call":         {{a}, {a, b}},
		"reordered":              {{b, a}, {a, b}},
		"one call counted twice": {{a, b}, {a, a}},
		"another value":          {{a, other}, {a, b}},
		"a value where zero was": {{b}, {{Target: b.Target}}},
	} {
		if err := matchCommittedCalls(c[0], c[1]); err == nil {
			t.Fatalf("%s matched", name)
		}
	}
}

func TestAnAttestationNamesOneSettlement(t *testing.T) {
	if tx, err := attestedSettlementTx(&attestation.AttestationMessage{AnchorTxHash: "0xAB", ExecutionTxHash: "ab"}); err != nil || tx != "0xAB" {
		t.Fatalf("the same transaction: %q %v", tx, err)
	}
	if _, err := attestedSettlementTx(&attestation.AttestationMessage{AnchorTxHash: "0xab", ExecutionTxHash: "0xcd"}); err == nil {
		t.Fatal("a result re-observed on one transaction and a binding proven on another")
	}
	if _, err := attestedSettlementTx(&attestation.AttestationMessage{ExecutionTxHash: "0xcd"}); err == nil {
		t.Fatal("no re-observed settlement")
	}
}

// The gate holds every member to its signed intent: a cycle it cannot read the signed intent for is
// refused, native or not. (It used to pass a cycle with no contract-call commitment untouched.)
func TestSettlementGateRefusesAMemberItCannotBind(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "v"}}
	for name, cm := range map[string]map[string]interface{}{
		"no commitment":            nil,
		"a native leg":             {"rbContractCall": false},
		"a contract call asserted": {"rbContractCall": true},
	} {
		cycle := &activeCycle{Request: &UnifiedProofCycleRequest{IntentID: "x", TargetChain: "84532", TxHashes: []string{"0xaa"},
			AccumulateTxHash: "h", AccumulateAccountURL: "a", CommitmentData: cm}}
		if _, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "84532"}); err == nil ||
			!strings.Contains(err.Error(), "signed intent") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// With the signed intent readable, the member must still have a leg on this chain.
	o.config.AccumulateQueryClient = &mockQueryClient{blobs: signedBlobs(t, "x", f77NativeLeg(421614, "1"))}
	cycle := &activeCycle{Request: &UnifiedProofCycleRequest{IntentID: "x", TargetChain: "84532", TxHashes: []string{"0xaa"},
		AccumulateTxHash: "h", AccumulateAccountURL: "a"}}
	if _, err := o.verifyContractCallGate(context.Background(), cycle, observedChain{id: "84532"}); err == nil ||
		!strings.Contains(err.Error(), "no legs on chain 84532") {
		t.Fatalf("a cycle on a chain the intent does not touch: %v", err)
	}
}

// Phase 8 attests the settlement the gate proved, and refuses a settlement cycle with none.
func TestPhase8RefusesASettlementTheGateDidNotProve(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{ValidatorID: "v"}}
	cycle := &activeCycle{
		CycleID: "c1",
		Request: &UnifiedProofCycleRequest{IntentID: "i1", TxHashes: []string{"0xabc"}, TargetChain: "11155111"},
		Result:  &UnifiedProofCycleResult{ChainID: "11155111", ObservationResults: []*chain.ObservationResult{{TxHash: "0xabc", ResultHash: [32]byte{1}}}},
	}
	if err := o.executePhase8(context.Background(), cycle, nil); err == nil || !strings.Contains(err.Error(), "proved no settlement") {
		t.Fatalf("phase 8 without a gate-proven settlement: %v", err)
	}
	if provenSettlementObservation(cycle.Result.ObservationResults, "0xABC") == nil ||
		provenSettlementObservation(cycle.Result.ObservationResults, "0xdef") != nil {
		t.Fatal("the proven settlement's observation is found by its hash, and only by it")
	}
}
