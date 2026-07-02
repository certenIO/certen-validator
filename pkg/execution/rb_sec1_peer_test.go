package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/accumulate"
	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
)

// RB-SEC-1: peer-side independent verification of the committed contract-call effect.
// These cover the trust-binding + fail-closed logic (the full VerifyExecutedCall path,
// which needs a live RPC, is covered by the adversarial-executor live test).

type mockQueryClient struct {
	blobs [][]byte
	err   error
}

func (m *mockQueryClient) GetTransactionGovernanceData(ctx context.Context, txHash, accountURL string) (*accumulate.TransactionGovernanceData, error) {
	return nil, nil
}
func (m *mockQueryClient) GetIntentBlobs(ctx context.Context, txHash, accountURL string) ([][]byte, error) {
	return m.blobs, m.err
}

func rbTopic0() common.Hash { return ethcrypto.Keccak256Hash([]byte("Pinged(bytes32,address,uint256)")) }

func intentBlob(id string) []byte {
	b, _ := json.Marshal(map[string]interface{}{"intent_id": id})
	return b
}
func ccdBlobCall(chain, contract string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"legs": []interface{}{map[string]interface{}{
			"chain": chain,
			"executionPayload": map[string]interface{}{
				"callData":       "0x33d425c4" + "11",
				"expectedEvents": []interface{}{map[string]interface{}{"contract": contract, "topic0": rbTopic0().Hex()}},
			},
		}},
	})
	return b
}
func ccdBlobNative(chain string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"legs": []interface{}{map[string]interface{}{
			"chain":            chain,
			"executionPayload": map[string]interface{}{"callData": "0x"},
		}},
	})
	return b
}

func orch(qc AccumulateQueryClient) *UnifiedOrchestrator {
	return &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{AccumulateQueryClient: qc, ValidatorID: "test"}}
}

func TestRBSec1_IntentIDBinding(t *testing.T) {
	if intentIDFromBlob(intentBlob("abc-123")) != "abc-123" {
		t.Fatal("intent_id extraction failed")
	}
}

func TestRBSec1_ParseCommittedCallLegs(t *testing.T) {
	legs := parseCommittedCallLegs(ccdBlobCall("ethereum-sepolia", "0xE3b7678231642e4de600C601Ff422654D17203f3"))
	if len(legs) != 1 || len(legs[0].events) != 1 || legs[0].chainKey != "ethereum-sepolia" {
		t.Fatalf("expected 1 call leg with 1 event, got %+v", legs)
	}
	if n := parseCommittedCallLegs(ccdBlobNative("ethereum-sepolia")); len(n) != 0 {
		t.Errorf("native leg must yield 0 call legs, got %d", len(n))
	}
}

// Fail-closed: no query client + contract calls enabled ⇒ refuse.
func TestRBSec1_NoQueryClientFailsClosed(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	o := orch(nil)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must fail closed when no query client and contract calls enabled")
	}
}

// Binding: fetched intent_id != attested intent_id ⇒ refuse (executor pointed elsewhere).
func TestRBSec1_IntentIDMismatchRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob("OTHER"), ccdBlobCall("ethereum-sepolia", "0xE3b7678231642e4de600C601Ff422654D17203f3")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "ATTESTED", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must refuse when fetched intent_id != attested intent_id")
	}
}

// Fetch error ⇒ refuse.
func TestRBSec1_FetchErrorRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{err: fmt.Errorf("boom")}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must refuse when the signed intent cannot be fetched")
	}
}

// No contract-call leg on this chain (native) ⇒ pass (nil), no observer needed.
func TestRBSec1_NativeIntentPasses(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob("x"), ccdBlobNative("ethereum-sepolia")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err != nil {
		t.Errorf("native intent must pass peer effect check, got %v", err)
	}
}

// H1: an empty IntentID must be refused — otherwise a non-JSON/benign blob makes
// intentIDFromBlob("")=="" satisfy the binding, letting a forged pointer through.
func TestRBSec1_EmptyIntentIDRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob(""), ccdBlobNative("ethereum-sepolia")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must refuse a contract-call attestation with an empty intent id")
	}
}

// H1: a native intent (no applicable call legs) with NO execution tx needs no observer and
// must pass even when no chain strategy is available — a genuinely native path.
func TestRBSec1_NativeNoExecTxNoObserverPasses(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob("x"), ccdBlobNative("ethereum-sepolia")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: ""}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err != nil {
		t.Errorf("native intent with no exec tx must pass without an observer, got %v", err)
	}
}

// H1: applicable==0 (executor claims "native") but an execution tx IS present, with no chain
// strategy to cross-check its calldata ⇒ fail closed rather than silently skip.
func TestRBSec1_NativeClaimWithExecTxNoObserverFailsClosed(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob("x"), ccdBlobNative("ethereum-sepolia")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must fail closed when an execution tx exists but calldata cannot be cross-checked")
	}
}

// Contract-call leg present but ExecutionTxHash missing ⇒ refuse.
func TestRBSec1_CallMissingExecTxRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: [][]byte{intentBlob("x"), ccdBlobCall("ethereum-sepolia", "0xE3b7678231642e4de600C601Ff422654D17203f3")}}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "ethereum-sepolia", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: ""}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil); err == nil {
		t.Error("must refuse a contract call with no execution tx hash")
	}
}
