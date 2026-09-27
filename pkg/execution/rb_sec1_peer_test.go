package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

func rbTopic0() common.Hash {
	return ethcrypto.Keccak256Hash([]byte("Pinged(bytes32,address,uint256)"))
}

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
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, nil, false); err == nil {
		t.Error("must fail closed when no query client and contract calls enabled")
	}
}

// Binding: fetched intent_id != attested intent_id ⇒ refuse (executor pointed elsewhere).
func TestRBSec1_IntentIDMismatchRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: signedBlobs(t, "OTHER", f77CallLeg(84532, true))}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "ATTESTED", TargetChain: "84532", AccumulateTxHash: "h", AccumulateAccountURL: "a", AnchorTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "84532"}, false); err == nil ||
		!strings.Contains(err.Error(), "fetched intent_id") {
		t.Errorf("must refuse when fetched intent_id != attested intent_id: %v", err)
	}
}

// Fetch error ⇒ refuse.
func TestRBSec1_FetchErrorRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{err: fmt.Errorf("boom")}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "84532", AccumulateTxHash: "h", AccumulateAccountURL: "a", AnchorTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "84532"}, false); err == nil ||
		!strings.Contains(err.Error(), "fetch signed intent") {
		t.Errorf("must refuse when the signed intent cannot be fetched: %v", err)
	}
}

// A native member used to pass the peer check whenever the transaction it named carried no inner
// calldata - any such transaction, the member's or not. It is bound like any other member (RB3-F77): a
// transaction that is not the member's account execution is refused, calldata or none.
func TestRBSec1_NativeMemberIsBound(t *testing.T) {
	for _, data := range [][]byte{nil, {0xde, 0xad, 0xbe, 0xef}} {
		rpcURL, txHash := txRPC(t, 11155111, data)
		o := orch(&mockQueryClient{blobs: signedBlobs(t, "x", f77NativeLeg(11155111, "1000"))})
		msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "11155111", AnchorTxHash: txHash.Hex(), AccumulateTxHash: "h", AccumulateAccountURL: "a"}
		if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "11155111", rpc: rpcURL}, false); err == nil {
			t.Errorf("a transaction that is not the member's settlement passed as its native transfer (calldata %x)", data)
		}
	}
}

// H1: an empty IntentID must be refused — otherwise a non-JSON/benign blob makes
// intentIDFromBlob("")=="" satisfy the binding, letting a forged pointer through.
func TestRBSec1_EmptyIntentIDRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: signedBlobs(t, "", f77NativeLeg(84532, "1"))}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "", TargetChain: "84532", AccumulateTxHash: "h", AccumulateAccountURL: "a", AnchorTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "84532"}, false); err == nil ||
		!strings.Contains(err.Error(), "no intent id") {
		t.Errorf("must refuse an attestation with an empty intent id: %v", err)
	}
}

// A native member with no RPC to prove its settlement on ⇒ fail closed rather than skip.
func TestRBSec1_NativeClaimWithExecTxNoObserverFailsClosed(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: signedBlobs(t, "x", f77NativeLeg(11155111, "1"))}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "11155111", AnchorTxHash: "0xabc", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: "0xabc"}
	if err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "11155111"}, false); err == nil {
		t.Error("must fail closed when an execution tx exists but calldata cannot be cross-checked")
	}
}

// A committed call on the observed chain with no execution to verify at all ⇒ refuse.
func TestRBSec1_CallMissingExecTxRefused(t *testing.T) {
	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true")
	qc := &mockQueryClient{blobs: signedBlobs(t, "x", f77CallLeg(84532, true))}
	o := orch(qc)
	msg := &attestation.AttestationMessage{IntentID: "x", TargetChain: "84532", AccumulateTxHash: "h", AccumulateAccountURL: "a", ExecutionTxHash: ""}
	err := o.peerVerifyCommittedEffect(context.Background(), msg, observedChain{id: "84532"}, false)
	if err == nil || !strings.Contains(err.Error(), "no settlement transaction named") {
		t.Errorf("must refuse a contract call with no execution to verify, got %v", err)
	}
}
