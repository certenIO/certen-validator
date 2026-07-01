package execution

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/intent"
)

// RB-4: committed expected-event gate for contract calls.
//
// A contract call "succeeds" only if the event it committed to appears in the
// receipt logs — status==1 non-revert is necessary but not sufficient. These tests
// drive ExecutionCommitment.VerifyAgainstResult for both the typed field path and the
// ComprehensiveData map fallback, and check the producer→validator leg parsing.

var (
	rb4Target = common.HexToAddress("0x5FbDB2315678afecb367f032d93F642f64180aa3")
	rb4Topic0 = crypto.Keccak256Hash([]byte("Completed(bytes32)"))
	rb4Order  = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
)

// rb4Result builds an EVM result whose outer tx targets rb4Target with the given
// selector, optionally emitting the Completed(orderId) event.
func rb4Result(selector [4]byte, withEvent bool) *ExternalChainResult {
	to := rb4Target
	txData := make([]byte, 0, 36)
	txData = append(txData, selector[:]...)
	txData = append(txData, make([]byte, 32)...)
	r := &ExternalChainResult{
		Chain:   "ethereum",
		ChainID: 11155111,
		Status:  1,
		TxTo:    &to,
		TxData:  txData,
		TxValue: big.NewInt(0),
	}
	if withEvent {
		r.Logs = []LogEntry{{
			Address: rb4Target,
			Topics:  []common.Hash{rb4Topic0, rb4Order},
			Data:    nil,
		}}
	}
	return r
}

func rb4CallCommitment(events []ExpectedEvent) *ExecutionCommitment {
	sel := [4]byte{0x1a, 0x17, 0x72, 0x68} // forceResolve(bytes32)
	return &ExecutionCommitment{
		TargetContract:     rb4Target,
		FunctionSelector:   sel,
		ExpectedValue:      big.NewInt(0),
		IsContractCall:     true,
		ExpectedCallEvents: events,
	}
}

func TestRB4_CallWithCommittedEvent_Passes(t *testing.T) {
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: rb4Topic0}})
	if !c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("call with the committed event present must verify")
	}
}

func TestRB4_CallMissingEvent_Rejected(t *testing.T) {
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: rb4Topic0}})
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, false)) {
		t.Error("call whose committed event is MISSING must be rejected (non-revert is not enough)")
	}
}

func TestRB4_CallWrongTopic_Rejected(t *testing.T) {
	wrong := crypto.Keccak256Hash([]byte("SomethingElse(bytes32)"))
	c := rb4CallCommitment([]ExpectedEvent{{Contract: rb4Target, Topic0: wrong}})
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("call must be rejected when the emitted event's topic0 differs from the committed one")
	}
}

func TestRB4_CallWrongContract_Rejected(t *testing.T) {
	other := common.HexToAddress("0x00000000000000000000000000000000DeaDBeef")
	c := rb4CallCommitment([]ExpectedEvent{{Contract: other, Topic0: rb4Topic0}})
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("call must be rejected when the event is emitted by a different contract than committed")
	}
}

func TestRB4_CallWithNoCommittedEvents_Rejected(t *testing.T) {
	// A call that commits to no events at all cannot be attested — success would be
	// indistinguishable from a no-op non-revert.
	c := rb4CallCommitment(nil)
	if c.VerifyAgainstResult(rb4Result(c.FunctionSelector, true)) {
		t.Error("contract call with zero committed events must be refused")
	}
}

func TestRB4_DataHashBinding(t *testing.T) {
	// Commit to the non-indexed data hash as well; wrong data ⇒ reject.
	payload := []byte("resolved")
	c := rb4CallCommitment([]ExpectedEvent{{
		Contract: rb4Target,
		Topic0:   rb4Topic0,
		DataHash: [32]byte(crypto.Keccak256Hash(payload)),
	}})
	r := rb4Result(c.FunctionSelector, true)
	// Right topic0 but empty data ⇒ dataHash mismatch ⇒ reject.
	if c.VerifyAgainstResult(r) {
		t.Error("must reject when committed event dataHash does not match the log data")
	}
	// Now set the matching data on the log.
	r.Logs[0].Data = payload
	if !c.VerifyAgainstResult(r) {
		t.Error("must accept when the committed event dataHash matches the log data")
	}
}

// TestRB4_ComprehensiveDataFallback exercises the map-driven path (isContractCall +
// expectedEvents carried in ComprehensiveData rather than the typed fields).
func TestRB4_ComprehensiveDataFallback(t *testing.T) {
	sel := [4]byte{0x1a, 0x17, 0x72, 0x68}
	// topic0 without 0x so both the RB-4 gate and legacy verifyComprehensive agree.
	topicNoPrefix := rb4Topic0.Hex()[2:]
	mk := func() *ExecutionCommitment {
		return &ExecutionCommitment{
			TargetContract:   rb4Target,
			FunctionSelector: sel,
			ExpectedValue:    big.NewInt(0),
			ComprehensiveData: map[string]interface{}{
				"isContractCall": true,
				"expectedEvents": []interface{}{
					map[string]interface{}{"contract": rb4Target.Hex(), "topic0": topicNoPrefix},
				},
			},
		}
	}
	if !mk().VerifyAgainstResult(rb4Result(sel, true)) {
		t.Error("map-fallback: call with committed event present must verify")
	}
	if mk().VerifyAgainstResult(rb4Result(sel, false)) {
		t.Error("map-fallback: call with missing committed event must be rejected")
	}
}

// TestRB4_NativeTransferUnaffected: a native value transfer (not a contract call) is
// NOT subject to the event gate.
func TestRB4_NativeTransferUnaffected(t *testing.T) {
	to := rb4Target
	c := &ExecutionCommitment{
		TargetContract:   rb4Target,
		FunctionSelector: [4]byte{}, // native: no selector
		ExpectedValue:    big.NewInt(0),
		IsContractCall:   false,
	}
	// Native result: TxData is just the (zero) selector, no logs, no events required.
	r := &ExternalChainResult{
		Chain: "ethereum", ChainID: 11155111, Status: 1,
		TxTo: &to, TxData: make([]byte, 4), TxValue: big.NewInt(0),
	}
	if !c.VerifyAgainstResult(r) {
		t.Error("native transfer must not be blocked by the contract-call event gate")
	}
}

// TestRB4_LegParsesExpectedEvents asserts the validator parses the user-signed
// expectedEvents from the executionPayload onto the leg, and flags it as a call.
func TestRB4_LegParsesExpectedEvents(t *testing.T) {
	callData := "0x1a1772681111111111111111111111111111111111111111111111111111111111111111"
	leg := map[string]interface{}{
		"legId":     "leg-0",
		"from":      "0x1111111111111111111111111111111111111111",
		"to":        rb4Target.Hex(),
		"amountWei": "0",
		"chainId":   11155111,
		"chain":     "ethereum sepolia",
		"executionPayload": map[string]interface{}{
			"target":              rb4Target.Hex(),
			"value":               "0",
			"callData":            callData,
			"dataHash":            crypto.Keccak256Hash(common.FromHex(callData)).Hex(),
			"chainId":             11155111,
			"executionCommitment": common.HexToHash("0x00").Hex(), // no commitment gate for this parse test
			"expectedEvents": []interface{}{
				map[string]interface{}{"contract": rb4Target.Hex(), "topic0": rb4Topic0.Hex()},
			},
		},
	}
	blob := map[string]interface{}{"protocol": "CERTEN", "version": "2.0", "legs": []interface{}{leg}}
	// Remove executionCommitment so the CRITICAL-003 gate is skipped (empty string).
	leg["executionPayload"].(map[string]interface{})["executionCommitment"] = ""
	ccd, _ := json.Marshal(blob)

	t.Setenv("CERTEN_ALLOW_CONTRACT_CALLS", "true") // opt in to arbitrary calls for this test

	btce := NewBFTTargetChainExecutor(rb1Logger{})
	legs := btce.extractAllLegsFromIntent(&intent.CertenIntent{IntentID: "rb4", CrossChainData: ccd})
	if len(legs) != 1 {
		t.Fatalf("expected 1 leg, got %d", len(legs))
	}
	if !legs[0].IsContractCall() {
		t.Error("leg with non-empty calldata must be flagged as a contract call")
	}
	if len(legs[0].ExpectedEvents) != 1 {
		t.Fatalf("expected 1 parsed expected event, got %d", len(legs[0].ExpectedEvents))
	}
	if legs[0].ExpectedEvents[0].Topic0 != rb4Topic0 || legs[0].ExpectedEvents[0].Contract != rb4Target {
		t.Error("parsed expected event does not match the signed executionPayload")
	}
}
