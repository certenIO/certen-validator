package execution

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Locks the commitment-map wire format the Phase-7 RB gate consumes: the consensus
// trigger writes rbExpectedEvents/rbExpectedState as []map[string]interface{}, and after
// a JSON roundtrip they arrive as []interface{} of map[string]interface{}. Both must
// reconstruct the same typed values.
func TestRBGate_ParseExpectedEvents(t *testing.T) {
	contract := "0xE3b7678231642e4de600C601Ff422654D17203f3"
	topic0 := crypto.Keccak256Hash([]byte("Pinged(bytes32,address,uint256)")).Hex()

	sameProcess := []map[string]interface{}{{"contract": contract, "topic0": topic0, "dataHash": ""}}
	jsonRoundtrip := []interface{}{map[string]interface{}{"contract": contract, "topic0": topic0}}

	for name, v := range map[string]interface{}{"same-process": sameProcess, "json-roundtrip": jsonRoundtrip} {
		got := parseRBExpectedEvents(v)
		if len(got) != 1 {
			t.Fatalf("%s: expected 1 event, got %d", name, len(got))
		}
		if got[0].Contract != common.HexToAddress(contract) {
			t.Errorf("%s: contract mismatch: %s", name, got[0].Contract.Hex())
		}
		if got[0].Topic0 != common.HexToHash(topic0) {
			t.Errorf("%s: topic0 mismatch: %s", name, got[0].Topic0.Hex())
		}
	}

	// Entries without a topic0 are skipped; nil input yields nil.
	if len(parseRBExpectedEvents([]interface{}{map[string]interface{}{"contract": contract}})) != 0 {
		t.Error("event without topic0 must be skipped")
	}
	if parseRBExpectedEvents(nil) != nil {
		t.Error("nil input must yield nil")
	}
}

func TestRBGate_ParseExpectedState(t *testing.T) {
	acct := "0x5FbDB2315678afecb367f032d93F642f64180aa3"
	slot := "0x0000000000000000000000000000000000000000000000000000000000000007"
	val := "0x000000000000000000000000000000000000000000000000000000000000002a"

	got := parseRBExpectedState([]interface{}{map[string]interface{}{"account": acct, "slot": slot, "value": val}})
	if len(got) != 1 {
		t.Fatalf("expected 1 slot, got %d", len(got))
	}
	if got[0].Account != common.HexToAddress(acct) || got[0].Slot != common.HexToHash(slot) || got[0].Value != common.HexToHash(val) {
		t.Errorf("state slot parse mismatch: %+v", got[0])
	}
}
