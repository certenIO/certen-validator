package ethrpc

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

// A real Ethereum Sepolia header captured 2026-10-06 after the chain began carrying blockAccessListHash (EIP-7928) and
// slotNumber (EIP-7843). A client whose Header type does not know those fields recomputes a wrong block hash, every
// provider "agrees" on it, and a read by that hash is answered "block not found": the validators refused to boot.
func TestASepoliaHeaderWithTheNewFieldsHashesToTheNodesHash(t *testing.T) {
	raw, err := os.ReadFile("testdata/sepolia_header_with_bal_hash_slot.json")
	if err != nil {
		t.Fatal(err)
	}
	var nodeSays struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(raw, &nodeSays); err != nil {
		t.Fatal(err)
	}
	var h types.Header
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if h.BlockAccessListHash == nil || h.SlotNumber == nil {
		t.Fatalf("header decoded without blockAccessListHash/slotNumber: go-ethereum does not know this chain's header")
	}
	if got := h.Hash().Hex(); got != nodeSays.Hash {
		t.Fatalf("recomputed block hash %s, the node says %s", got, nodeSays.Hash)
	}
}
