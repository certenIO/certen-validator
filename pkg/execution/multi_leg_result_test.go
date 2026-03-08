package execution

import (
	"testing"
)

// TestComputeMultiLegResultHash_Deterministic verifies that the same legs
// produce the same hash regardless of input order.
func TestComputeMultiLegResultHash_Deterministic(t *testing.T) {
	legs := []LegResult{
		{LegIndex: 2, Chain: "base-sepolia", ChainID: 84532, TxHash: "0xabc2", Status: 1},
		{LegIndex: 0, Chain: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xabc0", Status: 1},
		{LegIndex: 1, Chain: "aptos-testnet", ChainID: 2, TxHash: "0xabc1", Status: 1},
		{LegIndex: 3, Chain: "solana-devnet", ChainID: 0, TxHash: "tx_sol_123", Status: 1},
	}

	hash1 := ComputeMultiLegResultHash(legs)

	// Reverse the input order
	reversed := []LegResult{
		{LegIndex: 3, Chain: "solana-devnet", ChainID: 0, TxHash: "tx_sol_123", Status: 1},
		{LegIndex: 1, Chain: "aptos-testnet", ChainID: 2, TxHash: "0xabc1", Status: 1},
		{LegIndex: 0, Chain: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xabc0", Status: 1},
		{LegIndex: 2, Chain: "base-sepolia", ChainID: 84532, TxHash: "0xabc2", Status: 1},
	}

	hash2 := ComputeMultiLegResultHash(reversed)

	if hash1 != hash2 {
		t.Errorf("Hash not deterministic: %x != %x", hash1, hash2)
	}

	// Verify non-zero
	if hash1 == [32]byte{} {
		t.Error("Hash should not be zero for non-empty legs")
	}
}

// TestComputeMultiLegResultHash_Empty returns zero hash for empty input.
func TestComputeMultiLegResultHash_Empty(t *testing.T) {
	hash := ComputeMultiLegResultHash(nil)
	if hash != [32]byte{} {
		t.Errorf("Expected zero hash for nil input, got %x", hash)
	}

	hash2 := ComputeMultiLegResultHash([]LegResult{})
	if hash2 != [32]byte{} {
		t.Errorf("Expected zero hash for empty input, got %x", hash2)
	}
}

// TestComputeMultiLegResultHash_DifferentLegs_DifferentHash verifies that
// different leg data produces different hashes.
func TestComputeMultiLegResultHash_DifferentLegs_DifferentHash(t *testing.T) {
	legs1 := []LegResult{
		{LegIndex: 0, Chain: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xaaa", Status: 1},
	}

	legs2 := []LegResult{
		{LegIndex: 0, Chain: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xbbb", Status: 1},
	}

	hash1 := ComputeMultiLegResultHash(legs1)
	hash2 := ComputeMultiLegResultHash(legs2)

	if hash1 == hash2 {
		t.Error("Different legs should produce different hashes")
	}
}

// TestLegResult_FieldAccess verifies LegResult struct fields are accessible.
func TestLegResult_FieldAccess(t *testing.T) {
	lr := LegResult{
		LegIndex:      0,
		LegID:         "leg-0",
		Chain:         "ethereum-sepolia",
		ChainID:       11155111,
		TxHash:        "0xdeadbeef",
		BlockNumber:   12345,
		BlockHash:     "0xblockhash",
		Status:        1,
		GasUsed:       21000,
		TxFrom:        "0xsender",
		EventCount:    3,
		IsFinalized:   true,
		Confirmations: 12,
	}

	if lr.LegIndex != 0 {
		t.Errorf("Expected LegIndex 0, got %d", lr.LegIndex)
	}
	if lr.Chain != "ethereum-sepolia" {
		t.Errorf("Expected chain ethereum-sepolia, got %s", lr.Chain)
	}
	if lr.Status != 1 {
		t.Errorf("Expected status 1, got %d", lr.Status)
	}
}
