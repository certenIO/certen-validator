package execution

import (
	"strings"
	"testing"
)

// TestToDoubleHashFormat_SingleLeg_BackwardCompatible verifies that single-leg intents
// produce exactly 51 entries, unchanged from the v2.0 format.
func TestToDoubleHashFormat_SingleLeg_BackwardCompatible(t *testing.T) {
	entry := CertenDataEntry{
		EntryType: "certen:proof_result:v2",
		Version:   "2.0",
		ChainName: "ethereum",
		ChainID:   11155111,
		TxHash:    "0xdeadbeef",
		Success:   true,
		GasUsed:   21000,
		LegCount:  0, // Single leg (or unset)
	}

	entries := entry.ToDoubleHashFormat()

	// 51 base + 8 appended SEC-14 verifiable-aggregate entries.
	if len(entries) != 59 {
		t.Errorf("Expected 59 entries for single-leg, got %d", len(entries))
	}

	// Verify version is 2.0
	versionEntry := string(entries[1])
	if !strings.Contains(versionEntry, "version=2.0") {
		t.Errorf("Expected version=2.0 for single-leg, got %s", versionEntry)
	}

	// Verify schema_version is 2.0
	schemaEntry := string(entries[47])
	if !strings.Contains(schemaEntry, "schema_version=2.0") {
		t.Errorf("Expected schema_version=2.0, got %s", schemaEntry)
	}
}

// TestToDoubleHashFormat_MultiLeg_4Legs verifies that a 4-leg intent produces
// the correct number of entries with proper key names and values.
func TestToDoubleHashFormat_MultiLeg_4Legs(t *testing.T) {
	entry := CertenDataEntry{
		EntryType:          "certen:proof_result:v2",
		Version:            "2.0",
		ChainName:          "ethereum",
		ChainID:            11155111,
		TxHash:             "0xprimary",
		Success:            true,
		GasUsed:            21000,
		LegCount:           4,
		MultiLegResultHash: "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567",
		LegProofs: []LegProofEntry{
			{LegIndex: 0, ChainName: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xtx0", BlockNumber: 100, BlockHash: "0xbh0", Success: true, GasUsed: 21000, EventsHash: "0xeh0", EventCount: 2},
			{LegIndex: 1, ChainName: "base-sepolia", ChainID: 84532, TxHash: "0xtx1", BlockNumber: 200, BlockHash: "0xbh1", Success: true, GasUsed: 30000, EventsHash: "0xeh1", EventCount: 1},
			{LegIndex: 2, ChainName: "aptos-testnet", ChainID: 2, TxHash: "0xtx2", BlockNumber: 300, BlockHash: "0xbh2", Success: true, GasUsed: 500, EventsHash: "0xeh2", EventCount: 3},
			{LegIndex: 3, ChainName: "solana-devnet", ChainID: 0, TxHash: "tx_sol_3", BlockNumber: 400, BlockHash: "bh_sol_3", Success: true, GasUsed: 5000, EventsHash: "0xeh3", EventCount: 1},
		},
	}

	entries := entry.ToDoubleHashFormat()

	// 51 base + 2 (leg_count, multi_leg_result_hash) + 4*9 (per-leg entries) + 8 (SEC-14 aggregate)
	expectedCount := 51 + 2 + 4*9 + 8
	if len(entries) != expectedCount {
		t.Errorf("Expected %d entries for 4-leg intent, got %d", expectedCount, len(entries))
	}

	// Verify leg_count entry (index 51)
	legCountEntry := string(entries[51])
	if legCountEntry != "leg_count=4" {
		t.Errorf("Expected leg_count=4, got %s", legCountEntry)
	}

	// Verify multi_leg_result_hash entry (index 52)
	hashEntry := string(entries[52])
	if !strings.HasPrefix(hashEntry, "multi_leg_result_hash=") {
		t.Errorf("Expected multi_leg_result_hash= prefix, got %s", hashEntry)
	}

	// Verify leg_0 entries start at index 53
	leg0ChainName := string(entries[53])
	if leg0ChainName != "leg_0_chain_name=ethereum-sepolia" {
		t.Errorf("Expected leg_0_chain_name=ethereum-sepolia, got %s", leg0ChainName)
	}

	// Verify leg_1 entries start at index 62 (53 + 9)
	leg1ChainName := string(entries[62])
	if leg1ChainName != "leg_1_chain_name=base-sepolia" {
		t.Errorf("Expected leg_1_chain_name=base-sepolia, got %s", leg1ChainName)
	}

	// Verify leg_3 tx_hash (solana uses non-hex format)
	// leg_3 starts at 53 + 3*9 = 80, tx_hash is offset 2
	leg3TxHash := string(entries[82])
	if leg3TxHash != "leg_3_tx_hash=tx_sol_3" {
		t.Errorf("Expected leg_3_tx_hash=tx_sol_3, got %s", leg3TxHash)
	}
}

// TestToDoubleHashFormat_MultiLeg_VersionBump verifies that multi-leg entries
// use version "2.1" and schema_version "2.1".
func TestToDoubleHashFormat_MultiLeg_VersionBump(t *testing.T) {
	entry := CertenDataEntry{
		EntryType: "certen:proof_result:v2",
		Version:   "2.0",
		LegCount:  2,
		LegProofs: []LegProofEntry{
			{LegIndex: 0, ChainName: "ethereum-sepolia", ChainID: 11155111, TxHash: "0xtx0"},
			{LegIndex: 1, ChainName: "base-sepolia", ChainID: 84532, TxHash: "0xtx1"},
		},
	}

	entries := entry.ToDoubleHashFormat()

	// Verify version is 2.1
	versionEntry := string(entries[1])
	if !strings.Contains(versionEntry, "version=2.1") {
		t.Errorf("Expected version=2.1 for multi-leg, got %s", versionEntry)
	}

	// Verify schema_version is 2.1
	schemaEntry := string(entries[47])
	if !strings.Contains(schemaEntry, "schema_version=2.1") {
		t.Errorf("Expected schema_version=2.1 for multi-leg, got %s", schemaEntry)
	}
}

// TestToDoubleHashFormat_SingleLeg_NoMultiLegEntries verifies that single-leg intents
// don't include any multi-leg entries.
func TestToDoubleHashFormat_SingleLeg_NoMultiLegEntries(t *testing.T) {
	entry := CertenDataEntry{
		EntryType: "certen:proof_result:v2",
		Version:   "2.0",
		LegCount:  1, // Single leg
	}

	entries := entry.ToDoubleHashFormat()

	// Should be 51 base entries + 8 appended SEC-14 aggregate entries (no multi-leg data)
	if len(entries) != 59 {
		t.Errorf("Expected 59 entries for single-leg (LegCount=1), got %d", len(entries))
	}

	// Verify no entry contains "leg_count="
	for _, e := range entries {
		if strings.HasPrefix(string(e), "leg_count=") {
			t.Error("Single-leg entry should not contain leg_count entry")
		}
	}
}
