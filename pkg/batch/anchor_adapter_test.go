// Copyright 2025 Certen Protocol
//
// Phase 5 Unit Tests: Anchor Adapter
// Tests for:
// - deriveCrossChainCommitmentV2 (Phase 2 fix for HIGH-002)
// - deriveGovernanceRootV2 (Phase 2 fix for HIGH-003)
// - computeGovernanceMerkleRoot

package batch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// ============================================================================
// deriveCrossChainCommitmentV2 Tests (HIGH-002)
// ============================================================================

func TestDeriveCrossChainCommitmentV2_WithRealBPTRoot(t *testing.T) {
	// When BPT root is provided, it should be returned directly
	bptRoot := sha256Sum("real_bpt_root_from_accumulate")

	req := &BatchAnchorRequest{
		BatchID: uuid.New(),
		BPTRoot: bptRoot,
	}

	adapter := NewAnchorAdapter(nil, nil) // Creates adapter with default logger
	result, hasRealData := adapter.deriveCrossChainCommitmentV2(req)

	if !hasRealData {
		t.Error("Expected hasRealData=true when BPT root is provided")
	}
	if !bytes.Equal(result, bptRoot) {
		t.Error("Expected result to equal BPT root")
	}
	t.Logf("BPT root returned correctly: %s", hex.EncodeToString(result)[:16])
}

func TestDeriveCrossChainCommitmentV2_WithTransactionProofs(t *testing.T) {
	// When no BPT root but transaction proofs are provided
	proofJSON1 := json.RawMessage(`{"bpt_root": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"}`)
	proofJSON2 := json.RawMessage(`{"l2_anchor": "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"}`)

	req := &BatchAnchorRequest{
		BatchID:           uuid.New(),
		BPTRoot:           nil, // Not provided
		TransactionProofs: []json.RawMessage{proofJSON1, proofJSON2},
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, hasRealData := adapter.deriveCrossChainCommitmentV2(req)

	// Should extract BPT root from first proof
	if !hasRealData {
		t.Error("Expected hasRealData=true when extractable from proofs")
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	t.Logf("Extracted BPT root: %s", hex.EncodeToString(result)[:16])
}

func TestDeriveCrossChainCommitmentV2_FallbackToLegacy(t *testing.T) {
	// When no real proof data is available, should use legacy fallback
	req := &BatchAnchorRequest{
		BatchID:          uuid.New(),
		AccumulateHeight: 12345,
		AccumulateHash:   "abc123def456",
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, hasRealData := adapter.deriveCrossChainCommitmentV2(req)

	if hasRealData {
		t.Error("Expected hasRealData=false for legacy fallback")
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	t.Logf("Legacy fallback result: %s", hex.EncodeToString(result)[:16])
}

func TestDeriveCrossChainCommitmentV2_DeterministicOutput(t *testing.T) {
	// Same input should produce same output
	bptRoot := sha256Sum("deterministic_test")
	req := &BatchAnchorRequest{
		BatchID: uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		BPTRoot: bptRoot,
	}

	adapter := NewAnchorAdapter(nil, nil)
	result1, _ := adapter.deriveCrossChainCommitmentV2(req)
	result2, _ := adapter.deriveCrossChainCommitmentV2(req)

	if !bytes.Equal(result1, result2) {
		t.Error("Expected deterministic output for same input")
	}
}

// ============================================================================
// deriveGovernanceRootV2 Tests (HIGH-003)
// ============================================================================

func TestDeriveGovernanceRootV2_WithRealProofs(t *testing.T) {
	// When governance proofs are provided, should compute Merkle root
	govProof1 := json.RawMessage(`{"level": "G2", "txHash": "abc123", "receiptRoot": "def456"}`)
	govProof2 := json.RawMessage(`{"level": "G1", "txHash": "xyz789", "authorityProof": "auth123"}`)

	req := &BatchAnchorRequest{
		BatchID:          uuid.New(),
		GovernanceProofs: []json.RawMessage{govProof1, govProof2},
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, proofCount := adapter.deriveGovernanceRootV2(req)

	if proofCount != 2 {
		t.Errorf("Expected proof count 2, got %d", proofCount)
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	// Should not be all zeros (indicates real computation)
	if bytes.Equal(result, make([]byte, 32)) {
		t.Error("Result should not be zero hash for real proofs")
	}
	t.Logf("Governance root from %d proofs: %s", proofCount, hex.EncodeToString(result)[:16])
}

func TestDeriveGovernanceRootV2_NoProofs(t *testing.T) {
	// When no governance proofs, should return legacy fallback
	req := &BatchAnchorRequest{
		BatchID:     uuid.New(),
		ValidatorID: "test-validator",
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, proofCount := adapter.deriveGovernanceRootV2(req)

	if proofCount != 0 {
		t.Errorf("Expected proof count 0, got %d", proofCount)
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	t.Logf("Legacy fallback governance root: %s", hex.EncodeToString(result)[:16])
}

func TestDeriveGovernanceRootV2_SingleProof(t *testing.T) {
	// Single proof should return hash of that proof
	govProof := json.RawMessage(`{"level": "G0", "txHash": "single_tx_hash"}`)

	req := &BatchAnchorRequest{
		BatchID:          uuid.New(),
		GovernanceProofs: []json.RawMessage{govProof},
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, proofCount := adapter.deriveGovernanceRootV2(req)

	if proofCount != 1 {
		t.Errorf("Expected proof count 1, got %d", proofCount)
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}

	// For single proof, result should be hash of that proof
	expectedHash := sha256.Sum256(govProof)
	if !bytes.Equal(result, expectedHash[:]) {
		t.Error("Single proof result should equal hash of proof")
	}
}

func TestDeriveGovernanceRootV2_EmptyProofSkipped(t *testing.T) {
	// Empty proofs in array should be skipped
	govProof := json.RawMessage(`{"level": "G1", "txHash": "valid"}`)
	emptyProof := json.RawMessage(``)

	req := &BatchAnchorRequest{
		BatchID:          uuid.New(),
		GovernanceProofs: []json.RawMessage{emptyProof, govProof, emptyProof},
	}

	adapter := NewAnchorAdapter(nil, nil)
	result, proofCount := adapter.deriveGovernanceRootV2(req)

	if proofCount != 1 {
		t.Errorf("Expected proof count 1 (empty proofs skipped), got %d", proofCount)
	}
	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
}

// ============================================================================
// computeGovernanceMerkleRoot Tests
// ============================================================================

func TestComputeGovernanceMerkleRoot_Empty(t *testing.T) {
	result := computeGovernanceMerkleRoot([][]byte{})

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	// Empty should return zero hash
	if !bytes.Equal(result, make([]byte, 32)) {
		t.Error("Empty proofs should return zero hash")
	}
}

func TestComputeGovernanceMerkleRoot_SingleLeaf(t *testing.T) {
	leaf := sha256Sum("single_governance_leaf")
	result := computeGovernanceMerkleRoot([][]byte{leaf})

	// Single leaf: root equals the leaf
	if !bytes.Equal(result, leaf) {
		t.Error("Single leaf root should equal the leaf itself")
	}
}

func TestComputeGovernanceMerkleRoot_TwoLeaves(t *testing.T) {
	leaf1 := sha256Sum("gov_leaf_1")
	leaf2 := sha256Sum("gov_leaf_2")

	result := computeGovernanceMerkleRoot([][]byte{leaf1, leaf2})

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	// Should not equal either leaf
	if bytes.Equal(result, leaf1) || bytes.Equal(result, leaf2) {
		t.Error("Two-leaf root should not equal either leaf")
	}
}

func TestComputeGovernanceMerkleRoot_FourLeaves(t *testing.T) {
	leaves := [][]byte{
		sha256Sum("gov_leaf_1"),
		sha256Sum("gov_leaf_2"),
		sha256Sum("gov_leaf_3"),
		sha256Sum("gov_leaf_4"),
	}

	result := computeGovernanceMerkleRoot(leaves)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	t.Logf("4-leaf governance Merkle root: %s", hex.EncodeToString(result)[:16])
}

func TestComputeGovernanceMerkleRoot_OddLeaves(t *testing.T) {
	leaves := [][]byte{
		sha256Sum("gov_odd_1"),
		sha256Sum("gov_odd_2"),
		sha256Sum("gov_odd_3"),
	}

	result := computeGovernanceMerkleRoot(leaves)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	t.Logf("3-leaf (odd) governance Merkle root: %s", hex.EncodeToString(result)[:16])
}

func TestComputeGovernanceMerkleRoot_Deterministic(t *testing.T) {
	leaves := [][]byte{
		sha256Sum("deterministic_1"),
		sha256Sum("deterministic_2"),
	}

	result1 := computeGovernanceMerkleRoot(leaves)
	result2 := computeGovernanceMerkleRoot(leaves)

	if !bytes.Equal(result1, result2) {
		t.Error("Merkle root should be deterministic")
	}
}

// ============================================================================
// extractBPTRootFromProofJSON Tests
// ============================================================================

func TestExtractBPTRootFromProofJSON_BPTRootField(t *testing.T) {
	// Test extraction from bpt_root field
	bptRootHex := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	proofJSON := json.RawMessage(`{"bpt_root": "` + bptRootHex + `"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
	expectedBytes, _ := hex.DecodeString(bptRootHex)
	if !bytes.Equal(result, expectedBytes) {
		t.Error("Extracted BPT root doesn't match expected")
	}
}

func TestExtractBPTRootFromProofJSON_Layer2AnchorField(t *testing.T) {
	// Test extraction from layer2_anchor field
	anchorHex := "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3"
	proofJSON := json.RawMessage(`{"layer2_anchor": "` + anchorHex + `"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
}

func TestExtractBPTRootFromProofJSON_L2AnchorField(t *testing.T) {
	// Test extraction from l2_anchor field
	anchorHex := "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	proofJSON := json.RawMessage(`{"l2_anchor": "` + anchorHex + `"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if len(result) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result))
	}
}

func TestExtractBPTRootFromProofJSON_InvalidJSON(t *testing.T) {
	proofJSON := json.RawMessage(`{invalid json}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if result != nil {
		t.Error("Expected nil for invalid JSON")
	}
}

func TestExtractBPTRootFromProofJSON_MissingFields(t *testing.T) {
	proofJSON := json.RawMessage(`{"other_field": "value"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if result != nil {
		t.Error("Expected nil when no BPT fields present")
	}
}

func TestExtractBPTRootFromProofJSON_InvalidHex(t *testing.T) {
	proofJSON := json.RawMessage(`{"bpt_root": "not_valid_hex_xyz"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if result != nil {
		t.Error("Expected nil for invalid hex")
	}
}

func TestExtractBPTRootFromProofJSON_WrongLength(t *testing.T) {
	// Valid hex but not 32 bytes
	proofJSON := json.RawMessage(`{"bpt_root": "a1b2c3d4"}`)

	result := extractBPTRootFromProofJSON(proofJSON)

	if result != nil {
		t.Error("Expected nil for wrong length hex")
	}
}

// ============================================================================
// AnchorAdapter CreateBatchAnchor Integration Test
// ============================================================================

func TestAnchorAdapter_CreateBatchAnchor_NoManager(t *testing.T) {
	adapter := NewAnchorAdapter(nil, nil)

	req := &BatchAnchorRequest{
		BatchID:    uuid.New(),
		MerkleRoot: sha256Sum("test_merkle_root"),
	}

	_, err := adapter.CreateBatchAnchor(nil, req)
	if err == nil {
		t.Error("Expected error when anchor manager is nil")
	}
	if err.Error() != "anchor manager not configured" {
		t.Errorf("Unexpected error: %v", err)
	}
}

// ============================================================================
// AnchorOnChainRequest Tests
// ============================================================================

func TestAnchorOnChainRequest_Serialization(t *testing.T) {
	req := &AnchorOnChainRequest{
		BatchID:              uuid.New().String(),
		MerkleRoot:           sha256Sum("merkle"),
		OperationCommitment:  sha256Sum("operation"),
		CrossChainCommitment: sha256Sum("cross_chain"),
		GovernanceRoot:       sha256Sum("governance"),
		TxCount:              42,
		AccumulateHeight:     12345,
		AccumulateHash:       "abc123",
		TargetChain:          "ethereum",
		ValidatorID:          "validator-1",
		ProofDataIncluded:    true,
	}

	// Verify all fields are populated
	if req.TxCount != 42 {
		t.Errorf("Expected TxCount 42, got %d", req.TxCount)
	}
	if !req.ProofDataIncluded {
		t.Error("Expected ProofDataIncluded to be true")
	}
	if len(req.MerkleRoot) != 32 {
		t.Error("MerkleRoot should be 32 bytes")
	}
}

// ============================================================================
// Legacy Fallback Function Tests
// ============================================================================

func TestDeriveCrossChainCommitmentLegacy_Deterministic(t *testing.T) {
	req := &BatchAnchorRequest{
		BatchID:          uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		AccumulateHeight: 99999,
		AccumulateHash:   "fixed_hash_value",
	}

	result1 := deriveCrossChainCommitmentLegacy(req)
	result2 := deriveCrossChainCommitmentLegacy(req)

	if !bytes.Equal(result1, result2) {
		t.Error("Legacy commitment should be deterministic")
	}
	if len(result1) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result1))
	}
}

func TestDeriveGovernanceRootLegacy_Deterministic(t *testing.T) {
	req := &BatchAnchorRequest{
		BatchID:     uuid.MustParse("12345678-1234-1234-1234-123456789012"),
		ValidatorID: "validator-test-123",
	}

	result1 := deriveGovernanceRootLegacy(req)
	result2 := deriveGovernanceRootLegacy(req)

	if !bytes.Equal(result1, result2) {
		t.Error("Legacy governance root should be deterministic")
	}
	if len(result1) != 32 {
		t.Errorf("Expected 32-byte result, got %d bytes", len(result1))
	}
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkComputeGovernanceMerkleRoot_100Leaves(b *testing.B) {
	leaves := make([][]byte, 100)
	for i := range leaves {
		leaves[i] = sha256Sum("leaf_" + string(rune('0'+i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeGovernanceMerkleRoot(leaves)
	}
}

func BenchmarkDeriveCrossChainCommitmentV2(b *testing.B) {
	bptRoot := sha256Sum("benchmark_bpt_root")
	req := &BatchAnchorRequest{
		BatchID: uuid.New(),
		BPTRoot: bptRoot,
	}
	adapter := NewAnchorAdapter(nil, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.deriveCrossChainCommitmentV2(req)
	}
}
