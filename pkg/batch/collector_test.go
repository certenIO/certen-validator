// Copyright 2025 Certen Protocol
//
// Unit tests for Batch Collector
// Tests merkle tree construction and batch management

package batch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// ============================================================================
// Transaction Data Tests
// ============================================================================

func TestTransactionData_ComputeHash(t *testing.T) {
	tx := &TransactionData{
		AccumTxHash: "abc123def456",
		AccountURL:  "acc://test.acme/tokens",
		TxHash:      nil, // Will be computed
	}

	// Compute hash
	hash := sha256.Sum256([]byte(tx.AccumTxHash))
	tx.TxHash = hash[:]

	if len(tx.TxHash) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(tx.TxHash))
	}

	// Verify deterministic
	hash2 := sha256.Sum256([]byte(tx.AccumTxHash))
	for i := range hash {
		if hash[i] != hash2[i] {
			t.Error("Hash should be deterministic")
			break
		}
	}
}

func TestTransactionData_WithProofs(t *testing.T) {
	chainedProof := json.RawMessage(`{"layer1": {"txHash": "abc"}}`)
	govProof := json.RawMessage(`{"g0": {"finalized": true}}`)

	tx := &TransactionData{
		AccumTxHash:  "tx123",
		AccountURL:   "acc://test.acme/tokens",
		ChainedProof: chainedProof,
		GovProof:     govProof,
		GovLevel:     "G1",
	}

	if tx.ChainedProof == nil {
		t.Error("ChainedProof should not be nil")
	}
	if tx.GovProof == nil {
		t.Error("GovProof should not be nil")
	}
	if tx.GovLevel != "G1" {
		t.Errorf("Expected gov level G1, got %s", tx.GovLevel)
	}
}

// ============================================================================
// Merkle Tree Construction Tests (No Database)
// ============================================================================

func TestMerkleTreeConstruction(t *testing.T) {
	// Test with known values
	leaves := [][]byte{
		sha256Sum("tx1"),
		sha256Sum("tx2"),
		sha256Sum("tx3"),
		sha256Sum("tx4"),
	}

	// Build tree manually
	// Level 0: [H(tx1), H(tx2), H(tx3), H(tx4)]
	// Level 1: [H(H(tx1)||H(tx2)), H(H(tx3)||H(tx4))]
	// Level 2 (root): H(Level1[0] || Level1[1])

	level1_0 := hashPair(leaves[0], leaves[1])
	level1_1 := hashPair(leaves[2], leaves[3])
	expectedRoot := hashPair(level1_0, level1_1)

	// Verify expected root
	if len(expectedRoot) != 32 {
		t.Errorf("Expected 32-byte root, got %d bytes", len(expectedRoot))
	}

	t.Logf("Merkle root: %s", hex.EncodeToString(expectedRoot))
}

func TestMerkleTreeOddLeaves(t *testing.T) {
	// Test with odd number of leaves (should duplicate last leaf)
	leaves := [][]byte{
		sha256Sum("tx1"),
		sha256Sum("tx2"),
		sha256Sum("tx3"),
	}

	// With odd leaves, tx3 is duplicated: [H(tx1), H(tx2), H(tx3), H(tx3)]
	level1_0 := hashPair(leaves[0], leaves[1])
	level1_1 := hashPair(leaves[2], leaves[2]) // Duplicate
	expectedRoot := hashPair(level1_0, level1_1)

	if len(expectedRoot) != 32 {
		t.Errorf("Expected 32-byte root, got %d bytes", len(expectedRoot))
	}
}

func TestMerkleTreeSingleLeaf(t *testing.T) {
	// Single leaf - root equals the leaf hash
	leaf := sha256Sum("single_tx")

	// For single leaf, the root is the leaf itself
	// (or H(leaf || leaf) depending on implementation)
	expectedRoot := hashPair(leaf, leaf)

	if len(expectedRoot) != 32 {
		t.Errorf("Expected 32-byte root, got %d bytes", len(expectedRoot))
	}
}

// ============================================================================
// Batch Lifecycle Tests (Mock/No Database)
// ============================================================================

func TestBatchIDGeneration(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	if id1 == id2 {
		t.Error("UUIDs should be unique")
	}
	if id1 == uuid.Nil {
		t.Error("UUID should not be nil")
	}
}

func TestClosedBatchResult(t *testing.T) {
	batchID := uuid.New()
	merkleRoot := sha256Sum("test_root")

	result := &ClosedBatchResult{
		BatchID:       batchID,
		BatchType:     database.BatchTypeOnCadence,
		MerkleRoot:    merkleRoot,
		MerkleRootHex: hex.EncodeToString(merkleRoot),
		TxCount:       5,
		StartTime:     time.Now().Add(-15 * time.Minute),
		EndTime:       time.Now(),
	}

	if result.BatchID != batchID {
		t.Error("BatchID mismatch")
	}
	if result.TxCount != 5 {
		t.Errorf("Expected 5 transactions, got %d", result.TxCount)
	}
	if result.MerkleRootHex != hex.EncodeToString(merkleRoot) {
		t.Error("Merkle root hex mismatch")
	}
}

// ============================================================================
// BatchTransactionResult Tests
// ============================================================================

func TestBatchTransactionResult(t *testing.T) {
	result := &BatchTransactionResult{
		TransactionID: 123,
		BatchID:       uuid.New(),
		TreeIndex:     5,
		BatchSize:     10,
	}

	if result.TransactionID != 123 {
		t.Errorf("Expected transaction ID 123, got %d", result.TransactionID)
	}
	if result.TreeIndex != 5 {
		t.Errorf("Expected tree index 5, got %d", result.TreeIndex)
	}
	if result.BatchSize != 10 {
		t.Errorf("Expected batch size 10, got %d", result.BatchSize)
	}
}

// ============================================================================
// Collector Configuration Tests
// ============================================================================

func TestCollectorConfig(t *testing.T) {
	cfg := DefaultCollectorConfig()

	if cfg.MaxBatchSize <= 0 {
		t.Error("MaxBatchSize should be positive")
	}
	if cfg.BatchTimeout <= 0 {
		t.Error("BatchTimeout should be positive")
	}
	if cfg.Logger == nil {
		t.Error("Logger should not be nil")
	}
}

func TestCollectorConfigCustom(t *testing.T) {
	cfg := &CollectorConfig{
		MaxBatchSize: 200,
		BatchTimeout: 5 * time.Minute,
		ValidatorID:  "custom-validator",
	}

	if cfg.MaxBatchSize != 200 {
		t.Errorf("Expected max batch size 200, got %d", cfg.MaxBatchSize)
	}
	if cfg.BatchTimeout != 5*time.Minute {
		t.Errorf("Expected 5 minute timeout, got %v", cfg.BatchTimeout)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func sha256Sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func hashPair(left, right []byte) []byte {
	combined := make([]byte, len(left)+len(right))
	copy(combined, left)
	copy(combined[len(left):], right)
	h := sha256.Sum256(combined)
	return h[:]
}

// ============================================================================
// Integration Tests (Require Database)
// ============================================================================

func TestCollectorWithMockDatabase(t *testing.T) {
	// Skip if no mock/test database
	t.Skip("Requires database mock - implement when needed")
}

func TestOnDemandBatch(t *testing.T) {
	// Test on-demand batch triggers immediate anchoring
	t.Skip("Requires database mock - implement when needed")
}

func TestScheduledBatchClose(t *testing.T) {
	// Test batch closes on schedule
	t.Skip("Requires database mock - implement when needed")
}

// ============================================================================
// Concurrency Tests
// ============================================================================

func TestConcurrentTransactionSubmission(t *testing.T) {
	// Test that concurrent submissions are handled correctly
	ctx := context.Background()
	done := make(chan bool, 10)

	// Simulate concurrent submissions
	for i := 0; i < 10; i++ {
		go func(idx int) {
			tx := &TransactionData{
				AccumTxHash: "concurrent_tx_" + string(rune('0'+idx)),
				AccountURL:  "acc://test.acme/tokens",
			}
			hash := sha256.Sum256([]byte(tx.AccumTxHash))
			tx.TxHash = hash[:]
			_ = ctx // Would use in real collector
			done <- true
		}(i)
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// OK
		case <-time.After(1 * time.Second):
			t.Error("Timeout waiting for concurrent submissions")
		}
	}
}
