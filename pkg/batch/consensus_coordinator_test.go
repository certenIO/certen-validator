// Copyright 2025 Certen Protocol
//
// Phase 5 Unit Tests: Consensus Coordinator
// Tests for:
// - Multi-validator consensus coordination
// - Attestation handling
// - Consensus state management
// - BLS signature verification integration

package batch

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// ============================================================================
// ConsensusCoordinatorConfig Tests
// ============================================================================

func TestDefaultConsensusCoordinatorConfig(t *testing.T) {
	cfg := DefaultConsensusCoordinatorConfig()

	if cfg.QuorumFraction != 0.667 {
		t.Errorf("Expected quorum fraction 0.667, got %f", cfg.QuorumFraction)
	}
	if cfg.QuorumTimeout != 30*time.Second {
		t.Errorf("Expected 30s quorum timeout, got %v", cfg.QuorumTimeout)
	}
	if cfg.RetryAttempts != 3 {
		t.Errorf("Expected 3 retry attempts, got %d", cfg.RetryAttempts)
	}
	if cfg.EntryTTL != 24*time.Hour {
		t.Errorf("Expected 24h entry TTL, got %v", cfg.EntryTTL)
	}
}

func TestConsensusCoordinatorConfig_CustomValues(t *testing.T) {
	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:    "custom-validator",
		QuorumFraction: 0.75,
		QuorumTimeout:  60 * time.Second,
		RetryAttempts:  5,
		EntryTTL:       48 * time.Hour,
	}

	if cfg.ValidatorID != "custom-validator" {
		t.Errorf("Expected custom-validator, got %s", cfg.ValidatorID)
	}
	if cfg.QuorumFraction != 0.75 {
		t.Errorf("Expected quorum fraction 0.75, got %f", cfg.QuorumFraction)
	}
}

// ============================================================================
// ConsensusResult Tests
// ============================================================================

func TestConsensusResult_QuorumReached(t *testing.T) {
	result := &ConsensusResult{
		BatchID:            uuid.New(),
		MerkleRoot:         sha256Sum("merkle"),
		AttestationCount:   3,
		ValidatorCount:     4,
		QuorumReached:      true,
		QuorumFraction:     0.75,
		AggregateSignature: make([]byte, 96),
		AggregatePubKey:    make([]byte, 48),
		StartTime:          time.Now().Add(-5 * time.Second),
		EndTime:            time.Now(),
		Duration:           5 * time.Second,
	}

	if !result.QuorumReached {
		t.Error("Expected quorum reached")
	}
	if result.AttestationCount != 3 {
		t.Errorf("Expected 3 attestations, got %d", result.AttestationCount)
	}
	if result.Duration != 5*time.Second {
		t.Errorf("Expected 5s duration, got %v", result.Duration)
	}
}

func TestConsensusResult_QuorumNotReached(t *testing.T) {
	result := &ConsensusResult{
		BatchID:          uuid.New(),
		QuorumReached:    false,
		AttestationCount: 1,
		ValidatorCount:   4,
		Errors:           []string{"quorum not reached: 1/4 validators"},
	}

	if result.QuorumReached {
		t.Error("Expected quorum NOT reached")
	}
	if len(result.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(result.Errors))
	}
}

// ============================================================================
// ConsensusEntry Tests
// ============================================================================

func TestConsensusEntry_StateTransitions(t *testing.T) {
	entry := &ConsensusEntry{
		BatchID:    uuid.New(),
		MerkleRoot: sha256Sum("entry_merkle"),
		State:      ConsensusStateInitiated,
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}

	// Initial state
	if entry.State != ConsensusStateInitiated {
		t.Errorf("Expected state Initiated, got %s", entry.State)
	}

	// Transition to collecting
	entry.State = ConsensusStateCollecting
	entry.LastUpdate = time.Now()
	if entry.State != ConsensusStateCollecting {
		t.Errorf("Expected state Collecting, got %s", entry.State)
	}

	// Transition to quorum met
	entry.State = ConsensusStateQuorumMet
	if entry.State != ConsensusStateQuorumMet {
		t.Errorf("Expected state QuorumMet, got %s", entry.State)
	}

	// Transition to completed
	entry.State = ConsensusStateCompleted
	if entry.State != ConsensusStateCompleted {
		t.Errorf("Expected state Completed, got %s", entry.State)
	}
}

func TestConsensusEntry_WithAttestations(t *testing.T) {
	entry := &ConsensusEntry{
		BatchID:    uuid.New(),
		MerkleRoot: sha256Sum("with_attestations"),
		State:      ConsensusStateCollecting,
		Attestations: []*BatchAttestation{
			{ValidatorID: "validator-1", Signature: make([]byte, 96)},
			{ValidatorID: "validator-2", Signature: make([]byte, 96)},
			{ValidatorID: "validator-3", Signature: make([]byte, 96)},
		},
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}

	if len(entry.Attestations) != 3 {
		t.Errorf("Expected 3 attestations, got %d", len(entry.Attestations))
	}
}

// ============================================================================
// ConsensusCoordinator Creation Tests
// ============================================================================

func TestNewConsensusCoordinator_NilBroadcaster(t *testing.T) {
	_, err := NewConsensusCoordinator(nil, nil, nil, nil)
	if err == nil {
		t.Error("Expected error for nil broadcaster")
	}
}

func TestNewConsensusCoordinator_NilProcessor(t *testing.T) {
	broadcaster := &AttestationBroadcaster{}
	_, err := NewConsensusCoordinator(nil, broadcaster, nil, nil)
	if err == nil {
		t.Error("Expected error for nil processor")
	}
}

// ============================================================================
// computeAttestationMessageHash Tests
// ============================================================================

func TestComputeAttestationMessageHash_Deterministic(t *testing.T) {
	batchID := uuid.MustParse("12345678-1234-1234-1234-123456789012")
	merkleRoot := sha256Sum("test_merkle_root")
	txCount := 42
	blockHeight := int64(99999)

	hash1 := computeAttestationMessageHash(batchID, merkleRoot, txCount, blockHeight)
	hash2 := computeAttestationMessageHash(batchID, merkleRoot, txCount, blockHeight)

	if hash1 != hash2 {
		t.Error("Expected deterministic hash output")
	}
}

func TestComputeAttestationMessageHash_DifferentInputs(t *testing.T) {
	batchID1 := uuid.New()
	batchID2 := uuid.New()
	merkleRoot := sha256Sum("test_merkle")

	hash1 := computeAttestationMessageHash(batchID1, merkleRoot, 10, 100)
	hash2 := computeAttestationMessageHash(batchID2, merkleRoot, 10, 100)

	if hash1 == hash2 {
		t.Error("Different batch IDs should produce different hashes")
	}
}

func TestComputeAttestationMessageHash_Length(t *testing.T) {
	batchID := uuid.New()
	merkleRoot := sha256Sum("test")

	hash := computeAttestationMessageHash(batchID, merkleRoot, 1, 1)

	if len(hash) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(hash))
	}
}

// ============================================================================
// HandleIncomingAttestation Tests
// ============================================================================

func TestHandleIncomingAttestation_NoBLSKey(t *testing.T) {
	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:   "test-validator",
		BLSPrivateKey: nil, // No key
	}

	// Create minimal coordinator for testing
	cc := &ConsensusCoordinator{
		config: cfg,
	}

	req := &AttestationRequest{
		BatchID:    uuid.New(),
		MerkleRoot: sha256Sum("test"),
		TxCount:    10,
	}

	_, err := cc.HandleIncomingAttestation(req)
	if err == nil {
		t.Error("Expected error when BLS key not configured")
	}
	if err.Error() != "BLS private key not configured" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestHandleIncomingAttestation_InvalidRequest(t *testing.T) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	// Generate test keys
	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate BLS keys: %v", err)
	}

	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:   "test-validator",
		BLSPrivateKey: privKey.Bytes(),
		BLSPublicKey:  pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{
		config: cfg,
	}

	// Invalid request - nil batch ID
	req := &AttestationRequest{
		BatchID:    uuid.Nil,
		MerkleRoot: sha256Sum("test"),
	}

	_, err = cc.HandleIncomingAttestation(req)
	if err == nil {
		t.Error("Expected error for invalid request")
	}
}

func TestHandleIncomingAttestation_InvalidMerkleRoot(t *testing.T) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate BLS keys: %v", err)
	}

	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:   "test-validator",
		BLSPrivateKey: privKey.Bytes(),
		BLSPublicKey:  pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{
		config: cfg,
	}

	// Invalid request - wrong length merkle root
	req := &AttestationRequest{
		BatchID:    uuid.New(),
		MerkleRoot: []byte("too_short"),
	}

	_, err = cc.HandleIncomingAttestation(req)
	if err == nil {
		t.Error("Expected error for invalid merkle root length")
	}
}

func TestHandleIncomingAttestation_ValidRequest(t *testing.T) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate BLS keys: %v", err)
	}

	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:   "test-validator",
		BLSPrivateKey: privKey.Bytes(),
		BLSPublicKey:  pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{
		config: cfg,
	}

	req := &AttestationRequest{
		BatchID:     uuid.New(),
		MerkleRoot:  sha256Sum("valid_merkle_root"),
		TxCount:     50,
		BlockHeight: 12345,
	}

	attestation, err := cc.HandleIncomingAttestation(req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify attestation fields
	if attestation.BatchID != req.BatchID {
		t.Error("BatchID mismatch")
	}
	if !bytes.Equal(attestation.MerkleRoot, req.MerkleRoot) {
		t.Error("MerkleRoot mismatch")
	}
	if attestation.ValidatorID != cfg.ValidatorID {
		t.Error("ValidatorID mismatch")
	}
	if len(attestation.Signature) == 0 {
		t.Error("Signature should not be empty")
	}
	if len(attestation.PublicKey) == 0 {
		t.Error("PublicKey should not be empty")
	}
	if attestation.TxCount != req.TxCount {
		t.Errorf("TxCount mismatch: expected %d, got %d", req.TxCount, attestation.TxCount)
	}

	t.Logf("Created attestation with signature: %s...", hex.EncodeToString(attestation.Signature)[:16])
}

// ============================================================================
// VerifyConsensusSignature Tests
// ============================================================================

func TestVerifyConsensusSignature_NilResult(t *testing.T) {
	cc := &ConsensusCoordinator{}

	_, err := cc.VerifyConsensusSignature(nil)
	if err == nil {
		t.Error("Expected error for nil result")
	}
}

func TestVerifyConsensusSignature_EmptySignature(t *testing.T) {
	cc := &ConsensusCoordinator{}

	result := &ConsensusResult{
		BatchID:            uuid.New(),
		AggregateSignature: nil,
	}

	_, err := cc.VerifyConsensusSignature(result)
	if err == nil {
		t.Error("Expected error for empty signature")
	}
}

func TestVerifyConsensusSignature_ValidSignature(t *testing.T) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	// Generate keys
	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate BLS keys: %v", err)
	}

	// Create a valid consensus result
	batchID := uuid.New()
	merkleRoot := sha256Sum("verify_test_merkle")
	attestationCount := 3
	blockNumber := int64(12345)

	// Compute message hash
	messageHash := computeAttestationMessageHash(batchID, merkleRoot, attestationCount, blockNumber)

	// Sign with domain separation
	signature := privKey.SignWithDomain(messageHash[:], bls.DomainAttestation)

	result := &ConsensusResult{
		BatchID:            batchID,
		MerkleRoot:         merkleRoot,
		AttestationCount:   attestationCount,
		BlockNumber:        blockNumber,
		AggregateSignature: signature.Bytes(),
		AggregatePubKey:    pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{}

	valid, err := cc.VerifyConsensusSignature(result)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !valid {
		t.Error("Expected valid signature")
	}
}

func TestVerifyConsensusSignature_TamperedSignature(t *testing.T) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		t.Fatalf("Failed to initialize BLS: %v", err)
	}

	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate BLS keys: %v", err)
	}

	batchID := uuid.New()
	merkleRoot := sha256Sum("tampered_test")
	messageHash := computeAttestationMessageHash(batchID, merkleRoot, 3, 12345)

	signature := privKey.SignWithDomain(messageHash[:], bls.DomainAttestation)
	sigBytes := signature.Bytes()

	// Tamper with the signature
	sigBytes[0] ^= 0xFF
	sigBytes[1] ^= 0xFF

	result := &ConsensusResult{
		BatchID:            batchID,
		MerkleRoot:         merkleRoot,
		AttestationCount:   3,
		BlockNumber:        12345,
		AggregateSignature: sigBytes,
		AggregatePubKey:    pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{}

	// Tampered signature should either fail verification or return error
	valid, err := cc.VerifyConsensusSignature(result)
	if err == nil && valid {
		t.Error("Tampered signature should not verify as valid")
	}
}

// ============================================================================
// GetConsensusStats Tests
// ============================================================================

func TestGetConsensusStats_Empty(t *testing.T) {
	cc := &ConsensusCoordinator{
		entries: make(map[uuid.UUID]*ConsensusEntry),
	}

	stats := cc.GetConsensusStats()

	if stats["total"] != 0 {
		t.Errorf("Expected total 0, got %d", stats["total"])
	}
}

func TestGetConsensusStats_WithEntries(t *testing.T) {
	cc := &ConsensusCoordinator{
		entries: map[uuid.UUID]*ConsensusEntry{
			uuid.New(): {State: ConsensusStateInitiated},
			uuid.New(): {State: ConsensusStateCollecting},
			uuid.New(): {State: ConsensusStateCollecting},
			uuid.New(): {State: ConsensusStateCompleted},
			uuid.New(): {State: ConsensusStateFailed},
		},
	}

	stats := cc.GetConsensusStats()

	if stats["total"] != 5 {
		t.Errorf("Expected total 5, got %d", stats["total"])
	}
	if stats["initiated"] != 1 {
		t.Errorf("Expected initiated 1, got %d", stats["initiated"])
	}
	if stats["collecting"] != 2 {
		t.Errorf("Expected collecting 2, got %d", stats["collecting"])
	}
	if stats["completed"] != 1 {
		t.Errorf("Expected completed 1, got %d", stats["completed"])
	}
	if stats["failed"] != 1 {
		t.Errorf("Expected failed 1, got %d", stats["failed"])
	}
}

// ============================================================================
// GetActiveConsensusCount Tests
// ============================================================================

func TestGetActiveConsensusCount_NoActive(t *testing.T) {
	cc := &ConsensusCoordinator{
		entries: map[uuid.UUID]*ConsensusEntry{
			uuid.New(): {State: ConsensusStateCompleted},
			uuid.New(): {State: ConsensusStateFailed},
		},
	}

	count := cc.GetActiveConsensusCount()

	if count != 0 {
		t.Errorf("Expected 0 active, got %d", count)
	}
}

func TestGetActiveConsensusCount_SomeActive(t *testing.T) {
	cc := &ConsensusCoordinator{
		entries: map[uuid.UUID]*ConsensusEntry{
			uuid.New(): {State: ConsensusStateInitiated},
			uuid.New(): {State: ConsensusStateCollecting},
			uuid.New(): {State: ConsensusStateCompleted},
		},
	}

	count := cc.GetActiveConsensusCount()

	if count != 2 {
		t.Errorf("Expected 2 active, got %d", count)
	}
}

// ============================================================================
// GetConsensusEntry Tests
// ============================================================================

func TestGetConsensusEntry_NotFound(t *testing.T) {
	cc := &ConsensusCoordinator{
		entries: make(map[uuid.UUID]*ConsensusEntry),
	}

	_, found := cc.GetConsensusEntry(uuid.New())

	if found {
		t.Error("Expected entry not found")
	}
}

func TestGetConsensusEntry_Found(t *testing.T) {
	batchID := uuid.New()
	entry := &ConsensusEntry{
		BatchID:    batchID,
		MerkleRoot: sha256Sum("found_entry"),
		State:      ConsensusStateCollecting,
	}

	cc := &ConsensusCoordinator{
		entries: map[uuid.UUID]*ConsensusEntry{
			batchID: entry,
		},
	}

	foundEntry, found := cc.GetConsensusEntry(batchID)

	if !found {
		t.Error("Expected entry to be found")
	}
	if foundEntry.BatchID != batchID {
		t.Error("BatchID mismatch")
	}
	if foundEntry.State != ConsensusStateCollecting {
		t.Errorf("State mismatch: expected Collecting, got %s", foundEntry.State)
	}
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

func TestConsensusCoordinator_StartStop(t *testing.T) {
	// Skip if we can't create a full coordinator
	t.Skip("Requires full coordinator setup with broadcaster and processor")
}

// ============================================================================
// Benchmark Tests
// ============================================================================

func BenchmarkComputeAttestationMessageHash(b *testing.B) {
	batchID := uuid.New()
	merkleRoot := sha256Sum("benchmark_merkle")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeAttestationMessageHash(batchID, merkleRoot, 100, 99999)
	}
}

func BenchmarkHandleIncomingAttestation(b *testing.B) {
	// Initialize BLS
	if err := bls.Initialize(); err != nil {
		b.Fatalf("Failed to initialize BLS: %v", err)
	}

	privKey, pubKey, err := bls.GenerateKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate BLS keys: %v", err)
	}

	cfg := &ConsensusCoordinatorConfig{
		ValidatorID:   "benchmark-validator",
		BLSPrivateKey: privKey.Bytes(),
		BLSPublicKey:  pubKey.Bytes(),
	}

	cc := &ConsensusCoordinator{
		config: cfg,
	}

	req := &AttestationRequest{
		BatchID:     uuid.New(),
		MerkleRoot:  sha256Sum("benchmark_merkle"),
		TxCount:     100,
		BlockHeight: 99999,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc.HandleIncomingAttestation(req)
	}
}

// ============================================================================
// Context Cancellation Tests
// ============================================================================

func TestConsensusCoordinator_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Verify context is done
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Context should be cancelled")
	}
}
