// Copyright 2025 Certen Protocol
//
// Unit tests for ProofArtifactRepository
// Uses test database or mocks for isolation

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// Test database connection string (use test database or skip)
var testDB *sql.DB

func TestMain(m *testing.M) {
	// Try to connect to test database
	connStr := os.Getenv("CERTEN_TEST_DB")
	if connStr == "" {
		// Skip database tests if no test DB configured
		os.Exit(0)
	}

	var err error
	testDB, err = sql.Open("postgres", connStr)
	if err != nil {
		panic("Failed to connect to test database: " + err.Error())
	}

	// Run tests
	code := m.Run()

	// Cleanup
	testDB.Close()
	os.Exit(code)
}

// ============================================================================
// ProofArtifact Tests
// ============================================================================

func TestCreateProofArtifact(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create test artifact
	artifactJSON := json.RawMessage(`{"test": "data", "merkle": {"root": "abc123"}}`)

	input := &NewProofArtifact{
		ProofType:   ProofTypeCertenAnchor,
		AccumTxHash: "test_tx_" + uuid.New().String()[:8],
		AccountURL:  "acc://test.acme/tokens",
		ProofClass:  ProofClassOnCadence,
		ValidatorID: "test-validator-1",
		ArtifactJSON: artifactJSON,
	}

	proof, err := repo.CreateProofArtifact(ctx, input)
	if err != nil {
		t.Fatalf("Failed to create proof artifact: %v", err)
	}

	// Verify
	if proof.ProofID == uuid.Nil {
		t.Error("Expected non-nil proof ID")
	}
	if proof.ProofType != ProofTypeCertenAnchor {
		t.Errorf("Expected proof type %s, got %s", ProofTypeCertenAnchor, proof.ProofType)
	}
	if proof.Status != ProofStatusPending {
		t.Errorf("Expected status %s, got %s", ProofStatusPending, proof.Status)
	}

	// Verify artifact hash was computed
	expectedHash := sha256.Sum256(artifactJSON)
	if len(proof.ArtifactHash) != 32 {
		t.Error("Expected 32-byte artifact hash")
	}
	for i := range expectedHash {
		if proof.ArtifactHash[i] != expectedHash[i] {
			t.Error("Artifact hash mismatch")
			break
		}
	}

	// Cleanup
	_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
}

func TestGetProofByTxHash(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create test artifact
	txHash := "test_tx_" + uuid.New().String()[:8]
	input := &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  txHash,
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"test": true}`),
	}

	created, err := repo.CreateProofArtifact(ctx, input)
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", created.ProofID)
	}()

	// Retrieve by tx hash
	proof, err := repo.GetProofByTxHash(ctx, txHash)
	if err != nil {
		t.Fatalf("Failed to get proof by tx hash: %v", err)
	}
	if proof == nil {
		t.Fatal("Expected proof, got nil")
	}
	if proof.AccumTxHash != txHash {
		t.Errorf("Expected tx hash %s, got %s", txHash, proof.AccumTxHash)
	}

	// Test not found
	notFound, err := repo.GetProofByTxHash(ctx, "nonexistent_tx_hash")
	if err != nil {
		t.Fatalf("Unexpected error for nonexistent tx: %v", err)
	}
	if notFound != nil {
		t.Error("Expected nil for nonexistent tx hash")
	}
}

func TestGetProofsByAccount(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create test account URL with unique suffix
	accountURL := "acc://test-" + uuid.New().String()[:8] + ".acme/tokens"

	// Create multiple proofs for same account
	var createdIDs []uuid.UUID
	for i := 0; i < 3; i++ {
		input := &NewProofArtifact{
			ProofType:    ProofTypeCertenAnchor,
			AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
			AccountURL:   accountURL,
			ProofClass:   ProofClassOnCadence,
			ValidatorID:  "test-validator-1",
			ArtifactJSON: json.RawMessage(`{"index": ` + string(rune('0'+i)) + `}`),
		}
		proof, err := repo.CreateProofArtifact(ctx, input)
		if err != nil {
			t.Fatalf("Failed to create proof %d: %v", i, err)
		}
		createdIDs = append(createdIDs, proof.ProofID)
	}
	defer func() {
		for _, id := range createdIDs {
			_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", id)
		}
	}()

	// Query by account
	proofs, err := repo.GetProofsByAccount(ctx, accountURL, 10, 0)
	if err != nil {
		t.Fatalf("Failed to get proofs by account: %v", err)
	}
	if len(proofs) != 3 {
		t.Errorf("Expected 3 proofs, got %d", len(proofs))
	}

	// Test pagination
	page1, err := repo.GetProofsByAccount(ctx, accountURL, 2, 0)
	if err != nil {
		t.Fatalf("Failed to get page 1: %v", err)
	}
	if len(page1) != 2 {
		t.Errorf("Expected 2 proofs in page 1, got %d", len(page1))
	}

	page2, err := repo.GetProofsByAccount(ctx, accountURL, 2, 2)
	if err != nil {
		t.Fatalf("Failed to get page 2: %v", err)
	}
	if len(page2) != 1 {
		t.Errorf("Expected 1 proof in page 2, got %d", len(page2))
	}
}

func TestUpdateProofAnchored(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create test proof
	input := &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"test": true}`),
	}

	proof, err := repo.CreateProofArtifact(ctx, input)
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Update as anchored
	anchorID := uuid.New()
	anchorTxHash := "0x" + uuid.New().String()[:32]
	err = repo.UpdateProofAnchored(ctx, proof.ProofID, anchorID, anchorTxHash, 12345678, "ethereum")
	if err != nil {
		t.Fatalf("Failed to update proof as anchored: %v", err)
	}

	// Verify update
	updated, err := repo.GetProofByID(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to get updated proof: %v", err)
	}
	if updated.Status != ProofStatusAnchored {
		t.Errorf("Expected status %s, got %s", ProofStatusAnchored, updated.Status)
	}
	if updated.AnchorTxHash == nil || *updated.AnchorTxHash != anchorTxHash {
		t.Error("Anchor tx hash not updated correctly")
	}
	if updated.AnchoredAt == nil {
		t.Error("Expected anchored_at to be set")
	}
}

// ============================================================================
// ChainedProofLayer Tests
// ============================================================================

func TestChainedProofLayers(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create parent proof first
	proof, err := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeChained,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"type": "chained"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create parent proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM chained_proof_layers WHERE proof_id = $1", proof.ProofID)
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Create L1 layer
	bvnPartition := "BVN0"
	l1, err := repo.CreateChainedProofLayer(ctx, &NewChainedProofLayer{
		ProofID:      proof.ProofID,
		LayerNumber:  1,
		LayerName:    "tx_to_bvn",
		BVNPartition: &bvnPartition,
		LayerJSON:    json.RawMessage(`{"layer": 1, "partition": "BVN0"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create L1 layer: %v", err)
	}
	if l1.LayerNumber != 1 {
		t.Errorf("Expected layer number 1, got %d", l1.LayerNumber)
	}

	// Create L2 layer
	dnBlockHeight := int64(12345)
	l2, err := repo.CreateChainedProofLayer(ctx, &NewChainedProofLayer{
		ProofID:       proof.ProofID,
		LayerNumber:   2,
		LayerName:     "bvn_to_dn",
		DNBlockHeight: &dnBlockHeight,
		LayerJSON:     json.RawMessage(`{"layer": 2, "dn_height": 12345}`),
	})
	if err != nil {
		t.Fatalf("Failed to create L2 layer: %v", err)
	}
	if l2.LayerNumber != 2 {
		t.Errorf("Expected layer number 2, got %d", l2.LayerNumber)
	}

	// Get all layers
	layers, err := repo.GetChainedProofLayers(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to get layers: %v", err)
	}
	if len(layers) != 2 {
		t.Errorf("Expected 2 layers, got %d", len(layers))
	}
}

// ============================================================================
// GovernanceProofLevel Tests
// ============================================================================

func TestGovernanceProofLevels(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create parent proof
	govLevel := GovLevelG1
	proof, err := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeGovernance,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		GovLevel:     &govLevel,
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"type": "governance"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create parent proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM governance_proof_levels WHERE proof_id = $1", proof.ProofID)
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Create G0 level
	blockHeight := int64(10000)
	isAnchored := true
	g0, err := repo.CreateGovernanceProofLevel(ctx, &NewGovernanceProofLevel{
		ProofID:     proof.ProofID,
		GovLevel:    GovLevelG0,
		LevelName:   "inclusion_finality",
		BlockHeight: &blockHeight,
		IsAnchored:  &isAnchored,
		LevelJSON:   json.RawMessage(`{"level": "G0", "finalized": true}`),
	})
	if err != nil {
		t.Fatalf("Failed to create G0 level: %v", err)
	}
	if g0.GovLevel != GovLevelG0 {
		t.Errorf("Expected gov level G0, got %s", g0.GovLevel)
	}

	// Create G1 level
	authorityURL := "acc://test.acme/book"
	thresholdM := 2
	thresholdN := 3
	g1, err := repo.CreateGovernanceProofLevel(ctx, &NewGovernanceProofLevel{
		ProofID:      proof.ProofID,
		GovLevel:     GovLevelG1,
		LevelName:    "governance_correctness",
		AuthorityURL: &authorityURL,
		ThresholdM:   &thresholdM,
		ThresholdN:   &thresholdN,
		LevelJSON:    json.RawMessage(`{"level": "G1", "threshold": "2-of-3"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create G1 level: %v", err)
	}
	if g1.GovLevel != GovLevelG1 {
		t.Errorf("Expected gov level G1, got %s", g1.GovLevel)
	}

	// Get all levels
	levels, err := repo.GetGovernanceProofLevels(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to get levels: %v", err)
	}
	if len(levels) != 2 {
		t.Errorf("Expected 2 levels, got %d", len(levels))
	}
}

// ============================================================================
// Attestation Tests
// ============================================================================

func TestProofAttestations(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create parent proof
	proof, err := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"type": "anchor"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create parent proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM validator_attestations WHERE proof_id = $1", proof.ProofID)
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Create attestation
	pubkey := make([]byte, 32)
	signature := make([]byte, 64)
	attestedHash := make([]byte, 32)

	att, err := repo.CreateProofAttestation(ctx, &NewProofAttestation{
		ProofArtifactID: &proof.ProofID,
		ValidatorID:     "validator-1",
		ValidatorPubkey: pubkey,
		AttestedHash:    attestedHash,
		Signature:       signature,
		AttestedAt:      time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}
	if att.AttestationID == uuid.Nil {
		t.Error("Expected non-nil attestation ID")
	}

	// Get attestations
	attestations, err := repo.GetProofAttestationsByProof(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to get attestations: %v", err)
	}
	if len(attestations) != 1 {
		t.Errorf("Expected 1 attestation, got %d", len(attestations))
	}
}

// ============================================================================
// Verification Tests
// ============================================================================

func TestVerificationRecords(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create parent proof
	proof, err := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: json.RawMessage(`{"type": "anchor"}`),
	})
	if err != nil {
		t.Fatalf("Failed to create parent proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_verifications WHERE proof_id = $1", proof.ProofID)
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Create verification records
	durationMS := 15
	v1, err := repo.CreateVerificationRecord(ctx, proof.ProofID, "merkle", true, nil, nil, &durationMS)
	if err != nil {
		t.Fatalf("Failed to create verification record: %v", err)
	}
	if !v1.Passed {
		t.Error("Expected passed verification")
	}

	errorMsg := "signature invalid"
	v2, err := repo.CreateVerificationRecord(ctx, proof.ProofID, "signature", false, &errorMsg, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create failed verification record: %v", err)
	}
	if v2.Passed {
		t.Error("Expected failed verification")
	}

	// Get history
	history, err := repo.GetVerificationHistory(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to get verification history: %v", err)
	}
	if len(history) != 2 {
		t.Errorf("Expected 2 verification records, got %d", len(history))
	}
}

// ============================================================================
// Integrity Verification Tests
// ============================================================================

func TestVerifyArtifactIntegrity(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create proof with known artifact
	artifact := json.RawMessage(`{"test": "integrity", "value": 12345}`)
	proof, err := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeCertenAnchor,
		AccumTxHash:  "test_tx_" + uuid.New().String()[:8],
		AccountURL:   "acc://test.acme/tokens",
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "test-validator-1",
		ArtifactJSON: artifact,
	})
	if err != nil {
		t.Fatalf("Failed to create proof: %v", err)
	}
	defer func() {
		_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", proof.ProofID)
	}()

	// Verify integrity
	valid, err := repo.VerifyArtifactIntegrity(ctx, proof.ProofID)
	if err != nil {
		t.Fatalf("Failed to verify integrity: %v", err)
	}
	if !valid {
		t.Error("Expected valid integrity")
	}
}

// ============================================================================
// Query/Filter Tests
// ============================================================================

func TestQueryProofsWithFilters(t *testing.T) {
	if testDB == nil {
		t.Skip("Test database not configured")
	}

	repo := NewProofArtifactRepository(testDB)
	ctx := context.Background()

	// Create proofs with different attributes
	accountURL := "acc://filter-test-" + uuid.New().String()[:8] + ".acme/tokens"
	var createdIDs []uuid.UUID

	// G0 proof
	govLevelG0 := GovLevelG0
	p1, _ := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeGovernance,
		AccumTxHash:  "filter_tx_1_" + uuid.New().String()[:8],
		AccountURL:   accountURL,
		GovLevel:     &govLevelG0,
		ProofClass:   ProofClassOnCadence,
		ValidatorID:  "validator-1",
		ArtifactJSON: json.RawMessage(`{"gov": "G0"}`),
	})
	createdIDs = append(createdIDs, p1.ProofID)

	// G1 proof
	govLevelG1 := GovLevelG1
	p2, _ := repo.CreateProofArtifact(ctx, &NewProofArtifact{
		ProofType:    ProofTypeGovernance,
		AccumTxHash:  "filter_tx_2_" + uuid.New().String()[:8],
		AccountURL:   accountURL,
		GovLevel:     &govLevelG1,
		ProofClass:   ProofClassOnDemand,
		ValidatorID:  "validator-2",
		ArtifactJSON: json.RawMessage(`{"gov": "G1"}`),
	})
	createdIDs = append(createdIDs, p2.ProofID)

	defer func() {
		for _, id := range createdIDs {
			_, _ = testDB.ExecContext(ctx, "DELETE FROM proof_artifacts WHERE proof_id = $1", id)
		}
	}()

	// Query by gov level
	govFilter := GovLevelG1
	results, err := repo.QueryProofs(ctx, &ProofArtifactFilter{
		AccountURL: &accountURL,
		GovLevel:   &govFilter,
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("Failed to query proofs: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("Expected 1 G1 proof, got %d", len(results))
	}

	// Query by proof class
	proofClass := ProofClassOnDemand
	results2, err := repo.QueryProofs(ctx, &ProofArtifactFilter{
		AccountURL: &accountURL,
		ProofClass: &proofClass,
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("Failed to query proofs by class: %v", err)
	}
	if len(results2) != 1 {
		t.Errorf("Expected 1 on-demand proof, got %d", len(results2))
	}
}
