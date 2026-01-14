// Copyright 2025 Certen Protocol
//
// Unified Proof Verifier Tests
//
// These tests verify that the complete proof cycle (Levels 1-4) works correctly
// and that cross-level bindings are properly enforced.
//
// Test categories:
// 1. Full Proof Cycle - All 4 levels verify correctly
// 2. Cross-Level Bindings - Hash chains between levels
// 3. Tamper Detection - Any modification fails verification
// 4. Partial Proofs - Optional levels work correctly
// 5. Bundle Integrity - Complete bundle verification

package verification

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/merkle"
)

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// createValidMerkleReceipt creates a valid Merkle receipt for testing
func createValidMerkleReceipt(startData, siblingData string) (*merkle.Receipt, [32]byte, [32]byte) {
	startHash := sha256.Sum256([]byte(startData))
	siblingHash := sha256.Sum256([]byte(siblingData))
	anchor := sha256.Sum256(append(startHash[:], siblingHash[:]...))

	receipt := &merkle.Receipt{
		Start:      hex.EncodeToString(startHash[:]),
		Anchor:     hex.EncodeToString(anchor[:]),
		LocalBlock: 100,
		Entries: []merkle.ReceiptEntry{
			{Hash: hex.EncodeToString(siblingHash[:]), Right: true},
		},
	}

	return receipt, startHash, anchor
}

// createValidSignature creates a valid Ed25519 signature for testing
func createValidSignature(message [32]byte) (SignatureData, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(priv, message[:])

	return SignatureData{
		PublicKey:     pub,
		PublicKeyHash: sha256.Sum256(pub),
		Signature:     sig,
		SignedHash:    message,
		Weight:        1,
	}, priv
}

// computeChainedProofHash computes the correct ProofHash for Level 1
// Must match the algorithm in unified_verifier.go
func computeChainedProofHash(proof *ChainedProofBundle) [32]byte {
	data := make([]byte, 0, 256)
	data = append(data, proof.AccountHash[:]...)
	data = append(data, proof.BPTRoot[:]...)
	data = append(data, proof.PartitionRoot[:]...)
	data = append(data, proof.NetworkRoot[:]...)
	data = append(data, proof.BlockHash[:]...)
	return sha256.Sum256(data)
}

// computeGovernanceProofHash computes the correct ProofHash for Level 2
// Must match the algorithm in unified_verifier.go
func computeGovernanceProofHash(proof *GovernanceProofBundle) [32]byte {
	data := make([]byte, 0, 256)
	data = append(data, []byte(proof.DataAccountURL)...)
	data = append(data, proof.DataAccountHash[:]...)
	data = append(data, []byte(proof.AuthorityURL)...)
	data = append(data, proof.KeyPageHash[:]...)
	return sha256.Sum256(data)
}

// computeAnchorProofHash computes the correct ProofHash for Level 3
// Must match the algorithm in unified_verifier.go:computeAnchorProofHash
func computeAnchorProofHash(proof *AnchorProofBundle) [32]byte {
	data := make([]byte, 0, 256)
	if proof.StateProof != nil {
		data = append(data, proof.StateProof.NetworkRootHash[:]...)
	}
	if proof.AuthorityProof != nil {
		data = append(data, proof.AuthorityProof.KeyPageHash[:]...)
	}
	if proof.AnchorBinding != nil {
		data = append(data, proof.AnchorBinding.BindingHash[:]...)
	}
	return sha256.Sum256(data)
}

// computeResultHash computes the ResultHash for Level 4 ExternalChainResultData
// Must match the algorithm in unified_verifier.go:computeResultHash
func computeResultHash(result *ExternalChainResultData) [32]byte {
	data := make([]byte, 0, 512)
	data = append(data, result.ResultID[:]...)
	data = append(data, result.PreviousResultHash[:]...)
	data = append(data, result.AnchorProofHash[:]...)
	data = append(data, []byte(result.Chain)...)
	data = append(data, result.TxHash[:]...)
	data = append(data, result.BlockHash[:]...)
	data = append(data, result.TransactionsRoot[:]...)
	data = append(data, result.ReceiptsRoot[:]...)
	data = append(data, result.StateRoot[:]...)
	data = append(data, byte(result.Status))
	return sha256.Sum256(data)
}

// =============================================================================
// TEST 1: FULL PROOF CYCLE
// =============================================================================

// TestFullProofCycle_AllLevelsPass tests that a complete valid proof passes all levels
func TestFullProofCycle_AllLevelsPass(t *testing.T) {
	// Create Level 1: Chained Proof
	l1Receipt, accountHash, bptRoot := createValidMerkleReceipt("account_state", "bpt_sibling")
	l1Receipt2, _, partitionRoot := createValidMerkleReceipt("bpt_root", "partition_sibling")
	l1Receipt2.Start = hex.EncodeToString(bptRoot[:])
	l1Receipt3, _, _ := createValidMerkleReceipt("partition_root", "network_sibling")
	l1Receipt3.Start = hex.EncodeToString(partitionRoot[:])

	// Recompute anchors correctly
	partitionSibling := sha256.Sum256([]byte("partition_sibling"))
	actualPartitionRoot := sha256.Sum256(append(bptRoot[:], partitionSibling[:]...))
	l1Receipt2.Anchor = hex.EncodeToString(actualPartitionRoot[:])

	networkSibling := sha256.Sum256([]byte("network_sibling"))
	actualNetworkRoot := sha256.Sum256(append(actualPartitionRoot[:], networkSibling[:]...))
	l1Receipt3.Anchor = hex.EncodeToString(actualNetworkRoot[:])
	l1Receipt3.Start = hex.EncodeToString(actualPartitionRoot[:])

	level1 := &ChainedProofBundle{
		Layer1Receipt: l1Receipt,
		Layer2Receipt: l1Receipt2,
		Layer3Receipt: l1Receipt3,
		AccountHash:   accountHash,
		BPTRoot:       bptRoot,
		PartitionRoot: actualPartitionRoot,
		NetworkRoot:   actualNetworkRoot,
		BlockHeight:   12345,
	}
	level1.ProofHash = computeChainedProofHash(level1)

	// Create Level 2: Governance Proof
	govMessage := sha256.Sum256([]byte("governance_message"))
	sigData, _ := createValidSignature(govMessage)
	govReceipt, _, _ := createValidMerkleReceipt("gov_data", "gov_sibling")

	level2 := &GovernanceProofBundle{
		DataAccountURL:    "acc://test.acme/data",
		DataAccountHash:   sha256.Sum256([]byte("data_account")),
		AuthorityURL:      "acc://test.acme/book",
		KeyPageURL:        "acc://test.acme/book/1",
		KeyPageHash:       sha256.Sum256([]byte("key_page")),
		Signatures:        []SignatureData{sigData},
		RequiredThreshold: 1,
		AchievedWeight:    1,
		GovernanceReceipt: govReceipt,
	}
	level2.ProofHash = computeGovernanceProofHash(level2)

	// Create Level 3: Anchor Proof
	coordPub, coordPriv, _ := ed25519.GenerateKey(rand.Reader)
	merkleRootHash := sha256.Sum256([]byte("merkle_root"))
	anchorTxHash := sha256.Sum256([]byte("anchor_tx"))
	bindingHash := ComputeAnchorBindingHash(merkleRootHash, anchorTxHash, 12345)
	coordSig := ed25519.Sign(coordPriv, bindingHash[:])

	level3 := &AnchorProofBundle{
		StateProof: &StateProofData{
			Layer1Receipt:   l1Receipt,
			Layer1Anchor:    bptRoot,
			NetworkRootHash: actualNetworkRoot,
		},
		AuthorityProof: &AuthorityProofData{
			KeyPageURL:        "acc://test.acme/book/1",
			KeyPageHash:       level2.KeyPageHash,
			Signatures:        []SignatureData{sigData},
			RequiredThreshold: 1,
		},
		AnchorBinding: &AnchorBindingData{
			MerkleRootHash: merkleRootHash,
			AnchorTxHash:   anchorTxHash,
			AnchorBlockNum: 12345,
			BindingHash:    bindingHash,
			CoordinatorSig: coordSig,
			CoordinatorKey: coordPub,
		},
	}
	level3.ProofHash = computeAnchorProofHash(level3)

	// Create Level 4: Execution Proof
	validatorRoot := sha256.Sum256([]byte("validator_set"))
	snapshotID := sha256.Sum256([]byte("snapshot"))

	// First create the result without ResultHash
	execResult := &ExternalChainResultData{
		ResultID:        sha256.Sum256([]byte("result_id")),
		AnchorProofHash: level3.ProofHash, // Bind to Level 3
		Chain:           "ethereum",
		ChainID:         1,
		BlockNumber:     17000000,
		Status:          1,
		SequenceNumber:  0,
	}
	// Compute the correct ResultHash from the result fields
	execResult.ResultHash = computeResultHash(execResult)

	level4 := &ExecutionProofBundle{
		Result: execResult,
		Attestation: &AggregatedAttestationData{
			MessageHash:                execResult.ResultHash,
			ParticipantCount:           3,
			SnapshotID:                 snapshotID,
			ValidatorRoot:              validatorRoot,
			MessageConsistencyVerified: true,
		},
		ValidatorSnapshot: &ValidatorSnapshotData{
			SnapshotID:    snapshotID,
			BlockNumber:   17000000,
			ValidatorRoot: validatorRoot,
		},
	}

	// Create complete bundle
	bundle := &ProofBundle{
		BundleID:        sha256.Sum256([]byte("bundle")),
		OperationID:     sha256.Sum256([]byte("operation")),
		GeneratedAt:     time.Now(),
		ValidatorID:     "validator-1",
		ChainedProof:    level1,
		GovernanceProof: level2,
		AnchorProof:     level3,
		ExecutionProof:  level4,
	}

	// Create verifier and verify
	config := DefaultUnifiedVerifierConfig()
	verifier := NewUnifiedVerifier(config)

	result, err := verifier.VerifyFullProofCycle(bundle)
	if err != nil {
		t.Fatalf("Verification returned error: %v", err)
	}

	// Check all levels
	if !result.Level1Valid {
		t.Errorf("Level 1 should be valid. Errors: %v", result.Errors)
	}
	if !result.Level2Valid {
		t.Errorf("Level 2 should be valid. Errors: %v", result.Errors)
	}
	if !result.Level3Valid {
		t.Errorf("Level 3 should be valid. Errors: %v", result.Errors)
	}
	if !result.Level4Valid {
		t.Errorf("Level 4 should be valid. Errors: %v", result.Errors)
	}
	if !result.BindingsValid {
		t.Errorf("Bindings should be valid. Errors: %v", result.Errors)
	}
	if !result.AllValid {
		t.Errorf("Overall result should be valid. Errors: %v", result.Errors)
	}

	t.Logf("PASS: Full proof cycle verified successfully")
	t.Logf("  Level 1 (Chained):    %v", result.Level1Valid)
	t.Logf("  Level 2 (Governance): %v", result.Level2Valid)
	t.Logf("  Level 3 (Anchor):     %v", result.Level3Valid)
	t.Logf("  Level 4 (Execution):  %v", result.Level4Valid)
	t.Logf("  Cross-Level Bindings: %v", result.BindingsValid)
	t.Logf("  Duration: %v", result.Duration)
}

// =============================================================================
// TEST 2: CROSS-LEVEL BINDINGS
// =============================================================================

// TestCrossLevelBinding_L2toL3 tests Level 2 → Level 3 binding
func TestCrossLevelBinding_L2toL3(t *testing.T) {
	keyPageHash := sha256.Sum256([]byte("key_page"))

	level2 := &GovernanceProofBundle{
		DataAccountURL:  "acc://test.acme/data",
		DataAccountHash: sha256.Sum256([]byte("data")),
		AuthorityURL:    "acc://test.acme/book",
		KeyPageHash:     keyPageHash,
	}
	level2.ProofHash = computeGovernanceProofHash(level2)

	level3 := &AnchorProofBundle{
		AuthorityProof: &AuthorityProofData{
			KeyPageHash: keyPageHash, // Must match Level 2
		},
	}
	level3.ProofHash = computeAnchorProofHash(level3)

	bundle := &ProofBundle{
		GovernanceProof: level2,
		AnchorProof:     level3,
	}

	// This should pass because key page hashes match
	config := &UnifiedVerifierConfig{
		RequireLevel1:            false,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: true,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)
	if !result.BindingsValid {
		t.Errorf("L2→L3 binding should be valid: %v", result.Errors)
	}

	// Now break the binding
	level3.AuthorityProof.KeyPageHash = sha256.Sum256([]byte("different"))
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.BindingsValid {
		t.Error("Broken L2→L3 binding should fail")
	}

	t.Logf("PASS: L2→L3 binding verification works correctly")
}

// TestCrossLevelBinding_L3toL4 tests Level 3 → Level 4 binding
func TestCrossLevelBinding_L3toL4(t *testing.T) {
	anchorProofHash := sha256.Sum256([]byte("anchor_proof"))

	level3 := &AnchorProofBundle{}
	level3.ProofHash = anchorProofHash

	level4 := &ExecutionProofBundle{
		Result: &ExternalChainResultData{
			AnchorProofHash: anchorProofHash, // Must match Level 3
		},
	}
	level4.ProofHash = sha256.Sum256([]byte("result"))

	bundle := &ProofBundle{
		AnchorProof:    level3,
		ExecutionProof: level4,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            false,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: true,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)
	if !result.BindingsValid {
		t.Errorf("L3→L4 binding should be valid: %v", result.Errors)
	}

	// Now break the binding
	level4.Result.AnchorProofHash = sha256.Sum256([]byte("wrong"))
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.BindingsValid {
		t.Error("Broken L3→L4 binding should fail")
	}

	t.Logf("PASS: L3→L4 binding verification works correctly")
}

// =============================================================================
// TEST 3: TAMPER DETECTION
// =============================================================================

// TestTamperDetection_Level1Receipt tests that tampered Level 1 receipts fail
func TestTamperDetection_Level1Receipt(t *testing.T) {
	// Create a valid receipt chain
	receipt, accountHash, bptRoot := createValidMerkleReceipt("account", "bpt_sibling")

	level1 := &ChainedProofBundle{
		Layer1Receipt: receipt,
		AccountHash:   accountHash,
		BPTRoot:       bptRoot,
		PartitionRoot: sha256.Sum256([]byte("partition")),
		NetworkRoot:   sha256.Sum256([]byte("network")),
	}
	level1.ProofHash = computeChainedProofHash(level1)

	bundle := &ProofBundle{
		ChainedProof: level1,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            true,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	// Valid should pass
	result1, _ := verifier.VerifyFullProofCycle(bundle)
	if !result1.Level1Valid {
		t.Errorf("Valid Level 1 should pass: %v", result1.Errors)
	}

	// Tamper with receipt - changes should break verification
	tamperedHash := sha256.Sum256([]byte("tampered"))
	level1.Layer1Receipt.Entries[0].Hash = hex.EncodeToString(tamperedHash[:])
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.Level1Valid {
		t.Error("Tampered Level 1 receipt should fail")
	}

	t.Logf("PASS: Level 1 tamper detection works")
}

// TestTamperDetection_Level2Signature tests that tampered Level 2 signatures fail
func TestTamperDetection_Level2Signature(t *testing.T) {
	message := sha256.Sum256([]byte("message"))
	sigData, _ := createValidSignature(message)

	level2 := &GovernanceProofBundle{
		DataAccountURL:    "acc://test.acme/data",
		DataAccountHash:   sha256.Sum256([]byte("data_account")),
		AuthorityURL:      "acc://test.acme/book",
		KeyPageHash:       sha256.Sum256([]byte("key_page")),
		Signatures:        []SignatureData{sigData},
		RequiredThreshold: 1,
	}
	level2.ProofHash = computeGovernanceProofHash(level2)

	bundle := &ProofBundle{
		GovernanceProof: level2,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            false,
		RequireLevel2:            true,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	// Valid should pass
	result1, _ := verifier.VerifyFullProofCycle(bundle)
	if !result1.Level2Valid {
		t.Errorf("Valid Level 2 should pass: %v", result1.Errors)
	}

	// Tamper with signature
	level2.Signatures[0].Signature[0] ^= 0xFF
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.Level2Valid {
		t.Error("Tampered Level 2 signature should fail")
	}

	t.Logf("PASS: Level 2 tamper detection works")
}

// TestTamperDetection_Level3AnchorBinding tests anchor binding tamper detection
func TestTamperDetection_Level3AnchorBinding(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	merkleRoot := sha256.Sum256([]byte("merkle"))
	anchorTx := sha256.Sum256([]byte("anchor"))
	bindingHash := ComputeAnchorBindingHash(merkleRoot, anchorTx, 100)
	sig := ed25519.Sign(priv, bindingHash[:])

	level3 := &AnchorProofBundle{
		AnchorBinding: &AnchorBindingData{
			MerkleRootHash: merkleRoot,
			AnchorTxHash:   anchorTx,
			AnchorBlockNum: 100,
			BindingHash:    bindingHash,
			CoordinatorSig: sig,
			CoordinatorKey: pub,
		},
	}
	level3.ProofHash = computeAnchorProofHash(level3)

	bundle := &ProofBundle{
		AnchorProof: level3,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            false,
		RequireLevel2:            false,
		RequireLevel3:            true,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	// Valid should pass
	result1, _ := verifier.VerifyFullProofCycle(bundle)
	if !result1.Level3Valid {
		t.Errorf("Valid Level 3 should pass: %v", result1.Errors)
	}

	// Tamper with merkle root
	level3.AnchorBinding.MerkleRootHash[0] ^= 0xFF
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.Level3Valid {
		t.Error("Tampered Level 3 anchor binding should fail")
	}

	t.Logf("PASS: Level 3 tamper detection works")
}

// TestTamperDetection_Level4Result tests Level 4 result tamper detection
func TestTamperDetection_Level4Result(t *testing.T) {
	// Create result with all required fields
	result := &ExternalChainResultData{
		ResultID:        sha256.Sum256([]byte("result_id")),
		AnchorProofHash: sha256.Sum256([]byte("anchor")),
		Chain:           "ethereum",
		Status:          1,
	}
	// Compute the correct ResultHash
	result.ResultHash = computeResultHash(result)

	level4 := &ExecutionProofBundle{
		Result: result,
		Attestation: &AggregatedAttestationData{
			MessageHash:                result.ResultHash,
			MessageConsistencyVerified: true,
		},
	}

	bundle := &ProofBundle{
		ExecutionProof: level4,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            false,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            true,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	// Valid should pass
	result1, _ := verifier.VerifyFullProofCycle(bundle)
	if !result1.Level4Valid {
		t.Errorf("Valid Level 4 should pass: %v", result1.Errors)
	}

	// Tamper with result hash - this will cause mismatch when recomputed
	level4.Result.ResultHash[0] ^= 0xFF
	result2, _ := verifier.VerifyFullProofCycle(bundle)
	if result2.Level4Valid {
		t.Error("Tampered Level 4 result should fail")
	}

	t.Logf("PASS: Level 4 tamper detection works")
}

// =============================================================================
// TEST 4: PARTIAL PROOFS
// =============================================================================

// TestPartialProofs_Level1Only tests verification with only Level 1
func TestPartialProofs_Level1Only(t *testing.T) {
	receipt, accountHash, bptRoot := createValidMerkleReceipt("data", "sibling")

	level1 := &ChainedProofBundle{
		Layer1Receipt: receipt,
		AccountHash:   accountHash,
		BPTRoot:       bptRoot,
		PartitionRoot: sha256.Sum256([]byte("partition")),
		NetworkRoot:   sha256.Sum256([]byte("network")),
	}
	level1.ProofHash = computeChainedProofHash(level1)

	bundle := &ProofBundle{
		ChainedProof: level1,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            true,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)
	if !result.Level1Valid {
		t.Errorf("Level 1 should be valid: %v", result.Errors)
	}
	if !result.AllValid {
		t.Errorf("With only L1 required, overall should be valid: %v", result.Errors)
	}

	t.Logf("PASS: Partial proof (Level 1 only) works")
}

// TestPartialProofs_MissingRequired tests that missing required levels fail
func TestPartialProofs_MissingRequired(t *testing.T) {
	bundle := &ProofBundle{} // Empty bundle

	config := &UnifiedVerifierConfig{
		RequireLevel1:            true, // Required but missing
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)
	if result.Level1Valid {
		t.Error("Missing required Level 1 should fail")
	}
	if result.AllValid {
		t.Error("Missing required level should fail overall")
	}

	t.Logf("PASS: Missing required levels correctly detected")
}

// =============================================================================
// TEST 5: BUNDLE INTEGRITY
// =============================================================================

// TestBundleIntegrity_HashComputation tests bundle hash computation
func TestBundleIntegrity_HashComputation(t *testing.T) {
	bundle := &ProofBundle{
		BundleID:    sha256.Sum256([]byte("bundle")),
		OperationID: sha256.Sum256([]byte("operation")),
		GeneratedAt: time.Now(),
		ChainedProof: &ChainedProofBundle{
			ProofHash: sha256.Sum256([]byte("l1")),
		},
		GovernanceProof: &GovernanceProofBundle{
			ProofHash: sha256.Sum256([]byte("l2")),
		},
		AnchorProof: &AnchorProofBundle{
			ProofHash: sha256.Sum256([]byte("l3")),
		},
		ExecutionProof: &ExecutionProofBundle{
			Result: &ExternalChainResultData{
				ResultHash: sha256.Sum256([]byte("l4")),
			},
		},
	}

	verifier := NewUnifiedVerifier(nil)

	// Compute hash
	hash1 := verifier.ComputeBundleHash(bundle)
	hash2 := verifier.ComputeBundleHash(bundle)

	// Should be deterministic
	if hash1 != hash2 {
		t.Error("Bundle hash not deterministic")
	}

	// Change a component - hash should change
	bundle.ChainedProof.ProofHash = sha256.Sum256([]byte("changed"))
	hash3 := verifier.ComputeBundleHash(bundle)

	if hash1 == hash3 {
		t.Error("Bundle hash should change when component changes")
	}

	t.Logf("PASS: Bundle hash computation works correctly")
}

// =============================================================================
// TEST 6: ERROR ACCUMULATION
// =============================================================================

// TestErrorAccumulation tests that all errors are collected
func TestErrorAccumulation(t *testing.T) {
	// Create bundle with multiple invalid components
	bundle := &ProofBundle{
		ChainedProof: &ChainedProofBundle{
			Layer1Receipt: &merkle.Receipt{
				Start:  "invalid",
				Anchor: "invalid",
			},
		},
		GovernanceProof: &GovernanceProofBundle{
			Signatures:        []SignatureData{},
			RequiredThreshold: 5, // Can't be met with 0 signatures
		},
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            true,
		RequireLevel2:            true,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)

	// Should have multiple errors
	if len(result.Errors) < 2 {
		t.Errorf("Expected multiple errors, got %d: %v", len(result.Errors), result.Errors)
	}

	t.Logf("PASS: Error accumulation works, collected %d errors", len(result.Errors))
	for _, err := range result.Errors {
		t.Logf("  - %s", err)
	}
}

// =============================================================================
// TEST 7: TIMING
// =============================================================================

// TestVerificationTiming tests that timing information is recorded
func TestVerificationTiming(t *testing.T) {
	receipt, accountHash, bptRoot := createValidMerkleReceipt("data", "sibling")

	level1 := &ChainedProofBundle{
		Layer1Receipt: receipt,
		AccountHash:   accountHash,
		BPTRoot:       bptRoot,
		PartitionRoot: sha256.Sum256([]byte("partition")),
		NetworkRoot:   sha256.Sum256([]byte("network")),
	}
	level1.ProofHash = computeChainedProofHash(level1)

	bundle := &ProofBundle{
		ChainedProof: level1,
	}

	config := &UnifiedVerifierConfig{
		RequireLevel1:            true,
		RequireLevel2:            false,
		RequireLevel3:            false,
		RequireLevel4:            false,
		VerifyCrossLevelBindings: false,
	}
	verifier := NewUnifiedVerifier(config)

	result, _ := verifier.VerifyFullProofCycle(bundle)

	if result.StartTime.IsZero() {
		t.Error("StartTime should be set")
	}
	if result.EndTime.IsZero() {
		t.Error("EndTime should be set")
	}
	// Duration can be 0 on fast systems with low timer resolution
	// The important check is that EndTime is >= StartTime
	if result.EndTime.Before(result.StartTime) {
		t.Error("EndTime should be after or equal to StartTime")
	}
	// Verify Duration is computed correctly
	expectedDuration := result.EndTime.Sub(result.StartTime)
	if result.Duration != expectedDuration {
		t.Errorf("Duration mismatch: expected %v, got %v", expectedDuration, result.Duration)
	}

	t.Logf("PASS: Timing information recorded correctly")
	t.Logf("  StartTime: %v", result.StartTime)
	t.Logf("  EndTime: %v", result.EndTime)
	t.Logf("  Duration: %v", result.Duration)
}
