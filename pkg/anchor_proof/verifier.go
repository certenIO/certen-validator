// Copyright 2025 Certen Protocol
//
// Anchor Proof Verifier - Verifies all 4 components of a CertenAnchorProof
// Per Whitepaper Section 3.4.1:
// 1. Transaction Inclusion Proof (Merkle proof in batch)
// 2. Anchor Reference (ETH/BTC tx hash + block + confirmations)
// 3. State Proof (ChainedProof from Accumulate L1-L3)
// 4. Authority Proof (GovernanceProof G0-G2)

package anchor_proof

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"
)

// Verifier verifies CertenAnchorProofs
type Verifier struct {
	// Configuration
	config VerifierConfig

	// Attestation verifier for validator signatures
	attestationVerifier *AttestationVerifier
}

// VerifierConfig holds verifier configuration
type VerifierConfig struct {
	// Minimum confirmations required for anchor to be valid
	MinConfirmations int

	// Required attestation count for consensus
	RequiredAttestations int

	// Whether to verify attestation signatures
	VerifyAttestations bool

	// Whether state proof is required
	RequireStateProof bool

	// Whether authority proof is required
	RequireAuthorityProof bool

	// Minimum governance level if authority proof is required
	MinGovernanceLevel GovernanceLevel
}

// DefaultVerifierConfig returns default configuration
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		MinConfirmations:      12,           // 12 confirmations for Ethereum
		RequiredAttestations:  1,            // At least 1 attestation
		VerifyAttestations:    true,
		RequireStateProof:     false,        // Optional by default
		RequireAuthorityProof: false,        // Optional by default
		MinGovernanceLevel:    GovLevelNone,
	}
}

// NewVerifier creates a new proof verifier
func NewVerifier(config VerifierConfig) *Verifier {
	return &Verifier{
		config:              config,
		attestationVerifier: NewAttestationVerifier(),
	}
}

// RegisterValidator adds a known validator for attestation verification
func (v *Verifier) RegisterValidator(validatorID string, pubkeyHex string) error {
	return v.attestationVerifier.RegisterValidatorHex(validatorID, pubkeyHex)
}

// Verify performs full verification of a CertenAnchorProof
// with cryptographic re-verification of all components.
//
// Verification Order (fail-closed):
// 1. Verify OperationID binding
// 2. Verify Transaction Inclusion (Merkle proof)
// 3. Verify Anchor Reference (confirmations)
// 4. Verify Anchor Binding (cryptographic link)
// 5. Verify State Proof (3-layer receipt chain)
// 6. Verify Authority Proof (Ed25519 signatures)
// 7. Verify Attestations (multi-validator consensus)
func (v *Verifier) Verify(proof *CertenAnchorProof) *VerifyResult {
	startTime := time.Now()
	result := &VerifyResult{
		VerifiedAt: startTime,
		Errors:     make([]string, 0),
	}

	if proof == nil {
		result.Valid = false
		result.Message = "proof is nil"
		result.Errors = append(result.Errors, "proof is nil")
		return result
	}

	// Step 1: Verify Operation ID binding (Phase 1.4)
	operationIDValid := v.verifyOperationID(proof, result)

	// Step 2: Verify Component 1 - Transaction Inclusion
	result.TransactionInclusionValid = v.verifyTransactionInclusion(proof, result)

	// Step 3: Verify Component 2 - Anchor Reference
	result.AnchorReferenceValid = v.verifyAnchorReference(proof, result)

	// Step 4: Verify Anchor Binding (Phase 1.2)
	anchorBindingValid := v.verifyAnchorBinding(proof, result)

	// Step 5: Verify Component 3 - State Proof (cryptographic)
	result.StateProofValid = v.verifyStateProof(proof, result)

	// Step 6: Verify Component 4 - Authority Proof (cryptographic)
	result.AuthorityProofValid = v.verifyAuthorityProof(proof, result)

	// Step 7: Verify Attestations
	if v.config.VerifyAttestations && len(proof.Attestations) > 0 {
		result.AttestationsValid = v.verifyAttestations(proof, result)
	} else if v.config.RequiredAttestations > 0 && len(proof.Attestations) == 0 {
		result.AttestationsValid = false
		result.Errors = append(result.Errors, fmt.Sprintf("required %d attestations but got 0", v.config.RequiredAttestations))
	} else {
		result.AttestationsValid = true // No attestations required or none to verify
	}

	// Compute overall validity including new cryptographic bindings
	result.Valid = v.computeOverallValidity(result) && operationIDValid && anchorBindingValid
	if result.Valid {
		result.Message = "proof verification passed (cryptographic)"
	} else {
		result.Message = fmt.Sprintf("proof verification failed: %d errors", len(result.Errors))
	}

	result.VerificationTime = time.Since(startTime).Milliseconds()
	return result
}

// =============================================================================
// Operation ID Verification (Phase 1.4)
// =============================================================================

func (v *Verifier) verifyOperationID(proof *CertenAnchorProof, result *VerifyResult) bool {
	// If no operation ID is set, skip verification (backward compatibility)
	emptyID := OperationID{}
	if proof.OperationID == emptyID {
		return true
	}

	// Parse transaction hash
	txHashStr := proof.AccumulateTxHash
	if len(txHashStr) > 2 && txHashStr[:2] == "0x" {
		txHashStr = txHashStr[2:]
	}
	txHashBytes, err := hex.DecodeString(txHashStr)
	if err != nil || len(txHashBytes) != 32 {
		result.Errors = append(result.Errors, "operation ID: invalid transaction hash format")
		return false
	}

	var txHash [32]byte
	copy(txHash[:], txHashBytes)

	// Compute expected operation ID
	expectedID := ComputeOperationID(
		txHash,
		proof.AccountURL,
		uint64(proof.StateProof.BlockHeight),
		proof.CreatedAt,
	)

	// Compare computed with stored
	if proof.OperationID != expectedID {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"operation ID mismatch: stored %s != computed %s",
			proof.OperationID.String(), expectedID.String()))
		return false
	}

	return true
}

// =============================================================================
// Anchor Binding Verification (Phase 1.2)
// =============================================================================

func (v *Verifier) verifyAnchorBinding(proof *CertenAnchorProof, result *VerifyResult) bool {
	// If no anchor binding is set, skip verification (backward compatibility)
	if proof.AnchorBinding == nil {
		return true
	}

	// Perform full cryptographic verification of anchor binding
	if err := proof.AnchorBinding.Verify(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("anchor binding: %v", err))
		return false
	}

	// Verify binding matches proof's Merkle root
	merkleRoot, err := proof.GetMerkleRootBytes()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("anchor binding: cannot get merkle root: %v", err))
		return false
	}

	var expectedMerkleRoot [32]byte
	copy(expectedMerkleRoot[:], merkleRoot)

	if proof.AnchorBinding.MerkleRootHash != expectedMerkleRoot {
		result.Errors = append(result.Errors, "anchor binding: merkle root mismatch")
		return false
	}

	return true
}

// =============================================================================
// Component 1: Transaction Inclusion Verification
// =============================================================================

func (v *Verifier) verifyTransactionInclusion(proof *CertenAnchorProof, result *VerifyResult) bool {
	inclusion := proof.TransactionInclusion

	// Check required fields
	if inclusion.LeafHash == "" {
		result.Errors = append(result.Errors, "transaction inclusion: leaf hash is empty")
		return false
	}
	if inclusion.MerkleRoot == "" {
		result.Errors = append(result.Errors, "transaction inclusion: merkle root is empty")
		return false
	}
	if inclusion.TreeSize <= 0 {
		result.Errors = append(result.Errors, "transaction inclusion: invalid tree size")
		return false
	}
	if inclusion.LeafIndex < 0 || inclusion.LeafIndex >= inclusion.TreeSize {
		result.Errors = append(result.Errors, "transaction inclusion: leaf index out of range")
		return false
	}

	// Verify the Merkle proof
	valid, err := v.verifyMerkleProof(inclusion)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("transaction inclusion: %v", err))
		return false
	}
	if !valid {
		result.Errors = append(result.Errors, "transaction inclusion: merkle proof verification failed")
		return false
	}

	return true
}

// verifyMerkleProof verifies that the leaf is included in the tree with the given root
func (v *Verifier) verifyMerkleProof(inclusion MerkleInclusionProof) (bool, error) {
	// Decode leaf hash
	leafHash, err := hex.DecodeString(inclusion.LeafHash)
	if err != nil {
		return false, fmt.Errorf("invalid leaf hash: %w", err)
	}
	if len(leafHash) != 32 {
		return false, fmt.Errorf("leaf hash must be 32 bytes, got %d", len(leafHash))
	}

	// Decode expected root
	expectedRoot, err := hex.DecodeString(inclusion.MerkleRoot)
	if err != nil {
		return false, fmt.Errorf("invalid merkle root: %w", err)
	}
	if len(expectedRoot) != 32 {
		return false, fmt.Errorf("merkle root must be 32 bytes, got %d", len(expectedRoot))
	}

	// Start with the leaf hash
	currentHash := leafHash

	// Apply the proof path
	for _, node := range inclusion.Path {
		siblingHash, err := hex.DecodeString(node.Hash)
		if err != nil {
			return false, fmt.Errorf("invalid sibling hash: %w", err)
		}

		// Combine hashes based on position
		var combined []byte
		if node.Position == "left" {
			// Sibling is on the left: H(sibling || current)
			combined = append(siblingHash, currentHash...)
		} else {
			// Sibling is on the right: H(current || sibling)
			combined = append(currentHash, siblingHash...)
		}

		hash := sha256.Sum256(combined)
		currentHash = hash[:]
	}

	// Compare computed root with expected root using constant-time comparison
	// to prevent timing attacks that could leak information about the root
	if len(currentHash) != len(expectedRoot) {
		return false, nil
	}

	// Use constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(currentHash, expectedRoot) != 1 {
		return false, nil
	}

	return true, nil
}

// =============================================================================
// Component 2: Anchor Reference Verification
// =============================================================================

func (v *Verifier) verifyAnchorReference(proof *CertenAnchorProof, result *VerifyResult) bool {
	anchor := proof.AnchorReference

	// Check required fields
	if anchor.TxHash == "" {
		result.Errors = append(result.Errors, "anchor reference: tx hash is empty")
		return false
	}
	if anchor.BlockNumber <= 0 {
		result.Errors = append(result.Errors, "anchor reference: invalid block number")
		return false
	}
	if anchor.Chain == "" {
		result.Errors = append(result.Errors, "anchor reference: chain is empty")
		return false
	}

	// Validate chain type
	switch anchor.Chain {
	case AnchorChainEthereum, AnchorChainBitcoin:
		// Valid chains
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("anchor reference: unknown chain '%s'", anchor.Chain))
		return false
	}

	// Check confirmations
	if anchor.Confirmations < v.config.MinConfirmations {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"anchor reference: insufficient confirmations (got %d, need %d)",
			anchor.Confirmations, v.config.MinConfirmations))
		return false
	}

	// Validate tx hash format (basic check)
	if anchor.Chain == AnchorChainEthereum {
		// Ethereum tx hashes are 66 chars (0x + 64 hex)
		if len(anchor.TxHash) != 66 && len(anchor.TxHash) != 64 {
			result.Errors = append(result.Errors, "anchor reference: invalid ethereum tx hash format")
			return false
		}
	}

	return true
}

// =============================================================================
// Component 3: State Proof Verification (Cryptographic Re-Verification)
// =============================================================================

func (v *Verifier) verifyStateProof(proof *CertenAnchorProof, result *VerifyResult) bool {
	state := &proof.StateProof

	// If state proof is not included
	if !state.Included {
		if v.config.RequireStateProof {
			result.Errors = append(result.Errors, "state proof: required but not included")
			return false
		}
		return true // Not required, not included = OK
	}

	// Perform full cryptographic verification of receipt chains
	// This replaces boolean flag checking with actual Merkle re-computation
	if err := state.Verify(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("state proof: %v", err))
		return false
	}

	return true
}

// =============================================================================
// Component 4: Authority Proof Verification (Cryptographic Re-Verification)
// =============================================================================

func (v *Verifier) verifyAuthorityProof(proof *CertenAnchorProof, result *VerifyResult) bool {
	auth := &proof.AuthorityProof

	// If authority proof is not included
	if !auth.Included {
		if v.config.RequireAuthorityProof {
			result.Errors = append(result.Errors, "authority proof: required but not included")
			return false
		}
		return true // Not required, not included = OK
	}

	// Check governance level
	if v.config.MinGovernanceLevel != GovLevelNone {
		if !v.isGovernanceLevelSufficient(auth.Level, v.config.MinGovernanceLevel) {
			result.Errors = append(result.Errors, fmt.Sprintf(
				"authority proof: governance level %s does not meet minimum %s",
				auth.Level, v.config.MinGovernanceLevel))
			return false
		}
	}

	// Perform full cryptographic verification of Ed25519 signatures
	// This replaces boolean flag checking with actual signature verification
	if err := auth.Verify(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("authority proof: %v", err))
		return false
	}

	return true
}

// isGovernanceLevelSufficient checks if the actual level meets the minimum
func (v *Verifier) isGovernanceLevelSufficient(actual, minimum GovernanceLevel) bool {
	levelOrder := map[GovernanceLevel]int{
		GovLevelNone: 0,
		GovLevelG0:   1,
		GovLevelG1:   2,
		GovLevelG2:   3,
	}
	return levelOrder[actual] >= levelOrder[minimum]
}

// =============================================================================
// Attestation Verification
// =============================================================================

func (v *Verifier) verifyAttestations(proof *CertenAnchorProof, result *VerifyResult) bool {
	attResult, err := v.attestationVerifier.VerifyProofAttestations(proof)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("attestations: verification error: %v", err))
		return false
	}

	// Check if all attestations are valid
	if !attResult.AllValid {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"attestations: %d/%d attestations are invalid",
			attResult.InvalidCount, attResult.TotalCount))
		return false
	}

	// Check if we have enough unique validators
	if attResult.UniqueValidators < v.config.RequiredAttestations {
		result.Errors = append(result.Errors, fmt.Sprintf(
			"attestations: insufficient unique validators (%d/%d)",
			attResult.UniqueValidators, v.config.RequiredAttestations))
		return false
	}

	return true
}

// =============================================================================
// Overall Validity Computation
// =============================================================================

func (v *Verifier) computeOverallValidity(result *VerifyResult) bool {
	// Transaction inclusion and anchor reference are always required
	if !result.TransactionInclusionValid || !result.AnchorReferenceValid {
		return false
	}

	// State proof requirement is configurable
	if v.config.RequireStateProof && !result.StateProofValid {
		return false
	}

	// Authority proof requirement is configurable
	if v.config.RequireAuthorityProof && !result.AuthorityProofValid {
		return false
	}

	// Attestation requirement is configurable
	if v.config.RequiredAttestations > 0 && !result.AttestationsValid {
		return false
	}

	return true
}

// =============================================================================
// Convenience Functions
// =============================================================================

// QuickVerify performs verification with default config
func QuickVerify(proof *CertenAnchorProof) *VerifyResult {
	v := NewVerifier(DefaultVerifierConfig())
	return v.Verify(proof)
}

// VerifyMerkleOnly verifies only the merkle inclusion proof
func VerifyMerkleOnly(proof *CertenAnchorProof) bool {
	v := NewVerifier(VerifierConfig{})
	result := &VerifyResult{}
	return v.verifyTransactionInclusion(proof, result)
}

// VerifyAnchorOnly verifies only the anchor reference
func VerifyAnchorOnly(proof *CertenAnchorProof, minConfirmations int) bool {
	v := NewVerifier(VerifierConfig{MinConfirmations: minConfirmations})
	result := &VerifyResult{}
	return v.verifyAnchorReference(proof, result)
}

// =============================================================================
// Batch Verification
// =============================================================================

// BatchVerifyResult contains results for verifying multiple proofs
type BatchVerifyResult struct {
	Results      []*VerifyResult `json:"results"`
	TotalCount   int             `json:"total_count"`
	ValidCount   int             `json:"valid_count"`
	InvalidCount int             `json:"invalid_count"`
	AllValid     bool            `json:"all_valid"`
	VerifiedAt   time.Time       `json:"verified_at"`
	DurationMs   int64           `json:"duration_ms"`
}

// VerifyBatch verifies multiple proofs
func (v *Verifier) VerifyBatch(proofs []*CertenAnchorProof) *BatchVerifyResult {
	startTime := time.Now()
	result := &BatchVerifyResult{
		Results:    make([]*VerifyResult, len(proofs)),
		TotalCount: len(proofs),
		VerifiedAt: startTime,
	}

	for i, proof := range proofs {
		verifyResult := v.Verify(proof)
		result.Results[i] = verifyResult

		if verifyResult.Valid {
			result.ValidCount++
		} else {
			result.InvalidCount++
		}
	}

	result.AllValid = result.ValidCount == result.TotalCount
	result.DurationMs = time.Since(startTime).Milliseconds()

	return result
}
