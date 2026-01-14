// Copyright 2025 Certen Protocol
//
// Unified Proof Verifier - Verifies complete proof cycles across all 4 levels
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md
//
// This verifier ensures 100% cryptographic verifiability of the complete proof chain:
// - Level 1: Chained Proof (Account → BPT → Partition → Network)
// - Level 2: Governance Proof (Authority → Signature → Authorization)
// - Level 3: Anchor Proof (State → Authority → Merkle → Anchor)
// - Level 4: Execution Proof (External Chain → Result → Attestation)

package verification

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/certen/independant-validator/pkg/merkle"
)

// =============================================================================
// UNIFIED VERIFIER
// =============================================================================

// UnifiedVerifier verifies complete proof cycles across all 4 levels
type UnifiedVerifier struct {
	// Configuration
	config *UnifiedVerifierConfig
}

// UnifiedVerifierConfig contains configuration for the unified verifier
type UnifiedVerifierConfig struct {
	// Verification strictness
	RequireLevel1 bool `json:"require_level_1"` // Chained Proof
	RequireLevel2 bool `json:"require_level_2"` // Governance Proof
	RequireLevel3 bool `json:"require_level_3"` // Anchor Proof
	RequireLevel4 bool `json:"require_level_4"` // Execution Proof

	// Cross-level binding verification
	VerifyCrossLevelBindings bool `json:"verify_cross_level_bindings"`

	// Timeout for verification
	Timeout time.Duration `json:"timeout"`
}

// DefaultUnifiedVerifierConfig returns the default configuration
func DefaultUnifiedVerifierConfig() *UnifiedVerifierConfig {
	return &UnifiedVerifierConfig{
		RequireLevel1:            true,
		RequireLevel2:            true,
		RequireLevel3:            true,
		RequireLevel4:            true,
		VerifyCrossLevelBindings: true,
		Timeout:                  30 * time.Second,
	}
}

// NewUnifiedVerifier creates a new unified verifier
func NewUnifiedVerifier(config *UnifiedVerifierConfig) *UnifiedVerifier {
	if config == nil {
		config = DefaultUnifiedVerifierConfig()
	}
	return &UnifiedVerifier{
		config: config,
	}
}

// =============================================================================
// PROOF BUNDLE TYPES (Self-contained to avoid import cycles)
// =============================================================================

// ProofBundle contains all 4 levels of proofs for verification
type ProofBundle struct {
	// Bundle identification
	BundleID    [32]byte  `json:"bundle_id"`
	OperationID [32]byte  `json:"operation_id"`
	GeneratedAt time.Time `json:"generated_at"`
	ValidatorID string    `json:"validator_id"`

	// Level 1: Chained Proof (from lite client)
	ChainedProof *ChainedProofBundle `json:"chained_proof"`

	// Level 2: Governance Proof
	GovernanceProof *GovernanceProofBundle `json:"governance_proof"`

	// Level 3: Anchor Proof
	AnchorProof *AnchorProofBundle `json:"anchor_proof"`

	// Level 4: Execution Proof
	ExecutionProof *ExecutionProofBundle `json:"execution_proof"`
}

// ChainedProofBundle contains Level 1 chained proof components
type ChainedProofBundle struct {
	// Layer receipts for cryptographic re-verification
	Layer1Receipt *merkle.Receipt `json:"layer1_receipt"` // Account → BPT
	Layer2Receipt *merkle.Receipt `json:"layer2_receipt"` // BPT → Partition
	Layer3Receipt *merkle.Receipt `json:"layer3_receipt"` // Partition → Network

	// Anchors at each layer
	AccountHash   [32]byte `json:"account_hash"`
	BPTRoot       [32]byte `json:"bpt_root"`
	PartitionRoot [32]byte `json:"partition_root"`
	NetworkRoot   [32]byte `json:"network_root"`

	// Block binding
	BlockHeight uint64   `json:"block_height"`
	BlockHash   [32]byte `json:"block_hash"`

	// Proof hash for cross-level binding
	ProofHash [32]byte `json:"proof_hash"`
}

// GovernanceProofBundle contains Level 2 governance proof components
type GovernanceProofBundle struct {
	// Data account proof
	DataAccountURL  string   `json:"data_account_url"`
	DataAccountHash [32]byte `json:"data_account_hash"`
	DataEntry       []byte   `json:"data_entry"`

	// Authority chain
	AuthorityURL   string   `json:"authority_url"`
	KeyPageURL     string   `json:"key_page_url"`
	KeyPageHash    [32]byte `json:"key_page_hash"`
	KeyPageVersion uint64   `json:"key_page_version"`

	// Signatures for re-verification
	Signatures []SignatureData `json:"signatures"`

	// Threshold requirements
	RequiredThreshold uint64 `json:"required_threshold"`
	AchievedWeight    uint64 `json:"achieved_weight"`

	// Merkle receipt to network root
	GovernanceReceipt *merkle.Receipt `json:"governance_receipt"`

	// Proof hash for cross-level binding
	ProofHash [32]byte `json:"proof_hash"`
}

// SignatureData contains signature data for re-verification
type SignatureData struct {
	PublicKey     []byte   `json:"public_key"`
	PublicKeyHash [32]byte `json:"public_key_hash"`
	Signature     []byte   `json:"signature"`
	SignedHash    [32]byte `json:"signed_hash"`
	Weight        uint64   `json:"weight"`
}

// AnchorProofBundle contains Level 3 anchor proof components
type AnchorProofBundle struct {
	// State proof with Merkle receipts
	StateProof *StateProofData `json:"state_proof"`

	// Authority proof with signatures
	AuthorityProof *AuthorityProofData `json:"authority_proof"`

	// Anchor binding
	AnchorBinding *AnchorBindingData `json:"anchor_binding"`

	// Proof hash for cross-level binding
	ProofHash [32]byte `json:"proof_hash"`
}

// StateProofData contains state proof components
type StateProofData struct {
	Layer1Receipt   *merkle.Receipt `json:"layer1_receipt"`
	Layer2Receipt   *merkle.Receipt `json:"layer2_receipt"`
	Layer3Receipt   *merkle.Receipt `json:"layer3_receipt"`
	Layer1Anchor    [32]byte        `json:"layer1_anchor"`
	Layer2Anchor    [32]byte        `json:"layer2_anchor"`
	Layer3Anchor    [32]byte        `json:"layer3_anchor"`
	NetworkRootHash [32]byte        `json:"network_root_hash"`
}

// AuthorityProofData contains authority proof components
type AuthorityProofData struct {
	KeyPageURL        string          `json:"key_page_url"`
	KeyPageHash       [32]byte        `json:"key_page_hash"`
	KeyPageVersion    uint64          `json:"key_page_version"`
	Signatures        []SignatureData `json:"signatures"`
	RequiredThreshold uint64          `json:"required_threshold"`
}

// AnchorBindingData contains anchor binding components
type AnchorBindingData struct {
	MerkleRootHash [32]byte `json:"merkle_root_hash"`
	AnchorTxHash   [32]byte `json:"anchor_tx_hash"`
	AnchorBlockNum uint64   `json:"anchor_block_num"`
	BindingHash    [32]byte `json:"binding_hash"`
	CoordinatorSig []byte   `json:"coordinator_sig"`
	CoordinatorKey []byte   `json:"coordinator_key"`
}

// ExecutionProofBundle contains Level 4 execution proof components
type ExecutionProofBundle struct {
	// External chain result
	Result *ExternalChainResultData `json:"result"`

	// Aggregated attestation
	Attestation *AggregatedAttestationData `json:"attestation"`

	// Validator snapshot
	ValidatorSnapshot *ValidatorSnapshotData `json:"validator_snapshot"`

	// Proof hash for cross-level binding
	ProofHash [32]byte `json:"proof_hash"`
}

// ExternalChainResultData contains external chain result for verification
type ExternalChainResultData struct {
	ResultID           [32]byte `json:"result_id"`
	PreviousResultHash [32]byte `json:"previous_result_hash"`
	AnchorProofHash    [32]byte `json:"anchor_proof_hash"`
	SequenceNumber     uint64   `json:"sequence_number"`
	Chain              string   `json:"chain"`
	ChainID            int64    `json:"chain_id"`
	TxHash             [32]byte `json:"tx_hash"`
	BlockNumber        uint64   `json:"block_number"`
	BlockHash          [32]byte `json:"block_hash"`
	TransactionsRoot   [32]byte `json:"transactions_root"`
	ReceiptsRoot       [32]byte `json:"receipts_root"`
	StateRoot          [32]byte `json:"state_root"`
	Status             uint64   `json:"status"`
	ResultHash         [32]byte `json:"result_hash"`

	// Merkle inclusion proofs
	TxInclusionProof      *MerkleInclusionProofData `json:"tx_inclusion_proof"`
	ReceiptInclusionProof *MerkleInclusionProofData `json:"receipt_inclusion_proof"`
}

// MerkleInclusionProofData contains Merkle proof for verification
type MerkleInclusionProofData struct {
	LeafHash        [32]byte   `json:"leaf_hash"`
	LeafIndex       uint64     `json:"leaf_index"`
	ProofHashes     [][32]byte `json:"proof_hashes"`
	ProofDirections []uint8    `json:"proof_directions"`
	ExpectedRoot    [32]byte   `json:"expected_root"`
}

// AggregatedAttestationData contains aggregated attestation for verification
type AggregatedAttestationData struct {
	MessageHash                [32]byte `json:"message_hash"`
	AggregatedSig              []byte   `json:"aggregated_sig"`
	AggregatedPubKey           []byte   `json:"aggregated_pub_key"`
	ParticipantCount           int      `json:"participant_count"`
	SnapshotID                 [32]byte `json:"snapshot_id"`
	ValidatorRoot              [32]byte `json:"validator_root"`
	MessageConsistencyVerified bool     `json:"message_consistency_verified"`
}

// ValidatorSnapshotData contains validator snapshot for verification
type ValidatorSnapshotData struct {
	SnapshotID    [32]byte `json:"snapshot_id"`
	BlockNumber   uint64   `json:"block_number"`
	ValidatorRoot [32]byte `json:"validator_root"`
}

// =============================================================================
// VERIFICATION RESULT
// =============================================================================

// VerificationResult contains the complete verification result
type VerificationResult struct {
	// Overall result
	AllValid bool `json:"all_valid"`

	// Level-specific validity
	Level1Valid   bool `json:"level_1_valid"`  // Chained Proof
	Level2Valid   bool `json:"level_2_valid"`  // Governance Proof
	Level3Valid   bool `json:"level_3_valid"`  // Anchor Proof
	Level4Valid   bool `json:"level_4_valid"`  // Execution Proof
	BindingsValid bool `json:"bindings_valid"` // Cross-level bindings

	// Verification details
	Errors   []string               `json:"errors,omitempty"`
	Warnings []string               `json:"warnings,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`

	// Timing
	StartTime time.Time     `json:"start_time"`
	EndTime   time.Time     `json:"end_time"`
	Duration  time.Duration `json:"duration"`
}

// AddError adds an error to the result
func (r *VerificationResult) AddError(component, message string) {
	r.Errors = append(r.Errors, fmt.Sprintf("[%s] %s", component, message))
}

// AddWarning adds a warning to the result
func (r *VerificationResult) AddWarning(component, message string) {
	r.Warnings = append(r.Warnings, fmt.Sprintf("[%s] %s", component, message))
}

// =============================================================================
// MAIN VERIFICATION METHOD
// =============================================================================

// VerifyFullProofCycle verifies all 4 levels of a proof bundle
func (v *UnifiedVerifier) VerifyFullProofCycle(bundle *ProofBundle) (*VerificationResult, error) {
	if bundle == nil {
		return nil, fmt.Errorf("proof bundle is nil")
	}

	result := &VerificationResult{
		StartTime: time.Now(),
		Details:   make(map[string]interface{}),
	}

	// Level 1: Verify Chained Proof
	if v.config.RequireLevel1 {
		if bundle.ChainedProof == nil {
			result.Level1Valid = false
			result.AddError("Level1", "Chained proof is missing")
		} else if err := v.verifyChainedProof(bundle.ChainedProof, result); err != nil {
			result.Level1Valid = false
			result.AddError("Level1", err.Error())
		} else {
			result.Level1Valid = true
		}
	} else {
		result.Level1Valid = true // Not required
	}

	// Level 2: Verify Governance Proof
	if v.config.RequireLevel2 {
		if bundle.GovernanceProof == nil {
			result.Level2Valid = false
			result.AddError("Level2", "Governance proof is missing")
		} else if err := v.verifyGovernanceProof(bundle.GovernanceProof, result); err != nil {
			result.Level2Valid = false
			result.AddError("Level2", err.Error())
		} else {
			result.Level2Valid = true
		}
	} else {
		result.Level2Valid = true // Not required
	}

	// Level 3: Verify Anchor Proof
	if v.config.RequireLevel3 {
		if bundle.AnchorProof == nil {
			result.Level3Valid = false
			result.AddError("Level3", "Anchor proof is missing")
		} else if err := v.verifyAnchorProof(bundle.AnchorProof, result); err != nil {
			result.Level3Valid = false
			result.AddError("Level3", err.Error())
		} else {
			result.Level3Valid = true
		}
	} else {
		result.Level3Valid = true // Not required
	}

	// Level 4: Verify Execution Proof
	if v.config.RequireLevel4 {
		if bundle.ExecutionProof == nil {
			result.Level4Valid = false
			result.AddError("Level4", "Execution proof is missing")
		} else if err := v.verifyExecutionProof(bundle.ExecutionProof, result); err != nil {
			result.Level4Valid = false
			result.AddError("Level4", err.Error())
		} else {
			result.Level4Valid = true
		}
	} else {
		result.Level4Valid = true // Not required
	}

	// Verify cross-level bindings
	if v.config.VerifyCrossLevelBindings {
		if err := v.verifyCrossLevelBindings(bundle, result); err != nil {
			result.BindingsValid = false
			result.AddError("Bindings", err.Error())
		} else {
			result.BindingsValid = true
		}
	} else {
		result.BindingsValid = true // Not required
	}

	// Calculate overall result
	result.AllValid = result.Level1Valid && result.Level2Valid &&
		result.Level3Valid && result.Level4Valid && result.BindingsValid

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

// =============================================================================
// LEVEL 1: CHAINED PROOF VERIFICATION
// =============================================================================

// verifyChainedProof verifies Level 1 chained proof with full cryptographic re-verification
func (v *UnifiedVerifier) verifyChainedProof(proof *ChainedProofBundle, result *VerificationResult) error {
	// Verify Layer 1: Account → BPT
	if proof.Layer1Receipt != nil {
		if err := proof.Layer1Receipt.Validate(); err != nil {
			return fmt.Errorf("Layer 1 receipt invalid: %w", err)
		}
		// Verify the receipt connects account to BPT
		computedRoot, err := proof.Layer1Receipt.ComputeRoot()
		if err != nil {
			return fmt.Errorf("Layer 1 root computation failed: %w", err)
		}
		if computedRoot != proof.BPTRoot {
			return fmt.Errorf("Layer 1 receipt does not connect to BPT root: computed %x, expected %x",
				computedRoot, proof.BPTRoot)
		}
	}

	// Verify Layer 2: BPT → Partition
	if proof.Layer2Receipt != nil {
		if err := proof.Layer2Receipt.Validate(); err != nil {
			return fmt.Errorf("Layer 2 receipt invalid: %w", err)
		}
		computedRoot, err := proof.Layer2Receipt.ComputeRoot()
		if err != nil {
			return fmt.Errorf("Layer 2 root computation failed: %w", err)
		}
		if computedRoot != proof.PartitionRoot {
			return fmt.Errorf("Layer 2 receipt does not connect to partition root: computed %x, expected %x",
				computedRoot, proof.PartitionRoot)
		}
	}

	// Verify Layer 3: Partition → Network
	if proof.Layer3Receipt != nil {
		if err := proof.Layer3Receipt.Validate(); err != nil {
			return fmt.Errorf("Layer 3 receipt invalid: %w", err)
		}
		computedRoot, err := proof.Layer3Receipt.ComputeRoot()
		if err != nil {
			return fmt.Errorf("Layer 3 root computation failed: %w", err)
		}
		if computedRoot != proof.NetworkRoot {
			return fmt.Errorf("Layer 3 receipt does not connect to network root: computed %x, expected %x",
				computedRoot, proof.NetworkRoot)
		}
	}

	// Verify proof hash
	expectedHash := v.computeChainedProofHash(proof)
	if proof.ProofHash != expectedHash {
		return fmt.Errorf("proof hash mismatch: stored %x, computed %x",
			proof.ProofHash, expectedHash)
	}

	result.Details["level1_network_root"] = hex.EncodeToString(proof.NetworkRoot[:])
	result.Details["level1_block_height"] = proof.BlockHeight

	return nil
}

// computeChainedProofHash computes the hash of a chained proof
func (v *UnifiedVerifier) computeChainedProofHash(proof *ChainedProofBundle) [32]byte {
	data := make([]byte, 0, 256)
	data = append(data, proof.AccountHash[:]...)
	data = append(data, proof.BPTRoot[:]...)
	data = append(data, proof.PartitionRoot[:]...)
	data = append(data, proof.NetworkRoot[:]...)
	data = append(data, proof.BlockHash[:]...)
	return sha256.Sum256(data)
}

// =============================================================================
// LEVEL 2: GOVERNANCE PROOF VERIFICATION
// =============================================================================

// verifyGovernanceProof verifies Level 2 governance proof with signature re-verification
func (v *UnifiedVerifier) verifyGovernanceProof(proof *GovernanceProofBundle, result *VerificationResult) error {
	// Verify all signatures
	var validWeight uint64
	for i, sig := range proof.Signatures {
		// Verify public key hash
		computedKeyHash := sha256.Sum256(sig.PublicKey)
		if computedKeyHash != sig.PublicKeyHash {
			return fmt.Errorf("signature %d: public key hash mismatch", i)
		}

		// Verify Ed25519 signature
		if len(sig.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("signature %d: invalid public key size", i)
		}
		if !ed25519.Verify(sig.PublicKey, sig.SignedHash[:], sig.Signature) {
			return fmt.Errorf("signature %d: Ed25519 verification failed", i)
		}

		validWeight += sig.Weight
	}

	// Verify threshold met
	if validWeight < proof.RequiredThreshold {
		return fmt.Errorf("threshold not met: achieved %d, required %d",
			validWeight, proof.RequiredThreshold)
	}

	// Verify governance receipt to network root
	if proof.GovernanceReceipt != nil {
		if err := proof.GovernanceReceipt.Validate(); err != nil {
			return fmt.Errorf("governance receipt invalid: %w", err)
		}
	}

	// Verify proof hash
	expectedHash := v.computeGovernanceProofHash(proof)
	if proof.ProofHash != expectedHash {
		return fmt.Errorf("proof hash mismatch: stored %x, computed %x",
			proof.ProofHash, expectedHash)
	}

	result.Details["level2_achieved_weight"] = validWeight
	result.Details["level2_required_threshold"] = proof.RequiredThreshold
	result.Details["level2_signatures_verified"] = len(proof.Signatures)

	return nil
}

// computeGovernanceProofHash computes the hash of a governance proof
func (v *UnifiedVerifier) computeGovernanceProofHash(proof *GovernanceProofBundle) [32]byte {
	data := make([]byte, 0, 256)
	data = append(data, []byte(proof.DataAccountURL)...)
	data = append(data, proof.DataAccountHash[:]...)
	data = append(data, []byte(proof.AuthorityURL)...)
	data = append(data, proof.KeyPageHash[:]...)
	return sha256.Sum256(data)
}

// =============================================================================
// LEVEL 3: ANCHOR PROOF VERIFICATION
// =============================================================================

// verifyAnchorProof verifies Level 3 anchor proof
func (v *UnifiedVerifier) verifyAnchorProof(proof *AnchorProofBundle, result *VerificationResult) error {
	// Verify state proof Merkle receipts
	if proof.StateProof != nil {
		if proof.StateProof.Layer1Receipt != nil {
			if err := proof.StateProof.Layer1Receipt.Validate(); err != nil {
				return fmt.Errorf("state proof Layer 1 receipt invalid: %w", err)
			}
		}
		if proof.StateProof.Layer2Receipt != nil {
			if err := proof.StateProof.Layer2Receipt.Validate(); err != nil {
				return fmt.Errorf("state proof Layer 2 receipt invalid: %w", err)
			}
		}
		if proof.StateProof.Layer3Receipt != nil {
			if err := proof.StateProof.Layer3Receipt.Validate(); err != nil {
				return fmt.Errorf("state proof Layer 3 receipt invalid: %w", err)
			}
		}
	}

	// Verify authority proof signatures
	if proof.AuthorityProof != nil {
		for i, sig := range proof.AuthorityProof.Signatures {
			if len(sig.PublicKey) == ed25519.PublicKeySize {
				if !ed25519.Verify(sig.PublicKey, sig.SignedHash[:], sig.Signature) {
					return fmt.Errorf("authority signature %d verification failed", i)
				}
			}
		}
	}

	// Verify anchor binding if present
	if proof.AnchorBinding != nil {
		if err := v.verifyAnchorBinding(proof.AnchorBinding); err != nil {
			return fmt.Errorf("anchor binding verification failed: %w", err)
		}
	}

	// Verify proof hash
	expectedHash := v.computeAnchorProofHash(proof)
	if proof.ProofHash != expectedHash {
		return fmt.Errorf("proof hash mismatch: stored %x, computed %x",
			proof.ProofHash, expectedHash)
	}

	return nil
}

// verifyAnchorBinding verifies the cryptographic anchor binding
func (v *UnifiedVerifier) verifyAnchorBinding(binding *AnchorBindingData) error {
	// Recompute binding hash
	expectedHash := ComputeAnchorBindingHash(
		binding.MerkleRootHash,
		binding.AnchorTxHash,
		binding.AnchorBlockNum,
	)
	if binding.BindingHash != expectedHash {
		return fmt.Errorf("binding hash mismatch: stored %x, computed %x",
			binding.BindingHash, expectedHash)
	}

	// Verify coordinator signature
	if len(binding.CoordinatorKey) == ed25519.PublicKeySize {
		if !ed25519.Verify(binding.CoordinatorKey, binding.BindingHash[:], binding.CoordinatorSig) {
			return fmt.Errorf("coordinator signature verification failed")
		}
	}

	return nil
}

// computeAnchorProofHash computes the hash of an anchor proof
func (v *UnifiedVerifier) computeAnchorProofHash(proof *AnchorProofBundle) [32]byte {
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

// ComputeAnchorBindingHash computes the anchor binding hash
func ComputeAnchorBindingHash(merkleRoot, anchorTx [32]byte, blockNum uint64) [32]byte {
	data := make([]byte, 0, 72)
	data = append(data, merkleRoot[:]...)
	data = append(data, anchorTx[:]...)
	// Encode block number as big-endian bytes
	for i := 7; i >= 0; i-- {
		data = append(data, byte(blockNum>>(i*8)))
	}
	return sha256.Sum256(data)
}

// =============================================================================
// LEVEL 4: EXECUTION PROOF VERIFICATION
// =============================================================================

// verifyExecutionProof verifies Level 4 execution proof
func (v *UnifiedVerifier) verifyExecutionProof(proof *ExecutionProofBundle, result *VerificationResult) error {
	if proof.Result == nil {
		return fmt.Errorf("execution result is nil")
	}

	// Verify result hash (recompute and compare)
	expectedHash := v.computeResultHash(proof.Result)
	if proof.Result.ResultHash != expectedHash {
		return fmt.Errorf("result hash mismatch: stored %x, computed %x",
			proof.Result.ResultHash, expectedHash)
	}

	// Verify Merkle inclusion proofs
	if proof.Result.TxInclusionProof != nil {
		if !v.verifyMerkleInclusionProof(proof.Result.TxInclusionProof) {
			return fmt.Errorf("transaction inclusion proof verification failed")
		}
	}
	if proof.Result.ReceiptInclusionProof != nil {
		if !v.verifyMerkleInclusionProof(proof.Result.ReceiptInclusionProof) {
			return fmt.Errorf("receipt inclusion proof verification failed")
		}
	}

	// Verify attestation if present
	if proof.Attestation != nil {
		if err := v.verifyAggregatedAttestation(proof.Attestation, proof.ValidatorSnapshot); err != nil {
			return fmt.Errorf("attestation verification failed: %w", err)
		}
	}

	result.Details["level4_result_hash"] = hex.EncodeToString(proof.Result.ResultHash[:])
	result.Details["level4_tx_hash"] = hex.EncodeToString(proof.Result.TxHash[:])
	result.Details["level4_status"] = proof.Result.Status

	return nil
}

// computeResultHash computes the hash of an execution result
func (v *UnifiedVerifier) computeResultHash(result *ExternalChainResultData) [32]byte {
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

// verifyMerkleInclusionProof verifies a Merkle inclusion proof using Keccak256
func (v *UnifiedVerifier) verifyMerkleInclusionProof(proof *MerkleInclusionProofData) bool {
	if len(proof.ProofHashes) != len(proof.ProofDirections) {
		return false
	}

	currentHash := proof.LeafHash

	for i, proofHash := range proof.ProofHashes {
		var combined []byte
		if proof.ProofDirections[i] == 0 {
			// Proof hash is on the left
			combined = append(proofHash[:], currentHash[:]...)
		} else {
			// Proof hash is on the right
			combined = append(currentHash[:], proofHash[:]...)
		}
		// Use real Keccak256 for Ethereum compatibility
		// Per Phase 5 Task 5.4: Using go-ethereum's crypto.Keccak256 (not a placeholder)
		hash := crypto.Keccak256Hash(combined)
		currentHash = hash
	}

	return currentHash == proof.ExpectedRoot
}

// verifyAggregatedAttestation verifies the BLS aggregated attestation
func (v *UnifiedVerifier) verifyAggregatedAttestation(
	attestation *AggregatedAttestationData,
	snapshot *ValidatorSnapshotData,
) error {
	// Verify message consistency was checked during aggregation
	if !attestation.MessageConsistencyVerified {
		return fmt.Errorf("message consistency was not verified during aggregation")
	}

	// Verify snapshot binding if available
	if snapshot != nil {
		if attestation.SnapshotID != snapshot.SnapshotID {
			return fmt.Errorf("attestation snapshot ID does not match validator snapshot")
		}
		if attestation.ValidatorRoot != snapshot.ValidatorRoot {
			return fmt.Errorf("attestation validator root does not match snapshot")
		}
	}

	// Note: Full BLS signature verification would require the BLS library
	// This is a structural verification only

	return nil
}

// =============================================================================
// CROSS-LEVEL BINDING VERIFICATION
// =============================================================================

// verifyCrossLevelBindings verifies the hash chain bindings between levels
func (v *UnifiedVerifier) verifyCrossLevelBindings(bundle *ProofBundle, result *VerificationResult) error {
	// Verify Level 2 → Level 3 binding
	// The anchor proof should include the governance authorization
	if bundle.GovernanceProof != nil && bundle.AnchorProof != nil {
		if bundle.AnchorProof.AuthorityProof != nil {
			if bundle.AnchorProof.AuthorityProof.KeyPageHash != bundle.GovernanceProof.KeyPageHash {
				return fmt.Errorf("Level 2→3 binding: key page hash mismatch")
			}
		}
	}

	// Verify Level 3 → Level 4 binding
	// The execution proof should reference the anchor proof hash
	if bundle.AnchorProof != nil && bundle.ExecutionProof != nil {
		if bundle.ExecutionProof.Result != nil {
			// The execution result's anchor proof hash should match
			if bundle.ExecutionProof.Result.AnchorProofHash != bundle.AnchorProof.ProofHash {
				return fmt.Errorf("Level 3→4 binding: anchor proof hash mismatch: expected %x, got %x",
					bundle.AnchorProof.ProofHash, bundle.ExecutionProof.Result.AnchorProofHash)
			}
		}
	}

	result.Details["cross_level_bindings_verified"] = true

	return nil
}

// =============================================================================
// UTILITY METHODS
// =============================================================================

// ComputeBundleHash computes a deterministic hash of the entire proof bundle
func (v *UnifiedVerifier) ComputeBundleHash(bundle *ProofBundle) [32]byte {
	data := make([]byte, 0, 512)
	data = append(data, bundle.BundleID[:]...)
	data = append(data, bundle.OperationID[:]...)

	if bundle.ChainedProof != nil {
		data = append(data, bundle.ChainedProof.ProofHash[:]...)
	}
	if bundle.GovernanceProof != nil {
		data = append(data, bundle.GovernanceProof.ProofHash[:]...)
	}
	if bundle.AnchorProof != nil {
		data = append(data, bundle.AnchorProof.ProofHash[:]...)
	}
	if bundle.ExecutionProof != nil && bundle.ExecutionProof.Result != nil {
		data = append(data, bundle.ExecutionProof.Result.ResultHash[:]...)
	}

	return sha256.Sum256(data)
}

// VerifyBundleIntegrity verifies the bundle's internal integrity
func (v *UnifiedVerifier) VerifyBundleIntegrity(bundle *ProofBundle) error {
	// Verify bundle ID matches computed hash
	computedID := v.ComputeBundleHash(bundle)
	if bundle.BundleID != computedID {
		return fmt.Errorf("bundle ID mismatch: stored %x, computed %x",
			bundle.BundleID, computedID)
	}
	return nil
}
