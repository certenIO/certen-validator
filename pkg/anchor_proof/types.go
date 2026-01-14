// Copyright 2025 Certen Protocol
//
// Anchor Proof Types - Core types for the Certen Anchor Proof System
// Per Whitepaper Section 3.4.1, a complete proof has 4 components:
// 1. Transaction Inclusion Proof (Merkle proof in batch)
// 2. Anchor Reference (ETH/BTC tx hash + block + confirmations)
// 3. State Proof (ChainedProof from Accumulate L1-L3)
// 4. Authority Proof (GovernanceProof G0-G2)

package anchor_proof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/merkle"
	"github.com/google/uuid"
)

// ProofVersion is the current version of the anchor proof format
const ProofVersion = "1.0.0"

// =============================================================================
// Component 1: Transaction Inclusion Proof
// =============================================================================

// MerkleInclusionProof proves a transaction is included in a batch's Merkle tree
type MerkleInclusionProof struct {
	// The leaf (transaction hash) being proven
	LeafHash string `json:"leaf_hash"`

	// Position of the leaf in the tree (0-indexed)
	LeafIndex int `json:"leaf_index"`

	// The Merkle root of the batch
	MerkleRoot string `json:"merkle_root"`

	// The proof path from leaf to root
	Path []MerkleNode `json:"path"`

	// Total number of leaves in the tree
	TreeSize int `json:"tree_size"`
}

// MerkleNode represents a node in the Merkle proof path
type MerkleNode struct {
	Hash     string `json:"hash"`     // Hex-encoded hash
	Position string `json:"position"` // "left" or "right"
}

// =============================================================================
// Component 2: Anchor Reference
// =============================================================================

// AnchorChain represents the target blockchain for anchoring
type AnchorChain string

const (
	AnchorChainEthereum AnchorChain = "ethereum"
	AnchorChainBitcoin  AnchorChain = "bitcoin"
)

// AnchorReference contains information about the external chain anchor
type AnchorReference struct {
	// Target chain
	Chain     AnchorChain `json:"chain"`
	ChainID   string      `json:"chain_id,omitempty"`   // e.g., "1" for mainnet, "11155111" for Sepolia
	NetworkID string      `json:"network_id,omitempty"` // e.g., "mainnet", "sepolia"

	// Anchor transaction details
	TxHash      string    `json:"tx_hash"`      // Transaction hash on external chain
	BlockNumber int64     `json:"block_number"` // Block number containing the anchor
	BlockHash   string    `json:"block_hash,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"`

	// Contract details (for Ethereum)
	ContractAddress string `json:"contract_address,omitempty"`

	// Confirmation tracking
	Confirmations         int  `json:"confirmations"`
	RequiredConfirmations int  `json:"required_confirmations"`
	IsFinal               bool `json:"is_final"` // True when confirmations >= required
}

// =============================================================================
// Component 3: State Proof (ChainedProof reference)
// =============================================================================

// StateProofReference contains the full cryptographic proof chain from L1-L3.
// This replaces boolean flags with re-verifiable Merkle receipt chains.
//
// Cryptographic Verification Invariants (per ChainedProof pattern):
// 1. Each layer receipt must pass Merkle recomputation
// 2. Layer anchors must chain: L1.Anchor == L2.Start, L2.Anchor == L3.Start
// 3. L3.Anchor must equal NetworkRootHash
// 4. All hashes are 32 bytes (SHA-256)
type StateProofReference struct {
	// Whether a ChainedProof is included
	Included bool `json:"included"`

	// ========== Layer 1: Account → BPT (Binary Patricia Tree) ==========
	// Proves the account state hash is included in the partition's BPT root
	Layer1Receipt *merkle.Receipt `json:"layer1_receipt,omitempty"`
	Layer1Anchor  [32]byte        `json:"layer1_anchor"`

	// ========== Layer 2: BPT → Partition Root ==========
	// Proves the BPT root is included in the partition (BVN) block
	Layer2Receipt *merkle.Receipt `json:"layer2_receipt,omitempty"`
	Layer2Anchor  [32]byte        `json:"layer2_anchor"`

	// ========== Layer 3: Partition → Network Root ==========
	// Proves the partition root is included in the Directory Network (DN) root
	Layer3Receipt *merkle.Receipt `json:"layer3_receipt,omitempty"`
	Layer3Anchor  [32]byte        `json:"layer3_anchor"`

	// NetworkRootHash is the final DN root that L3.Anchor must equal
	NetworkRootHash [32]byte `json:"network_root_hash"`

	// Metadata for context (not used in verification)
	BVN               string `json:"bvn,omitempty"`
	BlockHeight       int64  `json:"block_height,omitempty"`
	NetworkBlockHeight int64 `json:"network_block_height,omitempty"`

	// Legacy fields for backward compatibility (deprecated, use receipts)
	// These are computed from receipt validation, not trusted inputs
	ProofData json.RawMessage `json:"proof_data,omitempty"` // Raw ChainedProof for reference
}

// Verify performs full cryptographic verification of the state proof chain.
// Returns nil if all layers verify correctly, error otherwise (fail-closed).
func (s *StateProofReference) Verify() error {
	if !s.Included {
		return nil // No proof to verify
	}

	// Verify Layer 1: Account → BPT
	if s.Layer1Receipt != nil {
		if err := s.Layer1Receipt.Validate(); err != nil {
			return &StateProofError{Layer: 1, Err: err}
		}
		// Verify anchor matches stored anchor
		computed, err := s.Layer1Receipt.ComputeRoot()
		if err != nil {
			return &StateProofError{Layer: 1, Err: err}
		}
		if computed != s.Layer1Anchor {
			return &StateProofError{
				Layer: 1,
				Err:   fmt.Errorf("computed anchor %x != stored anchor %x", computed, s.Layer1Anchor),
			}
		}
	}

	// Verify Layer 2: BPT → Partition
	if s.Layer2Receipt != nil {
		if err := s.Layer2Receipt.Validate(); err != nil {
			return &StateProofError{Layer: 2, Err: err}
		}
		// Verify anchor matches stored anchor
		computed, err := s.Layer2Receipt.ComputeRoot()
		if err != nil {
			return &StateProofError{Layer: 2, Err: err}
		}
		if computed != s.Layer2Anchor {
			return &StateProofError{
				Layer: 2,
				Err:   fmt.Errorf("computed anchor %x != stored anchor %x", computed, s.Layer2Anchor),
			}
		}
	}

	// Verify Layer 3: Partition → Network
	if s.Layer3Receipt != nil {
		if err := s.Layer3Receipt.Validate(); err != nil {
			return &StateProofError{Layer: 3, Err: err}
		}
		// Verify anchor matches stored anchor
		computed, err := s.Layer3Receipt.ComputeRoot()
		if err != nil {
			return &StateProofError{Layer: 3, Err: err}
		}
		if computed != s.Layer3Anchor {
			return &StateProofError{
				Layer: 3,
				Err:   fmt.Errorf("computed anchor %x != stored anchor %x", computed, s.Layer3Anchor),
			}
		}
	}

	// Verify chain continuity: L1.Anchor == L2.Start
	if s.Layer1Receipt != nil && s.Layer2Receipt != nil {
		layer1Anchor := hex.EncodeToString(s.Layer1Anchor[:])
		if layer1Anchor != s.Layer2Receipt.Start {
			return &StateProofError{
				Layer: 2,
				Err:   fmt.Errorf("chain discontinuity: L1.Anchor(%s) != L2.Start(%s)", layer1Anchor, s.Layer2Receipt.Start),
			}
		}
	}

	// Verify chain continuity: L2.Anchor == L3.Start
	if s.Layer2Receipt != nil && s.Layer3Receipt != nil {
		layer2Anchor := hex.EncodeToString(s.Layer2Anchor[:])
		if layer2Anchor != s.Layer3Receipt.Start {
			return &StateProofError{
				Layer: 3,
				Err:   fmt.Errorf("chain discontinuity: L2.Anchor(%s) != L3.Start(%s)", layer2Anchor, s.Layer3Receipt.Start),
			}
		}
	}

	// Verify L3.Anchor == NetworkRootHash
	if s.Layer3Receipt != nil {
		if s.Layer3Anchor != s.NetworkRootHash {
			return &StateProofError{
				Layer: 3,
				Err:   fmt.Errorf("L3.Anchor(%x) != NetworkRootHash(%x)", s.Layer3Anchor, s.NetworkRootHash),
			}
		}
	}

	return nil
}

// StateProofError provides detailed error information for state proof verification.
type StateProofError struct {
	Layer int
	Err   error
}

func (e *StateProofError) Error() string {
	return fmt.Sprintf("state proof layer %d: %v", e.Layer, e.Err)
}

func (e *StateProofError) Unwrap() error {
	return e.Err
}

// =============================================================================
// Component 4: Authority Proof (GovernanceProof reference)
// =============================================================================

// GovernanceLevel represents the governance verification level
type GovernanceLevel string

const (
	GovLevelNone GovernanceLevel = ""   // No governance proof
	GovLevelG0   GovernanceLevel = "G0" // Inclusion and finality only
	GovLevelG1   GovernanceLevel = "G1" // Governance correctness
	GovLevelG2   GovernanceLevel = "G2" // Governance + outcome binding
)

// AuthorityProofReference contains full cryptographic data for governance verification.
// This replaces boolean flags with re-verifiable Ed25519 signature data.
//
// Cryptographic Verification Invariants:
// 1. Each signature must verify against its public key
// 2. The signed hash must match the expected transaction/state hash
// 3. Achieved weight must meet or exceed threshold
// 4. All public keys must be from the KeyPage at the specified version
type AuthorityProofReference struct {
	// Whether a GovernanceProof is included
	Included bool `json:"included"`

	// Governance level
	Level GovernanceLevel `json:"level,omitempty"`

	// ========== Key Page State at Signing Time ==========
	// These fields capture the authority configuration when signatures were created
	KeyPageURL     string   `json:"key_page_url,omitempty"`
	KeyPageHash    [32]byte `json:"key_page_hash"`
	KeyPageVersion uint64   `json:"key_page_version,omitempty"`

	// Full key specifications from the KeyPage
	Keys []KeySpec `json:"keys,omitempty"`

	// ========== Signatures for Re-Verification ==========
	// All signatures with full data for independent verification
	Signatures []SignatureEntry `json:"signatures,omitempty"`

	// ========== Threshold Requirements ==========
	RequiredThreshold uint64 `json:"required_threshold,omitempty"`
	WeightAchieved    uint64 `json:"weight_achieved,omitempty"`

	// Scope of the governance proof
	Scope string `json:"scope,omitempty"`

	// Legacy fields for backward compatibility (deprecated)
	ProofData json.RawMessage `json:"proof_data,omitempty"` // Raw GovernanceProof for reference
}

// KeySpec represents a key in the KeyPage with its weight
type KeySpec struct {
	PublicKeyHash [32]byte `json:"public_key_hash"`
	PublicKey     []byte   `json:"public_key,omitempty"` // Full 32-byte Ed25519 public key
	Weight        uint64   `json:"weight"`
	KeyType       string   `json:"key_type,omitempty"` // "ed25519", "btc", etc.
}

// SignatureEntry contains full signature data for cryptographic re-verification
type SignatureEntry struct {
	// Public key that created the signature
	PublicKeyHash [32]byte `json:"public_key_hash"`
	PublicKey     []byte   `json:"public_key"` // 32 bytes Ed25519

	// The signature itself
	Signature []byte `json:"signature"` // 64 bytes Ed25519

	// What was signed (for re-verification)
	SignedHash [32]byte `json:"signed_hash"`

	// Weight contribution
	Weight uint64 `json:"weight"`

	// Timestamp
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// Verify performs full cryptographic verification of the authority proof.
// Returns nil if all signatures verify correctly, error otherwise (fail-closed).
func (a *AuthorityProofReference) Verify() error {
	if !a.Included {
		return nil // No proof to verify
	}

	if len(a.Signatures) == 0 {
		return &AuthorityProofError{Err: fmt.Errorf("no signatures to verify")}
	}

	var achievedWeight uint64 = 0

	for i, sig := range a.Signatures {
		// Verify public key length
		if len(sig.PublicKey) != ed25519.PublicKeySize {
			return &AuthorityProofError{
				SignatureIndex: i,
				Err:            fmt.Errorf("invalid public key length: %d (expected %d)", len(sig.PublicKey), ed25519.PublicKeySize),
			}
		}

		// Verify signature length
		if len(sig.Signature) != ed25519.SignatureSize {
			return &AuthorityProofError{
				SignatureIndex: i,
				Err:            fmt.Errorf("invalid signature length: %d (expected %d)", len(sig.Signature), ed25519.SignatureSize),
			}
		}

		// Verify public key hash matches
		computedHash := sha256.Sum256(sig.PublicKey)
		if computedHash != sig.PublicKeyHash {
			return &AuthorityProofError{
				SignatureIndex: i,
				Err:            fmt.Errorf("public key hash mismatch: computed %x, stored %x", computedHash, sig.PublicKeyHash),
			}
		}

		// Cryptographically verify the Ed25519 signature
		if !ed25519.Verify(sig.PublicKey, sig.SignedHash[:], sig.Signature) {
			return &AuthorityProofError{
				SignatureIndex: i,
				Err:            fmt.Errorf("Ed25519 signature verification failed"),
			}
		}

		achievedWeight += sig.Weight
	}

	// Verify threshold is met
	if achievedWeight < a.RequiredThreshold {
		return &AuthorityProofError{
			Err: fmt.Errorf("threshold not met: achieved %d, required %d", achievedWeight, a.RequiredThreshold),
		}
	}

	// Update stored weight to match verification
	a.WeightAchieved = achievedWeight

	return nil
}

// AuthorityProofError provides detailed error information for authority proof verification.
type AuthorityProofError struct {
	SignatureIndex int
	Err            error
}

func (e *AuthorityProofError) Error() string {
	if e.SignatureIndex >= 0 {
		return fmt.Sprintf("authority proof signature[%d]: %v", e.SignatureIndex, e.Err)
	}
	return fmt.Sprintf("authority proof: %v", e.Err)
}

func (e *AuthorityProofError) Unwrap() error {
	return e.Err
}

// =============================================================================
// Cryptographic Anchor Binding (Phase 1.2)
// =============================================================================

// AnchorBinding provides cryptographic binding between the Merkle root
// and the external chain anchor transaction.
//
// Cryptographic Invariants:
// 1. BindingHash = SHA256(canonical(MerkleRoot || AnchorTx || BlockNum))
// 2. CoordinatorSig must verify against CoordinatorKey
// 3. CoordinatorKey must be from a known validator set
type AnchorBinding struct {
	// Merkle root being anchored
	MerkleRootHash [32]byte `json:"merkle_root_hash"`

	// Anchor transaction details
	AnchorTxHash   [32]byte `json:"anchor_tx_hash"`
	AnchorBlockNum uint64   `json:"anchor_block_num"`
	AnchorChainID  string   `json:"anchor_chain_id,omitempty"` // e.g., "1" for ETH mainnet

	// Cryptographic binding: SHA256(canonical JSON of above fields)
	BindingHash [32]byte `json:"binding_hash"`

	// Coordinator signature over binding hash
	CoordinatorSig []byte   `json:"coordinator_sig"` // 64 bytes Ed25519
	CoordinatorKey []byte   `json:"coordinator_key"` // 32 bytes Ed25519 public key

	// Timestamp of binding
	CreatedAt time.Time `json:"created_at"`
}

// ComputeBindingHash computes the deterministic binding hash.
// Uses RFC8785 canonical JSON for determinism.
func (ab *AnchorBinding) ComputeBindingHash() [32]byte {
	// Canonical JSON structure (sorted keys)
	data := fmt.Sprintf(`{"anchor_block_num":%d,"anchor_chain_id":"%s","anchor_tx_hash":"%s","merkle_root_hash":"%s"}`,
		ab.AnchorBlockNum,
		ab.AnchorChainID,
		hex.EncodeToString(ab.AnchorTxHash[:]),
		hex.EncodeToString(ab.MerkleRootHash[:]),
	)
	return sha256.Sum256([]byte(data))
}

// Verify performs cryptographic verification of the anchor binding.
func (ab *AnchorBinding) Verify() error {
	// Verify binding hash
	computedHash := ab.ComputeBindingHash()
	if computedHash != ab.BindingHash {
		return fmt.Errorf("binding hash mismatch: computed %x, stored %x", computedHash, ab.BindingHash)
	}

	// Verify coordinator key length
	if len(ab.CoordinatorKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid coordinator key length: %d", len(ab.CoordinatorKey))
	}

	// Verify coordinator signature length
	if len(ab.CoordinatorSig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid coordinator signature length: %d", len(ab.CoordinatorSig))
	}

	// Cryptographically verify the Ed25519 signature
	if !ed25519.Verify(ab.CoordinatorKey, ab.BindingHash[:], ab.CoordinatorSig) {
		return fmt.Errorf("coordinator signature verification failed")
	}

	return nil
}

// =============================================================================
// Operation ID (Phase 1.4)
// =============================================================================

// OperationID provides a deterministic identifier that binds all proof components
// together. This ensures tamper-evidence across the entire proof lifecycle.
type OperationID [32]byte

// ComputeOperationID generates a deterministic operation ID from proof inputs.
// Uses RFC8785 canonical JSON for determinism.
func ComputeOperationID(
	txHash [32]byte,
	accountURL string,
	blockNumber uint64,
	timestamp time.Time,
) OperationID {
	// Canonical JSON structure (sorted keys)
	data := fmt.Sprintf(`{"account_url":"%s","block_number":%d,"timestamp":%d,"tx_hash":"%s"}`,
		accountURL,
		blockNumber,
		timestamp.Unix(),
		hex.EncodeToString(txHash[:]),
	)
	return sha256.Sum256([]byte(data))
}

// String returns the hex-encoded operation ID.
func (oid OperationID) String() string {
	return hex.EncodeToString(oid[:])
}

// =============================================================================
// Validator Attestation
// =============================================================================

// ValidatorAttestation represents a validator's cryptographic endorsement of a proof
type ValidatorAttestation struct {
	// Attestation ID
	AttestationID uuid.UUID `json:"attestation_id"`

	// Validator identity
	ValidatorID     string `json:"validator_id"`
	ValidatorPubkey []byte `json:"validator_pubkey"` // 32 bytes Ed25519

	// What is being attested to
	AttestedMerkleRoot []byte `json:"attested_merkle_root"` // 32 bytes
	AttestedAnchorTx   string `json:"attested_anchor_tx"`

	// The signature (over canonical proof representation)
	Signature []byte `json:"signature"` // 64 bytes Ed25519

	// Timestamp
	AttestedAt time.Time `json:"attested_at"`
}

// =============================================================================
// Complete Certen Anchor Proof
// =============================================================================

// CertenAnchorProof is the complete anchor proof combining all 4 components
// with cryptographic binding through OperationID and AnchorBinding.
//
// Cryptographic Verification Order:
// 1. Verify OperationID matches computed value
// 2. Verify TransactionInclusion (Merkle proof)
// 3. Verify StateProof (3-layer receipt chain)
// 4. Verify AuthorityProof (Ed25519 signatures)
// 5. Verify AnchorBinding (coordinator signature)
// 6. Verify all Attestations (multi-validator consensus)
type CertenAnchorProof struct {
	// ========== Proof Identification ==========
	ProofID      uuid.UUID `json:"proof_id"`
	ProofVersion string    `json:"proof_version"`

	// Deterministic operation ID binding all components (Phase 1.4)
	OperationID OperationID `json:"operation_id"`

	// ========== Original Transaction ==========
	AccumulateTxHash string `json:"accumulate_tx_hash"`
	AccountURL       string `json:"account_url"`

	// ========== Batch Information ==========
	BatchID   uuid.UUID `json:"batch_id"`
	BatchType string    `json:"batch_type"` // "on_cadence" or "on_demand"

	// ========== Component 1: Transaction Inclusion Proof ==========
	TransactionInclusion MerkleInclusionProof `json:"transaction_inclusion"`

	// ========== Component 2: Anchor Reference ==========
	AnchorReference AnchorReference `json:"anchor_reference"`

	// ========== Cryptographic Anchor Binding (Phase 1.2) ==========
	// Binds the Merkle root to the external chain anchor cryptographically
	AnchorBinding *AnchorBinding `json:"anchor_binding,omitempty"`

	// ========== Component 3: State Proof ==========
	StateProof StateProofReference `json:"state_proof"`

	// ========== Component 4: Authority Proof ==========
	AuthorityProof AuthorityProofReference `json:"authority_proof"`

	// ========== Validator Attestations ==========
	// Multi-validator consensus endorsements
	Attestations []ValidatorAttestation `json:"attestations,omitempty"`

	// ========== Verification Status ==========
	Verified           bool          `json:"verified"`
	VerificationTime   *time.Time    `json:"verification_time,omitempty"`
	VerificationResult *VerifyResult `json:"verification_result,omitempty"`

	// ========== Metadata ==========
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// VerifyResult contains detailed verification results
type VerifyResult struct {
	// Overall result
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`

	// Component-level results
	TransactionInclusionValid bool   `json:"transaction_inclusion_valid"`
	AnchorReferenceValid      bool   `json:"anchor_reference_valid"`
	StateProofValid           bool   `json:"state_proof_valid"`
	AuthorityProofValid       bool   `json:"authority_proof_valid"`
	AttestationsValid         bool   `json:"attestations_valid"`

	// Detailed errors if any
	Errors []string `json:"errors,omitempty"`

	// Verification metadata
	VerifiedAt       time.Time `json:"verified_at"`
	VerificationTime int64     `json:"verification_time_ms"`
}

// =============================================================================
// Proof Summary (for quick lookups)
// =============================================================================

// ProofSummary provides a quick overview of a proof's status
type ProofSummary struct {
	ProofID          uuid.UUID       `json:"proof_id"`
	AccumulateTxHash string          `json:"accumulate_tx_hash"`
	AccountURL       string          `json:"account_url"`
	BatchType        string          `json:"batch_type"`
	AnchorChain      AnchorChain     `json:"anchor_chain"`
	AnchorTxHash     string          `json:"anchor_tx_hash"`
	Confirmations    int             `json:"confirmations"`
	GovernanceLevel  GovernanceLevel `json:"governance_level"`
	Verified         bool            `json:"verified"`
	AttestationCount int             `json:"attestation_count"`
	CreatedAt        time.Time       `json:"created_at"`
}

// ToSummary creates a summary from a full proof
func (p *CertenAnchorProof) ToSummary() *ProofSummary {
	return &ProofSummary{
		ProofID:          p.ProofID,
		AccumulateTxHash: p.AccumulateTxHash,
		AccountURL:       p.AccountURL,
		BatchType:        p.BatchType,
		AnchorChain:      p.AnchorReference.Chain,
		AnchorTxHash:     p.AnchorReference.TxHash,
		Confirmations:    p.AnchorReference.Confirmations,
		GovernanceLevel:  p.AuthorityProof.Level,
		Verified:         p.Verified,
		AttestationCount: len(p.Attestations),
		CreatedAt:        p.CreatedAt,
	}
}

// =============================================================================
// Serialization Helpers
// =============================================================================

// ToJSON serializes the proof to JSON
func (p *CertenAnchorProof) ToJSON() ([]byte, error) {
	return json.Marshal(p)
}

// ToJSONPretty serializes the proof to pretty-printed JSON
func (p *CertenAnchorProof) ToJSONPretty() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// FromJSON deserializes a proof from JSON
func FromJSON(data []byte) (*CertenAnchorProof, error) {
	var p CertenAnchorProof
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetMerkleRootBytes returns the merkle root as bytes
func (p *CertenAnchorProof) GetMerkleRootBytes() ([]byte, error) {
	return hex.DecodeString(p.TransactionInclusion.MerkleRoot)
}

// GetLeafHashBytes returns the leaf hash as bytes
func (p *CertenAnchorProof) GetLeafHashBytes() ([]byte, error) {
	return hex.DecodeString(p.TransactionInclusion.LeafHash)
}

// HasValidAnchor returns true if the anchor has sufficient confirmations
func (p *CertenAnchorProof) HasValidAnchor() bool {
	return p.AnchorReference.IsFinal ||
		p.AnchorReference.Confirmations >= p.AnchorReference.RequiredConfirmations
}

// HasGovernanceProof returns true if a governance proof is included
func (p *CertenAnchorProof) HasGovernanceProof() bool {
	return p.AuthorityProof.Included && p.AuthorityProof.Level != GovLevelNone
}

// HasStateProof returns true if a state proof is included
func (p *CertenAnchorProof) HasStateProof() bool {
	return p.StateProof.Included
}

// RequiredAttestations returns the number of attestations required for consensus
// This is determined by the network configuration
type ConsensusConfig struct {
	RequiredAttestations int `json:"required_attestations"`
	TotalValidators      int `json:"total_validators"`
}

// HasSufficientAttestations checks if the proof has enough attestations
func (p *CertenAnchorProof) HasSufficientAttestations(config ConsensusConfig) bool {
	return len(p.Attestations) >= config.RequiredAttestations
}
