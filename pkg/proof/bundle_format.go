// Copyright 2025 Certen Protocol
//
// CertenProofBundle Format v1.0
// Self-contained verification bundle format for external proof retrieval
//
// Per Whitepaper Section 3.4.1, bundles contain four proof components:
// 1. Merkle Inclusion Proof (transaction in batch)
// 2. Anchor Reference (external chain anchor)
// 3. Chained Proof (L1/L2/L3 cryptographic chain)
// 4. Governance Proof (G0/G1/G2 authority validation)

package proof

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	lcproof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof"
)

// BundleVersion is the current bundle format version
const BundleVersion = "1.0"

// BundleSchemaURL is the JSON schema URL for validation
const BundleSchemaURL = "https://certen.io/schemas/proof-bundle/v1.0"

// =============================================================================
// CertenProofBundle - Self-contained verification bundle
// =============================================================================

// CertenProofBundle represents a complete, self-contained proof bundle
// that can be verified offline without network access.
type CertenProofBundle struct {
	// Bundle metadata
	Schema        string    `json:"$schema"`
	BundleVersion string    `json:"bundle_version"`
	BundleID      string    `json:"bundle_id"`
	GeneratedAt   time.Time `json:"generated_at"`

	// Transaction reference
	TransactionRef TransactionReference `json:"transaction_reference"`

	// Four proof components
	ProofComponents ProofComponents `json:"proof_components"`

	// Multi-validator attestations (2/3+1 quorum)
	ValidatorAttestations []ValidatorAttestation `json:"validator_attestations"`

	// Bundle integrity information
	BundleIntegrity BundleIntegrity `json:"bundle_integrity"`
}

// TransactionReference identifies the transaction being proven
type TransactionReference struct {
	AccumTxHash     string `json:"accum_tx_hash"`      // 64-char hex Accumulate tx hash
	AccountURL      string `json:"account_url"`        // acc://... URL
	TransactionType string `json:"transaction_type"`   // e.g., "sendTokens", "writeData"
	Principal       string `json:"principal,omitempty"` // Principal account URL
}

// ProofComponents contains all four proof component types
type ProofComponents struct {
	// Component 1: Merkle Inclusion Proof
	MerkleInclusion *MerkleInclusionProof `json:"1_merkle_inclusion,omitempty"`

	// Component 2: Anchor Reference
	AnchorReference *AnchorReferenceProof `json:"2_anchor_reference,omitempty"`

	// Component 3: Chained Proof (L1/L2/L3)
	ChainedProof *ChainedProofData `json:"3_chained_proof,omitempty"`

	// Component 4: Governance Proof (G0/G1/G2)
	GovernanceProof *GovernanceProof `json:"4_governance_proof,omitempty"`
}

// =============================================================================
// Component 1: Merkle Inclusion Proof
// =============================================================================

// MerkleInclusionProof proves transaction inclusion in a batch
type MerkleInclusionProof struct {
	MerkleRoot string            `json:"merkle_root"` // 32-byte hex root hash
	LeafHash   string            `json:"leaf_hash"`   // 32-byte hex leaf hash
	LeafIndex  int64             `json:"leaf_index"`  // Position in batch
	MerklePath []MerklePathEntry `json:"merkle_path"` // Path from leaf to root
	BatchID    string            `json:"batch_id,omitempty"`
	BatchSize  int               `json:"batch_size,omitempty"`
}

// MerklePathEntry represents a single entry in the Merkle path
type MerklePathEntry struct {
	Hash  string `json:"hash"`  // 32-byte hex sibling hash
	Right bool   `json:"right"` // true if sibling is on the right
}

// =============================================================================
// Component 2: Anchor Reference
// =============================================================================

// AnchorReferenceProof references the external blockchain anchor
type AnchorReferenceProof struct {
	TargetChain       string    `json:"target_chain"`        // "ethereum", "bitcoin", etc.
	AnchorTxHash      string    `json:"anchor_tx_hash"`      // External chain tx hash
	AnchorBlockNumber uint64    `json:"anchor_block_number"` // Block containing anchor
	AnchorBlockHash   string    `json:"anchor_block_hash,omitempty"`
	Confirmations     int       `json:"confirmations"`        // Current confirmations
	RequiredConfs     int       `json:"required_confirmations"` // Required for finality
	AnchoredAt        time.Time `json:"anchored_at"`
	ContractAddress   string    `json:"contract_address,omitempty"` // CertenAnchor contract
}

// =============================================================================
// Component 3: Chained Proof (L1/L2/L3)
// =============================================================================

// ChainedProofData contains the three-layer cryptographic proof
type ChainedProofData struct {
	// Layer 1: Transaction to BVN
	Layer1 *ProofLayer `json:"layer1,omitempty"`

	// Layer 2: BVN to DN
	Layer2 *ProofLayer `json:"layer2,omitempty"`

	// Layer 3: DN to Consensus
	Layer3 *ProofLayer `json:"layer3,omitempty"`

	// Complete proof from lite client (if available)
	CompleteProof *lcproof.CompleteProof `json:"complete_proof,omitempty"`

	// Verification status
	Verified      bool   `json:"verified"`
	VerifiedLevel string `json:"verified_level"` // "layer1", "layer2", "layer3", "complete"
}

// ProofLayer represents a single layer in the chained proof
type ProofLayer struct {
	SourceHash   string            `json:"source_hash"`   // Starting hash
	TargetHash   string            `json:"target_hash"`   // Ending hash
	ReceiptPath  []MerklePathEntry `json:"receipt_path"`  // Merkle path
	BlockHeight  uint64            `json:"block_height"`
	BlockHash    string            `json:"block_hash,omitempty"`
	PartitionID  string            `json:"partition_id,omitempty"` // BVN/DN identifier
	Verified     bool              `json:"verified"`
	VerifiedAt   time.Time         `json:"verified_at,omitempty"`
}

// =============================================================================
// Validator Attestations
// =============================================================================

// ValidatorAttestation represents a validator's attestation to the proof
type ValidatorAttestation struct {
	ValidatorID   string    `json:"validator_id"`
	ValidatorKey  string    `json:"validator_key,omitempty"` // Public key hex
	Signature     string    `json:"signature"`               // 64-byte Ed25519 hex
	SignedHash    string    `json:"signed_hash"`             // Hash that was signed
	AttestedAt    time.Time `json:"attested_at"`
	AttestType    string    `json:"attest_type"`             // "proof_valid", "batch_complete"
}

// =============================================================================
// Bundle Integrity
// =============================================================================

// BundleIntegrity contains integrity verification data
type BundleIntegrity struct {
	ArtifactHash     string `json:"artifact_hash"`      // SHA256 of proof components
	CustodyChainHash string `json:"custody_chain_hash"` // Hash linking to custody chain
	BundleSignature  string `json:"bundle_signature"`   // Coordinator signature
	SignerID         string `json:"signer_id,omitempty"`
}

// =============================================================================
// Bundle Creation and Serialization
// =============================================================================

// NewCertenProofBundle creates a new proof bundle with the given ID
func NewCertenProofBundle(bundleID string) *CertenProofBundle {
	return &CertenProofBundle{
		Schema:                BundleSchemaURL,
		BundleVersion:         BundleVersion,
		BundleID:              bundleID,
		GeneratedAt:           time.Now(),
		ValidatorAttestations: make([]ValidatorAttestation, 0),
	}
}

// SetTransactionRef sets the transaction reference
func (b *CertenProofBundle) SetTransactionRef(txHash, accountURL, txType string) {
	b.TransactionRef = TransactionReference{
		AccumTxHash:     txHash,
		AccountURL:      accountURL,
		TransactionType: txType,
	}
}

// SetMerkleInclusion sets the Merkle inclusion proof component
func (b *CertenProofBundle) SetMerkleInclusion(merkleRoot, leafHash string, leafIndex int64, path []MerklePathEntry) {
	b.ProofComponents.MerkleInclusion = &MerkleInclusionProof{
		MerkleRoot: merkleRoot,
		LeafHash:   leafHash,
		LeafIndex:  leafIndex,
		MerklePath: path,
	}
}

// SetAnchorReference sets the anchor reference proof component
func (b *CertenProofBundle) SetAnchorReference(chain, txHash string, blockNum uint64, confirmations int) {
	b.ProofComponents.AnchorReference = &AnchorReferenceProof{
		TargetChain:       chain,
		AnchorTxHash:      txHash,
		AnchorBlockNumber: blockNum,
		Confirmations:     confirmations,
		RequiredConfs:     12, // Default for Ethereum
		AnchoredAt:        time.Now(),
	}
}

// SetChainedProof sets the chained proof component from a CompleteProof
func (b *CertenProofBundle) SetChainedProof(completeProof *lcproof.CompleteProof) {
	if completeProof == nil {
		return
	}

	b.ProofComponents.ChainedProof = &ChainedProofData{
		CompleteProof: completeProof,
		Verified:      true,
		VerifiedLevel: "complete",
	}

	// Extract layer information if available
	if completeProof.MainChainProof != nil {
		b.ProofComponents.ChainedProof.Layer1 = &ProofLayer{
			SourceHash:  hex.EncodeToString(completeProof.AccountHash),
			TargetHash:  hex.EncodeToString(completeProof.MainChainProof.Anchor),
			BlockHeight: completeProof.BlockHeight,
			BlockHash:   hex.EncodeToString(completeProof.BlockHash),
			Verified:    true,
			VerifiedAt:  time.Now(),
		}
	}

	if completeProof.BVNAnchorProof != nil && completeProof.BVNAnchorProof.Receipt != nil {
		b.ProofComponents.ChainedProof.Layer2 = &ProofLayer{
			SourceHash: hex.EncodeToString(completeProof.BVNAnchorProof.Receipt.Start),
			TargetHash: hex.EncodeToString(completeProof.BVNAnchorProof.Receipt.Anchor),
			Verified:   true,
			VerifiedAt: time.Now(),
		}
	}

	if completeProof.DNAnchorProof != nil && completeProof.DNAnchorProof.Receipt != nil {
		b.ProofComponents.ChainedProof.Layer3 = &ProofLayer{
			SourceHash: hex.EncodeToString(completeProof.DNAnchorProof.Receipt.Start),
			TargetHash: hex.EncodeToString(completeProof.DNAnchorProof.Receipt.Anchor),
			Verified:   true,
			VerifiedAt: time.Now(),
		}
	}
}

// SetGovernanceProof sets the governance proof component
func (b *CertenProofBundle) SetGovernanceProof(govProof *GovernanceProof) {
	b.ProofComponents.GovernanceProof = govProof
}

// AddAttestation adds a validator attestation to the bundle
func (b *CertenProofBundle) AddAttestation(validatorID, signature, signedHash string, attestedAt time.Time) {
	b.ValidatorAttestations = append(b.ValidatorAttestations, ValidatorAttestation{
		ValidatorID: validatorID,
		Signature:   signature,
		SignedHash:  signedHash,
		AttestedAt:  attestedAt,
		AttestType:  "proof_valid",
	})
}

// HasQuorum returns true if attestations meet 2/3+1 quorum
func (b *CertenProofBundle) HasQuorum(totalValidators int) bool {
	required := (totalValidators * 2 / 3) + 1
	return len(b.ValidatorAttestations) >= required
}

// =============================================================================
// Serialization Methods
// =============================================================================

// ToJSON serializes the bundle to JSON
func (b *CertenProofBundle) ToJSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// ToCompressedJSON serializes and gzips the bundle
func (b *CertenProofBundle) ToCompressedJSON() ([]byte, error) {
	jsonData, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(jsonData); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return buf.Bytes(), nil
}

// FromJSON deserializes a bundle from JSON
func BundleFromJSON(data []byte) (*CertenProofBundle, error) {
	var bundle CertenProofBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal bundle: %w", err)
	}
	return &bundle, nil
}

// FromCompressedJSON deserializes a gzipped bundle
func BundleFromCompressedJSON(data []byte) (*CertenProofBundle, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer reader.Close()

	jsonData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read gzip: %w", err)
	}

	return BundleFromJSON(jsonData)
}

// =============================================================================
// Integrity Computation
// =============================================================================

// ComputeArtifactHash computes SHA256 of proof components
func (b *CertenProofBundle) ComputeArtifactHash() (string, error) {
	componentsJSON, err := json.Marshal(b.ProofComponents)
	if err != nil {
		return "", fmt.Errorf("marshal components: %w", err)
	}

	hash := sha256.Sum256(componentsJSON)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// FinalizeIntegrity computes and sets the bundle integrity fields
func (b *CertenProofBundle) FinalizeIntegrity(custodyChainHash, bundleSignature, signerID string) error {
	artifactHash, err := b.ComputeArtifactHash()
	if err != nil {
		return err
	}

	b.BundleIntegrity = BundleIntegrity{
		ArtifactHash:     artifactHash,
		CustodyChainHash: custodyChainHash,
		BundleSignature:  bundleSignature,
		SignerID:         signerID,
	}

	return nil
}

// VerifyIntegrity verifies the bundle's artifact hash matches
func (b *CertenProofBundle) VerifyIntegrity() (bool, error) {
	if b.BundleIntegrity.ArtifactHash == "" {
		return false, fmt.Errorf("no artifact hash set")
	}

	computed, err := b.ComputeArtifactHash()
	if err != nil {
		return false, err
	}

	return computed == b.BundleIntegrity.ArtifactHash, nil
}

// =============================================================================
// Validation Methods
// =============================================================================

// Validate performs structural validation of the bundle
func (b *CertenProofBundle) Validate() []string {
	var errors []string

	if b.BundleID == "" {
		errors = append(errors, "bundle_id is required")
	}

	if b.BundleVersion == "" {
		errors = append(errors, "bundle_version is required")
	}

	if b.TransactionRef.AccumTxHash == "" && b.TransactionRef.AccountURL == "" {
		errors = append(errors, "transaction_reference requires tx_hash or account_url")
	}

	// Validate at least one proof component exists
	hasComponent := b.ProofComponents.MerkleInclusion != nil ||
		b.ProofComponents.AnchorReference != nil ||
		b.ProofComponents.ChainedProof != nil ||
		b.ProofComponents.GovernanceProof != nil

	if !hasComponent {
		errors = append(errors, "at least one proof component is required")
	}

	// Validate Merkle proof if present
	if m := b.ProofComponents.MerkleInclusion; m != nil {
		if len(m.MerkleRoot) != 64 {
			errors = append(errors, "merkle_root must be 64 hex characters")
		}
		if len(m.LeafHash) != 64 {
			errors = append(errors, "leaf_hash must be 64 hex characters")
		}
	}

	// Validate anchor reference if present
	if a := b.ProofComponents.AnchorReference; a != nil {
		if a.TargetChain == "" {
			errors = append(errors, "anchor_reference.target_chain is required")
		}
		if a.AnchorTxHash == "" {
			errors = append(errors, "anchor_reference.anchor_tx_hash is required")
		}
	}

	// Validate governance proof if present
	if g := b.ProofComponents.GovernanceProof; g != nil {
		if !g.IsValid() {
			errors = append(errors, "governance_proof is invalid for its level")
		}
	}

	return errors
}

// IsComplete returns true if all four proof components are present
func (b *CertenProofBundle) IsComplete() bool {
	return b.ProofComponents.MerkleInclusion != nil &&
		b.ProofComponents.AnchorReference != nil &&
		b.ProofComponents.ChainedProof != nil &&
		b.ProofComponents.GovernanceProof != nil
}

// GetCompletionStatus returns which components are present
func (b *CertenProofBundle) GetCompletionStatus() map[string]bool {
	return map[string]bool{
		"merkle_inclusion": b.ProofComponents.MerkleInclusion != nil,
		"anchor_reference": b.ProofComponents.AnchorReference != nil,
		"chained_proof":    b.ProofComponents.ChainedProof != nil,
		"governance_proof": b.ProofComponents.GovernanceProof != nil,
	}
}

// GetSize returns the approximate JSON size in bytes
func (b *CertenProofBundle) GetSize() (int, error) {
	data, err := b.ToJSON()
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
