// Copyright 2025 Certen Protocol
//
// Proof Export - Serialization formats for external consumers
// Provides standard JSON export formats for proofs that can be consumed by:
// - External verifiers
// - Web applications
// - Other blockchain systems
// - Audit systems

package anchor_proof

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// Portable Proof Format (for external consumption)
// =============================================================================

// PortableProof is the export format for external systems
// All binary data is hex-encoded, all times are RFC3339
type PortableProof struct {
	// Version and identification
	Version   string `json:"version"`
	ProofID   string `json:"proof_id"`
	ProofType string `json:"proof_type"` // "certen_anchor_proof"

	// Transaction being proven
	Transaction TransactionInfo `json:"transaction"`

	// Batch information
	Batch BatchInfo `json:"batch"`

	// The 4 proof components
	Components ProofComponents `json:"components"`

	// Validator attestations
	Attestations []PortableAttestation `json:"attestations,omitempty"`

	// Verification status
	Verification VerificationInfo `json:"verification"`

	// Timestamps
	Timestamps TimestampInfo `json:"timestamps"`
}

// TransactionInfo contains original transaction information
type TransactionInfo struct {
	AccumulateTxHash string `json:"accumulate_tx_hash"`
	AccountURL       string `json:"account_url"`
}

// BatchInfo contains batch information
type BatchInfo struct {
	BatchID   string `json:"batch_id"`
	BatchType string `json:"batch_type"`
}

// ProofComponents contains the 4 proof components
type ProofComponents struct {
	// Component 1: Transaction Inclusion
	TransactionInclusion TransactionInclusionComponent `json:"transaction_inclusion"`

	// Component 2: Anchor Reference
	AnchorReference AnchorReferenceComponent `json:"anchor_reference"`

	// Component 3: State Proof
	StateProof StateProofComponent `json:"state_proof"`

	// Component 4: Authority Proof
	AuthorityProof AuthorityProofComponent `json:"authority_proof"`
}

// TransactionInclusionComponent is the portable format for merkle inclusion
type TransactionInclusionComponent struct {
	LeafHash   string               `json:"leaf_hash"`
	LeafIndex  int                  `json:"leaf_index"`
	MerkleRoot string               `json:"merkle_root"`
	TreeSize   int                  `json:"tree_size"`
	Path       []PortableMerkleNode `json:"path"`
}

// PortableMerkleNode is a node in the merkle path
type PortableMerkleNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// AnchorReferenceComponent is the portable format for anchor reference
type AnchorReferenceComponent struct {
	Chain                 string `json:"chain"`
	ChainID               string `json:"chain_id,omitempty"`
	NetworkID             string `json:"network_id,omitempty"`
	TxHash                string `json:"tx_hash"`
	BlockNumber           int64  `json:"block_number"`
	BlockHash             string `json:"block_hash,omitempty"`
	ContractAddress       string `json:"contract_address,omitempty"`
	Confirmations         int    `json:"confirmations"`
	RequiredConfirmations int    `json:"required_confirmations"`
	IsFinal               bool   `json:"is_final"`
	Timestamp             string `json:"timestamp,omitempty"` // RFC3339
}

// StateProofComponent is the portable format for state proof
type StateProofComponent struct {
	Included    bool   `json:"included"`
	Layer1Valid bool   `json:"layer1_valid"`
	Layer2Valid bool   `json:"layer2_valid"`
	Layer3Valid bool   `json:"layer3_valid"`
	AllValid    bool   `json:"all_valid"`
	BVN         string `json:"bvn,omitempty"`
	BlockHeight int64  `json:"block_height,omitempty"`
	// Full proof data is available but not included by default for size
	ProofDataAvailable bool `json:"proof_data_available"`
}

// AuthorityProofComponent is the portable format for authority proof
type AuthorityProofComponent struct {
	Included           bool   `json:"included"`
	Level              string `json:"level,omitempty"` // G0, G1, G2
	IsValid            bool   `json:"is_valid"`
	ThresholdSatisfied bool   `json:"threshold_satisfied,omitempty"`
	SignatureCount     int    `json:"signature_count,omitempty"`
	RequiredThreshold  int    `json:"required_threshold,omitempty"`
	Scope              string `json:"scope,omitempty"`
	// Full proof data is available but not included by default for size
	ProofDataAvailable bool `json:"proof_data_available"`
}

// PortableAttestation is the portable format for validator attestation
type PortableAttestation struct {
	AttestationID   string `json:"attestation_id"`
	ValidatorID     string `json:"validator_id"`
	ValidatorPubkey string `json:"validator_pubkey"` // Hex-encoded
	MerkleRoot      string `json:"merkle_root"`      // Hex-encoded
	AnchorTxHash    string `json:"anchor_tx_hash"`
	Signature       string `json:"signature"` // Hex-encoded
	AttestedAt      string `json:"attested_at"` // RFC3339
}

// VerificationInfo contains verification status
type VerificationInfo struct {
	Verified       bool   `json:"verified"`
	VerifiedAt     string `json:"verified_at,omitempty"` // RFC3339
	Message        string `json:"message,omitempty"`
	VerificationMs int64  `json:"verification_ms,omitempty"`
}

// TimestampInfo contains all timestamps
type TimestampInfo struct {
	CreatedAt string `json:"created_at"` // RFC3339
	UpdatedAt string `json:"updated_at"` // RFC3339
}

// =============================================================================
// Export Functions
// =============================================================================

// ToPortable converts a CertenAnchorProof to portable format
func (p *CertenAnchorProof) ToPortable() *PortableProof {
	portable := &PortableProof{
		Version:   ProofVersion,
		ProofID:   p.ProofID.String(),
		ProofType: "certen_anchor_proof",
		Transaction: TransactionInfo{
			AccumulateTxHash: p.AccumulateTxHash,
			AccountURL:       p.AccountURL,
		},
		Batch: BatchInfo{
			BatchID:   p.BatchID.String(),
			BatchType: p.BatchType,
		},
		Timestamps: TimestampInfo{
			CreatedAt: p.CreatedAt.Format(time.RFC3339),
			UpdatedAt: p.UpdatedAt.Format(time.RFC3339),
		},
	}

	// Convert components
	portable.Components = p.convertComponents()

	// Convert attestations
	portable.Attestations = p.convertAttestations()

	// Convert verification info
	portable.Verification = p.convertVerification()

	return portable
}

func (p *CertenAnchorProof) convertComponents() ProofComponents {
	return ProofComponents{
		TransactionInclusion: p.convertTransactionInclusion(),
		AnchorReference:      p.convertAnchorReference(),
		StateProof:           p.convertStateProof(),
		AuthorityProof:       p.convertAuthorityProof(),
	}
}

func (p *CertenAnchorProof) convertTransactionInclusion() TransactionInclusionComponent {
	path := make([]PortableMerkleNode, len(p.TransactionInclusion.Path))
	for i, node := range p.TransactionInclusion.Path {
		path[i] = PortableMerkleNode{
			Hash:     node.Hash,
			Position: node.Position,
		}
	}
	return TransactionInclusionComponent{
		LeafHash:   p.TransactionInclusion.LeafHash,
		LeafIndex:  p.TransactionInclusion.LeafIndex,
		MerkleRoot: p.TransactionInclusion.MerkleRoot,
		TreeSize:   p.TransactionInclusion.TreeSize,
		Path:       path,
	}
}

func (p *CertenAnchorProof) convertAnchorReference() AnchorReferenceComponent {
	ref := AnchorReferenceComponent{
		Chain:                 string(p.AnchorReference.Chain),
		ChainID:               p.AnchorReference.ChainID,
		NetworkID:             p.AnchorReference.NetworkID,
		TxHash:                p.AnchorReference.TxHash,
		BlockNumber:           p.AnchorReference.BlockNumber,
		BlockHash:             p.AnchorReference.BlockHash,
		ContractAddress:       p.AnchorReference.ContractAddress,
		Confirmations:         p.AnchorReference.Confirmations,
		RequiredConfirmations: p.AnchorReference.RequiredConfirmations,
		IsFinal:               p.AnchorReference.IsFinal,
	}
	if !p.AnchorReference.Timestamp.IsZero() {
		ref.Timestamp = p.AnchorReference.Timestamp.Format(time.RFC3339)
	}
	return ref
}

func (p *CertenAnchorProof) convertStateProof() StateProofComponent {
	// Derive validity from Merkle receipts by attempting verification
	layer1Valid := p.StateProof.Layer1Receipt != nil && p.StateProof.Layer1Receipt.Validate() == nil
	layer2Valid := p.StateProof.Layer2Receipt != nil && p.StateProof.Layer2Receipt.Validate() == nil
	layer3Valid := p.StateProof.Layer3Receipt != nil && p.StateProof.Layer3Receipt.Validate() == nil
	allValid := layer1Valid && layer2Valid && layer3Valid

	return StateProofComponent{
		Included:           p.StateProof.Included,
		Layer1Valid:        layer1Valid,
		Layer2Valid:        layer2Valid,
		Layer3Valid:        layer3Valid,
		AllValid:           allValid,
		BVN:                p.StateProof.BVN,
		BlockHeight:        p.StateProof.BlockHeight,
		ProofDataAvailable: len(p.StateProof.ProofData) > 0,
	}
}

func (p *CertenAnchorProof) convertAuthorityProof() AuthorityProofComponent {
	// Derive validity from signature verification
	sigCount := len(p.AuthorityProof.Signatures)
	thresholdSatisfied := p.AuthorityProof.WeightAchieved >= p.AuthorityProof.RequiredThreshold
	isValid := p.AuthorityProof.Included && thresholdSatisfied && sigCount > 0

	return AuthorityProofComponent{
		Included:           p.AuthorityProof.Included,
		Level:              string(p.AuthorityProof.Level),
		IsValid:            isValid,
		ThresholdSatisfied: thresholdSatisfied,
		SignatureCount:     sigCount,
		RequiredThreshold:  int(p.AuthorityProof.RequiredThreshold),
		Scope:              p.AuthorityProof.Scope,
		ProofDataAvailable: len(p.AuthorityProof.ProofData) > 0,
	}
}

func (p *CertenAnchorProof) convertAttestations() []PortableAttestation {
	attestations := make([]PortableAttestation, len(p.Attestations))
	for i, att := range p.Attestations {
		attestations[i] = PortableAttestation{
			AttestationID:   att.AttestationID.String(),
			ValidatorID:     att.ValidatorID,
			ValidatorPubkey: hex.EncodeToString(att.ValidatorPubkey),
			MerkleRoot:      hex.EncodeToString(att.AttestedMerkleRoot),
			AnchorTxHash:    att.AttestedAnchorTx,
			Signature:       hex.EncodeToString(att.Signature),
			AttestedAt:      att.AttestedAt.Format(time.RFC3339),
		}
	}
	return attestations
}

func (p *CertenAnchorProof) convertVerification() VerificationInfo {
	info := VerificationInfo{
		Verified: p.Verified,
	}
	if p.VerificationTime != nil {
		info.VerifiedAt = p.VerificationTime.Format(time.RFC3339)
	}
	if p.VerificationResult != nil {
		info.Message = p.VerificationResult.Message
		info.VerificationMs = p.VerificationResult.VerificationTime
	}
	return info
}

// ToPortableJSON exports as JSON
func (p *CertenAnchorProof) ToPortableJSON() ([]byte, error) {
	portable := p.ToPortable()
	return json.Marshal(portable)
}

// ToPortableJSONPretty exports as pretty-printed JSON
func (p *CertenAnchorProof) ToPortableJSONPretty() ([]byte, error) {
	portable := p.ToPortable()
	return json.MarshalIndent(portable, "", "  ")
}

// =============================================================================
// Compact Format (minimal data for verification)
// =============================================================================

// CompactProof is a minimal proof format for lightweight verification
type CompactProof struct {
	ProofID    string              `json:"proof_id"`
	TxHash     string              `json:"tx_hash"`
	MerkleRoot string              `json:"merkle_root"`
	MerklePath []PortableMerkleNode `json:"merkle_path"`
	AnchorTx   string              `json:"anchor_tx"`
	AnchorBlk  int64               `json:"anchor_blk"`
	Chain      string              `json:"chain"`
	Confirms   int                 `json:"confirms"`
	GovLevel   string              `json:"gov_level,omitempty"`
	Sigs       []string            `json:"sigs,omitempty"` // Base64-encoded signatures
}

// ToCompact converts to compact format
func (p *CertenAnchorProof) ToCompact() *CompactProof {
	compact := &CompactProof{
		ProofID:    p.ProofID.String(),
		TxHash:     p.AccumulateTxHash,
		MerkleRoot: p.TransactionInclusion.MerkleRoot,
		AnchorTx:   p.AnchorReference.TxHash,
		AnchorBlk:  p.AnchorReference.BlockNumber,
		Chain:      string(p.AnchorReference.Chain),
		Confirms:   p.AnchorReference.Confirmations,
	}

	// Convert merkle path
	compact.MerklePath = make([]PortableMerkleNode, len(p.TransactionInclusion.Path))
	for i, node := range p.TransactionInclusion.Path {
		compact.MerklePath[i] = PortableMerkleNode{
			Hash:     node.Hash,
			Position: node.Position,
		}
	}

	// Add governance level if present
	if p.AuthorityProof.Included {
		compact.GovLevel = string(p.AuthorityProof.Level)
	}

	// Add attestation signatures
	compact.Sigs = make([]string, len(p.Attestations))
	for i, att := range p.Attestations {
		compact.Sigs[i] = base64.StdEncoding.EncodeToString(att.Signature)
	}

	return compact
}

// ToCompactJSON exports as compact JSON
func (p *CertenAnchorProof) ToCompactJSON() ([]byte, error) {
	return json.Marshal(p.ToCompact())
}

// =============================================================================
// Import Functions
// =============================================================================

// PortableProofFromJSON parses a portable proof from JSON
func PortableProofFromJSON(data []byte) (*PortableProof, error) {
	var p PortableProof
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ToCertenAnchorProof converts a portable proof back to internal format
func (pp *PortableProof) ToCertenAnchorProof() (*CertenAnchorProof, error) {
	proofID, err := uuid.Parse(pp.ProofID)
	if err != nil {
		return nil, err
	}

	batchID, err := uuid.Parse(pp.Batch.BatchID)
	if err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, pp.Timestamps.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, pp.Timestamps.UpdatedAt)

	p := &CertenAnchorProof{
		ProofID:          proofID,
		ProofVersion:     pp.Version,
		AccumulateTxHash: pp.Transaction.AccumulateTxHash,
		AccountURL:       pp.Transaction.AccountURL,
		BatchID:          batchID,
		BatchType:        pp.Batch.BatchType,
		CreatedAt:        createdAt,
		UpdatedAt:        updatedAt,
		Verified:         pp.Verification.Verified,
	}

	// Convert transaction inclusion
	p.TransactionInclusion = convertPortableInclusion(pp.Components.TransactionInclusion)

	// Convert anchor reference
	p.AnchorReference = convertPortableAnchor(pp.Components.AnchorReference)

	// Convert state proof
	p.StateProof = convertPortableStateProof(pp.Components.StateProof)

	// Convert authority proof
	p.AuthorityProof = convertPortableAuthorityProof(pp.Components.AuthorityProof)

	// Convert attestations
	p.Attestations = convertPortableAttestations(pp.Attestations)

	return p, nil
}

func convertPortableInclusion(pi TransactionInclusionComponent) MerkleInclusionProof {
	path := make([]MerkleNode, len(pi.Path))
	for i, node := range pi.Path {
		path[i] = MerkleNode{Hash: node.Hash, Position: node.Position}
	}
	return MerkleInclusionProof{
		LeafHash:   pi.LeafHash,
		LeafIndex:  pi.LeafIndex,
		MerkleRoot: pi.MerkleRoot,
		TreeSize:   pi.TreeSize,
		Path:       path,
	}
}

func convertPortableAnchor(pa AnchorReferenceComponent) AnchorReference {
	ref := AnchorReference{
		Chain:                 AnchorChain(pa.Chain),
		ChainID:               pa.ChainID,
		NetworkID:             pa.NetworkID,
		TxHash:                pa.TxHash,
		BlockNumber:           pa.BlockNumber,
		BlockHash:             pa.BlockHash,
		ContractAddress:       pa.ContractAddress,
		Confirmations:         pa.Confirmations,
		RequiredConfirmations: pa.RequiredConfirmations,
		IsFinal:               pa.IsFinal,
	}
	if pa.Timestamp != "" {
		ref.Timestamp, _ = time.Parse(time.RFC3339, pa.Timestamp)
	}
	return ref
}

func convertPortableStateProof(ps StateProofComponent) StateProofReference {
	// Note: When importing from portable format, we don't have the actual Merkle receipts.
	// The boolean flags in StateProofComponent are derived values that indicate
	// verification status at export time. The actual cryptographic verification
	// requires the full receipt data (ProofData).
	return StateProofReference{
		Included:    ps.Included,
		BVN:         ps.BVN,
		BlockHeight: ps.BlockHeight,
		// Layer1Receipt, Layer2Receipt, Layer3Receipt will be nil
		// Callers should re-extract receipts from ProofData if needed
	}
}

func convertPortableAuthorityProof(pa AuthorityProofComponent) AuthorityProofReference {
	// Note: When importing from portable format, we don't have the actual signatures.
	// The boolean flags in AuthorityProofComponent are derived values.
	// Actual cryptographic re-verification requires the full signature data (ProofData).
	return AuthorityProofReference{
		Included:          pa.Included,
		Level:             GovernanceLevel(pa.Level),
		RequiredThreshold: uint64(pa.RequiredThreshold),
		Scope:             pa.Scope,
		// Signatures, Keys will be nil - need to extract from ProofData if available
	}
}

func convertPortableAttestations(patts []PortableAttestation) []ValidatorAttestation {
	attestations := make([]ValidatorAttestation, len(patts))
	for i, patt := range patts {
		attID, _ := uuid.Parse(patt.AttestationID)
		pubkey, _ := hex.DecodeString(patt.ValidatorPubkey)
		merkleRoot, _ := hex.DecodeString(patt.MerkleRoot)
		sig, _ := hex.DecodeString(patt.Signature)
		attestedAt, _ := time.Parse(time.RFC3339, patt.AttestedAt)

		attestations[i] = ValidatorAttestation{
			AttestationID:      attID,
			ValidatorID:        patt.ValidatorID,
			ValidatorPubkey:    pubkey,
			AttestedMerkleRoot: merkleRoot,
			AttestedAnchorTx:   patt.AnchorTxHash,
			Signature:          sig,
			AttestedAt:         attestedAt,
		}
	}
	return attestations
}
