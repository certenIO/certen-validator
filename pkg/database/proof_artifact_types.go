// Copyright 2025 Certen Protocol
//
// Comprehensive Proof Artifact Types
// Per PROOF_SCHEMA_DESIGN.md - Full proof storage schema types

package database

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ProofType classifies the type of proof artifact
type ProofType string

const (
	ProofTypeCertenAnchor ProofType = "certen_anchor"
	ProofTypeChained      ProofType = "chained"
	ProofTypeGovernance   ProofType = "governance"
	ProofTypeMerkle       ProofType = "merkle"
)

// ProofClass identifies the pricing tier for proof generation
type ProofClass string

const (
	ProofClassOnCadence ProofClass = "on_cadence" // ~$0.05/proof - batched
	ProofClassOnDemand  ProofClass = "on_demand"  // ~$0.25/proof - immediate
)

// ProofStatus tracks the lifecycle of a proof
type ProofStatus string

const (
	ProofStatusPending  ProofStatus = "pending"
	ProofStatusBatched  ProofStatus = "batched"
	ProofStatusAnchored ProofStatus = "anchored"
	ProofStatusAttested ProofStatus = "attested"
	ProofStatusVerified ProofStatus = "verified"
	ProofStatusFailed   ProofStatus = "failed"
)

// VerificationStatus tracks verification state
type VerificationStatus string

const (
	VerificationStatusPending  VerificationStatus = "pending"
	VerificationStatusVerified VerificationStatus = "verified"
	VerificationStatusFailed   VerificationStatus = "failed"
)

// ============================================================================
// Core Proof Artifact
// ============================================================================

// ProofArtifact is the master proof registry record
type ProofArtifact struct {
	// Primary Key
	ProofID uuid.UUID `json:"proof_id" db:"proof_id"`

	// Classification
	ProofType    ProofType `json:"proof_type" db:"proof_type"`
	ProofVersion string    `json:"proof_version" db:"proof_version"`

	// Transaction Reference
	AccumTxHash string `json:"accum_tx_hash" db:"accum_tx_hash"`
	AccountURL  string `json:"account_url" db:"account_url"`

	// Batch Reference
	BatchID       *uuid.UUID `json:"batch_id,omitempty" db:"batch_id"`
	BatchPosition *int       `json:"batch_position,omitempty" db:"batch_position"`

	// Anchor Reference
	AnchorID          *uuid.UUID `json:"anchor_id,omitempty" db:"anchor_id"`
	AnchorTxHash      *string    `json:"anchor_tx_hash,omitempty" db:"anchor_tx_hash"`
	AnchorBlockNumber *int64     `json:"anchor_block_number,omitempty" db:"anchor_block_number"`
	AnchorChain       *string    `json:"anchor_chain,omitempty" db:"anchor_chain"`

	// Merkle Inclusion
	MerkleRoot []byte `json:"merkle_root,omitempty" db:"merkle_root"`
	LeafHash   []byte `json:"leaf_hash,omitempty" db:"leaf_hash"`
	LeafIndex  *int   `json:"leaf_index,omitempty" db:"leaf_index"`

	// Governance Level
	GovLevel *GovernanceLevel `json:"gov_level,omitempty" db:"gov_level"`

	// Proof Class
	ProofClass ProofClass `json:"proof_class" db:"proof_class"`

	// Validator Attribution
	ValidatorID string `json:"validator_id" db:"validator_id"`

	// Status
	Status             ProofStatus         `json:"status" db:"status"`
	VerificationStatus *VerificationStatus `json:"verification_status,omitempty" db:"verification_status"`

	// Timestamps
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	AnchoredAt *time.Time `json:"anchored_at,omitempty" db:"anchored_at"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	// Full JSON Artifact
	ArtifactJSON json.RawMessage `json:"artifact_json" db:"artifact_json"`

	// Computed
	ArtifactHash []byte `json:"artifact_hash" db:"artifact_hash"`

	// Intent Tracking (for Firestore linking)
	UserID   *string `json:"user_id,omitempty" db:"user_id"`
	IntentID *string `json:"intent_id,omitempty" db:"intent_id"`
}

// NewProofArtifact is used to create a new proof artifact
type NewProofArtifact struct {
	ProofType    ProofType        `json:"proof_type"`
	AccumTxHash  string           `json:"accum_tx_hash"`
	AccountURL   string           `json:"account_url"`
	BatchID      *uuid.UUID       `json:"batch_id,omitempty"`
	MerkleRoot   []byte           `json:"merkle_root,omitempty"`
	LeafHash     []byte           `json:"leaf_hash,omitempty"`
	LeafIndex    *int             `json:"leaf_index,omitempty"`
	GovLevel     *GovernanceLevel `json:"gov_level,omitempty"`
	ProofClass   ProofClass       `json:"proof_class"`
	ValidatorID  string           `json:"validator_id"`
	ArtifactJSON json.RawMessage  `json:"artifact_json"`
	// Intent Tracking (for Firestore linking)
	UserID   *string `json:"user_id,omitempty"`
	IntentID *string `json:"intent_id,omitempty"`
}

// ============================================================================
// Chained Proof Layers (L1/L2/L3)
// ============================================================================

// ChainedProofLayer represents a single layer of a ChainedProof
type ChainedProofLayer struct {
	LayerID uuid.UUID `json:"layer_id" db:"layer_id"`
	ProofID uuid.UUID `json:"proof_id" db:"proof_id"`

	LayerNumber int    `json:"layer_number" db:"layer_number"`
	LayerName   string `json:"layer_name" db:"layer_name"`

	// Layer 1 Fields
	BVNPartition  *string `json:"bvn_partition,omitempty" db:"bvn_partition"`
	ReceiptAnchor []byte  `json:"receipt_anchor,omitempty" db:"receipt_anchor"`

	// Layer 2 Fields
	BVNRoot        []byte `json:"bvn_root,omitempty" db:"bvn_root"`
	DNRoot         []byte `json:"dn_root,omitempty" db:"dn_root"`
	AnchorSequence *int64 `json:"anchor_sequence,omitempty" db:"anchor_sequence"`
	BVNPartitionID *string `json:"bvn_partition_id,omitempty" db:"bvn_partition_id"`

	// Layer 3 Fields
	DNBlockHash        []byte     `json:"dn_block_hash,omitempty" db:"dn_block_hash"`
	DNBlockHeight      *int64     `json:"dn_block_height,omitempty" db:"dn_block_height"`
	ConsensusTimestamp *time.Time `json:"consensus_timestamp,omitempty" db:"consensus_timestamp"`

	// Full Layer Artifact
	LayerJSON json.RawMessage `json:"layer_json" db:"layer_json"`

	// Verification
	Verified   bool       `json:"verified" db:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewChainedProofLayer is used to create a new layer record
type NewChainedProofLayer struct {
	ProofID            uuid.UUID       `json:"proof_id"`
	LayerNumber        int             `json:"layer_number"`
	LayerName          string          `json:"layer_name"`
	BVNPartition       *string         `json:"bvn_partition,omitempty"`
	ReceiptAnchor      []byte          `json:"receipt_anchor,omitempty"`
	BVNRoot            []byte          `json:"bvn_root,omitempty"`
	DNRoot             []byte          `json:"dn_root,omitempty"`
	AnchorSequence     *int64          `json:"anchor_sequence,omitempty"`
	BVNPartitionID     *string         `json:"bvn_partition_id,omitempty"`
	DNBlockHash        []byte          `json:"dn_block_hash,omitempty"`
	DNBlockHeight      *int64          `json:"dn_block_height,omitempty"`
	ConsensusTimestamp *time.Time      `json:"consensus_timestamp,omitempty"`
	LayerJSON          json.RawMessage `json:"layer_json"`
}

// ============================================================================
// Governance Proof Levels (G0/G1/G2)
// ============================================================================

// GovernanceProofLevel represents a governance proof level
type GovernanceProofLevel struct {
	LevelID uuid.UUID `json:"level_id" db:"level_id"`
	ProofID uuid.UUID `json:"proof_id" db:"proof_id"`

	GovLevel  GovernanceLevel `json:"gov_level" db:"gov_level"`
	LevelName string          `json:"level_name" db:"level_name"`

	// G0 Fields
	BlockHeight       *int64     `json:"block_height,omitempty" db:"block_height"`
	FinalityTimestamp *time.Time `json:"finality_timestamp,omitempty" db:"finality_timestamp"`
	AnchorHeight      *int64     `json:"anchor_height,omitempty" db:"anchor_height"`
	IsAnchored        *bool      `json:"is_anchored,omitempty" db:"is_anchored"`

	// G1 Fields
	AuthorityURL   *string `json:"authority_url,omitempty" db:"authority_url"`
	KeyPageCount   *int    `json:"key_page_count,omitempty" db:"key_page_count"`
	ThresholdM     *int    `json:"threshold_m,omitempty" db:"threshold_m"`
	ThresholdN     *int    `json:"threshold_n,omitempty" db:"threshold_n"`
	SignatureCount *int    `json:"signature_count,omitempty" db:"signature_count"`

	// G2 Fields
	OutcomeType     *string `json:"outcome_type,omitempty" db:"outcome_type"`
	OutcomeHash     []byte  `json:"outcome_hash,omitempty" db:"outcome_hash"`
	BindingEnforced *bool   `json:"binding_enforced,omitempty" db:"binding_enforced"`

	// Full Level Artifact
	LevelJSON json.RawMessage `json:"level_json" db:"level_json"`

	// Verification
	Verified   bool       `json:"verified" db:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewGovernanceProofLevel is used to create a new governance level record
type NewGovernanceProofLevel struct {
	ProofID           uuid.UUID       `json:"proof_id"`
	GovLevel          GovernanceLevel `json:"gov_level"`
	LevelName         string          `json:"level_name"`
	BlockHeight       *int64          `json:"block_height,omitempty"`
	FinalityTimestamp *time.Time      `json:"finality_timestamp,omitempty"`
	AnchorHeight      *int64          `json:"anchor_height,omitempty"`
	IsAnchored        *bool           `json:"is_anchored,omitempty"`
	AuthorityURL      *string         `json:"authority_url,omitempty"`
	KeyPageCount      *int            `json:"key_page_count,omitempty"`
	ThresholdM        *int            `json:"threshold_m,omitempty"`
	ThresholdN        *int            `json:"threshold_n,omitempty"`
	SignatureCount    *int            `json:"signature_count,omitempty"`
	OutcomeType       *string         `json:"outcome_type,omitempty"`
	OutcomeHash       []byte          `json:"outcome_hash,omitempty"`
	BindingEnforced   *bool           `json:"binding_enforced,omitempty"`
	LevelJSON         json.RawMessage `json:"level_json"`
}

// ============================================================================
// Merkle Inclusion Proofs
// ============================================================================

// MerkleInclusionRecord stores merkle path proofs
type MerkleInclusionRecord struct {
	InclusionID uuid.UUID `json:"inclusion_id" db:"inclusion_id"`
	ProofID     uuid.UUID `json:"proof_id" db:"proof_id"`

	MerkleRoot []byte `json:"merkle_root" db:"merkle_root"`
	LeafHash   []byte `json:"leaf_hash" db:"leaf_hash"`
	LeafIndex  int    `json:"leaf_index" db:"leaf_index"`
	TreeSize   int    `json:"tree_size" db:"tree_size"`

	// Merkle Path [{hash, position}]
	MerklePath json.RawMessage `json:"merkle_path" db:"merkle_path"`

	// Verification
	Verified   bool       `json:"verified" db:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// Validator Attestations
// ============================================================================

// ProofAttestation stores multi-validator Ed25519 signatures for the new schema
// Note: This extends the existing ValidatorAttestation with batch support
type ProofAttestation struct {
	AttestationID uuid.UUID `json:"attestation_id" db:"attestation_id"`

	// Parent (one or the other)
	ProofArtifactID *uuid.UUID `json:"proof_artifact_id,omitempty" db:"proof_id"`
	BatchID         *uuid.UUID `json:"batch_id,omitempty" db:"batch_id"`

	// Validator Identity
	ValidatorID     string `json:"validator_id" db:"validator_id"`
	ValidatorPubkey []byte `json:"validator_pubkey" db:"validator_pubkey"` // Ed25519 32 bytes

	// Attestation Data
	AttestedHash []byte `json:"attested_hash" db:"attested_hash"` // SHA256(merkle_root || anchor_tx_hash)
	Signature    []byte `json:"signature" db:"signature"`         // Ed25519 64 bytes

	// Context
	AnchorTxHash *string `json:"anchor_tx_hash,omitempty" db:"anchor_tx_hash"`
	MerkleRoot   []byte  `json:"merkle_root,omitempty" db:"merkle_root"`
	BlockNumber  *int64  `json:"block_number,omitempty" db:"block_number"`

	// Verification
	SignatureValid bool       `json:"signature_valid" db:"signature_valid"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	// Timestamps
	AttestedAt time.Time `json:"attested_at" db:"attested_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// NewProofAttestation is used to create a new attestation in the proof_artifacts schema
type NewProofAttestation struct {
	ProofArtifactID *uuid.UUID `json:"proof_artifact_id,omitempty"`
	BatchID         *uuid.UUID `json:"batch_id,omitempty"`
	ValidatorID     string     `json:"validator_id"`
	ValidatorPubkey []byte     `json:"validator_pubkey"`
	AttestedHash    []byte     `json:"attested_hash"`
	Signature       []byte     `json:"signature"`
	AnchorTxHash    *string    `json:"anchor_tx_hash,omitempty"`
	MerkleRoot      []byte     `json:"merkle_root,omitempty"`
	BlockNumber     *int64     `json:"block_number,omitempty"`
	AttestedAt      time.Time  `json:"attested_at"`
}

// ============================================================================
// Anchor References
// ============================================================================

// AnchorReferenceRecord links proofs to external chain anchors
type AnchorReferenceRecord struct {
	ReferenceID uuid.UUID `json:"reference_id" db:"reference_id"`
	ProofID     uuid.UUID `json:"proof_id" db:"proof_id"`

	// Target Chain
	TargetChain string `json:"target_chain" db:"target_chain"`
	ChainID     string `json:"chain_id" db:"chain_id"`
	NetworkName string `json:"network_name" db:"network_name"`

	// Anchor Transaction
	AnchorTxHash      string     `json:"anchor_tx_hash" db:"anchor_tx_hash"`
	AnchorBlockNumber int64      `json:"anchor_block_number" db:"anchor_block_number"`
	AnchorBlockHash   *string    `json:"anchor_block_hash,omitempty" db:"anchor_block_hash"`
	AnchorTimestamp   *time.Time `json:"anchor_timestamp,omitempty" db:"anchor_timestamp"`

	// Contract Reference
	ContractAddress *string `json:"contract_address,omitempty" db:"contract_address"`

	// Confirmation Status
	Confirmations int        `json:"confirmations" db:"confirmations"`
	IsConfirmed   bool       `json:"is_confirmed" db:"is_confirmed"`
	ConfirmedAt   *time.Time `json:"confirmed_at,omitempty" db:"confirmed_at"`

	// Gas Costs
	GasUsed      *int64  `json:"gas_used,omitempty" db:"gas_used"`
	GasPriceWei  *string `json:"gas_price_wei,omitempty" db:"gas_price_wei"`
	TotalCostWei *string `json:"total_cost_wei,omitempty" db:"total_cost_wei"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// Receipt Steps
// ============================================================================

// ReceiptStep stores individual steps in a merkle receipt path
type ReceiptStep struct {
	StepID  uuid.UUID `json:"step_id" db:"step_id"`
	LayerID uuid.UUID `json:"layer_id" db:"layer_id"`

	StepIndex int    `json:"step_index" db:"step_index"`
	Hash      []byte `json:"hash" db:"hash"`
	IsRight   bool   `json:"is_right" db:"is_right"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// Validated Signatures
// ============================================================================

// ValidatedSignatureRecord stores governance signature verification results
type ValidatedSignatureRecord struct {
	SigID   uuid.UUID `json:"sig_id" db:"sig_id"`
	LevelID uuid.UUID `json:"level_id" db:"level_id"`

	// Signer Identity
	SignerURL string `json:"signer_url" db:"signer_url"`
	KeyHash   []byte `json:"key_hash" db:"key_hash"`
	PublicKey []byte `json:"public_key" db:"public_key"`
	KeyType   string `json:"key_type" db:"key_type"` // ed25519, rcd1, etc.

	// Signature Data
	Signature  []byte `json:"signature" db:"signature"`
	SignedHash []byte `json:"signed_hash" db:"signed_hash"`

	// Validation
	IsValid     bool       `json:"is_valid" db:"is_valid"`
	ValidatedAt *time.Time `json:"validated_at,omitempty" db:"validated_at"`

	// Key Page Reference
	KeyPageIndex *int `json:"key_page_index,omitempty" db:"key_page_index"`
	KeyIndex     *int `json:"key_index,omitempty" db:"key_index"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// Proof Verifications (Audit Log)
// ============================================================================

// ProofVerificationRecord stores verification audit history
type ProofVerificationRecord struct {
	VerificationID uuid.UUID `json:"verification_id" db:"verification_id"`
	ProofID        uuid.UUID `json:"proof_id" db:"proof_id"`

	VerificationType string `json:"verification_type" db:"verification_type"` // merkle, signature, state, governance, full

	// Result
	Passed       bool    `json:"passed" db:"passed"`
	ErrorMessage *string `json:"error_message,omitempty" db:"error_message"`
	ErrorCode    *string `json:"error_code,omitempty" db:"error_code"`

	// Context
	VerifierID         *string `json:"verifier_id,omitempty" db:"verifier_id"`
	VerificationMethod *string `json:"verification_method,omitempty" db:"verification_method"`

	// Performance
	DurationMS *int `json:"duration_ms,omitempty" db:"duration_ms"`

	// Artifacts Checked
	ArtifactsJSON json.RawMessage `json:"artifacts_json,omitempty" db:"artifacts_json"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// ============================================================================
// Query Filters
// ============================================================================

// ProofArtifactFilter defines filters for proof queries
type ProofArtifactFilter struct {
	// Transaction filters
	AccumTxHash *string `json:"accum_tx_hash,omitempty"`
	AccountURL  *string `json:"account_url,omitempty"`

	// Batch/Anchor filters
	BatchID      *uuid.UUID `json:"batch_id,omitempty"`
	AnchorTxHash *string    `json:"anchor_tx_hash,omitempty"`

	// Classification filters
	ProofType  *ProofType       `json:"proof_type,omitempty"`
	GovLevel   *GovernanceLevel `json:"gov_level,omitempty"`
	ProofClass *ProofClass      `json:"proof_class,omitempty"`

	// Status filters
	Status             *ProofStatus        `json:"status,omitempty"`
	VerificationStatus *VerificationStatus `json:"verification_status,omitempty"`

	// Validator filter
	ValidatorID *string `json:"validator_id,omitempty"`

	// Chain filter
	AnchorChain       *string `json:"anchor_chain,omitempty"`
	AnchorBlockNumber *int64  `json:"anchor_block_number,omitempty"`

	// Time range
	CreatedAfter  *time.Time `json:"created_after,omitempty"`
	CreatedBefore *time.Time `json:"created_before,omitempty"`

	// Pagination
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`

	// Bulk filter arrays (for bulk export operations)
	AccountURLs       []string `json:"account_urls,omitempty"`
	Statuses          []string `json:"statuses,omitempty"`
	GovernanceLevels  []string `json:"governance_levels,omitempty"`
	GovernanceLevel   *string  `json:"governance_level,omitempty"`
}

// ============================================================================
// API Response Types
// ============================================================================

// ProofArtifactWithDetails includes related records
type ProofArtifactWithDetails struct {
	ProofArtifact
	ChainedLayers    []ChainedProofLayer       `json:"chained_layers,omitempty"`
	GovernanceLevels []GovernanceProofLevel    `json:"governance_levels,omitempty"`
	Attestations     []ProofAttestation        `json:"attestations,omitempty"`
	AnchorReference  *AnchorReferenceRecord    `json:"anchor_reference,omitempty"`
	Verifications    []ProofVerificationRecord `json:"verifications,omitempty"`
}

// ProofSummary is a lightweight proof listing
type ProofSummary struct {
	ProofID           uuid.UUID       `json:"proof_id"`
	ProofType         ProofType       `json:"proof_type"`
	AccumTxHash       string          `json:"accum_tx_hash"`
	AccountURL        string          `json:"account_url"`
	GovLevel          *GovernanceLevel `json:"gov_level,omitempty"`
	Status            ProofStatus     `json:"status"`
	CreatedAt         time.Time       `json:"created_at"`
	AnchoredAt        *time.Time      `json:"anchored_at,omitempty"`
	AttestationCount  int             `json:"attestation_count"`
}

// BatchProofStats provides statistics for a batch
type BatchProofStats struct {
	BatchID          uuid.UUID `json:"batch_id"`
	ProofCount       int       `json:"proof_count"`
	AttestationCount int       `json:"attestation_count"`
	VerifiedCount    int       `json:"verified_count"`
	FailedCount      int       `json:"failed_count"`
}

// ============================================================================
// Proof Bundle Types (for external retrieval)
// ============================================================================

// ProofBundle represents a self-contained verification bundle
type ProofBundle struct {
	BundleID      uuid.UUID `json:"bundle_id" db:"bundle_id"`
	ProofID       uuid.UUID `json:"proof_id" db:"proof_id"`

	// Bundle metadata
	BundleFormat  string `json:"bundle_format" db:"bundle_format"`   // "certen_v1"
	BundleVersion string `json:"bundle_version" db:"bundle_version"` // "1.0"

	// Bundle data (gzipped JSON)
	BundleData    []byte `json:"bundle_data" db:"bundle_data"`
	BundleHash    []byte `json:"bundle_hash" db:"bundle_hash"` // SHA256 of uncompressed
	BundleSizeBytes int  `json:"bundle_size_bytes" db:"bundle_size_bytes"`

	// Component flags
	IncludesChained    bool `json:"includes_chained" db:"includes_chained"`
	IncludesGovernance bool `json:"includes_governance" db:"includes_governance"`
	IncludesMerkle     bool `json:"includes_merkle" db:"includes_merkle"`
	IncludesAnchor     bool `json:"includes_anchor" db:"includes_anchor"`

	// Attestation count at bundle creation
	AttestationCount int `json:"attestation_count" db:"attestation_count"`

	// Expiration (optional)
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewProofBundle is used to create a new bundle record
type NewProofBundle struct {
	ProofID            uuid.UUID `json:"proof_id"`
	BundleFormat       string    `json:"bundle_format"`
	BundleVersion      string    `json:"bundle_version"`
	BundleData         []byte    `json:"bundle_data"`
	BundleHash         []byte    `json:"bundle_hash"`
	BundleSizeBytes    int       `json:"bundle_size_bytes"`
	IncludesChained    bool      `json:"includes_chained"`
	IncludesGovernance bool      `json:"includes_governance"`
	IncludesMerkle     bool      `json:"includes_merkle"`
	IncludesAnchor     bool      `json:"includes_anchor"`
	AttestationCount   int       `json:"attestation_count"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
}

// CustodyChainEvent represents an audit trail event
type CustodyChainEvent struct {
	EventID       uuid.UUID `json:"event_id" db:"event_id"`
	ProofID       uuid.UUID `json:"proof_id" db:"proof_id"`

	// Event classification
	EventType     string    `json:"event_type" db:"event_type"` // "created", "anchored", "attested", "verified", "retrieved"
	EventTimestamp time.Time `json:"event_timestamp" db:"event_timestamp"`

	// Actor information
	ActorType     string  `json:"actor_type" db:"actor_type"` // "validator", "api", "system", "external"
	ActorID       *string `json:"actor_id,omitempty" db:"actor_id"`

	// Chain hashes
	PreviousHash  []byte `json:"previous_hash,omitempty" db:"previous_hash"`
	CurrentHash   []byte `json:"current_hash" db:"current_hash"`

	// Event details
	EventDetails  json.RawMessage `json:"event_details,omitempty" db:"event_details"`

	// Signature (optional, for validator events)
	Signature     []byte `json:"signature,omitempty" db:"signature"`

	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// NewCustodyChainEvent is used to create a custody chain event
type NewCustodyChainEvent struct {
	ProofID       uuid.UUID       `json:"proof_id"`
	EventType     string          `json:"event_type"`
	ActorType     string          `json:"actor_type"`
	ActorID       *string         `json:"actor_id,omitempty"`
	PreviousHash  []byte          `json:"previous_hash,omitempty"`
	CurrentHash   []byte          `json:"current_hash"`
	EventDetails  json.RawMessage `json:"event_details,omitempty"`
	Signature     []byte          `json:"signature,omitempty"`
}

// APIKey represents an external API key for proof access
type APIKey struct {
	KeyID           uuid.UUID  `json:"key_id" db:"key_id"`
	KeyHash         []byte     `json:"key_hash" db:"key_hash"` // SHA256 of key

	// Client information
	ClientName      string `json:"client_name" db:"client_name"`
	ClientType      string `json:"client_type" db:"client_type"` // "auditor", "service", "institution"

	// Permissions
	CanReadProofs   bool `json:"can_read_proofs" db:"can_read_proofs"`
	CanRequestProofs bool `json:"can_request_proofs" db:"can_request_proofs"`
	CanBulkDownload bool `json:"can_bulk_download" db:"can_bulk_download"`

	// Rate limiting
	RateLimitPerMin int `json:"rate_limit_per_min" db:"rate_limit_per_min"`

	// Status
	IsActive        bool       `json:"is_active" db:"is_active"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Metadata
	Description  *string `json:"description,omitempty" db:"description"`
	ContactEmail *string `json:"contact_email,omitempty" db:"contact_email"`

	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// NewAPIKey is used to create a new API key
type NewAPIKey struct {
	KeyHash          []byte     `json:"key_hash"`
	ClientName       string     `json:"client_name"`
	ClientType       string     `json:"client_type"`
	CanReadProofs    bool       `json:"can_read_proofs"`
	CanRequestProofs bool       `json:"can_request_proofs"`
	CanBulkDownload  bool       `json:"can_bulk_download"`
	RateLimitPerMin  int        `json:"rate_limit_per_min"`
	IsActive         bool       `json:"is_active"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	Description      *string    `json:"description,omitempty"`
	ContactEmail     *string    `json:"contact_email,omitempty"`
}

// BundleProofRequest represents a proof request in the proof_requests table (for bundle handlers)
// Named differently from ProofRequest in types.go to avoid conflict
type BundleProofRequest struct {
	RequestID       uuid.UUID  `json:"request_id" db:"request_id"`
	AccumTxHash     *string    `json:"accum_tx_hash,omitempty" db:"accum_tx_hash"`
	AccountURL      *string    `json:"account_url,omitempty" db:"account_url"`
	ProofClass      string     `json:"proof_class" db:"proof_class"`
	GovernanceLevel *string    `json:"governance_level,omitempty" db:"governance_level"`
	APIKeyID        *uuid.UUID `json:"api_key_id,omitempty" db:"api_key_id"`
	CallbackURL     *string    `json:"callback_url,omitempty" db:"callback_url"`
	Status          string     `json:"status" db:"status"`
	ProofID         *uuid.UUID `json:"proof_id,omitempty" db:"proof_id"`
	ErrorMessage    *string    `json:"error_message,omitempty" db:"error_message"`
	RetryCount      int        `json:"retry_count" db:"retry_count"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	ProcessedAt     *time.Time `json:"processed_at,omitempty" db:"processed_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// NewBundleProofRequest is used to create a new proof request (for bundle handlers)
type NewBundleProofRequest struct {
	AccumTxHash     *string    `json:"accum_tx_hash,omitempty"`
	AccountURL      *string    `json:"account_url,omitempty"`
	ProofClass      string     `json:"proof_class"`
	GovernanceLevel *string    `json:"governance_level,omitempty"`
	APIKeyID        *uuid.UUID `json:"api_key_id,omitempty"`
	CallbackURL     *string    `json:"callback_url,omitempty"`
	Status          string     `json:"status"`
}

// NewBundleDownload is used to record a bundle download
type NewBundleDownload struct {
	BundleID     uuid.UUID  `json:"bundle_id"`
	APIKeyID     *uuid.UUID `json:"api_key_id,omitempty"`
	ClientIP     string     `json:"client_ip"`
	UserAgent    *string    `json:"user_agent,omitempty"`
	ResponseCode int        `json:"response_code"`
	BytesSent    int        `json:"bytes_sent"`
}

// ProofPricingTier defines pricing for proof generation
type ProofPricingTier struct {
	TierID            string    `json:"tier_id" db:"tier_id"`
	TierName          string    `json:"tier_name" db:"tier_name"`
	BaseCostUSD       float64   `json:"base_cost_usd" db:"base_cost_usd"`
	BatchDelaySeconds int       `json:"batch_delay_seconds" db:"batch_delay_seconds"`
	Priority          int       `json:"priority" db:"priority"`
	IsActive          bool      `json:"is_active" db:"is_active"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
}

// BundleDownloadRecord tracks bundle downloads for auditing
type BundleDownloadRecord struct {
	DownloadID  uuid.UUID  `json:"download_id" db:"download_id"`
	BundleID    uuid.UUID  `json:"bundle_id" db:"bundle_id"`
	APIKeyID    *uuid.UUID `json:"api_key_id,omitempty" db:"api_key_id"`

	// Request info
	ClientIP  string `json:"client_ip" db:"client_ip"`
	UserAgent string `json:"user_agent" db:"user_agent"`

	// Response info
	ResponseCode int `json:"response_code" db:"response_code"`
	BytesSent    int `json:"bytes_sent" db:"bytes_sent"`

	DownloadedAt time.Time `json:"downloaded_at" db:"downloaded_at"`
}

// ============================================================================
// LEVEL 4: External Chain Execution Proof Types
// ============================================================================

// ExternalChainResultRecord stores execution results with hash chain binding
type ExternalChainResultRecord struct {
	ResultID uuid.UUID `json:"result_id" db:"result_id"`
	ProofID  uuid.UUID `json:"proof_id" db:"proof_id"`

	// External Chain Reference
	ChainID         string `json:"chain_id" db:"chain_id"`
	ChainName       string `json:"chain_name" db:"chain_name"`
	BlockNumber     int64  `json:"block_number" db:"block_number"`
	BlockHash       []byte `json:"block_hash" db:"block_hash"`
	TransactionHash []byte `json:"transaction_hash" db:"transaction_hash"`

	// Execution Details
	ExecutionStatus uint8  `json:"execution_status" db:"execution_status"`
	GasUsed         int64  `json:"gas_used" db:"gas_used"`
	ReturnData      []byte `json:"return_data,omitempty" db:"return_data"`

	// Patricia/Merkle Proof (Keccak256-based for Ethereum)
	StorageProofJSON json.RawMessage `json:"storage_proof_json,omitempty" db:"storage_proof_json"`
	StorageProofHash []byte          `json:"storage_proof_hash,omitempty" db:"storage_proof_hash"`

	// Hash Chain Binding (RFC8785 canonical JSON)
	SequenceNumber     int64  `json:"sequence_number" db:"sequence_number"`
	PreviousResultHash []byte `json:"previous_result_hash,omitempty" db:"previous_result_hash"`
	ResultHash         []byte `json:"result_hash" db:"result_hash"`

	// Binding to Level 3 Anchor Proof
	AnchorProofHash []byte `json:"anchor_proof_hash" db:"anchor_proof_hash"`

	// Full Artifact
	ArtifactJSON json.RawMessage `json:"artifact_json" db:"artifact_json"`

	// Verification
	Verified   bool       `json:"verified" db:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewExternalChainResult is used to create a new execution result record
type NewExternalChainResult struct {
	ProofID            uuid.UUID       `json:"proof_id"`
	ChainID            string          `json:"chain_id"`
	ChainName          string          `json:"chain_name"`
	BlockNumber        int64           `json:"block_number"`
	BlockHash          []byte          `json:"block_hash"`
	TransactionHash    []byte          `json:"transaction_hash"`
	ExecutionStatus    uint8           `json:"execution_status"`
	GasUsed            int64           `json:"gas_used"`
	ReturnData         []byte          `json:"return_data,omitempty"`
	StorageProofJSON   json.RawMessage `json:"storage_proof_json,omitempty"`
	StorageProofHash   []byte          `json:"storage_proof_hash,omitempty"`
	SequenceNumber     int64           `json:"sequence_number"`
	PreviousResultHash []byte          `json:"previous_result_hash,omitempty"`
	ResultHash         []byte          `json:"result_hash"`
	AnchorProofHash    []byte          `json:"anchor_proof_hash"`
	ArtifactJSON       json.RawMessage `json:"artifact_json"`
}

// BLSAttestationRecord stores individual BLS12-381 attestations
type BLSAttestationRecord struct {
	AttestationID uuid.UUID `json:"attestation_id" db:"attestation_id"`
	ResultID      uuid.UUID `json:"result_id" db:"result_id"`
	SnapshotID    uuid.UUID `json:"snapshot_id" db:"snapshot_id"`

	// Validator Identity
	ValidatorID string `json:"validator_id" db:"validator_id"`
	PublicKey   []byte `json:"public_key" db:"public_key"` // BLS12-381 G2 point (96 bytes compressed)

	// Message Being Attested
	MessageHash []byte `json:"message_hash" db:"message_hash"` // SHA256 of canonical result

	// BLS Signature
	Signature []byte `json:"signature" db:"signature"` // BLS12-381 G1 point (48 bytes compressed)

	// Validator Weight
	Weight int64 `json:"weight" db:"weight"`

	// Subgroup Validation (security check)
	SubgroupValid bool `json:"subgroup_valid" db:"subgroup_valid"`

	// Verification
	SignatureValid bool       `json:"signature_valid" db:"signature_valid"`
	VerifiedAt     *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	AttestedAt time.Time `json:"attested_at" db:"attested_at"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// NewBLSAttestation is used to create a new BLS attestation record
type NewBLSAttestation struct {
	ResultID      uuid.UUID `json:"result_id"`
	SnapshotID    uuid.UUID `json:"snapshot_id"`
	ValidatorID   string    `json:"validator_id"`
	PublicKey     []byte    `json:"public_key"`
	MessageHash   []byte    `json:"message_hash"`
	Signature     []byte    `json:"signature"`
	Weight        int64     `json:"weight"`
	SubgroupValid bool      `json:"subgroup_valid"`
	AttestedAt    time.Time `json:"attested_at"`
}

// AggregatedAttestationRecord stores BLS aggregated attestations
type AggregatedAttestationRecord struct {
	AggregationID uuid.UUID `json:"aggregation_id" db:"aggregation_id"`
	ResultID      uuid.UUID `json:"result_id" db:"result_id"`
	SnapshotID    uuid.UUID `json:"snapshot_id" db:"snapshot_id"`

	// Aggregated Message (must match all individual attestations)
	MessageHash []byte `json:"message_hash" db:"message_hash"`

	// Aggregated BLS Signature
	AggregatedSignature []byte `json:"aggregated_signature" db:"aggregated_signature"` // BLS12-381 G1
	AggregatedPublicKey []byte `json:"aggregated_public_key" db:"aggregated_public_key"` // BLS12-381 G2

	// Participant Information
	ParticipantIDs   json.RawMessage `json:"participant_ids" db:"participant_ids"`     // JSON array of validator IDs
	ParticipantCount int             `json:"participant_count" db:"participant_count"`

	// Weight Calculations
	TotalWeight     int64 `json:"total_weight" db:"total_weight"`
	ThresholdWeight int64 `json:"threshold_weight" db:"threshold_weight"` // 2/3+1 of total
	AchievedWeight  int64 `json:"achieved_weight" db:"achieved_weight"`

	// Threshold Met
	ThresholdMet bool `json:"threshold_met" db:"threshold_met"`

	// Message Consistency Check (all attestations signed same message)
	MessageConsistencyValid bool `json:"message_consistency_valid" db:"message_consistency_valid"`

	// Verification
	AggregationValid bool       `json:"aggregation_valid" db:"aggregation_valid"`
	VerifiedAt       *time.Time `json:"verified_at,omitempty" db:"verified_at"`

	AggregatedAt time.Time `json:"aggregated_at" db:"aggregated_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// NewAggregatedAttestation is used to create a new aggregated attestation record
type NewAggregatedAttestation struct {
	ResultID                uuid.UUID       `json:"result_id"`
	SnapshotID              uuid.UUID       `json:"snapshot_id"`
	MessageHash             []byte          `json:"message_hash"`
	AggregatedSignature     []byte          `json:"aggregated_signature"`
	AggregatedPublicKey     []byte          `json:"aggregated_public_key"`
	ParticipantIDs          json.RawMessage `json:"participant_ids"`
	ParticipantCount        int             `json:"participant_count"`
	TotalWeight             int64           `json:"total_weight"`
	ThresholdWeight         int64           `json:"threshold_weight"`
	AchievedWeight          int64           `json:"achieved_weight"`
	ThresholdMet            bool            `json:"threshold_met"`
	MessageConsistencyValid bool            `json:"message_consistency_valid"`
	AggregatedAt            time.Time       `json:"aggregated_at"`
}

// ValidatorSetSnapshotRecord stores validator set state at attestation time
type ValidatorSetSnapshotRecord struct {
	SnapshotID uuid.UUID `json:"snapshot_id" db:"snapshot_id"`

	// Snapshot Binding
	BlockNumber int64  `json:"block_number" db:"block_number"`
	BlockHash   []byte `json:"block_hash,omitempty" db:"block_hash"`

	// Validator Set
	ValidatorsJSON json.RawMessage `json:"validators_json" db:"validators_json"` // Array of ValidatorEntry

	// Computed Values
	ValidatorRoot   []byte `json:"validator_root" db:"validator_root"` // Merkle root of validators
	ValidatorCount  int    `json:"validator_count" db:"validator_count"`
	TotalWeight     int64  `json:"total_weight" db:"total_weight"`
	ThresholdWeight int64  `json:"threshold_weight" db:"threshold_weight"` // 2/3+1

	// Snapshot Hash (RFC8785 canonical JSON)
	SnapshotHash []byte `json:"snapshot_hash" db:"snapshot_hash"`

	// Chain Reference
	ChainID   string `json:"chain_id" db:"chain_id"`
	ChainName string `json:"chain_name" db:"chain_name"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// NewValidatorSetSnapshot is used to create a new validator set snapshot
type NewValidatorSetSnapshot struct {
	BlockNumber     int64           `json:"block_number"`
	BlockHash       []byte          `json:"block_hash,omitempty"`
	ValidatorsJSON  json.RawMessage `json:"validators_json"`
	ValidatorRoot   []byte          `json:"validator_root"`
	ValidatorCount  int             `json:"validator_count"`
	TotalWeight     int64           `json:"total_weight"`
	ThresholdWeight int64           `json:"threshold_weight"`
	SnapshotHash    []byte          `json:"snapshot_hash"`
	ChainID         string          `json:"chain_id"`
	ChainName       string          `json:"chain_name"`
}

// ValidatorEntry represents a single validator in a snapshot
type ValidatorEntry struct {
	ValidatorID string `json:"validator_id"`
	PublicKey   []byte `json:"public_key"`   // BLS12-381 G2 point
	Weight      int64  `json:"weight"`
	Index       int    `json:"index"`        // Position in validator set
}

// ProofCycleCompletionRecord tracks complete proof cycles through all 4 levels
type ProofCycleCompletionRecord struct {
	CompletionID uuid.UUID `json:"completion_id" db:"completion_id"`
	ProofID      uuid.UUID `json:"proof_id" db:"proof_id"`

	// Level 1: Chained Proof
	Level1Complete bool      `json:"level1_complete" db:"level1_complete"`
	Level1ProofID  uuid.UUID `json:"level1_proof_id,omitempty" db:"level1_proof_id"`
	Level1Hash     []byte    `json:"level1_hash,omitempty" db:"level1_hash"`

	// Level 2: Governance Proof
	Level2Complete bool      `json:"level2_complete" db:"level2_complete"`
	Level2ProofID  uuid.UUID `json:"level2_proof_id,omitempty" db:"level2_proof_id"`
	Level2Hash     []byte    `json:"level2_hash,omitempty" db:"level2_hash"`

	// Level 3: Anchor Proof
	Level3Complete bool      `json:"level3_complete" db:"level3_complete"`
	Level3ProofID  uuid.UUID `json:"level3_proof_id,omitempty" db:"level3_proof_id"`
	Level3Hash     []byte    `json:"level3_hash,omitempty" db:"level3_hash"`

	// Level 4: Execution Proof
	Level4Complete bool      `json:"level4_complete" db:"level4_complete"`
	Level4ResultID uuid.UUID `json:"level4_result_id,omitempty" db:"level4_result_id"`
	Level4Hash     []byte    `json:"level4_hash,omitempty" db:"level4_hash"`

	// Cross-Level Bindings Valid
	BindingsValid bool `json:"bindings_valid" db:"bindings_valid"`

	// Complete Cycle Hash (all levels bound together)
	CycleHash []byte `json:"cycle_hash" db:"cycle_hash"`

	// Cycle Status
	AllLevelsComplete bool `json:"all_levels_complete" db:"all_levels_complete"`

	// Timestamps
	Level1At    *time.Time `json:"level1_at,omitempty" db:"level1_at"`
	Level2At    *time.Time `json:"level2_at,omitempty" db:"level2_at"`
	Level3At    *time.Time `json:"level3_at,omitempty" db:"level3_at"`
	Level4At    *time.Time `json:"level4_at,omitempty" db:"level4_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty" db:"completed_at"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// NewProofCycleCompletion is used to create a new proof cycle completion record
type NewProofCycleCompletion struct {
	ProofID uuid.UUID `json:"proof_id"`
}

// ProofCycleCompletionUpdate is used to update a proof cycle completion record
type ProofCycleCompletionUpdate struct {
	CompletionID      uuid.UUID  `json:"completion_id"`
	Level1Complete    *bool      `json:"level1_complete,omitempty"`
	Level1ProofID     *uuid.UUID `json:"level1_proof_id,omitempty"`
	Level1Hash        []byte     `json:"level1_hash,omitempty"`
	Level2Complete    *bool      `json:"level2_complete,omitempty"`
	Level2ProofID     *uuid.UUID `json:"level2_proof_id,omitempty"`
	Level2Hash        []byte     `json:"level2_hash,omitempty"`
	Level3Complete    *bool      `json:"level3_complete,omitempty"`
	Level3ProofID     *uuid.UUID `json:"level3_proof_id,omitempty"`
	Level3Hash        []byte     `json:"level3_hash,omitempty"`
	Level4Complete    *bool      `json:"level4_complete,omitempty"`
	Level4ResultID    *uuid.UUID `json:"level4_result_id,omitempty"`
	Level4Hash        []byte     `json:"level4_hash,omitempty"`
	BindingsValid     *bool      `json:"bindings_valid,omitempty"`
	CycleHash         []byte     `json:"cycle_hash,omitempty"`
	AllLevelsComplete *bool      `json:"all_levels_complete,omitempty"`
}
