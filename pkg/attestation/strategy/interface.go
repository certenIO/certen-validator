// Copyright 2025 Certen Protocol
//
// Attestation Strategy Interface - Multi-Scheme Cryptographic Attestation
// Supports BLS12-381, Ed25519, and future attestation schemes
//
// Per Unified Multi-Chain Architecture:
// - Common interface for all attestation schemes
// - Enables pluggable signature aggregation
// - Chain-agnostic attestation collection

package strategy

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// ATTESTATION SCHEME IDENTIFIERS
// =============================================================================

// AttestationScheme identifies the cryptographic scheme used for attestations
type AttestationScheme string

const (
	// AttestationSchemeBLS12381 is BLS12-381 with signature aggregation
	// Used for EVM chains with ZK-verified on-chain aggregation
	AttestationSchemeBLS12381 AttestationScheme = "bls12-381"

	// AttestationSchemeEd25519 is Ed25519 for chains with native support
	// Used for Solana, CosmWasm, Move, TON, NEAR
	AttestationSchemeEd25519 AttestationScheme = "ed25519"

	// AttestationSchemeSchnorr is Schnorr signatures (future)
	AttestationSchemeSchnorr AttestationScheme = "schnorr"

	// AttestationSchemeThreshold is threshold signatures (future)
	AttestationSchemeThreshold AttestationScheme = "threshold"
)

// String returns the string representation of the scheme
func (s AttestationScheme) String() string {
	return string(s)
}

// IsValid checks if the scheme is a known valid scheme
func (s AttestationScheme) IsValid() bool {
	switch s {
	case AttestationSchemeBLS12381, AttestationSchemeEd25519,
		AttestationSchemeSchnorr, AttestationSchemeThreshold:
		return true
	default:
		return false
	}
}

// =============================================================================
// ATTESTATION MESSAGE
// =============================================================================

// AttestationMessage is the canonical message to be signed by validators
// This structure is scheme-agnostic and represents what validators attest to
type AttestationMessage struct {
	// IntentID is the unique identifier of the intent being attested
	IntentID string `json:"intent_id"`

	// ResultHash is the SHA-256 hash of the execution result
	ResultHash [32]byte `json:"result_hash"`

	// AnchorTxHash is the transaction hash of the anchor on the target chain
	AnchorTxHash string `json:"anchor_tx_hash"`

	// BlockNumber is the block number where the anchor was included
	BlockNumber uint64 `json:"block_number"`

	// TargetChain identifies the target blockchain
	TargetChain string `json:"target_chain"`

	// ChainID is the numeric chain ID for EVM chains or string ID for others
	ChainID string `json:"chain_id"`

	// Timestamp is the Unix timestamp when the message was created
	Timestamp int64 `json:"timestamp"`

	// CycleID links to the proof cycle this attestation belongs to
	CycleID string `json:"cycle_id,omitempty"`

	// BundleID is the operation bundle identifier
	BundleID [32]byte `json:"bundle_id,omitempty"`

	// MerkleRoot is the root of the transaction merkle tree (for batches)
	MerkleRoot [32]byte `json:"merkle_root,omitempty"`
}

// Hash computes the canonical hash of the attestation message
// This is what validators actually sign
func (m *AttestationMessage) Hash() [32]byte {
	// Import is avoided to keep interface clean
	// Implementation will use commitment.HashCanonical
	var hash [32]byte
	// Hash computation delegated to strategy implementations
	return hash
}

// =============================================================================
// INDIVIDUAL ATTESTATION
// =============================================================================

// Attestation represents a single validator's attestation over a message
type Attestation struct {
	// AttestationID is the unique identifier for this attestation
	AttestationID uuid.UUID `json:"attestation_id"`

	// Scheme identifies the cryptographic scheme used
	Scheme AttestationScheme `json:"scheme"`

	// ValidatorID is the unique identifier of the attesting validator
	ValidatorID string `json:"validator_id"`

	// ValidatorIndex is the validator's position in the active set
	ValidatorIndex uint32 `json:"validator_index,omitempty"`

	// PublicKey is the validator's public key for this scheme
	// BLS: 96 bytes (G2 point), Ed25519: 32 bytes
	PublicKey []byte `json:"public_key"`

	// Signature is the cryptographic signature
	// BLS: 48 bytes (G1 point), Ed25519: 64 bytes
	Signature []byte `json:"signature"`

	// Message is the attested message
	Message *AttestationMessage `json:"message"`

	// MessageHash is the hash of the message that was signed
	MessageHash [32]byte `json:"message_hash"`

	// Weight is the validator's voting power for quorum calculation
	Weight int64 `json:"weight"`

	// Timestamp when the attestation was created
	Timestamp time.Time `json:"timestamp"`

	// BlockNumber at which attestation was made (for ordering)
	AttestedBlockNumber uint64 `json:"attested_block_number,omitempty"`

	// Verified indicates if the signature has been verified
	Verified bool `json:"verified,omitempty"`

	// VerifiedAt is when the signature was verified
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
}

// =============================================================================
// AGGREGATED ATTESTATION
// =============================================================================

// AggregatedAttestation represents multiple attestations combined
// For BLS: signatures are cryptographically aggregated into one
// For Ed25519: attestations are collected but not cryptographically combined
type AggregatedAttestation struct {
	// AggregationID is the unique identifier for this aggregation
	AggregationID uuid.UUID `json:"aggregation_id"`

	// Scheme identifies the cryptographic scheme used
	Scheme AttestationScheme `json:"scheme"`

	// MessageHash is the hash of the message all validators signed
	MessageHash [32]byte `json:"message_hash"`

	// AggregatedSignature is the combined signature (BLS only)
	// For Ed25519, this is nil as signatures cannot be aggregated
	AggregatedSignature []byte `json:"aggregated_signature,omitempty"`

	// AggregatedPublicKey is the combined public key (BLS only)
	// For Ed25519, this is nil
	AggregatedPublicKey []byte `json:"aggregated_public_key,omitempty"`

	// Attestations holds individual attestations
	// For BLS: kept for audit trail
	// For Ed25519: required for verification (no aggregation)
	Attestations []*Attestation `json:"attestations"`

	// ParticipantIDs lists the validator IDs that participated
	ParticipantIDs []string `json:"participant_ids"`

	// ParticipantCount is the number of validators who signed
	ParticipantCount int `json:"participant_count"`

	// ValidatorBitfield encodes which validators signed (compact representation)
	ValidatorBitfield []byte `json:"validator_bitfield,omitempty"`

	// TotalWeight is the total voting power of all active validators
	TotalWeight int64 `json:"total_weight"`

	// AchievedWeight is the voting power of validators who signed
	AchievedWeight int64 `json:"achieved_weight"`

	// ThresholdWeight is the minimum weight required for consensus
	ThresholdWeight int64 `json:"threshold_weight"`

	// ThresholdMet indicates if consensus threshold was reached
	ThresholdMet bool `json:"threshold_met"`

	// FirstAttestation is the timestamp of the first attestation
	FirstAttestation time.Time `json:"first_attestation"`

	// LastAttestation is the timestamp of the last attestation
	LastAttestation time.Time `json:"last_attestation"`

	// AggregatedAt is when the aggregation was performed
	AggregatedAt time.Time `json:"aggregated_at"`

	// Verified indicates if the aggregated signature has been verified
	Verified bool `json:"verified,omitempty"`

	// VerifiedAt is when the aggregation was verified
	VerifiedAt *time.Time `json:"verified_at,omitempty"`

	// CycleID links to the proof cycle
	CycleID string `json:"cycle_id,omitempty"`

	// ProofID links to the proof artifact
	ProofID *uuid.UUID `json:"proof_id,omitempty"`
}

// =============================================================================
// ATTESTATION STRATEGY INTERFACE
// =============================================================================

// AttestationStrategy defines the interface for all attestation schemes
// Implementations must be thread-safe
type AttestationStrategy interface {
	// Scheme returns the attestation scheme identifier
	Scheme() AttestationScheme

	// Sign creates an attestation for the given message
	// The implementation handles key management and signing
	Sign(ctx context.Context, message *AttestationMessage) (*Attestation, error)

	// Verify verifies a single attestation's signature
	// Returns true if valid, false if invalid, error for failures
	Verify(ctx context.Context, attestation *Attestation) (bool, error)

	// Aggregate combines multiple attestations
	// For BLS: performs cryptographic aggregation
	// For Ed25519: collects attestations without cryptographic combination
	Aggregate(ctx context.Context, attestations []*Attestation) (*AggregatedAttestation, error)

	// VerifyAggregated verifies an aggregated attestation
	// For BLS: verifies the aggregated signature
	// For Ed25519: verifies each individual signature
	VerifyAggregated(ctx context.Context, agg *AggregatedAttestation) (bool, error)

	// SupportsAggregation returns true if the scheme supports signature aggregation
	// BLS: true (signatures can be combined into one)
	// Ed25519: false (signatures must be verified individually)
	SupportsAggregation() bool

	// PublicKey returns this validator's public key for the scheme
	PublicKey() []byte

	// ValidatorID returns the validator identifier
	ValidatorID() string

	// ValidatorIndex returns the validator's index in the active set
	ValidatorIndex() uint32

	// ComputeMessageHash computes the canonical hash of a message for signing
	ComputeMessageHash(message *AttestationMessage) ([32]byte, error)
}

// =============================================================================
// ATTESTATION COLLECTOR INTERFACE
// =============================================================================

// AttestationCollector collects attestations from multiple validators
type AttestationCollector interface {
	// RequestAttestation requests attestation from a specific validator
	RequestAttestation(ctx context.Context, validatorID string, message *AttestationMessage) (*Attestation, error)

	// BroadcastRequest broadcasts attestation request to all known validators
	BroadcastRequest(ctx context.Context, message *AttestationMessage) ([]*Attestation, error)

	// CollectUntilThreshold collects attestations until threshold is met
	// Returns aggregated attestation when threshold is reached or timeout occurs
	CollectUntilThreshold(ctx context.Context, message *AttestationMessage, timeout time.Duration) (*AggregatedAttestation, error)

	// GetCollectedAttestations returns all collected attestations for a message
	GetCollectedAttestations(messageHash [32]byte) []*Attestation

	// AddLocalAttestation adds the local validator's attestation
	AddLocalAttestation(attestation *Attestation) error
}

// =============================================================================
// THRESHOLD CONFIGURATION
// =============================================================================

// ThresholdConfig configures the consensus threshold requirements
type ThresholdConfig struct {
	// Numerator is the threshold numerator (e.g., 2 for 2/3)
	Numerator uint64 `json:"numerator"`

	// Denominator is the threshold denominator (e.g., 3 for 2/3)
	Denominator uint64 `json:"denominator"`

	// MinValidators is the minimum number of validators required
	MinValidators int `json:"min_validators"`
}

// DefaultThresholdConfig returns the default 2/3+1 threshold configuration
func DefaultThresholdConfig() *ThresholdConfig {
	return &ThresholdConfig{
		Numerator:     2,
		Denominator:   3,
		MinValidators: 3,
	}
}

// CalculateThresholdWeight calculates the required weight for consensus
func (c *ThresholdConfig) CalculateThresholdWeight(totalWeight int64) int64 {
	// threshold = (totalWeight * numerator / denominator) + 1
	return (totalWeight*int64(c.Numerator))/int64(c.Denominator) + 1
}

// IsThresholdMet checks if achieved weight meets the threshold
func (c *ThresholdConfig) IsThresholdMet(achievedWeight, totalWeight int64) bool {
	return achievedWeight >= c.CalculateThresholdWeight(totalWeight)
}
