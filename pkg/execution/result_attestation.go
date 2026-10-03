// Copyright 2025 Certen Protocol
//
// Result Attestation Types - Multi-validator consensus on external chain results
// Per CERTEN_COMPLETE_PROOF_CYCLE_SPEC.md Phase 8
//
// These types represent the cryptographic attestations that validators create
// when they observe and verify external chain execution results. BLS signature
// aggregation enables efficient multi-validator consensus.

package execution

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// RESULT ATTESTATION - Validator's Cryptographic Statement
// =============================================================================

// ResultAttestation represents a single validator's attestation of an external
// chain execution result. Each validator independently observes and attests.
type ResultAttestation struct {
	// What is being attested
	ResultHash [32]byte `json:"result_hash"` // Hash of ExternalChainResult
	BundleID   [32]byte `json:"bundle_id"`   // Original bundle that triggered execution

	// Validator identification
	ValidatorID      string         `json:"validator_id"`
	ValidatorAddress common.Address `json:"validator_address"`
	ValidatorIndex   uint32         `json:"validator_index"` // Index in validator set

	// BLS signature over the result
	BLSSignature []byte   `json:"bls_signature"` // BLS signature over message hash
	MessageHash  [32]byte `json:"message_hash"`  // Hash that was signed

	// Attestation metadata
	AttestationTime time.Time `json:"attestation_time"`
	BlockNumber     *big.Int  `json:"block_number"`  // External chain block observed
	Confirmations   int       `json:"confirmations"` // Block confirmations at attestation time

	// Verification status
	Verified bool `json:"verified"`
}

// =============================================================================
// AGGREGATED ATTESTATION - Combined Multi-Validator Attestation
// =============================================================================

// AggregatedAttestation combines multiple validator attestations with an
// aggregated BLS signature. This is what gets recorded on-chain.
type AggregatedAttestation struct {
	// Core data (same across all attestations)
	ResultHash  [32]byte `json:"result_hash"`
	BundleID    [32]byte `json:"bundle_id"`
	BlockNumber *big.Int `json:"block_number"`
	MessageHash [32]byte `json:"message_hash"`

	// Aggregated BLS signature
	AggregateSignature []byte `json:"aggregate_signature"`

	// Validator set snapshot binding (Phase 2.2)
	// Binds the attestation to a specific validator set to prevent replay
	SnapshotID    [32]byte `json:"snapshot_id"`
	ValidatorRoot [32]byte `json:"validator_root"` // Merkle root of validators at attestation time

	// Participating validators
	ValidatorBitfield  []byte           `json:"validator_bitfield"`  // Bitmap of participating validators
	ValidatorCount     int              `json:"validator_count"`     // Number of validators who attested
	ValidatorAddresses []common.Address `json:"validator_addresses"` // Ordered list of attestors

	// Voting power tracking
	TotalVotingPower     *big.Int `json:"total_voting_power"`    // Total power in validator set
	SignedVotingPower    *big.Int `json:"signed_voting_power"`   // Power of attestors
	ThresholdNumerator   uint64   `json:"threshold_numerator"`   // e.g., 2
	ThresholdDenominator uint64   `json:"threshold_denominator"` // e.g., 3

	// What a third party needs to verify the quorum from the write-back alone (RB5-F14): the exact message signed
	// (sha256(MessagePreimage) == MessageHash), the snapshot's validators and block, the minimum signer count, the
	// signature scheme and its domain.
	MessagePreimage   []byte               `json:"message_preimage,omitempty"`
	Validators        []WriteBackValidator `json:"validators,omitempty"`
	SnapshotBlock     uint64               `json:"snapshot_block,omitempty"`
	MinValidators     int                  `json:"min_validators,omitempty"`
	SignatureScheme   string               `json:"signature_scheme,omitempty"`
	AttestationDomain string               `json:"attestation_domain,omitempty"`

	// Timing
	FirstAttestation time.Time `json:"first_attestation"`
	LastAttestation  time.Time `json:"last_attestation"`
	FinalizedAt      time.Time `json:"finalized_at"`

	// Status
	ThresholdMet bool `json:"threshold_met"`
	Finalized    bool `json:"finalized"`

	// Message consistency verified (Phase 2.3)
	// True if all attestations signed the exact same message hash
	MessageConsistencyVerified bool `json:"message_consistency_verified"`

	// Individual attestations (for verification/audit)
	Attestations []ResultAttestation `json:"attestations,omitempty"`
}

// ComputeAggregateHash computes a deterministic hash of the aggregated attestation
func (a *AggregatedAttestation) ComputeAggregateHash() [32]byte {
	data := make([]byte, 0, 256)

	data = append(data, []byte("CERTEN_AGGREGATED_ATTESTATION_V1")...)
	data = append(data, a.ResultHash[:]...)
	data = append(data, a.BundleID[:]...)
	data = append(data, a.MessageHash[:]...)
	data = append(data, a.AggregateSignature...)

	// Include validator set snapshot binding (Phase 2.2)
	data = append(data, a.SnapshotID[:]...)
	data = append(data, a.ValidatorRoot[:]...)

	// Include validator participation
	data = append(data, a.ValidatorBitfield...)

	// Include voting power
	if a.SignedVotingPower != nil {
		data = append(data, a.SignedVotingPower.Bytes()...)
	}

	return sha256.Sum256(data)
}

// minQuorumDistinctSigners is the hard floor on the number of DISTINCT validators whose
// signatures must back a result before it can finalize, independent of the fractional
// supermajority. It prevents a single-node / empty-peer set from trivially "meeting" a
// 2/3 threshold (SEC-H2). Kept in step with attestation.ThresholdConfig.MinValidators.
const minQuorumDistinctSigners = 3

// CheckThreshold verifies if the attestation meets the required threshold
func (a *AggregatedAttestation) CheckThreshold() bool {
	if a.TotalVotingPower == nil || a.SignedVotingPower == nil {
		return false
	}

	// Calculate threshold: signed >= (total * numerator) / denominator
	threshold := new(big.Int).Mul(a.TotalVotingPower, big.NewInt(int64(a.ThresholdNumerator)))
	threshold.Div(threshold, big.NewInt(int64(a.ThresholdDenominator)))

	a.ThresholdMet = a.SignedVotingPower.Cmp(threshold) >= 0
	return a.ThresholdMet
}

// MeetsSupermajority reports whether the signed voting power is at least 2/3 of the
// total — the BFT quorum required to treat a result as quorum-attested. RB-3 gates
// finalization on this hard floor in addition to the configured threshold, so a
// forked minority (< 1/3) can never produce a finalized attestation for its result.
func (a *AggregatedAttestation) MeetsSupermajority() bool {
	if a.TotalVotingPower == nil || a.SignedVotingPower == nil || a.TotalVotingPower.Sign() == 0 {
		return false
	}
	// signed >= total * 2/3  ⇔  signed*3 >= total*2
	lhs := new(big.Int).Mul(a.SignedVotingPower, big.NewInt(3))
	rhs := new(big.Int).Mul(a.TotalVotingPower, big.NewInt(2))
	return lhs.Cmp(rhs) >= 0
}

// ToHex returns a hex representation for logging
func (a *AggregatedAttestation) ToHex() string {
	hash := a.ComputeAggregateHash()
	return hex.EncodeToString(hash[:])
}

// =============================================================================
// ATTESTATION COLLECTOR - Gathers and Aggregates Attestations
// =============================================================================

// AttestationCollector gathers individual attestations and aggregates them
type AttestationCollector struct {
	mu sync.RWMutex

	// Configuration
	validatorSet   *ValidatorSet
	thresholdNum   uint64
	thresholdDenom uint64

	// Validator set snapshot (Phase 2.2)
	// Captured at collector creation for binding attestations
	snapshot *ValidatorSetSnapshot

	// Attestations by result hash
	attestations map[[32]byte]map[string]*ResultAttestation // resultHash -> validatorID -> attestation

	// Aggregated results
	aggregated map[[32]byte]*AggregatedAttestation

	// Callbacks
	onThresholdMet func(*AggregatedAttestation)
}

// ValidatorSet represents the current set of validators with voting power
type ValidatorSet struct {
	Validators       []ValidatorInfo
	TotalVotingPower *big.Int
	ValidatorCount   int
}

// ValidatorInfo contains information about a single validator
type ValidatorInfo struct {
	ID           string
	Address      common.Address
	Index        uint32
	VotingPower  *big.Int
	BLSPublicKey []byte
	Active       bool
}

// =============================================================================
// VALIDATOR SET SNAPSHOT - Cryptographic binding for attestations (Phase 2.2)
// =============================================================================

// ValidatorSetSnapshot represents a point-in-time snapshot of the validator set
// This is cryptographically bound to aggregated attestations to prevent
// attestation replay with different validator sets.
type ValidatorSetSnapshot struct {
	// Unique identifier for this snapshot (computed from contents)
	SnapshotID [32]byte `json:"snapshot_id"`

	// When this snapshot was taken
	BlockNumber uint64    `json:"block_number"`
	CreatedAt   time.Time `json:"created_at"`

	// Validators in this snapshot
	Validators []ValidatorEntry `json:"validators"`

	// Merkle root of validators (for compact verification)
	ValidatorRoot [32]byte `json:"validator_root"`

	// Voting power thresholds
	TotalWeight     *big.Int `json:"total_weight"`
	ThresholdWeight *big.Int `json:"threshold_weight"` // 2/3+1 for BFT consensus
}

// ValidatorEntry represents a single validator in the snapshot
type ValidatorEntry struct {
	ValidatorID string         `json:"validator_id"`
	Address     common.Address `json:"address"`
	PublicKey   []byte         `json:"public_key"` // BLS12-381 G1 point (48 bytes)
	Weight      *big.Int       `json:"weight"`
	Index       uint32         `json:"index"`
}

// ComputeSnapshotID computes the deterministic snapshot ID from contents
// Per RFC8785 canonical JSON specification for determinism
func (s *ValidatorSetSnapshot) ComputeSnapshotID() [32]byte {
	data := make([]byte, 0, 256)

	// Domain separator
	data = append(data, []byte("CERTEN_VALIDATOR_SNAPSHOT_V1")...)

	// Block number as big-endian bytes
	blockBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		blockBytes[7-i] = byte(s.BlockNumber >> (8 * i))
	}
	data = append(data, blockBytes...)

	// Include validator root
	data = append(data, s.ValidatorRoot[:]...)

	// Include total weight
	if s.TotalWeight != nil {
		data = append(data, s.TotalWeight.Bytes()...)
	}

	return sha256.Sum256(data)
}

// ComputeValidatorRoot computes the Merkle root of validators
// This enables compact verification of validator set membership
func (s *ValidatorSetSnapshot) ComputeValidatorRoot() [32]byte {
	if len(s.Validators) == 0 {
		return [32]byte{}
	}

	// Hash each validator entry
	leaves := make([][32]byte, len(s.Validators))
	for i, v := range s.Validators {
		leaves[i] = hashValidatorEntry(&v)
	}

	// Build Merkle tree
	return computeMerkleRoot(leaves)
}

// hashValidatorEntry computes the deterministic hash of a validator entry
func hashValidatorEntry(v *ValidatorEntry) [32]byte {
	data := make([]byte, 0, 128)

	data = append(data, []byte(v.ValidatorID)...)
	data = append(data, v.Address.Bytes()...)
	data = append(data, v.PublicKey...)
	if v.Weight != nil {
		data = append(data, v.Weight.Bytes()...)
	}

	return sha256.Sum256(data)
}

// computeMerkleRoot computes a Merkle root from leaves
func computeMerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Pad to power of 2 if needed
	for len(leaves)&(len(leaves)-1) != 0 {
		leaves = append(leaves, leaves[len(leaves)-1])
	}

	// Build tree
	for len(leaves) > 1 {
		nextLevel := make([][32]byte, len(leaves)/2)
		for i := 0; i < len(leaves); i += 2 {
			combined := make([]byte, 64)
			copy(combined[:32], leaves[i][:])
			copy(combined[32:], leaves[i+1][:])
			nextLevel[i/2] = sha256.Sum256(combined)
		}
		leaves = nextLevel
	}

	return leaves[0]
}

// =============================================================================
// BLS SIGNATURE AGGREGATION - REAL CRYPTOGRAPHIC IMPLEMENTATION
// =============================================================================

// =============================================================================
// RESULT VERIFIER SERVICE
// =============================================================================

// ResultVerifier verifies external chain results and creates attestations
// SECURITY CRITICAL: This is the Phase 8 component that validates external chain
// execution before creating attestations. It ensures the elected executor
// performed the correct transaction as specified in the intent.
//
// MANDATORY: Commitment verification is REQUIRED. Without a commitment, attestation
// is REFUSED. This is the core security mechanism that prevents executor misbehavior.
type ResultVerifier struct {
	validatorID      string
	validatorAddress common.Address
	validatorIndex   uint32

	// BLS signing key - real BLS12-381 private key
	blsPrivateKey *bls.PrivateKey

	// Collector for aggregating attestations
	collector *AttestationCollector

	// Verification configuration
	requiredConfirmations int
}

// =============================================================================
// ATTESTATION SERIALIZATION
// =============================================================================

// AttestationBundle represents a complete bundle of attestations for submission
type AttestationBundle struct {
	// Core identification
	BundleID   [32]byte `json:"bundle_id"`
	ResultHash [32]byte `json:"result_hash"`

	// The aggregated attestation
	Aggregated *AggregatedAttestation `json:"aggregated"`

	// External chain result that was attested
	Result *ExternalChainResult `json:"result"`

	// Multi-leg proof data (populated for multi-chain intents)
	LegResults         []LegResult `json:"leg_results,omitempty"`
	MultiLegResultHash [32]byte    `json:"multi_leg_result_hash,omitempty"`

	// Bundle hash for verification
	BundleHash [32]byte `json:"bundle_hash"`

	// Timing
	CreatedAt time.Time `json:"created_at"`
}

// ComputeBundleHash computes a deterministic hash of the bundle
func (b *AttestationBundle) ComputeBundleHash() [32]byte {
	data := make([]byte, 0, 128)

	data = append(data, []byte("CERTEN_ATTESTATION_BUNDLE_V1")...)
	data = append(data, b.BundleID[:]...)
	data = append(data, b.ResultHash[:]...)

	if b.Aggregated != nil {
		aggHash := b.Aggregated.ComputeAggregateHash()
		data = append(data, aggHash[:]...)
	}

	// Include multi-leg result hash when multiple legs are present
	if len(b.LegResults) > 1 {
		data = append(data, b.MultiLegResultHash[:]...)
	}

	return sha256.Sum256(data)
}

// IsComplete returns true if the bundle has all required components
func (b *AttestationBundle) IsComplete() bool {
	if b.Aggregated == nil || b.Result == nil {
		return false
	}

	if !b.Aggregated.ThresholdMet {
		return false
	}

	if !b.Aggregated.Finalized {
		return false
	}

	return true
}

// ToHex returns a hex representation for logging
func (b *AttestationBundle) ToHex() string {
	return hex.EncodeToString(b.BundleHash[:])
}
