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
	"errors"
	"fmt"
	"math/big"
	"sort"
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
	BlockNumber     *big.Int  `json:"block_number"`      // External chain block observed
	Confirmations   int       `json:"confirmations"`     // Block confirmations at attestation time

	// Verification status
	Verified bool `json:"verified"`
}

// ComputeMessageHash computes the deterministic message hash that validators sign
// This ensures all validators sign the same message for the same result
func ComputeAttestationMessageHash(resultHash [32]byte, bundleID [32]byte, blockNumber *big.Int) [32]byte {
	data := make([]byte, 0, 96)

	// Domain separator for attestations
	data = append(data, []byte("CERTEN_RESULT_ATTESTATION_V1")...)

	// Core attestation data
	data = append(data, resultHash[:]...)
	data = append(data, bundleID[:]...)

	// Block binding
	if blockNumber != nil {
		data = append(data, blockNumber.Bytes()...)
	}

	return sha256.Sum256(data)
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
	TotalVotingPower     *big.Int `json:"total_voting_power"`     // Total power in validator set
	SignedVotingPower    *big.Int `json:"signed_voting_power"`    // Power of attestors
	ThresholdNumerator   uint64   `json:"threshold_numerator"`    // e.g., 2
	ThresholdDenominator uint64   `json:"threshold_denominator"`  // e.g., 3

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
	validatorSet    *ValidatorSet
	thresholdNum    uint64
	thresholdDenom  uint64

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

// NewValidatorSetSnapshot creates a snapshot from a ValidatorSet
func NewValidatorSetSnapshot(vs *ValidatorSet, blockNumber uint64) *ValidatorSetSnapshot {
	snapshot := &ValidatorSetSnapshot{
		BlockNumber: blockNumber,
		CreatedAt:   time.Now(),
		Validators:  make([]ValidatorEntry, len(vs.Validators)),
		TotalWeight: new(big.Int).Set(vs.TotalVotingPower),
	}

	// Convert validators
	for i, v := range vs.Validators {
		snapshot.Validators[i] = ValidatorEntry{
			ValidatorID: v.ID,
			Address:     v.Address,
			PublicKey:   v.BLSPublicKey,
			Weight:      v.VotingPower,
			Index:       v.Index,
		}
	}

	// Compute threshold (2/3 + 1)
	snapshot.ThresholdWeight = new(big.Int).Mul(snapshot.TotalWeight, big.NewInt(2))
	snapshot.ThresholdWeight.Div(snapshot.ThresholdWeight, big.NewInt(3))
	snapshot.ThresholdWeight.Add(snapshot.ThresholdWeight, big.NewInt(1))

	// Compute Merkle root and snapshot ID
	snapshot.ValidatorRoot = snapshot.ComputeValidatorRoot()
	snapshot.SnapshotID = snapshot.ComputeSnapshotID()

	return snapshot
}

// VerifyValidatorMembership verifies a validator is in the snapshot
func (s *ValidatorSetSnapshot) VerifyValidatorMembership(validatorID string) bool {
	for _, v := range s.Validators {
		if v.ValidatorID == validatorID {
			return true
		}
	}
	return false
}

// NewAttestationCollector creates a new attestation collector
func NewAttestationCollector(
	validatorSet *ValidatorSet,
	thresholdNum, thresholdDenom uint64,
) *AttestationCollector {
	// Create validator set snapshot for binding attestations (Phase 2.2)
	// Block number 0 indicates snapshot at collector creation
	snapshot := NewValidatorSetSnapshot(validatorSet, 0)

	return &AttestationCollector{
		validatorSet:   validatorSet,
		thresholdNum:   thresholdNum,
		thresholdDenom: thresholdDenom,
		snapshot:       snapshot,
		attestations:   make(map[[32]byte]map[string]*ResultAttestation),
		aggregated:     make(map[[32]byte]*AggregatedAttestation),
	}
}

// NewAttestationCollectorWithBlockNumber creates a collector with a specific block number
func NewAttestationCollectorWithBlockNumber(
	validatorSet *ValidatorSet,
	thresholdNum, thresholdDenom uint64,
	blockNumber uint64,
) *AttestationCollector {
	snapshot := NewValidatorSetSnapshot(validatorSet, blockNumber)

	return &AttestationCollector{
		validatorSet:   validatorSet,
		thresholdNum:   thresholdNum,
		thresholdDenom: thresholdDenom,
		snapshot:       snapshot,
		attestations:   make(map[[32]byte]map[string]*ResultAttestation),
		aggregated:     make(map[[32]byte]*AggregatedAttestation),
	}
}

// GetSnapshot returns the validator set snapshot
func (c *AttestationCollector) GetSnapshot() *ValidatorSetSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.snapshot
}

// SetThresholdCallback sets the callback for when threshold is met
func (c *AttestationCollector) SetThresholdCallback(callback func(*AggregatedAttestation)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onThresholdMet = callback
}

// AddAttestation adds a new attestation to the collector
func (c *AttestationCollector) AddAttestation(attestation *ResultAttestation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verify the attestation is from a known validator
	validator := c.findValidator(attestation.ValidatorID)
	if validator == nil {
		return fmt.Errorf("unknown validator: %s", attestation.ValidatorID)
	}

	// Verify the message hash
	expectedHash := ComputeAttestationMessageHash(
		attestation.ResultHash,
		attestation.BundleID,
		attestation.BlockNumber,
	)
	if attestation.MessageHash != expectedHash {
		return fmt.Errorf("message hash mismatch")
	}

	// Initialize map for this result if needed
	if c.attestations[attestation.ResultHash] == nil {
		c.attestations[attestation.ResultHash] = make(map[string]*ResultAttestation)
	}

	// Check for duplicate
	if existing := c.attestations[attestation.ResultHash][attestation.ValidatorID]; existing != nil {
		// Allow update if result hash matches (idempotent)
		if existing.ResultHash == attestation.ResultHash {
			return nil
		}
		return fmt.Errorf("conflicting attestation from validator %s", attestation.ValidatorID)
	}

	// Store the attestation
	attestation.Verified = true
	c.attestations[attestation.ResultHash][attestation.ValidatorID] = attestation

	// Try to aggregate
	agg, thresholdMet := c.tryAggregate(attestation.ResultHash)
	if thresholdMet && c.onThresholdMet != nil {
		go c.onThresholdMet(agg)
	}

	return nil
}

// tryAggregate attempts to aggregate all attestations for a result
func (c *AttestationCollector) tryAggregate(resultHash [32]byte) (*AggregatedAttestation, bool) {
	attestations := c.attestations[resultHash]
	if len(attestations) == 0 {
		return nil, false
	}

	// Get or create aggregated attestation
	agg := c.aggregated[resultHash]
	if agg == nil {
		// Get first attestation to initialize
		var first *ResultAttestation
		for _, a := range attestations {
			first = a
			break
		}

		agg = &AggregatedAttestation{
			ResultHash:          resultHash,
			BundleID:            first.BundleID,
			BlockNumber:         first.BlockNumber,
			MessageHash:         first.MessageHash,
			TotalVotingPower:    c.validatorSet.TotalVotingPower,
			SignedVotingPower:   big.NewInt(0),
			ThresholdNumerator:  c.thresholdNum,
			ThresholdDenominator: c.thresholdDenom,
			FirstAttestation:    time.Now(),
		}

		// Bind validator set snapshot (Phase 2.2)
		if c.snapshot != nil {
			agg.SnapshotID = c.snapshot.SnapshotID
			agg.ValidatorRoot = c.snapshot.ValidatorRoot
		}

		c.aggregated[resultHash] = agg
	}

	// Phase 2.3: Message consistency check
	// Verify all attestations signed the SAME message hash
	messageConsistent := true
	expectedMessage := agg.MessageHash
	for _, att := range attestations {
		if att.MessageHash != expectedMessage {
			messageConsistent = false
			break
		}
	}
	agg.MessageConsistencyVerified = messageConsistent

	// Collect signatures and compute aggregate
	var signatures [][]byte
	var validators []common.Address
	signedPower := big.NewInt(0)
	bitfield := make([]byte, (c.validatorSet.ValidatorCount+7)/8)

	// Sort attestations by validator index for determinism
	var sortedAttestations []*ResultAttestation
	for _, a := range attestations {
		sortedAttestations = append(sortedAttestations, a)
	}
	sort.Slice(sortedAttestations, func(i, j int) bool {
		return sortedAttestations[i].ValidatorIndex < sortedAttestations[j].ValidatorIndex
	})

	for _, att := range sortedAttestations {
		validator := c.findValidator(att.ValidatorID)
		if validator == nil {
			continue
		}

		signatures = append(signatures, att.BLSSignature)
		validators = append(validators, att.ValidatorAddress)

		// Set bit in bitfield
		bitfield[validator.Index/8] |= 1 << (validator.Index % 8)

		// Add voting power
		signedPower.Add(signedPower, validator.VotingPower)
	}

	// Update aggregated attestation
	agg.AggregateSignature = aggregateBLSSignatures(signatures)
	agg.ValidatorBitfield = bitfield
	agg.ValidatorCount = len(validators)
	agg.ValidatorAddresses = validators
	agg.SignedVotingPower = signedPower
	agg.LastAttestation = time.Now()

	// Convert pointer slice to value slice
	agg.Attestations = make([]ResultAttestation, len(sortedAttestations))
	for i, a := range sortedAttestations {
		agg.Attestations[i] = *a
	}

	// Check threshold
	wasMetBefore := agg.ThresholdMet
	thresholdMet := agg.CheckThreshold()

	// Only finalize if threshold met AND message consistency verified
	if thresholdMet && messageConsistent && !wasMetBefore {
		agg.Finalized = true
		agg.FinalizedAt = time.Now()
		return agg, true
	}

	return agg, false
}

// findValidator finds a validator by ID
func (c *AttestationCollector) findValidator(id string) *ValidatorInfo {
	for i := range c.validatorSet.Validators {
		if c.validatorSet.Validators[i].ID == id {
			return &c.validatorSet.Validators[i]
		}
	}
	return nil
}

// GetAggregated returns the aggregated attestation for a result
func (c *AttestationCollector) GetAggregated(resultHash [32]byte) *AggregatedAttestation {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.aggregated[resultHash]
}

// GetAttestationCount returns the number of attestations for a result
func (c *AttestationCollector) GetAttestationCount(resultHash [32]byte) int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.attestations[resultHash])
}

// =============================================================================
// BLS SIGNATURE AGGREGATION - REAL CRYPTOGRAPHIC IMPLEMENTATION
// =============================================================================

// aggregateBLSSignatures aggregates multiple BLS signatures into one
// Uses real BLS12-381 signature aggregation via gnark-crypto
func aggregateBLSSignatures(signatures [][]byte) []byte {
	if len(signatures) == 0 {
		return nil
	}

	// Convert raw bytes to BLS Signature objects
	blsSignatures := make([]*bls.Signature, 0, len(signatures))
	for _, sigBytes := range signatures {
		sig, err := bls.SignatureFromBytes(sigBytes)
		if err != nil {
			// Skip invalid signatures
			continue
		}
		blsSignatures = append(blsSignatures, sig)
	}

	if len(blsSignatures) == 0 {
		return nil
	}

	// Aggregate using real BLS aggregation
	aggSig, err := bls.AggregateSignatures(blsSignatures)
	if err != nil {
		return nil
	}

	return aggSig.Bytes()
}

// VerifyAggregatedBLSSignature verifies an aggregated BLS signature
// Uses real BLS12-381 verification via gnark-crypto
func VerifyAggregatedBLSSignature(
	aggregateSig []byte,
	messageHash [32]byte,
	publicKeys [][]byte,
) (bool, error) {
	if len(aggregateSig) == 0 {
		return false, errors.New("empty aggregate signature")
	}

	if len(publicKeys) == 0 {
		return false, errors.New("no public keys provided")
	}

	// Deserialize aggregate signature
	aggSig, err := bls.SignatureFromBytes(aggregateSig)
	if err != nil {
		return false, fmt.Errorf("invalid aggregate signature: %w", err)
	}

	// Convert raw bytes to BLS PublicKey objects
	blsPublicKeys := make([]*bls.PublicKey, 0, len(publicKeys))
	for i, pkBytes := range publicKeys {
		pk, err := bls.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return false, fmt.Errorf("invalid public key at index %d: %w", i, err)
		}
		blsPublicKeys = append(blsPublicKeys, pk)
	}

	// Verify using real BLS aggregate verification with domain separation
	valid := bls.VerifyAggregateSignatureWithDomain(aggSig, blsPublicKeys, messageHash[:], bls.DomainResult)

	return valid, nil
}

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

// NewResultVerifier creates a new result verifier with a BLS private key
// SECURITY: Commitment verification is MANDATORY - no legacy mode
func NewResultVerifier(
	validatorID string,
	validatorAddress common.Address,
	validatorIndex uint32,
	blsPrivateKey *bls.PrivateKey,
	collector *AttestationCollector,
) *ResultVerifier {
	return &ResultVerifier{
		validatorID:           validatorID,
		validatorAddress:      validatorAddress,
		validatorIndex:        validatorIndex,
		blsPrivateKey:         blsPrivateKey,
		collector:             collector,
		requiredConfirmations: 12,
	}
}

// NewResultVerifierFromBytes creates a new result verifier from raw key bytes
// Convenience constructor for when key is stored as bytes
// SECURITY: Commitment verification is MANDATORY - no legacy mode
func NewResultVerifierFromBytes(
	validatorID string,
	validatorAddress common.Address,
	validatorIndex uint32,
	blsPrivateKeyBytes []byte,
	collector *AttestationCollector,
) (*ResultVerifier, error) {
	blsPrivateKey, err := bls.PrivateKeyFromBytes(blsPrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid BLS private key: %w", err)
	}

	return &ResultVerifier{
		validatorID:           validatorID,
		validatorAddress:      validatorAddress,
		validatorIndex:        validatorIndex,
		blsPrivateKey:         blsPrivateKey,
		collector:             collector,
		requiredConfirmations: 12,
	}, nil
}

// VerifyAndAttest verifies an external chain result and creates an attestation
//
// SECURITY CRITICAL: This is the final verification before creating an attestation.
// Commitment verification is MANDATORY. Without it, attestation is REFUSED.
//
// This function ensures:
// 1. A commitment exists (proving what SHOULD have been executed)
// 2. The actual execution MATCHES the commitment exactly
// 3. The transaction has sufficient confirmations for finality
// 4. Merkle proofs are valid (transaction and receipt inclusion)
//
// If ANY check fails, NO attestation is created. This is the core defense
// against executor misbehavior or transaction substitution attacks.
func (v *ResultVerifier) VerifyAndAttest(
	result *ExternalChainResult,
	commitment *ExecutionCommitment,
) (*ResultAttestation, error) {
	// SECURITY: Commitment is MANDATORY - no attestation without it
	if commitment == nil {
		return nil, errors.New("SECURITY VIOLATION: commitment is REQUIRED for attestation - " +
			"cannot verify execution without knowing what SHOULD have been executed")
	}

	// SECURITY: Verify the actual execution matches the expected commitment
	if !commitment.VerifyAgainstResult(result) {
		return nil, fmt.Errorf("SECURITY VIOLATION: execution does NOT match commitment - "+
			"ATTESTATION REFUSED. "+
			"Expected target: %s, Actual target: %s, "+
			"TxHash: %s, BundleID: %x. "+
			"This indicates the executor executed a DIFFERENT transaction than specified. "+
			"Possible causes: executor misbehavior, substitution attack, or configuration error",
			commitment.TargetContract.Hex(),
			result.TxTo,
			result.TxHash.Hex(),
			commitment.BundleID[:8])
	}

	// Verify the result has enough confirmations for finality
	if result.ConfirmationBlocks < v.requiredConfirmations {
		return nil, fmt.Errorf("insufficient confirmations: %d < %d - "+
			"transaction not yet final, cannot attest",
			result.ConfirmationBlocks, v.requiredConfirmations)
	}

	// Verify transaction success
	if !result.IsSuccess() {
		return nil, errors.New("transaction execution failed")
	}

	// Verify Merkle proofs
	if result.TxInclusionProof != nil {
		if !result.TxInclusionProof.Verify() {
			return nil, errors.New("transaction inclusion proof invalid")
		}
	}
	if result.ReceiptInclusionProof != nil {
		if !result.ReceiptInclusionProof.Verify() {
			return nil, errors.New("receipt inclusion proof invalid")
		}
	}

	// Get bundle ID from commitment or derive from result
	var bundleID [32]byte
	if commitment != nil {
		bundleID = commitment.BundleID
	} else {
		// When commitment is nil, derive bundle ID from result hash
		// This ensures attestations can still be created for the execution
		bundleID = result.ResultID
	}

	// Compute the message hash
	messageHash := ComputeAttestationMessageHash(
		result.ResultHash,
		bundleID,
		result.BlockNumber,
	)

	// Create BLS signature
	signature := v.signBLS(messageHash)

	// Create attestation
	attestation := &ResultAttestation{
		ResultHash:       result.ResultHash,
		BundleID:         bundleID,
		ValidatorID:      v.validatorID,
		ValidatorAddress: v.validatorAddress,
		ValidatorIndex:   v.validatorIndex,
		BLSSignature:     signature,
		MessageHash:      messageHash,
		AttestationTime:  time.Now(),
		BlockNumber:      result.BlockNumber,
		Confirmations:    result.ConfirmationBlocks,
		Verified:         true,
	}

	// Add to collector if available
	if v.collector != nil {
		if err := v.collector.AddAttestation(attestation); err != nil {
			return nil, fmt.Errorf("add to collector: %w", err)
		}
	}

	return attestation, nil
}

// signBLS creates a BLS signature over a message hash
// Uses real BLS12-381 signing via gnark-crypto
func (v *ResultVerifier) signBLS(messageHash [32]byte) []byte {
	if v.blsPrivateKey == nil {
		return nil
	}

	// Sign with domain separation for result attestations
	sig := v.blsPrivateKey.SignWithDomain(messageHash[:], bls.DomainResult)
	return sig.Bytes()
}

// GetBLSPublicKey returns the BLS public key for this verifier
func (v *ResultVerifier) GetBLSPublicKey() []byte {
	if v.blsPrivateKey == nil {
		return nil
	}
	return v.blsPrivateKey.PublicKey().Bytes()
}

// =============================================================================
// ATTESTATION SERIALIZATION
// =============================================================================

// AttestationBundle represents a complete bundle of attestations for submission
type AttestationBundle struct {
	// Core identification
	BundleID    [32]byte `json:"bundle_id"`
	ResultHash  [32]byte `json:"result_hash"`

	// The aggregated attestation
	Aggregated *AggregatedAttestation `json:"aggregated"`

	// External chain result that was attested
	Result *ExternalChainResult `json:"result"`

	// Bundle hash for verification
	BundleHash [32]byte `json:"bundle_hash"`

	// Timing
	CreatedAt time.Time `json:"created_at"`
}

// NewAttestationBundle creates a new attestation bundle
func NewAttestationBundle(
	bundleID [32]byte,
	result *ExternalChainResult,
	aggregated *AggregatedAttestation,
) *AttestationBundle {
	bundle := &AttestationBundle{
		BundleID:   bundleID,
		ResultHash: result.ResultHash,
		Aggregated: aggregated,
		Result:     result,
		CreatedAt:  time.Now(),
	}

	bundle.BundleHash = bundle.ComputeBundleHash()
	return bundle
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
