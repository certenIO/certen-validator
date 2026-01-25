// Copyright 2025 Certen Protocol
//
// BLS12-381 Attestation Strategy
// Implements AttestationStrategy for BLS12-381 with signature aggregation
//
// Per Unified Multi-Chain Architecture:
// - Primary attestation scheme for EVM chains
// - Supports cryptographic signature aggregation
// - ZK-verified on-chain verification

package strategy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// =============================================================================
// BLS STRATEGY CONFIGURATION
// =============================================================================

// BLSStrategyConfig holds configuration for the BLS attestation strategy
type BLSStrategyConfig struct {
	// ValidatorID is the unique identifier for this validator
	ValidatorID string

	// ValidatorIndex is the validator's position in the active set
	ValidatorIndex uint32

	// PrivateKey is the BLS private key (32 bytes)
	// If nil, a new key pair will be generated
	PrivateKeyBytes []byte

	// Domain is the signing domain for attestations
	// Default: "CERTEN_RESULT_ATTESTATION_V1"
	Domain string

	// ThresholdConfig for consensus
	ThresholdConfig *ThresholdConfig
}

// DefaultBLSStrategyConfig returns default configuration
func DefaultBLSStrategyConfig() *BLSStrategyConfig {
	return &BLSStrategyConfig{
		Domain:          bls.DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}
}

// =============================================================================
// BLS ATTESTATION STRATEGY
// =============================================================================

// BLSStrategy implements AttestationStrategy for BLS12-381
type BLSStrategy struct {
	mu sync.RWMutex

	// Configuration
	config *BLSStrategyConfig

	// Key pair
	privateKey *bls.PrivateKey
	publicKey  *bls.PublicKey

	// Cached public key bytes
	publicKeyBytes []byte

	// Initialized flag
	initialized bool
}

// NewBLSStrategy creates a new BLS attestation strategy
func NewBLSStrategy(config *BLSStrategyConfig) (*BLSStrategy, error) {
	if config == nil {
		config = DefaultBLSStrategyConfig()
	}

	if config.ValidatorID == "" {
		return nil, fmt.Errorf("validator ID is required")
	}

	if config.Domain == "" {
		config.Domain = bls.DomainResult
	}

	if config.ThresholdConfig == nil {
		config.ThresholdConfig = DefaultThresholdConfig()
	}

	strategy := &BLSStrategy{
		config: config,
	}

	// Initialize BLS library
	if err := bls.Initialize(); err != nil {
		return nil, fmt.Errorf("initialize BLS library: %w", err)
	}

	// Load or generate key pair
	if len(config.PrivateKeyBytes) > 0 {
		// Load existing key
		sk, err := bls.PrivateKeyFromBytes(config.PrivateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("load BLS private key: %w", err)
		}
		strategy.privateKey = sk
		strategy.publicKey = sk.PublicKey()
	} else {
		// Generate new key pair
		sk, pk, err := bls.GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate BLS key pair: %w", err)
		}
		strategy.privateKey = sk
		strategy.publicKey = pk
	}

	// Cache public key bytes
	strategy.publicKeyBytes = strategy.publicKey.Bytes()
	strategy.initialized = true

	return strategy, nil
}

// =============================================================================
// ATTESTATION STRATEGY INTERFACE IMPLEMENTATION
// =============================================================================

// Scheme returns the attestation scheme identifier
func (s *BLSStrategy) Scheme() AttestationScheme {
	return AttestationSchemeBLS12381
}

// Sign creates a BLS attestation for the given message
func (s *BLSStrategy) Sign(ctx context.Context, message *AttestationMessage) (*Attestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("BLS strategy not initialized")
	}

	// Compute message hash
	messageHash, err := s.ComputeMessageHash(message)
	if err != nil {
		return nil, fmt.Errorf("compute message hash: %w", err)
	}

	// Sign with domain separation
	signature := s.privateKey.SignWithDomain(messageHash[:], s.config.Domain)

	attestation := &Attestation{
		AttestationID:  uuid.New(),
		Scheme:         AttestationSchemeBLS12381,
		ValidatorID:    s.config.ValidatorID,
		ValidatorIndex: s.config.ValidatorIndex,
		PublicKey:      s.publicKeyBytes,
		Signature:      signature.Bytes(),
		Message:        message,
		MessageHash:    messageHash,
		Weight:         1, // Default weight, should be overridden by caller
		Timestamp:      time.Now().UTC(),
	}

	return attestation, nil
}

// Verify verifies a single BLS attestation's signature
func (s *BLSStrategy) Verify(ctx context.Context, attestation *Attestation) (bool, error) {
	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	if attestation.Scheme != AttestationSchemeBLS12381 {
		return false, fmt.Errorf("invalid scheme: expected %s, got %s",
			AttestationSchemeBLS12381, attestation.Scheme)
	}

	// Load public key
	publicKey, err := bls.PublicKeyFromBytes(attestation.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	// Load signature
	signature, err := bls.SignatureFromBytes(attestation.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}

	// Verify with domain separation
	valid := publicKey.VerifyWithDomain(signature, attestation.MessageHash[:], s.config.Domain)

	return valid, nil
}

// Aggregate combines multiple BLS attestations into a single aggregated attestation
func (s *BLSStrategy) Aggregate(ctx context.Context, attestations []*Attestation) (*AggregatedAttestation, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations to aggregate")
	}

	// Validate all attestations have same message hash
	baseHash := attestations[0].MessageHash
	for i, att := range attestations {
		if att.Scheme != AttestationSchemeBLS12381 {
			return nil, fmt.Errorf("attestation %d has wrong scheme: %s", i, att.Scheme)
		}
		if att.MessageHash != baseHash {
			return nil, fmt.Errorf("attestation %d has different message hash", i)
		}
	}

	// Collect signatures and public keys
	signatures := make([]*bls.Signature, len(attestations))
	publicKeys := make([]*bls.PublicKey, len(attestations))
	participantIDs := make([]string, len(attestations))
	var totalWeight int64

	for i, att := range attestations {
		sig, err := bls.SignatureFromBytes(att.Signature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature at index %d: %w", i, err)
		}
		signatures[i] = sig

		pk, err := bls.PublicKeyFromBytes(att.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid public key at index %d: %w", i, err)
		}
		publicKeys[i] = pk

		participantIDs[i] = att.ValidatorID
		totalWeight += att.Weight
	}

	// Aggregate signatures
	aggSig, err := bls.AggregateSignatures(signatures)
	if err != nil {
		return nil, fmt.Errorf("aggregate signatures: %w", err)
	}

	// Aggregate public keys
	aggPk, err := bls.AggregatePublicKeys(publicKeys)
	if err != nil {
		return nil, fmt.Errorf("aggregate public keys: %w", err)
	}

	// Build validator bitfield (simple encoding)
	bitfield := buildValidatorBitfield(attestations)

	// Determine timestamps
	var firstTime, lastTime time.Time
	for _, att := range attestations {
		if firstTime.IsZero() || att.Timestamp.Before(firstTime) {
			firstTime = att.Timestamp
		}
		if att.Timestamp.After(lastTime) {
			lastTime = att.Timestamp
		}
	}

	// Create aggregated attestation
	agg := &AggregatedAttestation{
		AggregationID:       uuid.New(),
		Scheme:              AttestationSchemeBLS12381,
		MessageHash:         baseHash,
		AggregatedSignature: aggSig.Bytes(),
		AggregatedPublicKey: aggPk.Bytes(),
		Attestations:        attestations,
		ParticipantIDs:      participantIDs,
		ParticipantCount:    len(attestations),
		ValidatorBitfield:   bitfield,
		AchievedWeight:      totalWeight,
		FirstAttestation:    firstTime,
		LastAttestation:     lastTime,
		AggregatedAt:        time.Now().UTC(),
	}

	return agg, nil
}

// VerifyAggregated verifies an aggregated BLS attestation
func (s *BLSStrategy) VerifyAggregated(ctx context.Context, agg *AggregatedAttestation) (bool, error) {
	if agg == nil {
		return false, fmt.Errorf("aggregated attestation is nil")
	}

	if agg.Scheme != AttestationSchemeBLS12381 {
		return false, fmt.Errorf("invalid scheme: expected %s, got %s",
			AttestationSchemeBLS12381, agg.Scheme)
	}

	// Load aggregated signature
	aggSig, err := bls.SignatureFromBytes(agg.AggregatedSignature)
	if err != nil {
		return false, fmt.Errorf("invalid aggregated signature: %w", err)
	}

	// Load aggregated public key
	aggPk, err := bls.PublicKeyFromBytes(agg.AggregatedPublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid aggregated public key: %w", err)
	}

	// Verify with domain separation
	valid := aggPk.VerifyWithDomain(aggSig, agg.MessageHash[:], s.config.Domain)

	return valid, nil
}

// SupportsAggregation returns true - BLS supports signature aggregation
func (s *BLSStrategy) SupportsAggregation() bool {
	return true
}

// PublicKey returns this validator's BLS public key
func (s *BLSStrategy) PublicKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.publicKeyBytes
}

// ValidatorID returns the validator identifier
func (s *BLSStrategy) ValidatorID() string {
	return s.config.ValidatorID
}

// ValidatorIndex returns the validator's index in the active set
func (s *BLSStrategy) ValidatorIndex() uint32 {
	return s.config.ValidatorIndex
}

// ComputeMessageHash computes the canonical hash of an attestation message
func (s *BLSStrategy) ComputeMessageHash(message *AttestationMessage) ([32]byte, error) {
	// Serialize message to canonical JSON
	data, err := json.Marshal(message)
	if err != nil {
		return [32]byte{}, fmt.Errorf("marshal message: %w", err)
	}

	// SHA-256 hash
	return sha256.Sum256(data), nil
}

// =============================================================================
// ADDITIONAL METHODS
// =============================================================================

// PrivateKeyBytes returns the private key bytes (for secure storage)
func (s *BLSStrategy) PrivateKeyBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.privateKey == nil {
		return nil
	}
	return s.privateKey.Bytes()
}

// PublicKeyHex returns the public key as hex string
func (s *BLSStrategy) PublicKeyHex() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.publicKey == nil {
		return ""
	}
	return s.publicKey.Hex()
}

// VerifySignatureBytes verifies a signature given raw bytes
func (s *BLSStrategy) VerifySignatureBytes(publicKey, signature, messageHash []byte) (bool, error) {
	pk, err := bls.PublicKeyFromBytes(publicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}

	sig, err := bls.SignatureFromBytes(signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}

	valid := pk.VerifyWithDomain(sig, messageHash, s.config.Domain)
	return valid, nil
}

// GetDomain returns the signing domain
func (s *BLSStrategy) GetDomain() string {
	return s.config.Domain
}

// GetThresholdConfig returns the threshold configuration
func (s *BLSStrategy) GetThresholdConfig() *ThresholdConfig {
	return s.config.ThresholdConfig
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// buildValidatorBitfield creates a compact bitfield representation of participating validators
func buildValidatorBitfield(attestations []*Attestation) []byte {
	// Find max validator index
	maxIndex := uint32(0)
	for _, att := range attestations {
		if att.ValidatorIndex > maxIndex {
			maxIndex = att.ValidatorIndex
		}
	}

	// Create bitfield (ceil(maxIndex/8) bytes)
	bitfieldSize := (maxIndex + 8) / 8
	bitfield := make([]byte, bitfieldSize)

	// Set bits for participating validators
	for _, att := range attestations {
		byteIndex := att.ValidatorIndex / 8
		bitIndex := att.ValidatorIndex % 8
		if byteIndex < uint32(len(bitfield)) {
			bitfield[byteIndex] |= (1 << bitIndex)
		}
	}

	return bitfield
}

// =============================================================================
// BLS STRATEGY FACTORY
// =============================================================================

// NewBLSStrategyFromKeyHex creates a BLS strategy from a hex-encoded private key
func NewBLSStrategyFromKeyHex(validatorID string, validatorIndex uint32, privateKeyHex string) (*BLSStrategy, error) {
	sk, err := bls.PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	config := &BLSStrategyConfig{
		ValidatorID:     validatorID,
		ValidatorIndex:  validatorIndex,
		PrivateKeyBytes: sk.Bytes(),
		Domain:          bls.DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}

	return NewBLSStrategy(config)
}

// NewBLSStrategyWithNewKey creates a BLS strategy with a newly generated key pair
func NewBLSStrategyWithNewKey(validatorID string, validatorIndex uint32) (*BLSStrategy, error) {
	config := &BLSStrategyConfig{
		ValidatorID:     validatorID,
		ValidatorIndex:  validatorIndex,
		PrivateKeyBytes: nil, // Will generate new key
		Domain:          bls.DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}

	return NewBLSStrategy(config)
}
