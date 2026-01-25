// Copyright 2025 Certen Protocol
//
// Ed25519 Attestation Strategy
// Implements AttestationStrategy for Ed25519 signatures
//
// Per Unified Multi-Chain Architecture:
// - Default attestation scheme for non-EVM chains (CosmWasm, Solana, Move, TON, NEAR)
// - Native support on many chains with low verification cost
// - Does not support cryptographic signature aggregation

package strategy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// =============================================================================
// DOMAIN CONSTANTS
// =============================================================================

const (
	// Ed25519DomainAttestation is the domain for general attestations
	Ed25519DomainAttestation = "CERTEN_ATTESTATION_V1"

	// Ed25519DomainResult is the domain for result attestations
	Ed25519DomainResult = "CERTEN_RESULT_ATTESTATION_V1"
)

// =============================================================================
// ED25519 STRATEGY CONFIGURATION
// =============================================================================

// Ed25519StrategyConfig holds configuration for the Ed25519 attestation strategy
type Ed25519StrategyConfig struct {
	// ValidatorID is the unique identifier for this validator
	ValidatorID string

	// ValidatorIndex is the validator's position in the active set
	ValidatorIndex uint32

	// PrivateKey is the Ed25519 private key (64 bytes)
	// If nil, a new key pair will be generated
	PrivateKey ed25519.PrivateKey

	// Domain is the signing domain for attestations
	// Default: "CERTEN_RESULT_ATTESTATION_V1"
	Domain string

	// ThresholdConfig for consensus
	ThresholdConfig *ThresholdConfig
}

// DefaultEd25519StrategyConfig returns default configuration
func DefaultEd25519StrategyConfig() *Ed25519StrategyConfig {
	return &Ed25519StrategyConfig{
		Domain:          Ed25519DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}
}

// =============================================================================
// ED25519 ATTESTATION STRATEGY
// =============================================================================

// Ed25519Strategy implements AttestationStrategy for Ed25519
type Ed25519Strategy struct {
	mu sync.RWMutex

	// Configuration
	config *Ed25519StrategyConfig

	// Key pair
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	// Initialized flag
	initialized bool
}

// NewEd25519Strategy creates a new Ed25519 attestation strategy
func NewEd25519Strategy(config *Ed25519StrategyConfig) (*Ed25519Strategy, error) {
	if config == nil {
		config = DefaultEd25519StrategyConfig()
	}

	if config.ValidatorID == "" {
		return nil, fmt.Errorf("validator ID is required")
	}

	if config.Domain == "" {
		config.Domain = Ed25519DomainResult
	}

	if config.ThresholdConfig == nil {
		config.ThresholdConfig = DefaultThresholdConfig()
	}

	strategy := &Ed25519Strategy{
		config: config,
	}

	// Load or generate key pair
	if len(config.PrivateKey) > 0 {
		// Validate and load existing key
		if len(config.PrivateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
				ed25519.PrivateKeySize, len(config.PrivateKey))
		}
		strategy.privateKey = config.PrivateKey
		strategy.publicKey = config.PrivateKey.Public().(ed25519.PublicKey)
	} else {
		// Generate new key pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate Ed25519 key pair: %w", err)
		}
		strategy.privateKey = priv
		strategy.publicKey = pub
	}

	strategy.initialized = true

	return strategy, nil
}

// =============================================================================
// ATTESTATION STRATEGY INTERFACE IMPLEMENTATION
// =============================================================================

// Scheme returns the attestation scheme identifier
func (s *Ed25519Strategy) Scheme() AttestationScheme {
	return AttestationSchemeEd25519
}

// Sign creates an Ed25519 attestation for the given message
func (s *Ed25519Strategy) Sign(ctx context.Context, message *AttestationMessage) (*Attestation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.initialized {
		return nil, fmt.Errorf("Ed25519 strategy not initialized")
	}

	// Compute message hash
	messageHash, err := s.ComputeMessageHash(message)
	if err != nil {
		return nil, fmt.Errorf("compute message hash: %w", err)
	}

	// Create domain-separated message
	domainMsg := s.createDomainMessage(messageHash[:])

	// Sign the message
	signature := ed25519.Sign(s.privateKey, domainMsg)

	attestation := &Attestation{
		AttestationID:  uuid.New(),
		Scheme:         AttestationSchemeEd25519,
		ValidatorID:    s.config.ValidatorID,
		ValidatorIndex: s.config.ValidatorIndex,
		PublicKey:      []byte(s.publicKey),
		Signature:      signature,
		Message:        message,
		MessageHash:    messageHash,
		Weight:         1, // Default weight, should be overridden by caller
		Timestamp:      time.Now().UTC(),
	}

	return attestation, nil
}

// Verify verifies a single Ed25519 attestation's signature
func (s *Ed25519Strategy) Verify(ctx context.Context, attestation *Attestation) (bool, error) {
	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	if attestation.Scheme != AttestationSchemeEd25519 {
		return false, fmt.Errorf("invalid scheme: expected %s, got %s",
			AttestationSchemeEd25519, attestation.Scheme)
	}

	// Validate key and signature sizes
	if len(attestation.PublicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d",
			ed25519.PublicKeySize, len(attestation.PublicKey))
	}

	if len(attestation.Signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: expected %d, got %d",
			ed25519.SignatureSize, len(attestation.Signature))
	}

	// Create domain-separated message for verification
	domainMsg := s.createDomainMessage(attestation.MessageHash[:])

	// Verify the signature
	valid := ed25519.Verify(attestation.PublicKey, domainMsg, attestation.Signature)

	return valid, nil
}

// Aggregate collects Ed25519 attestations (no cryptographic aggregation)
// Ed25519 doesn't support signature aggregation, so we just collect them
func (s *Ed25519Strategy) Aggregate(ctx context.Context, attestations []*Attestation) (*AggregatedAttestation, error) {
	if len(attestations) == 0 {
		return nil, fmt.Errorf("no attestations to aggregate")
	}

	// Validate all attestations have same message hash
	baseHash := attestations[0].MessageHash
	for i, att := range attestations {
		if att.Scheme != AttestationSchemeEd25519 {
			return nil, fmt.Errorf("attestation %d has wrong scheme: %s", i, att.Scheme)
		}
		if att.MessageHash != baseHash {
			return nil, fmt.Errorf("attestation %d has different message hash", i)
		}
	}

	// Verify each attestation and collect metadata
	participantIDs := make([]string, len(attestations))
	var totalWeight int64
	seenPublicKeys := make(map[string]bool)

	for i, att := range attestations {
		// Check for duplicate public keys
		pkHex := hex.EncodeToString(att.PublicKey)
		if seenPublicKeys[pkHex] {
			return nil, fmt.Errorf("duplicate attestation from public key at index %d", i)
		}
		seenPublicKeys[pkHex] = true

		participantIDs[i] = att.ValidatorID
		totalWeight += att.Weight
	}

	// Build validator bitfield
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

	// Create aggregated attestation (without cryptographic aggregation)
	agg := &AggregatedAttestation{
		AggregationID:       uuid.New(),
		Scheme:              AttestationSchemeEd25519,
		MessageHash:         baseHash,
		AggregatedSignature: nil, // Ed25519 cannot aggregate signatures
		AggregatedPublicKey: nil, // Ed25519 cannot aggregate public keys
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

// VerifyAggregated verifies each attestation individually
// Ed25519 doesn't support aggregated verification
func (s *Ed25519Strategy) VerifyAggregated(ctx context.Context, agg *AggregatedAttestation) (bool, error) {
	if agg == nil {
		return false, fmt.Errorf("aggregated attestation is nil")
	}

	if agg.Scheme != AttestationSchemeEd25519 {
		return false, fmt.Errorf("invalid scheme: expected %s, got %s",
			AttestationSchemeEd25519, agg.Scheme)
	}

	// Ed25519 requires verifying each signature individually
	if len(agg.Attestations) == 0 {
		return false, fmt.Errorf("no attestations to verify")
	}

	for i, att := range agg.Attestations {
		valid, err := s.Verify(ctx, att)
		if err != nil {
			return false, fmt.Errorf("verify attestation %d: %w", i, err)
		}
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// SupportsAggregation returns false - Ed25519 doesn't support signature aggregation
func (s *Ed25519Strategy) SupportsAggregation() bool {
	return false
}

// PublicKey returns this validator's Ed25519 public key
func (s *Ed25519Strategy) PublicKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return []byte(s.publicKey)
}

// ValidatorID returns the validator identifier
func (s *Ed25519Strategy) ValidatorID() string {
	return s.config.ValidatorID
}

// ValidatorIndex returns the validator's index in the active set
func (s *Ed25519Strategy) ValidatorIndex() uint32 {
	return s.config.ValidatorIndex
}

// ComputeMessageHash computes the canonical hash of an attestation message
func (s *Ed25519Strategy) ComputeMessageHash(message *AttestationMessage) ([32]byte, error) {
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
func (s *Ed25519Strategy) PrivateKeyBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return []byte(s.privateKey)
}

// PublicKeyHex returns the public key as hex string
func (s *Ed25519Strategy) PublicKeyHex() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return hex.EncodeToString(s.publicKey)
}

// VerifySignatureBytes verifies a signature given raw bytes
func (s *Ed25519Strategy) VerifySignatureBytes(publicKey, signature, messageHash []byte) (bool, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size")
	}

	if len(signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size")
	}

	domainMsg := s.createDomainMessage(messageHash)
	valid := ed25519.Verify(publicKey, domainMsg, signature)

	return valid, nil
}

// GetDomain returns the signing domain
func (s *Ed25519Strategy) GetDomain() string {
	return s.config.Domain
}

// GetThresholdConfig returns the threshold configuration
func (s *Ed25519Strategy) GetThresholdConfig() *ThresholdConfig {
	return s.config.ThresholdConfig
}

// createDomainMessage creates a domain-separated message for signing
func (s *Ed25519Strategy) createDomainMessage(messageHash []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(s.config.Domain)
	buf.Write(messageHash)

	hash := sha256.Sum256(buf.Bytes())
	return hash[:]
}

// =============================================================================
// ED25519 STRATEGY FACTORY
// =============================================================================

// NewEd25519StrategyFromKeyHex creates an Ed25519 strategy from a hex-encoded private key
func NewEd25519StrategyFromKeyHex(validatorID string, validatorIndex uint32, privateKeyHex string) (*Ed25519Strategy, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(privateKeyBytes))
	}

	config := &Ed25519StrategyConfig{
		ValidatorID:     validatorID,
		ValidatorIndex:  validatorIndex,
		PrivateKey:      privateKeyBytes,
		Domain:          Ed25519DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}

	return NewEd25519Strategy(config)
}

// NewEd25519StrategyWithNewKey creates an Ed25519 strategy with a newly generated key pair
func NewEd25519StrategyWithNewKey(validatorID string, validatorIndex uint32) (*Ed25519Strategy, error) {
	config := &Ed25519StrategyConfig{
		ValidatorID:     validatorID,
		ValidatorIndex:  validatorIndex,
		PrivateKey:      nil, // Will generate new key
		Domain:          Ed25519DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}

	return NewEd25519Strategy(config)
}

// NewEd25519StrategyFromSeed creates an Ed25519 strategy from a seed (for deterministic key generation)
func NewEd25519StrategyFromSeed(validatorID string, validatorIndex uint32, seed []byte) (*Ed25519Strategy, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: expected %d, got %d", ed25519.SeedSize, len(seed))
	}

	privateKey := ed25519.NewKeyFromSeed(seed)

	config := &Ed25519StrategyConfig{
		ValidatorID:     validatorID,
		ValidatorIndex:  validatorIndex,
		PrivateKey:      privateKey,
		Domain:          Ed25519DomainResult,
		ThresholdConfig: DefaultThresholdConfig(),
	}

	return NewEd25519Strategy(config)
}
