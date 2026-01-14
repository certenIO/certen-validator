// Copyright 2025 Certen Protocol
//
// AttestationCollectorService - Multi-validator attestation collection with Ed25519 verification
//
// Per Whitepaper Section 3.4.1:
// - Attestations require 2/3+1 validator quorum
// - Ed25519 signatures for cryptographic verification
// - P2P broadcast for decentralized attestation collection
//
// This service handles:
// - Creating attestations with Ed25519 signatures
// - Collecting attestations from other validators via P2P
// - Verifying attestation signatures
// - Checking quorum status
// - Broadcasting attestations to the network

package proof

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/google/uuid"
)

// =============================================================================
// Attestation Types
// =============================================================================

// Attestation represents a validator's attestation to a proof
type Attestation struct {
	AttestationID   uuid.UUID `json:"attestation_id"`
	ProofID         uuid.UUID `json:"proof_id"`
	BatchID         *uuid.UUID `json:"batch_id,omitempty"`
	ValidatorID     string    `json:"validator_id"`
	ValidatorPubKey []byte    `json:"validator_pubkey"` // Ed25519 public key (32 bytes)
	AttestedHash    []byte    `json:"attested_hash"`    // SHA256 hash being attested
	Signature       []byte    `json:"signature"`        // Ed25519 signature (64 bytes)
	AnchorTxHash    string    `json:"anchor_tx_hash,omitempty"`
	MerkleRoot      []byte    `json:"merkle_root,omitempty"`
	BlockNumber     int64     `json:"block_number,omitempty"`
	AttestedAt      time.Time `json:"attested_at"`
	SignatureValid  bool      `json:"signature_valid"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
}

// AttestationMessage is the message format for P2P broadcast
type AttestationMessage struct {
	Type        string       `json:"type"` // "attestation", "request", "response"
	Attestation *Attestation `json:"attestation,omitempty"`
	ProofID     *uuid.UUID   `json:"proof_id,omitempty"`
	SenderID    string       `json:"sender_id"`
	Timestamp   time.Time    `json:"timestamp"`
	Signature   []byte       `json:"signature"` // Signature of the entire message
}

// QuorumStatus represents the current attestation quorum status
type QuorumStatus struct {
	ProofID            uuid.UUID `json:"proof_id"`
	TotalValidators    int       `json:"total_validators"`
	RequiredQuorum     int       `json:"required_quorum"`
	CollectedCount     int       `json:"collected_count"`
	ValidCount         int       `json:"valid_count"`
	QuorumReached      bool      `json:"quorum_reached"`
	AttestationDetails []AttestationDetail `json:"attestation_details"`
}

// AttestationDetail contains information about a single attestation
type AttestationDetail struct {
	ValidatorID    string    `json:"validator_id"`
	SignatureValid bool      `json:"signature_valid"`
	AttestedAt     time.Time `json:"attested_at"`
}

// =============================================================================
// AttestationCollectorService
// =============================================================================

// AttestationCollectorService handles multi-validator attestation collection
type AttestationCollectorService struct {
	// Configuration
	config *AttestationConfig

	// Validator identity
	validatorID     string
	privateKey      ed25519.PrivateKey
	publicKey       ed25519.PublicKey

	// Known validators
	knownValidators map[string]ed25519.PublicKey
	validatorMu     sync.RWMutex

	// Repository for persistence
	repo *database.ProofArtifactRepository

	// Pending attestations (in-memory cache before DB persistence)
	pendingAttestations map[uuid.UUID][]*Attestation
	pendingMu           sync.RWMutex

	// P2P message handlers
	messageHandlers []AttestationMessageHandler
	handlerMu       sync.RWMutex

	// Quorum listeners
	quorumListeners []QuorumReachedListener
	listenerMu      sync.RWMutex

	// Metrics
	metrics *AttestationMetrics
}

// AttestationConfig contains service configuration
type AttestationConfig struct {
	TotalValidators      int           `json:"total_validators"`
	QuorumThreshold      float64       `json:"quorum_threshold"` // Default 2/3
	AttestationTimeout   time.Duration `json:"attestation_timeout"`
	BroadcastInterval    time.Duration `json:"broadcast_interval"`
	RetryAttempts        int           `json:"retry_attempts"`
	VerifyOnReceive      bool          `json:"verify_on_receive"`
}

// AttestationMessageHandler handles incoming attestation messages
type AttestationMessageHandler func(msg *AttestationMessage) error

// QuorumReachedListener is called when quorum is reached for a proof
type QuorumReachedListener func(proofID uuid.UUID, status *QuorumStatus)

// AttestationMetrics tracks service metrics
type AttestationMetrics struct {
	AttestationsCreated   int64
	AttestationsReceived  int64
	AttestationsVerified  int64
	AttestationsFailed    int64
	QuorumsReached        int64
	BroadcastsSent        int64
	BroadcastsReceived    int64
	LastAttestationAt     time.Time
	AverageVerificationMs float64
}

// DefaultAttestationConfig returns default configuration
func DefaultAttestationConfig() *AttestationConfig {
	return &AttestationConfig{
		TotalValidators:    4,
		QuorumThreshold:    2.0 / 3.0,
		AttestationTimeout: 30 * time.Second,
		BroadcastInterval:  5 * time.Second,
		RetryAttempts:      3,
		VerifyOnReceive:    true,
	}
}

// NewAttestationCollectorService creates a new attestation collector
func NewAttestationCollectorService(
	repo *database.ProofArtifactRepository,
	validatorID string,
	privateKey ed25519.PrivateKey,
	config *AttestationConfig,
) (*AttestationCollectorService, error) {
	if repo == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	if config == nil {
		config = DefaultAttestationConfig()
	}

	// Derive public key from private key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &AttestationCollectorService{
		config:              config,
		validatorID:         validatorID,
		privateKey:          privateKey,
		publicKey:           publicKey,
		knownValidators:     make(map[string]ed25519.PublicKey),
		repo:                repo,
		pendingAttestations: make(map[uuid.UUID][]*Attestation),
		messageHandlers:     make([]AttestationMessageHandler, 0),
		quorumListeners:     make([]QuorumReachedListener, 0),
		metrics:             &AttestationMetrics{},
	}, nil
}

// =============================================================================
// Validator Management
// =============================================================================

// RegisterValidator registers a known validator with their public key
func (s *AttestationCollectorService) RegisterValidator(validatorID string, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: got %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}

	s.validatorMu.Lock()
	defer s.validatorMu.Unlock()

	s.knownValidators[validatorID] = publicKey
	return nil
}

// RemoveValidator removes a validator from the known set
func (s *AttestationCollectorService) RemoveValidator(validatorID string) {
	s.validatorMu.Lock()
	defer s.validatorMu.Unlock()

	delete(s.knownValidators, validatorID)
}

// GetValidatorPublicKey returns the public key for a validator
func (s *AttestationCollectorService) GetValidatorPublicKey(validatorID string) (ed25519.PublicKey, bool) {
	s.validatorMu.RLock()
	defer s.validatorMu.RUnlock()

	key, ok := s.knownValidators[validatorID]
	return key, ok
}

// GetKnownValidatorCount returns the number of known validators
func (s *AttestationCollectorService) GetKnownValidatorCount() int {
	s.validatorMu.RLock()
	defer s.validatorMu.RUnlock()

	return len(s.knownValidators) + 1 // +1 for self
}

// =============================================================================
// Attestation Creation
// =============================================================================

// CreateAttestation creates a new attestation for a proof
func (s *AttestationCollectorService) CreateAttestation(ctx context.Context, proofID uuid.UUID, anchorTxHash string, merkleRoot []byte, blockNumber int64) (*Attestation, error) {
	// Compute the hash to be signed
	attestedHash := s.computeAttestedHash(proofID, anchorTxHash, merkleRoot, blockNumber)

	// Sign the hash with our private key
	signature := ed25519.Sign(s.privateKey, attestedHash)

	attestation := &Attestation{
		AttestationID:   uuid.New(),
		ProofID:         proofID,
		ValidatorID:     s.validatorID,
		ValidatorPubKey: s.publicKey,
		AttestedHash:    attestedHash,
		Signature:       signature,
		AnchorTxHash:    anchorTxHash,
		MerkleRoot:      merkleRoot,
		BlockNumber:     blockNumber,
		AttestedAt:      time.Now(),
		SignatureValid:  true, // We just signed it
	}

	// Verify our own signature (sanity check)
	if !ed25519.Verify(s.publicKey, attestedHash, signature) {
		return nil, fmt.Errorf("failed to verify own signature")
	}

	now := time.Now()
	attestation.VerifiedAt = &now

	// Store in database
	if err := s.storeAttestation(ctx, attestation); err != nil {
		return nil, fmt.Errorf("store attestation: %w", err)
	}

	// Add to pending cache
	s.addToPending(attestation)

	// Update metrics
	s.metrics.AttestationsCreated++
	s.metrics.LastAttestationAt = time.Now()

	return attestation, nil
}

// CreateBatchAttestation creates an attestation for a batch of proofs
func (s *AttestationCollectorService) CreateBatchAttestation(ctx context.Context, batchID uuid.UUID, anchorTxHash string, merkleRoot []byte, blockNumber int64) (*Attestation, error) {
	// Compute batch hash
	attestedHash := s.computeBatchAttestedHash(batchID, anchorTxHash, merkleRoot, blockNumber)

	// Sign the hash
	signature := ed25519.Sign(s.privateKey, attestedHash)

	attestation := &Attestation{
		AttestationID:   uuid.New(),
		BatchID:         &batchID,
		ValidatorID:     s.validatorID,
		ValidatorPubKey: s.publicKey,
		AttestedHash:    attestedHash,
		Signature:       signature,
		AnchorTxHash:    anchorTxHash,
		MerkleRoot:      merkleRoot,
		BlockNumber:     blockNumber,
		AttestedAt:      time.Now(),
		SignatureValid:  true,
	}

	now := time.Now()
	attestation.VerifiedAt = &now

	// Store in database
	if err := s.storeBatchAttestation(ctx, attestation); err != nil {
		return nil, fmt.Errorf("store batch attestation: %w", err)
	}

	s.metrics.AttestationsCreated++
	s.metrics.LastAttestationAt = time.Now()

	return attestation, nil
}

// computeAttestedHash computes the hash to be signed for a proof attestation
func (s *AttestationCollectorService) computeAttestedHash(proofID uuid.UUID, anchorTxHash string, merkleRoot []byte, blockNumber int64) []byte {
	// Canonical hash: SHA256(proof_id || anchor_tx_hash || merkle_root || block_number)
	data := fmt.Sprintf("%s|%s|%s|%d",
		proofID.String(),
		anchorTxHash,
		hex.EncodeToString(merkleRoot),
		blockNumber,
	)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// computeBatchAttestedHash computes the hash to be signed for a batch attestation
func (s *AttestationCollectorService) computeBatchAttestedHash(batchID uuid.UUID, anchorTxHash string, merkleRoot []byte, blockNumber int64) []byte {
	data := fmt.Sprintf("batch|%s|%s|%s|%d",
		batchID.String(),
		anchorTxHash,
		hex.EncodeToString(merkleRoot),
		blockNumber,
	)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

// =============================================================================
// Attestation Verification
// =============================================================================

// VerifyAttestation verifies an attestation's Ed25519 signature
func (s *AttestationCollectorService) VerifyAttestation(attestation *Attestation) (bool, error) {
	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	// Validate key sizes
	if len(attestation.ValidatorPubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("invalid public key size: got %d, want %d",
			len(attestation.ValidatorPubKey), ed25519.PublicKeySize)
	}
	if len(attestation.Signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid signature size: got %d, want %d",
			len(attestation.Signature), ed25519.SignatureSize)
	}
	if len(attestation.AttestedHash) != sha256.Size {
		return false, fmt.Errorf("invalid attested hash size: got %d, want %d",
			len(attestation.AttestedHash), sha256.Size)
	}

	startTime := time.Now()

	// Verify Ed25519 signature
	valid := ed25519.Verify(
		attestation.ValidatorPubKey,
		attestation.AttestedHash,
		attestation.Signature,
	)

	// Update metrics
	duration := time.Since(startTime).Milliseconds()
	if valid {
		s.metrics.AttestationsVerified++
	} else {
		s.metrics.AttestationsFailed++
	}

	// Update running average
	total := s.metrics.AttestationsVerified + s.metrics.AttestationsFailed
	s.metrics.AverageVerificationMs = (s.metrics.AverageVerificationMs*float64(total-1) + float64(duration)) / float64(total)

	return valid, nil
}

// VerifyAndStoreAttestation verifies and stores an incoming attestation
func (s *AttestationCollectorService) VerifyAndStoreAttestation(ctx context.Context, attestation *Attestation) error {
	// Verify the signature
	valid, err := s.VerifyAttestation(attestation)
	if err != nil {
		return fmt.Errorf("verify attestation: %w", err)
	}

	attestation.SignatureValid = valid
	now := time.Now()
	attestation.VerifiedAt = &now

	// Optionally verify the validator is known
	if pubKey, ok := s.GetValidatorPublicKey(attestation.ValidatorID); ok {
		// Verify the public key matches
		if !bytesEqualAttest(pubKey, attestation.ValidatorPubKey) {
			return fmt.Errorf("public key mismatch for validator %s", attestation.ValidatorID)
		}
	}

	// Store in database
	if err := s.storeAttestation(ctx, attestation); err != nil {
		return fmt.Errorf("store attestation: %w", err)
	}

	// Add to pending cache
	s.addToPending(attestation)

	// Check if quorum is reached
	if attestation.ProofID != uuid.Nil {
		s.checkAndNotifyQuorum(ctx, attestation.ProofID)
	}

	s.metrics.AttestationsReceived++

	return nil
}

// =============================================================================
// Quorum Management
// =============================================================================

// CalculateRequiredQuorum calculates the required quorum (2/3+1)
func (s *AttestationCollectorService) CalculateRequiredQuorum() int {
	return int(float64(s.config.TotalValidators)*s.config.QuorumThreshold) + 1
}

// GetQuorumStatus returns the current quorum status for a proof
func (s *AttestationCollectorService) GetQuorumStatus(ctx context.Context, proofID uuid.UUID) (*QuorumStatus, error) {
	// Get attestations from database
	attestations, err := s.repo.GetProofAttestationsByProof(ctx, proofID)
	if err != nil {
		return nil, fmt.Errorf("get attestations: %w", err)
	}

	requiredQuorum := s.CalculateRequiredQuorum()

	status := &QuorumStatus{
		ProofID:            proofID,
		TotalValidators:    s.config.TotalValidators,
		RequiredQuorum:     requiredQuorum,
		CollectedCount:     len(attestations),
		ValidCount:         0,
		QuorumReached:      false,
		AttestationDetails: make([]AttestationDetail, 0, len(attestations)),
	}

	for _, att := range attestations {
		detail := AttestationDetail{
			ValidatorID:    att.ValidatorID,
			SignatureValid: att.SignatureValid,
			AttestedAt:     att.AttestedAt,
		}
		status.AttestationDetails = append(status.AttestationDetails, detail)

		if att.SignatureValid {
			status.ValidCount++
		}
	}

	status.QuorumReached = status.ValidCount >= requiredQuorum

	return status, nil
}

// CheckQuorum checks if a proof has reached quorum
func (s *AttestationCollectorService) CheckQuorum(ctx context.Context, proofID uuid.UUID) (bool, int, error) {
	status, err := s.GetQuorumStatus(ctx, proofID)
	if err != nil {
		return false, 0, err
	}

	return status.QuorumReached, status.ValidCount, nil
}

// checkAndNotifyQuorum checks quorum and notifies listeners if reached
func (s *AttestationCollectorService) checkAndNotifyQuorum(ctx context.Context, proofID uuid.UUID) {
	status, err := s.GetQuorumStatus(ctx, proofID)
	if err != nil {
		return
	}

	if status.QuorumReached {
		s.metrics.QuorumsReached++
		s.notifyQuorumListeners(proofID, status)
	}
}

// AddQuorumListener adds a listener for quorum reached events
func (s *AttestationCollectorService) AddQuorumListener(listener QuorumReachedListener) {
	s.listenerMu.Lock()
	defer s.listenerMu.Unlock()
	s.quorumListeners = append(s.quorumListeners, listener)
}

// notifyQuorumListeners notifies all registered quorum listeners
func (s *AttestationCollectorService) notifyQuorumListeners(proofID uuid.UUID, status *QuorumStatus) {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()

	for _, listener := range s.quorumListeners {
		go listener(proofID, status)
	}
}

// =============================================================================
// P2P Message Handling
// =============================================================================

// BroadcastAttestation broadcasts an attestation to other validators
func (s *AttestationCollectorService) BroadcastAttestation(attestation *Attestation) (*AttestationMessage, error) {
	msg := &AttestationMessage{
		Type:        "attestation",
		Attestation: attestation,
		SenderID:    s.validatorID,
		Timestamp:   time.Now(),
	}

	// Sign the message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}

	msgHash := sha256.Sum256(msgBytes)
	msg.Signature = ed25519.Sign(s.privateKey, msgHash[:])

	s.metrics.BroadcastsSent++

	return msg, nil
}

// HandleIncomingMessage handles an incoming attestation message from P2P
func (s *AttestationCollectorService) HandleIncomingMessage(ctx context.Context, msgBytes []byte) error {
	var msg AttestationMessage
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		return fmt.Errorf("unmarshal message: %w", err)
	}

	// Verify message signature
	senderPubKey, ok := s.GetValidatorPublicKey(msg.SenderID)
	if !ok {
		return fmt.Errorf("unknown sender: %s", msg.SenderID)
	}

	// Create a copy of the message without the signature for verification
	msgCopy := msg
	msgCopy.Signature = nil
	msgCopyBytes, err := json.Marshal(msgCopy)
	if err != nil {
		return fmt.Errorf("marshal message copy: %w", err)
	}

	msgHash := sha256.Sum256(msgCopyBytes)
	if !ed25519.Verify(senderPubKey, msgHash[:], msg.Signature) {
		return fmt.Errorf("invalid message signature from %s", msg.SenderID)
	}

	s.metrics.BroadcastsReceived++

	// Handle based on message type
	switch msg.Type {
	case "attestation":
		if msg.Attestation != nil {
			return s.VerifyAndStoreAttestation(ctx, msg.Attestation)
		}
	case "request":
		// Handle attestation request (respond with our attestation if we have one)
		if msg.ProofID != nil {
			return s.handleAttestationRequest(ctx, *msg.ProofID, msg.SenderID)
		}
	}

	return nil
}

// handleAttestationRequest handles a request for attestations
func (s *AttestationCollectorService) handleAttestationRequest(ctx context.Context, proofID uuid.UUID, requesterID string) error {
	// Check if we have an attestation for this proof
	s.pendingMu.RLock()
	attestations, ok := s.pendingAttestations[proofID]
	s.pendingMu.RUnlock()

	if !ok || len(attestations) == 0 {
		return nil // No attestation to share
	}

	// Find our attestation
	for _, att := range attestations {
		if att.ValidatorID == s.validatorID {
			// We have an attestation - would normally broadcast it back
			// This would be handled by the P2P layer
			return nil
		}
	}

	return nil
}

// AddMessageHandler adds a handler for incoming messages
func (s *AttestationCollectorService) AddMessageHandler(handler AttestationMessageHandler) {
	s.handlerMu.Lock()
	defer s.handlerMu.Unlock()
	s.messageHandlers = append(s.messageHandlers, handler)
}

// =============================================================================
// Storage Operations
// =============================================================================

// storeAttestation stores an attestation in the database
func (s *AttestationCollectorService) storeAttestation(ctx context.Context, attestation *Attestation) error {
	input := &database.NewProofAttestation{
		ProofArtifactID: &attestation.ProofID,
		ValidatorID:     attestation.ValidatorID,
		ValidatorPubkey: attestation.ValidatorPubKey,
		AttestedHash:    attestation.AttestedHash,
		Signature:       attestation.Signature,
		MerkleRoot:      attestation.MerkleRoot,
		BlockNumber:     &attestation.BlockNumber,
		AttestedAt:      attestation.AttestedAt,
	}

	if attestation.AnchorTxHash != "" {
		input.AnchorTxHash = &attestation.AnchorTxHash
	}

	_, err := s.repo.CreateProofAttestation(ctx, input)
	return err
}

// storeBatchAttestation stores a batch attestation in the database
func (s *AttestationCollectorService) storeBatchAttestation(ctx context.Context, attestation *Attestation) error {
	input := &database.NewProofAttestation{
		BatchID:         attestation.BatchID,
		ValidatorID:     attestation.ValidatorID,
		ValidatorPubkey: attestation.ValidatorPubKey,
		AttestedHash:    attestation.AttestedHash,
		Signature:       attestation.Signature,
		MerkleRoot:      attestation.MerkleRoot,
		BlockNumber:     &attestation.BlockNumber,
		AttestedAt:      attestation.AttestedAt,
	}

	if attestation.AnchorTxHash != "" {
		input.AnchorTxHash = &attestation.AnchorTxHash
	}

	_, err := s.repo.CreateProofAttestation(ctx, input)
	return err
}

// addToPending adds an attestation to the pending cache
func (s *AttestationCollectorService) addToPending(attestation *Attestation) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	key := attestation.ProofID
	if key == uuid.Nil && attestation.BatchID != nil {
		key = *attestation.BatchID
	}

	s.pendingAttestations[key] = append(s.pendingAttestations[key], attestation)
}

// GetPendingAttestations returns pending attestations for a proof
func (s *AttestationCollectorService) GetPendingAttestations(proofID uuid.UUID) []*Attestation {
	s.pendingMu.RLock()
	defer s.pendingMu.RUnlock()

	attestations, ok := s.pendingAttestations[proofID]
	if !ok {
		return nil
	}

	// Return a copy
	result := make([]*Attestation, len(attestations))
	copy(result, attestations)
	return result
}

// ClearPendingAttestations clears pending attestations for a proof
func (s *AttestationCollectorService) ClearPendingAttestations(proofID uuid.UUID) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	delete(s.pendingAttestations, proofID)
}

// =============================================================================
// Batch Operations
// =============================================================================

// CollectAttestationsForProof actively collects attestations for a proof
func (s *AttestationCollectorService) CollectAttestationsForProof(ctx context.Context, proofID uuid.UUID, timeout time.Duration) (*QuorumStatus, error) {
	// Create a request message
	msg := &AttestationMessage{
		Type:      "request",
		ProofID:   &proofID,
		SenderID:  s.validatorID,
		Timestamp: time.Now(),
	}

	// Sign the message
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	msgHash := sha256.Sum256(msgBytes)
	msg.Signature = ed25519.Sign(s.privateKey, msgHash[:])

	// Notify handlers to broadcast the request
	s.handlerMu.RLock()
	for _, handler := range s.messageHandlers {
		msgBytesWithSig, _ := json.Marshal(msg)
		go handler(&AttestationMessage{
			Type:      "broadcast",
			SenderID:  s.validatorID,
			Timestamp: time.Now(),
			Signature: msgBytesWithSig,
		})
	}
	s.handlerMu.RUnlock()

	// Wait for attestations with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Timeout - return current status
			return s.GetQuorumStatus(context.Background(), proofID)
		case <-ticker.C:
			// Check if quorum is reached
			status, err := s.GetQuorumStatus(context.Background(), proofID)
			if err != nil {
				continue
			}
			if status.QuorumReached {
				return status, nil
			}
		}
	}
}

// =============================================================================
// Metrics and Status
// =============================================================================

// GetMetrics returns service metrics
func (s *AttestationCollectorService) GetMetrics() AttestationMetrics {
	return *s.metrics
}

// GetValidatorID returns this validator's ID
func (s *AttestationCollectorService) GetValidatorID() string {
	return s.validatorID
}

// GetPublicKey returns this validator's public key
func (s *AttestationCollectorService) GetPublicKey() ed25519.PublicKey {
	return s.publicKey
}

// =============================================================================
// Helper Functions
// =============================================================================

// bytesEqualAttest compares two byte slices for equality
func bytesEqualAttest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GenerateValidatorKeyPair generates a new Ed25519 key pair for a validator
func GenerateValidatorKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// SerializePublicKey serializes an Ed25519 public key to hex
func SerializePublicKey(pubKey ed25519.PublicKey) string {
	return hex.EncodeToString(pubKey)
}

// DeserializePublicKey deserializes a hex-encoded Ed25519 public key
func DeserializePublicKey(hexKey string) (ed25519.PublicKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(keyBytes), ed25519.PublicKeySize)
	}
	return keyBytes, nil
}
