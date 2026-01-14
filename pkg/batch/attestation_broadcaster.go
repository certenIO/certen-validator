// Copyright 2025 Certen Protocol
//
// Phase 4: Multi-Validator Attestation Broadcaster
// Per CERTEN Whitepaper Section 3.4.1 Component 4: Multi-validator consensus
//
// This package handles broadcasting batch attestations to peer validators and
// collecting their BLS-signed attestations to reach quorum (2/3+1) before anchoring.
//
// Key features:
// - Broadcast attestation requests to validator network
// - Collect BLS-signed attestations from peers
// - Verify attestation signatures using real BLS12-381 cryptography
// - Enforce quorum requirements (2/3+1 validators)
// - Aggregate BLS signatures for on-chain verification

package batch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/google/uuid"
)

// =============================================================================
// ATTESTATION TYPES
// =============================================================================

// BatchAttestation represents a validator's signed attestation of a batch
type BatchAttestation struct {
	BatchID        uuid.UUID `json:"batch_id"`
	ValidatorID    string    `json:"validator_id"`
	MerkleRoot     []byte    `json:"merkle_root"`
	Signature      []byte    `json:"signature"`       // BLS signature over attestation data
	PublicKey      []byte    `json:"public_key"`      // Validator's BLS public key
	TxCount        int       `json:"tx_count"`
	BlockHeight    int64     `json:"block_height"`
	Timestamp      time.Time `json:"timestamp"`
	AttestationID  string    `json:"attestation_id"`
}

// AttestationRequest is sent to peers requesting attestation of a batch
type AttestationRequest struct {
	BatchID        uuid.UUID `json:"batch_id"`
	MerkleRoot     []byte    `json:"merkle_root"`
	TxHashes       [][]byte  `json:"tx_hashes"`
	TxCount        int       `json:"tx_count"`
	BlockHeight    int64     `json:"block_height"`
	RequesterID    string    `json:"requester_id"`
	Timestamp      time.Time `json:"timestamp"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// AttestationResult contains the outcome of attestation collection
type AttestationResult struct {
	BatchID              uuid.UUID            `json:"batch_id"`
	Attestations         []*BatchAttestation  `json:"attestations"`
	QuorumReached        bool                 `json:"quorum_reached"`
	AttestationCount     int                  `json:"attestation_count"`
	RequiredCount        int                  `json:"required_count"`
	AggregatedSignature  []byte               `json:"aggregated_signature,omitempty"`
	AggregatedPublicKey  []byte               `json:"aggregated_public_key,omitempty"`
	Timestamp            time.Time            `json:"timestamp"`
	CollectionDuration   time.Duration        `json:"collection_duration"`
}

// ValidatorPeer represents a peer validator in the network
type ValidatorPeer struct {
	ValidatorID   string    `json:"validator_id"`
	PublicKey     []byte    `json:"public_key"`
	Endpoint      string    `json:"endpoint"`
	VotingPower   int64     `json:"voting_power"`
	LastSeen      time.Time `json:"last_seen"`
	IsActive      bool      `json:"is_active"`
}

// =============================================================================
// PEER MANAGER INTERFACE
// =============================================================================

// PeerManager provides access to the validator peer network
type PeerManager interface {
	// GetValidatorPeers returns all known validator peers
	GetValidatorPeers() []*ValidatorPeer

	// SendAttestationRequest sends an attestation request to a specific peer
	SendAttestationRequest(ctx context.Context, peer *ValidatorPeer, req *AttestationRequest) (*BatchAttestation, error)

	// GetOwnValidatorID returns this validator's ID
	GetOwnValidatorID() string

	// GetOwnPrivateKey returns this validator's BLS private key for signing
	GetOwnPrivateKey() *bls.PrivateKey

	// GetOwnPublicKey returns this validator's BLS public key
	GetOwnPublicKey() *bls.PublicKey

	// GetTotalVotingPower returns the total voting power of all validators
	GetTotalVotingPower() int64
}

// =============================================================================
// ATTESTATION BROADCASTER
// =============================================================================

// AttestationBroadcaster handles broadcasting batch attestations to peers
// and collecting their responses for multi-validator consensus
type AttestationBroadcaster struct {
	peerManager    PeerManager
	attestations   map[string][]*BatchAttestation // batchID -> attestations
	attestationsMu sync.RWMutex
	quorumFraction float64       // Required fraction (default 2/3)
	timeout        time.Duration // Attestation collection timeout
	logger         *log.Logger
}

// AttestationBroadcasterConfig contains configuration for the broadcaster
type AttestationBroadcasterConfig struct {
	QuorumFraction float64       // Required fraction of validators (default 0.67 = 2/3)
	Timeout        time.Duration // Collection timeout (default 30s)
	Logger         *log.Logger
}

// DefaultAttestationBroadcasterConfig returns default configuration
func DefaultAttestationBroadcasterConfig() *AttestationBroadcasterConfig {
	return &AttestationBroadcasterConfig{
		QuorumFraction: 0.67, // 2/3 majority per BFT requirements
		Timeout:        30 * time.Second,
		Logger:         log.New(log.Writer(), "[AttestationBroadcaster] ", log.LstdFlags),
	}
}

// NewAttestationBroadcaster creates a new attestation broadcaster
func NewAttestationBroadcaster(pm PeerManager, cfg *AttestationBroadcasterConfig) (*AttestationBroadcaster, error) {
	if pm == nil {
		return nil, fmt.Errorf("peer manager cannot be nil")
	}
	if cfg == nil {
		cfg = DefaultAttestationBroadcasterConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[AttestationBroadcaster] ", log.LstdFlags)
	}
	if cfg.QuorumFraction <= 0 || cfg.QuorumFraction > 1 {
		cfg.QuorumFraction = 0.67
	}

	return &AttestationBroadcaster{
		peerManager:    pm,
		attestations:   make(map[string][]*BatchAttestation),
		quorumFraction: cfg.QuorumFraction,
		timeout:        cfg.Timeout,
		logger:         cfg.Logger,
	}, nil
}

// BroadcastAndCollect broadcasts attestation request and collects responses
// Returns attestations when quorum is reached or timeout expires
func (ab *AttestationBroadcaster) BroadcastAndCollect(
	ctx context.Context,
	batch *ClosedBatchResult,
) (*AttestationResult, error) {
	if batch == nil {
		return nil, fmt.Errorf("batch cannot be nil")
	}

	startTime := time.Now()
	batchIDStr := batch.BatchID.String()

	ab.logger.Printf("🔔 Starting attestation collection for batch %s (txs=%d)", batchIDStr[:8], batch.TxCount)

	// Create attestation request
	req := &AttestationRequest{
		BatchID:     batch.BatchID,
		MerkleRoot:  batch.MerkleRoot,
		TxHashes:    extractTxHashesFromBatch(batch),
		TxCount:     batch.TxCount,
		BlockHeight: batch.AccumulateHeight,
		RequesterID: ab.peerManager.GetOwnValidatorID(),
		Timestamp:   time.Now(),
		ExpiresAt:   time.Now().Add(ab.timeout),
	}

	// Get validator peers
	peers := ab.peerManager.GetValidatorPeers()
	if len(peers) == 0 {
		ab.logger.Printf("⚠️ No validator peers available")
		// Return self-attestation only
		return ab.createSelfAttestationResult(batch, startTime)
	}

	// Calculate required quorum
	totalValidators := len(peers) + 1 // +1 for self
	requiredCount := int(float64(totalValidators)*ab.quorumFraction) + 1
	if requiredCount > totalValidators {
		requiredCount = totalValidators
	}

	ab.logger.Printf("📊 Quorum requirement: %d/%d validators (%.0f%%)",
		requiredCount, totalValidators, ab.quorumFraction*100)

	// Create self-attestation first
	selfAttestation, err := ab.createSelfAttestation(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to create self attestation: %w", err)
	}

	collected := []*BatchAttestation{selfAttestation}
	ab.logger.Printf("✅ Self-attestation created")

	// Broadcast to peers in parallel
	responses := make(chan *BatchAttestation, len(peers))
	errors := make(chan error, len(peers))

	var wg sync.WaitGroup
	for _, peer := range peers {
		wg.Add(1)
		go func(p *ValidatorPeer) {
			defer wg.Done()
			att, err := ab.requestAttestationFromPeer(ctx, p, req)
			if err != nil {
				errors <- fmt.Errorf("peer %s: %w", p.ValidatorID, err)
				return
			}
			if att != nil {
				responses <- att
			}
		}(peer)
	}

	// Close channels when all goroutines complete
	go func() {
		wg.Wait()
		close(responses)
		close(errors)
	}()

	// Collect responses with timeout
	deadline := time.After(ab.timeout)

	collectLoop:
	for {
		select {
		case att, ok := <-responses:
			if !ok {
				break collectLoop
			}
			// Verify attestation signature
			if ab.verifyAttestation(att, batch.MerkleRoot) {
				collected = append(collected, att)
				ab.logger.Printf("✅ Valid attestation from %s (%d/%d)",
					att.ValidatorID[:8], len(collected), requiredCount)

				if len(collected) >= requiredCount {
					ab.logger.Printf("🎉 Quorum reached!")
					break collectLoop
				}
			} else {
				ab.logger.Printf("⚠️ Invalid attestation signature from %s", att.ValidatorID[:8])
			}

		case err := <-errors:
			ab.logger.Printf("⚠️ Attestation error: %v", err)

		case <-deadline:
			ab.logger.Printf("⏰ Collection timeout reached")
			break collectLoop

		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Store collected attestations
	ab.attestationsMu.Lock()
	ab.attestations[batchIDStr] = collected
	ab.attestationsMu.Unlock()

	// Build result
	result := &AttestationResult{
		BatchID:            batch.BatchID,
		Attestations:       collected,
		QuorumReached:      len(collected) >= requiredCount,
		AttestationCount:   len(collected),
		RequiredCount:      requiredCount,
		Timestamp:          time.Now(),
		CollectionDuration: time.Since(startTime),
	}

	// Aggregate signatures if quorum reached
	if result.QuorumReached {
		aggSig, aggPk, err := ab.aggregateSignatures(collected)
		if err != nil {
			ab.logger.Printf("⚠️ Failed to aggregate signatures: %v", err)
		} else {
			result.AggregatedSignature = aggSig
			result.AggregatedPublicKey = aggPk
			ab.logger.Printf("✅ Aggregated %d BLS signatures", len(collected))
		}
	}

	ab.logger.Printf("📋 Attestation collection complete: %d attestations, quorum=%v, duration=%s",
		len(collected), result.QuorumReached, result.CollectionDuration)

	return result, nil
}

// requestAttestationFromPeer requests attestation from a specific peer
func (ab *AttestationBroadcaster) requestAttestationFromPeer(
	ctx context.Context,
	peer *ValidatorPeer,
	req *AttestationRequest,
) (*BatchAttestation, error) {
	// Use peer manager to send request
	att, err := ab.peerManager.SendAttestationRequest(ctx, peer, req)
	if err != nil {
		return nil, err
	}

	return att, nil
}

// createSelfAttestation creates this validator's own attestation of the batch
func (ab *AttestationBroadcaster) createSelfAttestation(batch *ClosedBatchResult) (*BatchAttestation, error) {
	privateKey := ab.peerManager.GetOwnPrivateKey()
	publicKey := ab.peerManager.GetOwnPublicKey()

	if privateKey == nil || publicKey == nil {
		return nil, fmt.Errorf("BLS keys not configured")
	}

	// Compute attestation message hash
	msgHash := computeAttestationMessageHash(batch.BatchID, batch.MerkleRoot, batch.TxCount, batch.AccumulateHeight)

	// Sign with BLS using attestation domain
	signature := privateKey.SignWithDomain(msgHash[:], bls.DomainAttestation)

	attestation := &BatchAttestation{
		BatchID:       batch.BatchID,
		ValidatorID:   ab.peerManager.GetOwnValidatorID(),
		MerkleRoot:    batch.MerkleRoot,
		Signature:     signature.Bytes(),
		PublicKey:     publicKey.Bytes(),
		TxCount:       batch.TxCount,
		BlockHeight:   batch.AccumulateHeight,
		Timestamp:     time.Now(),
		AttestationID: fmt.Sprintf("att_%s_%s", batch.BatchID.String()[:8], ab.peerManager.GetOwnValidatorID()[:8]),
	}

	return attestation, nil
}

// createSelfAttestationResult creates a result with only self-attestation (for standalone mode)
func (ab *AttestationBroadcaster) createSelfAttestationResult(
	batch *ClosedBatchResult,
	startTime time.Time,
) (*AttestationResult, error) {
	selfAttestation, err := ab.createSelfAttestation(batch)
	if err != nil {
		return nil, err
	}

	return &AttestationResult{
		BatchID:            batch.BatchID,
		Attestations:       []*BatchAttestation{selfAttestation},
		QuorumReached:      false, // Single validator cannot reach quorum
		AttestationCount:   1,
		RequiredCount:      2, // Minimum for any quorum
		Timestamp:          time.Now(),
		CollectionDuration: time.Since(startTime),
	}, nil
}

// verifyAttestation verifies a peer's attestation signature
func (ab *AttestationBroadcaster) verifyAttestation(att *BatchAttestation, expectedRoot []byte) bool {
	// 1. Check merkle root matches
	if !bytes.Equal(att.MerkleRoot, expectedRoot) {
		ab.logger.Printf("⚠️ Merkle root mismatch from %s", att.ValidatorID[:8])
		return false
	}

	// 2. Validate public key format
	if err := bls.ValidateBLSPublicKeySubgroup(att.PublicKey); err != nil {
		ab.logger.Printf("⚠️ Invalid public key from %s: %v", att.ValidatorID[:8], err)
		return false
	}

	// 3. Validate signature format
	if err := bls.ValidateBLSSignatureSubgroup(att.Signature); err != nil {
		ab.logger.Printf("⚠️ Invalid signature from %s: %v", att.ValidatorID[:8], err)
		return false
	}

	// 4. Deserialize public key and signature
	pubKey, err := bls.PublicKeyFromBytes(att.PublicKey)
	if err != nil {
		ab.logger.Printf("⚠️ Failed to parse public key from %s: %v", att.ValidatorID[:8], err)
		return false
	}

	sig, err := bls.SignatureFromBytes(att.Signature)
	if err != nil {
		ab.logger.Printf("⚠️ Failed to parse signature from %s: %v", att.ValidatorID[:8], err)
		return false
	}

	// 5. Compute expected message hash
	msgHash := computeAttestationMessageHash(att.BatchID, att.MerkleRoot, att.TxCount, att.BlockHeight)

	// 6. Verify BLS signature with domain separation
	if !pubKey.VerifyWithDomain(sig, msgHash[:], bls.DomainAttestation) {
		ab.logger.Printf("⚠️ Signature verification failed for %s", att.ValidatorID[:8])
		return false
	}

	return true
}

// aggregateSignatures aggregates BLS signatures from multiple attestations
func (ab *AttestationBroadcaster) aggregateSignatures(attestations []*BatchAttestation) ([]byte, []byte, error) {
	if len(attestations) == 0 {
		return nil, nil, fmt.Errorf("no attestations to aggregate")
	}

	// Collect signatures and public keys
	sigs := make([]*bls.Signature, 0, len(attestations))
	pks := make([]*bls.PublicKey, 0, len(attestations))

	for _, att := range attestations {
		sig, err := bls.SignatureFromBytes(att.Signature)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse signature: %w", err)
		}
		sigs = append(sigs, sig)

		pk, err := bls.PublicKeyFromBytes(att.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		pks = append(pks, pk)
	}

	// Aggregate signatures
	aggSig, err := bls.AggregateSignatures(sigs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	// Aggregate public keys
	aggPk, err := bls.AggregatePublicKeys(pks)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to aggregate public keys: %w", err)
	}

	return aggSig.Bytes(), aggPk.Bytes(), nil
}

// GetAttestations retrieves stored attestations for a batch
func (ab *AttestationBroadcaster) GetAttestations(batchID uuid.UUID) []*BatchAttestation {
	ab.attestationsMu.RLock()
	defer ab.attestationsMu.RUnlock()
	return ab.attestations[batchID.String()]
}

// ClearAttestations removes attestations for a batch (after successful anchoring)
func (ab *AttestationBroadcaster) ClearAttestations(batchID uuid.UUID) {
	ab.attestationsMu.Lock()
	defer ab.attestationsMu.Unlock()
	delete(ab.attestations, batchID.String())
}

// =============================================================================
// ATTESTATION HANDLER (for receiving requests from peers)
// =============================================================================

// AttestationHandler handles incoming attestation requests from peers
type AttestationHandler struct {
	privateKey  *bls.PrivateKey
	publicKey   *bls.PublicKey
	validatorID string
	verifyBatch func(req *AttestationRequest) bool // Callback to verify batch data
	logger      *log.Logger
}

// NewAttestationHandler creates a handler for incoming attestation requests
func NewAttestationHandler(
	privateKey *bls.PrivateKey,
	publicKey *bls.PublicKey,
	validatorID string,
	verifyBatch func(req *AttestationRequest) bool,
	logger *log.Logger,
) *AttestationHandler {
	if logger == nil {
		logger = log.New(log.Writer(), "[AttestationHandler] ", log.LstdFlags)
	}
	return &AttestationHandler{
		privateKey:  privateKey,
		publicKey:   publicKey,
		validatorID: validatorID,
		verifyBatch: verifyBatch,
		logger:      logger,
	}
}

// HandleAttestationRequest processes an incoming attestation request
func (ah *AttestationHandler) HandleAttestationRequest(
	ctx context.Context,
	req *AttestationRequest,
) (*BatchAttestation, error) {
	ah.logger.Printf("📥 Received attestation request for batch %s from %s",
		req.BatchID.String()[:8], req.RequesterID[:8])

	// Check expiration
	if time.Now().After(req.ExpiresAt) {
		return nil, fmt.Errorf("attestation request expired")
	}

	// Verify batch data if verifier callback is set
	if ah.verifyBatch != nil && !ah.verifyBatch(req) {
		return nil, fmt.Errorf("batch verification failed")
	}

	// Verify merkle root length
	if len(req.MerkleRoot) != 32 {
		return nil, fmt.Errorf("invalid merkle root length: %d", len(req.MerkleRoot))
	}

	// Compute attestation message hash
	msgHash := computeAttestationMessageHash(req.BatchID, req.MerkleRoot, req.TxCount, req.BlockHeight)

	// Sign with BLS using attestation domain
	signature := ah.privateKey.SignWithDomain(msgHash[:], bls.DomainAttestation)

	attestation := &BatchAttestation{
		BatchID:       req.BatchID,
		ValidatorID:   ah.validatorID,
		MerkleRoot:    req.MerkleRoot,
		Signature:     signature.Bytes(),
		PublicKey:     ah.publicKey.Bytes(),
		TxCount:       req.TxCount,
		BlockHeight:   req.BlockHeight,
		Timestamp:     time.Now(),
		AttestationID: fmt.Sprintf("att_%s_%s", req.BatchID.String()[:8], ah.validatorID[:8]),
	}

	ah.logger.Printf("✅ Created attestation for batch %s", req.BatchID.String()[:8])
	return attestation, nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// computeAttestationMessageHash computes the canonical message hash for signing
func computeAttestationMessageHash(batchID uuid.UUID, merkleRoot []byte, txCount int, blockHeight int64) [32]byte {
	// Canonical format: batch_id || merkle_root || tx_count || block_height
	h := sha256.New()
	h.Write(batchID[:])
	h.Write(merkleRoot)
	h.Write([]byte(fmt.Sprintf("%d", txCount)))
	h.Write([]byte(fmt.Sprintf("%d", blockHeight)))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// ComputeAttestationMessageHashExported is an exported version for testing
func ComputeAttestationMessageHashExported(batchID uuid.UUID, merkleRoot []byte, txCount int, blockHeight int64) [32]byte {
	return computeAttestationMessageHash(batchID, merkleRoot, txCount, blockHeight)
}

// extractTxHashesFromBatch extracts transaction hashes from a closed batch
func extractTxHashesFromBatch(batch *ClosedBatchResult) [][]byte {
	if batch.Transactions == nil {
		return nil
	}

	hashes := make([][]byte, 0, len(batch.Transactions))
	for _, tx := range batch.Transactions {
		if len(tx.TxHash) > 0 {
			hashCopy := make([]byte, len(tx.TxHash))
			copy(hashCopy, tx.TxHash)
			hashes = append(hashes, hashCopy)
		}
	}
	return hashes
}

// SerializeAttestation serializes an attestation to JSON
func SerializeAttestation(att *BatchAttestation) ([]byte, error) {
	return json.Marshal(att)
}

// DeserializeAttestation deserializes an attestation from JSON
func DeserializeAttestation(data []byte) (*BatchAttestation, error) {
	var att BatchAttestation
	if err := json.Unmarshal(data, &att); err != nil {
		return nil, err
	}
	return &att, nil
}

// SerializeAttestationRequest serializes an attestation request to JSON
func SerializeAttestationRequest(req *AttestationRequest) ([]byte, error) {
	return json.Marshal(req)
}

// DeserializeAttestationRequest deserializes an attestation request from JSON
func DeserializeAttestationRequest(data []byte) (*AttestationRequest, error) {
	var req AttestationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, err
	}
	return &req, nil
}

// AttestationToHexSummary creates a hex summary of an attestation for logging
func AttestationToHexSummary(att *BatchAttestation) string {
	return fmt.Sprintf("{batch=%s, validator=%s, sig=%s..., root=%s...}",
		att.BatchID.String()[:8],
		att.ValidatorID[:8],
		hex.EncodeToString(att.Signature[:8]),
		hex.EncodeToString(att.MerkleRoot[:8]))
}
