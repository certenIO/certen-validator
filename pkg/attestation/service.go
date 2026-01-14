// Copyright 2025 Certen Protocol
//
// Attestation Service - Multi-Validator Attestation Collection
// Per Whitepaper Section 3.4.1 Component 4: Validator attestations
//
// This service:
// - Broadcasts attestation requests to peer validators
// - Collects attestations from the network
// - Aggregates attestations into bundles
// - Stores attestations in the database
// - Provides API for validators to exchange attestations

package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/anchor_proof"
	"github.com/certen/independant-validator/pkg/database"
)

// Service manages multi-validator attestation collection
type Service struct {
	mu sync.RWMutex

	// Dependencies
	repos  *database.Repositories
	signer *anchor_proof.AttestationSigner

	// Configuration
	validatorID   string
	peerEndpoints []string // URLs of peer validators (e.g., "http://validator-2:8080")
	requiredCount int      // Required attestations for consensus (typically 2f+1)
	timeout       time.Duration

	// Pending attestation bundles (proofID -> bundle)
	bundles map[uuid.UUID]*anchor_proof.AttestationBundle

	// HTTP client for peer communication
	httpClient *http.Client

	// Logging
	logger *log.Logger
}

// Config holds service configuration
type Config struct {
	ValidatorID     string
	PrivateKey      ed25519.PrivateKey
	PeerEndpoints   []string
	RequiredCount   int // Number of attestations required (e.g., 3 for 4 validators with f=1)
	Timeout         time.Duration
	Logger          *log.Logger
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		RequiredCount: 3, // 2f+1 where f=1 for 4 validators
		Timeout:       30 * time.Second,
		Logger:        log.New(log.Writer(), "[Attestation] ", log.LstdFlags),
	}
}

// NewService creates a new attestation service
func NewService(repos *database.Repositories, cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(log.Writer(), "[Attestation] ", log.LstdFlags)
	}

	// Create signer
	signer, err := anchor_proof.NewAttestationSigner(cfg.ValidatorID, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Service{
		repos:         repos,
		signer:        signer,
		validatorID:   cfg.ValidatorID,
		peerEndpoints: cfg.PeerEndpoints,
		requiredCount: cfg.RequiredCount,
		timeout:       cfg.Timeout,
		bundles:       make(map[uuid.UUID]*anchor_proof.AttestationBundle),
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		logger: cfg.Logger,
	}, nil
}

// =============================================================================
// Attestation Request/Response Types
// =============================================================================

// AttestationRequest is sent to peer validators requesting attestation
type AttestationRequest struct {
	// Request ID for tracking
	RequestID uuid.UUID `json:"request_id"`

	// Proof identification
	ProofID  uuid.UUID `json:"proof_id"`
	BatchID  uuid.UUID `json:"batch_id"`

	// What to attest to
	MerkleRoot   []byte `json:"merkle_root"`
	AnchorTxHash string `json:"anchor_tx_hash"`
	TxCount      int    `json:"tx_count"`

	// Anchor details
	AnchorBlockNumber int64  `json:"anchor_block_number"`
	AnchorChain       string `json:"anchor_chain"`

	// Requesting validator
	RequestingValidator string    `json:"requesting_validator"`
	RequestedAt         time.Time `json:"requested_at"`
}

// AttestationResponse is the response from a peer validator
type AttestationResponse struct {
	RequestID   uuid.UUID                       `json:"request_id"`
	Success     bool                            `json:"success"`
	Error       string                          `json:"error,omitempty"`
	Attestation *anchor_proof.ValidatorAttestation `json:"attestation,omitempty"`
}

// AttestationStatus tracks the collection status for a proof
type AttestationStatus struct {
	ProofID        uuid.UUID `json:"proof_id"`
	MerkleRoot     string    `json:"merkle_root"`
	AnchorTxHash   string    `json:"anchor_tx_hash"`
	RequiredCount  int       `json:"required_count"`
	CollectedCount int       `json:"collected_count"`
	IsSufficient   bool      `json:"is_sufficient"`
	Validators     []string  `json:"validators"` // Validator IDs who have attested
	StartedAt      time.Time `json:"started_at"`
}

// =============================================================================
// Attestation Collection
// =============================================================================

// RequestAttestations broadcasts attestation requests to all peer validators
// and collects their responses. This is called after an anchor is created.
func (s *Service) RequestAttestations(ctx context.Context, req *AttestationRequest) (*AttestationStatus, error) {
	s.mu.Lock()

	// Create or get existing bundle
	bundle, exists := s.bundles[req.ProofID]
	if !exists {
		bundle = anchor_proof.NewAttestationBundle(
			req.ProofID,
			req.MerkleRoot,
			req.AnchorTxHash,
			s.requiredCount,
		)
		s.bundles[req.ProofID] = bundle
	}
	s.mu.Unlock()

	s.logger.Printf("Requesting attestations from %d peers for proof %s", len(s.peerEndpoints), req.ProofID)

	// First, add our own attestation
	ownAttestation, err := s.signer.SignMerkleRoot(req.MerkleRoot, req.AnchorTxHash)
	if err != nil {
		s.logger.Printf("Failed to create own attestation: %v", err)
	} else {
		s.mu.Lock()
		if err := bundle.AddAttestation(ownAttestation); err != nil {
			s.logger.Printf("Failed to add own attestation: %v", err)
		} else {
			s.logger.Printf("Added own attestation to bundle")
		}
		s.mu.Unlock()

		// Store own attestation in database
		if s.repos != nil {
			s.storeAttestation(ctx, req.ProofID, ownAttestation)
		}
	}

	// Request attestations from peers in parallel
	var wg sync.WaitGroup
	responses := make(chan *AttestationResponse, len(s.peerEndpoints))

	for _, peer := range s.peerEndpoints {
		wg.Add(1)
		go func(peerURL string) {
			defer wg.Done()
			resp, err := s.requestFromPeer(ctx, peerURL, req)
			if err != nil {
				s.logger.Printf("Failed to get attestation from %s: %v", peerURL, err)
				responses <- &AttestationResponse{
					RequestID: req.RequestID,
					Success:   false,
					Error:     err.Error(),
				}
				return
			}
			responses <- resp
		}(peer)
	}

	// Wait for all requests to complete (or timeout)
	go func() {
		wg.Wait()
		close(responses)
	}()

	// Collect responses
	for resp := range responses {
		if resp.Success && resp.Attestation != nil {
			s.mu.Lock()
			if err := bundle.AddAttestation(resp.Attestation); err != nil {
				s.logger.Printf("Failed to add attestation: %v", err)
			} else {
				s.logger.Printf("Added attestation from %s", resp.Attestation.ValidatorID)
				// Store in database
				if s.repos != nil {
					s.storeAttestation(ctx, req.ProofID, resp.Attestation)
				}
			}
			s.mu.Unlock()
		}
	}

	// Return status
	s.mu.RLock()
	defer s.mu.RUnlock()

	return &AttestationStatus{
		ProofID:        req.ProofID,
		MerkleRoot:     fmt.Sprintf("%x", req.MerkleRoot),
		AnchorTxHash:   req.AnchorTxHash,
		RequiredCount:  s.requiredCount,
		CollectedCount: bundle.ValidCount,
		IsSufficient:   bundle.IsSufficient,
		Validators:     bundle.GetValidatorIDs(),
		StartedAt:      bundle.CreatedAt,
	}, nil
}

// requestFromPeer sends an attestation request to a single peer
func (s *Service) requestFromPeer(ctx context.Context, peerURL string, req *AttestationRequest) (*AttestationResponse, error) {
	// Serialize request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/attestations/request", peerURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Validator-ID", s.validatorID)

	// Send request
	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var attResp AttestationResponse
	if err := json.Unmarshal(body, &attResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &attResp, nil
}

// =============================================================================
// Attestation Handling (receiving requests from peers)
// =============================================================================

// HandleAttestationRequest processes an attestation request from a peer validator
// and returns our attestation if we agree with the proof
func (s *Service) HandleAttestationRequest(ctx context.Context, req *AttestationRequest) (*AttestationResponse, error) {
	s.logger.Printf("Received attestation request from %s for proof %s",
		req.RequestingValidator, req.ProofID)

	// Validate the request
	if len(req.MerkleRoot) != 32 {
		return &AttestationResponse{
			RequestID: req.RequestID,
			Success:   false,
			Error:     "invalid merkle root: must be 32 bytes",
		}, nil
	}

	if req.AnchorTxHash == "" {
		return &AttestationResponse{
			RequestID: req.RequestID,
			Success:   false,
			Error:     "anchor tx hash is required",
		}, nil
	}

	// TODO: Add additional validation:
	// - Verify the anchor tx exists on-chain
	// - Verify the merkle root matches our calculation
	// - Verify we have seen the transactions in the batch
	// For now, we trust the requesting validator (they are in our peer list)

	// Create our attestation
	attestation, err := s.signer.SignMerkleRoot(req.MerkleRoot, req.AnchorTxHash)
	if err != nil {
		return &AttestationResponse{
			RequestID: req.RequestID,
			Success:   false,
			Error:     fmt.Sprintf("failed to create attestation: %v", err),
		}, nil
	}

	s.logger.Printf("Created attestation for proof %s", req.ProofID)

	// Store our attestation
	if s.repos != nil {
		s.storeAttestation(ctx, req.ProofID, attestation)
	}

	return &AttestationResponse{
		RequestID:   req.RequestID,
		Success:     true,
		Attestation: attestation,
	}, nil
}

// storeAttestation stores an attestation in the database
func (s *Service) storeAttestation(ctx context.Context, proofID uuid.UUID, att *anchor_proof.ValidatorAttestation) {
	if s.repos == nil || s.repos.Attestations == nil {
		return
	}

	input := &database.NewValidatorAttestation{
		ProofID:            proofID,
		ValidatorID:        att.ValidatorID,
		ValidatorPubkey:    att.ValidatorPubkey,
		AttestedMerkleRoot: att.AttestedMerkleRoot,
		AttestedAnchorTx:   att.AttestedAnchorTx,
		Signature:          att.Signature,
	}

	_, err := s.repos.Attestations.CreateAttestation(ctx, input)
	if err != nil {
		s.logger.Printf("Failed to store attestation: %v", err)
	}
}

// =============================================================================
// Status and Bundle Management
// =============================================================================

// GetAttestationStatus returns the current status of attestation collection for a proof
func (s *Service) GetAttestationStatus(proofID uuid.UUID) *AttestationStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bundle, exists := s.bundles[proofID]
	if !exists {
		return nil
	}

	return &AttestationStatus{
		ProofID:        proofID,
		MerkleRoot:     fmt.Sprintf("%x", bundle.MerkleRoot),
		AnchorTxHash:   bundle.AnchorTxHash,
		RequiredCount:  bundle.RequiredCount,
		CollectedCount: bundle.ValidCount,
		IsSufficient:   bundle.IsSufficient,
		Validators:     bundle.GetValidatorIDs(),
		StartedAt:      bundle.CreatedAt,
	}
}

// GetBundle returns the attestation bundle for a proof
func (s *Service) GetBundle(proofID uuid.UUID) *anchor_proof.AttestationBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundles[proofID]
}

// CleanupOldBundles removes bundles older than the specified duration
func (s *Service) CleanupOldBundles(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	count := 0

	for id, bundle := range s.bundles {
		if bundle.CreatedAt.Before(cutoff) {
			delete(s.bundles, id)
			count++
		}
	}

	if count > 0 {
		s.logger.Printf("Cleaned up %d old attestation bundles", count)
	}
	return count
}

// =============================================================================
// Peer Management
// =============================================================================

// UpdatePeers updates the list of peer endpoints
func (s *Service) UpdatePeers(peers []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peerEndpoints = peers
	s.logger.Printf("Updated peer list: %v", peers)
}

// GetPeers returns the current peer endpoints
func (s *Service) GetPeers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.peerEndpoints
}

// GetValidatorID returns this validator's ID
func (s *Service) GetValidatorID() string {
	return s.validatorID
}

// GetPublicKey returns this validator's public key
func (s *Service) GetPublicKey() ed25519.PublicKey {
	return s.signer.GetPublicKey()
}

// =============================================================================
// Integration with Batch Processing
// =============================================================================

// OnBatchAnchored is called when a batch is successfully anchored to external chain
// This triggers attestation collection from peer validators
func (s *Service) OnBatchAnchored(ctx context.Context, batchID uuid.UUID, merkleRoot []byte, anchorTxHash string, txCount int, blockNumber int64) (*AttestationStatus, error) {
	req := &AttestationRequest{
		RequestID:           uuid.New(),
		ProofID:             uuid.New(), // Generate new proof ID for this batch
		BatchID:             batchID,
		MerkleRoot:          merkleRoot,
		AnchorTxHash:        anchorTxHash,
		TxCount:             txCount,
		AnchorBlockNumber:   blockNumber,
		AnchorChain:         "ethereum",
		RequestingValidator: s.validatorID,
		RequestedAt:         time.Now(),
	}

	return s.RequestAttestations(ctx, req)
}
