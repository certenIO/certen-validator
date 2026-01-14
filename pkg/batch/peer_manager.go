// Copyright 2025 Certen Protocol
//
// PeerManager - HTTP-based Peer Manager for Multi-Validator Attestation
// Per Implementation Plan Phase 4, Task 4.2: P2P Attestation Broadcast
//
// This component implements the PeerManager interface used by AttestationBroadcaster
// to communicate with peer validators via HTTP. It bridges the BLS-based attestation
// system with HTTP peer communication.

package batch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/crypto/bls"
)

// =============================================================================
// HTTP Peer Manager Implementation
// =============================================================================

// HTTPPeerManager implements the PeerManager interface for HTTP-based peer communication
// This enables BLS-based attestation collection across validator network via HTTP
type HTTPPeerManager struct {
	// Validator identity
	validatorID string
	privateKey  *bls.PrivateKey
	publicKey   *bls.PublicKey

	// Peer configuration
	peers     []*ValidatorPeer
	peersMu   sync.RWMutex
	peersByID map[string]*ValidatorPeer

	// HTTP client for peer communication
	httpClient *http.Client

	// Total voting power tracking
	totalVotingPower int64

	logger *log.Logger
}

// HTTPPeerManagerConfig holds configuration for the HTTP peer manager
type HTTPPeerManagerConfig struct {
	ValidatorID    string
	BLSPrivateKey  []byte // 32-byte BLS private key
	PeerEndpoints  []PeerEndpointConfig
	RequestTimeout time.Duration
	Logger         *log.Logger
}

// PeerEndpointConfig holds configuration for a peer endpoint
type PeerEndpointConfig struct {
	ValidatorID string
	Endpoint    string
	PublicKey   []byte // BLS public key (48 bytes)
	VotingPower int64
}

// NewHTTPPeerManager creates a new HTTP-based peer manager
func NewHTTPPeerManager(cfg *HTTPPeerManagerConfig) (*HTTPPeerManager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if cfg.ValidatorID == "" {
		return nil, fmt.Errorf("validator ID is required")
	}
	if len(cfg.BLSPrivateKey) == 0 {
		return nil, fmt.Errorf("BLS private key is required")
	}

	// Parse BLS private key
	privateKey, err := bls.PrivateKeyFromBytes(cfg.BLSPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid BLS private key: %w", err)
	}

	// Derive public key
	publicKey := privateKey.PublicKey()

	timeout := cfg.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[HTTPPeerManager] ", log.LstdFlags)
	}

	pm := &HTTPPeerManager{
		validatorID: cfg.ValidatorID,
		privateKey:  privateKey,
		publicKey:   publicKey,
		peers:       make([]*ValidatorPeer, 0),
		peersByID:   make(map[string]*ValidatorPeer),
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}

	// Initialize peers from configuration
	for _, peerCfg := range cfg.PeerEndpoints {
		peer := &ValidatorPeer{
			ValidatorID: peerCfg.ValidatorID,
			PublicKey:   peerCfg.PublicKey,
			Endpoint:    peerCfg.Endpoint,
			VotingPower: peerCfg.VotingPower,
			LastSeen:    time.Time{},
			IsActive:    true,
		}
		pm.peers = append(pm.peers, peer)
		pm.peersByID[peerCfg.ValidatorID] = peer
		pm.totalVotingPower += peerCfg.VotingPower
	}

	// Add own voting power (assuming 1)
	pm.totalVotingPower++

	logger.Printf("HTTPPeerManager initialized: validator=%s, peers=%d, totalPower=%d",
		cfg.ValidatorID, len(pm.peers), pm.totalVotingPower)

	return pm, nil
}

// =============================================================================
// PeerManager Interface Implementation
// =============================================================================

// GetValidatorPeers returns all known validator peers
func (pm *HTTPPeerManager) GetValidatorPeers() []*ValidatorPeer {
	pm.peersMu.RLock()
	defer pm.peersMu.RUnlock()

	// Return a copy to prevent external modification
	peersCopy := make([]*ValidatorPeer, len(pm.peers))
	copy(peersCopy, pm.peers)
	return peersCopy
}

// SendAttestationRequest sends an attestation request to a specific peer via HTTP
func (pm *HTTPPeerManager) SendAttestationRequest(
	ctx context.Context,
	peer *ValidatorPeer,
	req *AttestationRequest,
) (*BatchAttestation, error) {
	if peer == nil {
		return nil, fmt.Errorf("peer is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("attestation request is nil")
	}

	// Serialize request
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}

	// Build URL
	url := fmt.Sprintf("%s/api/attestations/bls/request", peer.Endpoint)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Validator-ID", pm.validatorID)
	httpReq.Header.Set("X-Request-Type", "bls-attestation")

	// Send request
	startTime := time.Now()
	resp, err := pm.httpClient.Do(httpReq)
	if err != nil {
		pm.markPeerInactive(peer.ValidatorID)
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse attestation response
	var attResp BLSAttestationResponse
	if err := json.Unmarshal(body, &attResp); err != nil {
		return nil, fmt.Errorf("failed to parse attestation response: %w", err)
	}

	if !attResp.Success {
		return nil, fmt.Errorf("peer declined attestation: %s", attResp.Error)
	}

	if attResp.Attestation == nil {
		return nil, fmt.Errorf("peer response missing attestation")
	}

	// Update peer status
	pm.markPeerActive(peer.ValidatorID)

	pm.logger.Printf("Received BLS attestation from %s in %s",
		peer.ValidatorID[:8], time.Since(startTime))

	return attResp.Attestation, nil
}

// GetOwnValidatorID returns this validator's ID
func (pm *HTTPPeerManager) GetOwnValidatorID() string {
	return pm.validatorID
}

// GetOwnPrivateKey returns this validator's BLS private key for signing
func (pm *HTTPPeerManager) GetOwnPrivateKey() *bls.PrivateKey {
	return pm.privateKey
}

// GetOwnPublicKey returns this validator's BLS public key
func (pm *HTTPPeerManager) GetOwnPublicKey() *bls.PublicKey {
	return pm.publicKey
}

// GetTotalVotingPower returns the total voting power of all validators
func (pm *HTTPPeerManager) GetTotalVotingPower() int64 {
	pm.peersMu.RLock()
	defer pm.peersMu.RUnlock()
	return pm.totalVotingPower
}

// =============================================================================
// Peer Management Methods
// =============================================================================

// AddPeer adds a new peer to the manager
func (pm *HTTPPeerManager) AddPeer(peer *ValidatorPeer) error {
	if peer == nil {
		return fmt.Errorf("peer is nil")
	}
	if peer.ValidatorID == "" {
		return fmt.Errorf("peer validator ID is required")
	}
	if peer.Endpoint == "" {
		return fmt.Errorf("peer endpoint is required")
	}

	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()

	// Check if peer already exists
	if _, exists := pm.peersByID[peer.ValidatorID]; exists {
		// Update existing peer
		for i, p := range pm.peers {
			if p.ValidatorID == peer.ValidatorID {
				pm.peers[i] = peer
				break
			}
		}
		pm.peersByID[peer.ValidatorID] = peer
		return nil
	}

	// Add new peer
	pm.peers = append(pm.peers, peer)
	pm.peersByID[peer.ValidatorID] = peer
	pm.totalVotingPower += peer.VotingPower

	pm.logger.Printf("Added peer %s (endpoint=%s, power=%d)",
		peer.ValidatorID, peer.Endpoint, peer.VotingPower)

	return nil
}

// RemovePeer removes a peer from the manager
func (pm *HTTPPeerManager) RemovePeer(validatorID string) {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()

	peer, exists := pm.peersByID[validatorID]
	if !exists {
		return
	}

	// Remove from slice
	for i, p := range pm.peers {
		if p.ValidatorID == validatorID {
			pm.peers = append(pm.peers[:i], pm.peers[i+1:]...)
			break
		}
	}

	// Remove from map
	delete(pm.peersByID, validatorID)

	// Update total voting power
	pm.totalVotingPower -= peer.VotingPower

	pm.logger.Printf("Removed peer %s", validatorID)
}

// GetPeer returns a specific peer by validator ID
func (pm *HTTPPeerManager) GetPeer(validatorID string) (*ValidatorPeer, bool) {
	pm.peersMu.RLock()
	defer pm.peersMu.RUnlock()
	peer, exists := pm.peersByID[validatorID]
	return peer, exists
}

// GetActivePeers returns only peers marked as active
func (pm *HTTPPeerManager) GetActivePeers() []*ValidatorPeer {
	pm.peersMu.RLock()
	defer pm.peersMu.RUnlock()

	active := make([]*ValidatorPeer, 0)
	for _, peer := range pm.peers {
		if peer.IsActive {
			active = append(active, peer)
		}
	}
	return active
}

// UpdatePeerEndpoints updates peer list from configuration
func (pm *HTTPPeerManager) UpdatePeerEndpoints(endpoints []PeerEndpointConfig) {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()

	// Clear existing peers
	pm.peers = make([]*ValidatorPeer, 0)
	pm.peersByID = make(map[string]*ValidatorPeer)
	pm.totalVotingPower = 1 // Own voting power

	// Add new peers
	for _, cfg := range endpoints {
		peer := &ValidatorPeer{
			ValidatorID: cfg.ValidatorID,
			PublicKey:   cfg.PublicKey,
			Endpoint:    cfg.Endpoint,
			VotingPower: cfg.VotingPower,
			IsActive:    true,
		}
		pm.peers = append(pm.peers, peer)
		pm.peersByID[cfg.ValidatorID] = peer
		pm.totalVotingPower += cfg.VotingPower
	}

	pm.logger.Printf("Updated peer endpoints: %d peers, total power=%d",
		len(pm.peers), pm.totalVotingPower)
}

// markPeerActive marks a peer as active after successful communication
func (pm *HTTPPeerManager) markPeerActive(validatorID string) {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()

	if peer, exists := pm.peersByID[validatorID]; exists {
		peer.IsActive = true
		peer.LastSeen = time.Now()
	}
}

// markPeerInactive marks a peer as inactive after failed communication
func (pm *HTTPPeerManager) markPeerInactive(validatorID string) {
	pm.peersMu.Lock()
	defer pm.peersMu.Unlock()

	if peer, exists := pm.peersByID[validatorID]; exists {
		peer.IsActive = false
	}
}

// =============================================================================
// HTTP Response Types
// =============================================================================

// BLSAttestationResponse is the HTTP response containing a BLS attestation
type BLSAttestationResponse struct {
	Success     bool              `json:"success"`
	Error       string            `json:"error,omitempty"`
	Attestation *BatchAttestation `json:"attestation,omitempty"`
}

// =============================================================================
// BLS Attestation HTTP Handler
// =============================================================================

// BLSAttestationHandler handles incoming BLS attestation requests via HTTP
// This allows peer validators to request BLS attestations from this validator
type BLSAttestationHandler struct {
	privateKey    *bls.PrivateKey
	publicKey     *bls.PublicKey
	validatorID   string
	verifyRequest func(req *AttestationRequest) bool // Optional request verifier
	logger        *log.Logger
}

// NewBLSAttestationHandler creates a new BLS attestation HTTP handler
func NewBLSAttestationHandler(
	privateKey *bls.PrivateKey,
	publicKey *bls.PublicKey,
	validatorID string,
	verifyRequest func(req *AttestationRequest) bool,
	logger *log.Logger,
) *BLSAttestationHandler {
	if logger == nil {
		logger = log.New(log.Writer(), "[BLSAttestHandler] ", log.LstdFlags)
	}
	return &BLSAttestationHandler{
		privateKey:    privateKey,
		publicKey:     publicKey,
		validatorID:   validatorID,
		verifyRequest: verifyRequest,
		logger:        logger,
	}
}

// HandleBLSAttestationRequest processes an incoming HTTP request for BLS attestation
// This is the HTTP handler that should be registered at /api/attestations/bls/request
func (h *BLSAttestationHandler) HandleBLSAttestationRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		writeErrorResponse(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request
	var req AttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if len(req.MerkleRoot) != 32 {
		writeErrorResponse(w, "merkle_root must be 32 bytes", http.StatusBadRequest)
		return
	}

	// Check expiration
	if !req.ExpiresAt.IsZero() && time.Now().After(req.ExpiresAt) {
		writeErrorResponse(w, "attestation request expired", http.StatusBadRequest)
		return
	}

	// Optional: Verify request using custom callback
	if h.verifyRequest != nil && !h.verifyRequest(&req) {
		writeErrorResponse(w, "attestation request verification failed", http.StatusForbidden)
		return
	}

	h.logger.Printf("📥 Received BLS attestation request for batch %s from %s",
		req.BatchID.String()[:8], req.RequesterID[:8])

	// Compute message hash
	msgHash := computeAttestationMessageHash(req.BatchID, req.MerkleRoot, req.TxCount, req.BlockHeight)

	// Sign with BLS using attestation domain
	signature := h.privateKey.SignWithDomain(msgHash[:], bls.DomainAttestation)

	// Create attestation
	attestation := &BatchAttestation{
		BatchID:       req.BatchID,
		ValidatorID:   h.validatorID,
		MerkleRoot:    req.MerkleRoot,
		Signature:     signature.Bytes(),
		PublicKey:     h.publicKey.Bytes(),
		TxCount:       req.TxCount,
		BlockHeight:   req.BlockHeight,
		Timestamp:     time.Now(),
		AttestationID: fmt.Sprintf("att_%s_%s", req.BatchID.String()[:8], h.validatorID[:8]),
	}

	h.logger.Printf("✅ Created BLS attestation for batch %s (sig=%s...)",
		req.BatchID.String()[:8], hex.EncodeToString(attestation.Signature[:8]))

	// Send response
	resp := &BLSAttestationResponse{
		Success:     true,
		Attestation: attestation,
	}

	json.NewEncoder(w).Encode(resp)
}

// writeErrorResponse writes an error JSON response
func writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	resp := &BLSAttestationResponse{
		Success: false,
		Error:   message,
	}
	json.NewEncoder(w).Encode(resp)
}

// =============================================================================
// Factory Functions
// =============================================================================

// NewHTTPPeerManagerFromConfig creates an HTTPPeerManager from validator configuration
func NewHTTPPeerManagerFromConfig(
	validatorID string,
	blsPrivateKey []byte,
	peerEndpoints []string,
	logger *log.Logger,
) (*HTTPPeerManager, error) {
	// Convert simple endpoint strings to PeerEndpointConfig
	// For now, assume validators are named validator-1, validator-2, etc.
	// and extract validator ID from endpoint URL
	peerConfigs := make([]PeerEndpointConfig, 0)
	for i, endpoint := range peerEndpoints {
		peerID := fmt.Sprintf("validator-%d", i+1)
		// Try to extract validator ID from URL if it contains validator pattern
		if idx := len(endpoint); idx > 0 {
			// Use endpoint index as validator number
			peerID = fmt.Sprintf("peer-validator-%d", i+1)
		}

		peerConfigs = append(peerConfigs, PeerEndpointConfig{
			ValidatorID: peerID,
			Endpoint:    endpoint,
			VotingPower: 1, // Default voting power
		})
	}

	cfg := &HTTPPeerManagerConfig{
		ValidatorID:    validatorID,
		BLSPrivateKey:  blsPrivateKey,
		PeerEndpoints:  peerConfigs,
		RequestTimeout: 30 * time.Second,
		Logger:         logger,
	}

	return NewHTTPPeerManager(cfg)
}
