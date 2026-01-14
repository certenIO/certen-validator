// Copyright 2025 Certen Protocol
//
// Attestation API Handlers
// Per Whitepaper Section 3.4.1 Component 4: Validator attestations
//
// These handlers:
// - Accept attestation requests from peer validators
// - Return attestation status for ongoing collection
// - Provide attestation bundle information

package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/attestation"
)

// AttestationHandlers provides HTTP handlers for multi-validator attestation
type AttestationHandlers struct {
	service     *attestation.Service
	validatorID string
	logger      *log.Logger
}

// NewAttestationHandlers creates new attestation handlers
func NewAttestationHandlers(service *attestation.Service, validatorID string, logger *log.Logger) *AttestationHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[AttestationAPI] ", log.LstdFlags)
	}
	return &AttestationHandlers{
		service:     service,
		validatorID: validatorID,
		logger:      logger,
	}
}

// HandleAttestationRequest handles POST /api/attestations/request
// This is called by peer validators requesting our attestation for a proof
func (h *AttestationHandlers) HandleAttestationRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		writeJSONError(w, "attestation service not available", http.StatusServiceUnavailable)
		return
	}

	// Parse the attestation request from peer
	var req attestation.AttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if len(req.MerkleRoot) != 32 {
		writeJSONError(w, "merkle_root must be 32 bytes", http.StatusBadRequest)
		return
	}
	if req.AnchorTxHash == "" {
		writeJSONError(w, "anchor_tx_hash is required", http.StatusBadRequest)
		return
	}

	h.logger.Printf("Received attestation request from %s for proof %s",
		req.RequestingValidator, req.ProofID)

	// Process the attestation request
	resp, err := h.service.HandleAttestationRequest(r.Context(), &req)
	if err != nil {
		h.logger.Printf("Failed to handle attestation request: %v", err)
		writeJSONError(w, "failed to process attestation request", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

// HandleGetAttestationStatus handles GET /api/attestations/status/:proof_id
// Returns the current attestation collection status for a proof
func (h *AttestationHandlers) HandleGetAttestationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		writeJSONError(w, "attestation service not available", http.StatusServiceUnavailable)
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/attestations/status/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "proof ID required", http.StatusBadRequest)
		return
	}

	proofID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid proof ID", http.StatusBadRequest)
		return
	}

	// Get attestation status
	status := h.service.GetAttestationStatus(proofID)
	if status == nil {
		writeJSONError(w, "no attestation collection for this proof", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(status)
}

// HandleGetAttestationBundle handles GET /api/attestations/bundle/:proof_id
// Returns the full attestation bundle for a proof
func (h *AttestationHandlers) HandleGetAttestationBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		writeJSONError(w, "attestation service not available", http.StatusServiceUnavailable)
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/attestations/bundle/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "proof ID required", http.StatusBadRequest)
		return
	}

	proofID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid proof ID", http.StatusBadRequest)
		return
	}

	// Get attestation bundle
	bundle := h.service.GetBundle(proofID)
	if bundle == nil {
		writeJSONError(w, "no attestation bundle for this proof", http.StatusNotFound)
		return
	}

	// Return bundle info (without exposing raw signatures directly)
	response := map[string]interface{}{
		"proof_id":        proofID,
		"merkle_root":     bundle.MerkleRootHex(),
		"anchor_tx_hash":  bundle.AnchorTxHash,
		"required_count":  bundle.RequiredCount,
		"collected_count": bundle.ValidCount,
		"is_sufficient":   bundle.IsSufficient,
		"validators":      bundle.GetValidatorIDs(),
		"created_at":      bundle.CreatedAt.Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// HandleGetPeers handles GET /api/attestations/peers
// Returns the configured peer validators for attestation
func (h *AttestationHandlers) HandleGetPeers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.service == nil {
		writeJSONError(w, "attestation service not available", http.StatusServiceUnavailable)
		return
	}

	response := map[string]interface{}{
		"validator_id": h.validatorID,
		"peers":        h.service.GetPeers(),
		"public_key":   h.service.GetPublicKey(),
	}

	json.NewEncoder(w).Encode(response)
}

// HandleAttestationInfo handles GET /api/attestations
// Returns general attestation service information
func (h *AttestationHandlers) HandleAttestationInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"service":      "attestation",
		"validator_id": h.validatorID,
		"available":    h.service != nil,
		"description":  "Multi-validator attestation collection per Whitepaper Section 3.4.1",
		"endpoints": []string{
			"POST /api/attestations/request - Receive attestation request from peer",
			"GET /api/attestations/status/:proof_id - Get attestation collection status",
			"GET /api/attestations/bundle/:proof_id - Get attestation bundle",
			"GET /api/attestations/peers - Get configured peer validators",
		},
	}

	if h.service != nil {
		response["peers_count"] = len(h.service.GetPeers())
	}

	json.NewEncoder(w).Encode(response)
}
