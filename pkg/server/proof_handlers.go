// Copyright 2025 Certen Protocol
//
// Proof Artifact API Handlers
// Implements endpoints from API_ACCESS_PATTERNS.md for external customers and auditing nodes

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// ProofHandlers provides HTTP handlers for proof artifact operations
type ProofHandlers struct {
	repos       *database.Repositories
	validatorID string
	logger      *log.Logger
}

// NewProofHandlers creates new proof artifact handlers
func NewProofHandlers(repos *database.Repositories, validatorID string, logger *log.Logger) *ProofHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[ProofAPI] ", log.LstdFlags)
	}
	return &ProofHandlers{
		repos:       repos,
		validatorID: validatorID,
		logger:      logger,
	}
}

// ============================================================================
// PROOF DISCOVERY ENDPOINTS
// ============================================================================

// HandleGetProofByTxHash handles GET /api/v1/proofs/tx/{accum_tx_hash}
func (h *ProofHandlers) HandleGetProofByTxHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract tx hash from path: /api/v1/proofs/tx/{hash}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/tx/")
	txHash := strings.TrimSuffix(path, "/")
	if txHash == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_TX_HASH", "Transaction hash is required")
		return
	}

	ctx := r.Context()
	proof, err := h.repos.ProofArtifacts.GetProofByTxHash(ctx, txHash)
	if err != nil {
		h.logger.Printf("Error getting proof by tx hash: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proof")
		return
	}

	if proof == nil {
		h.writeError(w, http.StatusNotFound, "PROOF_NOT_FOUND", fmt.Sprintf("No proof found for tx hash: %s", txHash))
		return
	}

	h.writeJSON(w, http.StatusOK, proof)
}

// HandleGetProofByID handles GET /api/v1/proofs/{proof_id}
func (h *ProofHandlers) HandleGetProofByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path: /api/v1/proofs/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	proofIDStr := strings.Split(path, "/")[0]

	proofID, err := uuid.Parse(proofIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	proof, err := h.repos.ProofArtifacts.GetProofWithDetails(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting proof: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proof")
		return
	}

	if proof == nil {
		h.writeError(w, http.StatusNotFound, "PROOF_NOT_FOUND", fmt.Sprintf("No proof found with ID: %s", proofID))
		return
	}

	h.writeJSON(w, http.StatusOK, proof)
}

// HandleGetProofsByAccount handles GET /api/v1/proofs/account/{account_url}
func (h *ProofHandlers) HandleGetProofsByAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract account URL from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/account/")
	accountURL := strings.TrimSuffix(path, "/")
	if accountURL == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_ACCOUNT", "Account URL is required")
		return
	}

	// Parse pagination params
	limit := h.parseIntParam(r, "limit", 50)
	offset := h.parseIntParam(r, "offset", 0)
	if limit > 1000 {
		limit = 1000
	}

	ctx := r.Context()
	proofs, err := h.repos.ProofArtifacts.GetProofsByAccount(ctx, accountURL, limit, offset)
	if err != nil {
		h.logger.Printf("Error getting proofs by account: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proofs")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"account_url": accountURL,
		"proofs":      proofs,
		"count":       len(proofs),
		"limit":       limit,
		"offset":      offset,
	})
}

// HandleGetProofsByBatch handles GET /api/v1/proofs/batch/{batch_id}
func (h *ProofHandlers) HandleGetProofsByBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract batch ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/batch/")
	batchIDStr := strings.TrimSuffix(path, "/")

	batchID, err := uuid.Parse(batchIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_BATCH_ID", "Invalid batch ID format")
		return
	}

	ctx := r.Context()
	proofs, err := h.repos.ProofArtifacts.GetProofsByBatch(ctx, batchID)
	if err != nil {
		h.logger.Printf("Error getting proofs by batch: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proofs")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"batch_id": batchID,
		"proofs":   proofs,
		"count":    len(proofs),
	})
}

// HandleGetProofsByAnchor handles GET /api/v1/proofs/anchor/{anchor_tx_hash}
func (h *ProofHandlers) HandleGetProofsByAnchor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract anchor tx hash from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/anchor/")
	anchorTxHash := strings.TrimSuffix(path, "/")
	if anchorTxHash == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_ANCHOR_TX", "Anchor transaction hash is required")
		return
	}

	ctx := r.Context()
	proofs, err := h.repos.ProofArtifacts.GetProofsByAnchorTx(ctx, anchorTxHash)
	if err != nil {
		h.logger.Printf("Error getting proofs by anchor: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proofs")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"anchor_tx_hash": anchorTxHash,
		"proofs":         proofs,
		"count":          len(proofs),
	})
}

// HandleQueryProofs handles POST /api/v1/proofs/query
func (h *ProofHandlers) HandleQueryProofs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	var filter database.ProofArtifactFilter
	if err := json.NewDecoder(r.Body).Decode(&filter); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid filter format")
		return
	}

	ctx := r.Context()
	proofs, err := h.repos.ProofArtifacts.QueryProofs(ctx, &filter)
	if err != nil {
		h.logger.Printf("Error querying proofs: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to query proofs")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proofs": proofs,
		"count":  len(proofs),
		"filter": filter,
	})
}

// ============================================================================
// PROOF DETAIL ENDPOINTS
// ============================================================================

// HandleGetProofArtifact handles GET /api/v1/proofs/{proof_id}/artifact
func (h *ProofHandlers) HandleGetProofArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "artifact" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	proof, err := h.repos.ProofArtifacts.GetProofByID(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting proof artifact: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve proof")
		return
	}

	if proof == nil {
		h.writeError(w, http.StatusNotFound, "PROOF_NOT_FOUND", fmt.Sprintf("No proof found with ID: %s", proofID))
		return
	}

	// Return raw artifact JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(proof.ArtifactJSON)
}

// HandleGetProofLayers handles GET /api/v1/proofs/{proof_id}/layers
func (h *ProofHandlers) HandleGetProofLayers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "layers" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	layers, err := h.repos.ProofArtifacts.GetChainedProofLayers(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting proof layers: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve layers")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id": proofID,
		"layers":   layers,
	})
}

// HandleGetProofGovernance handles GET /api/v1/proofs/{proof_id}/governance
func (h *ProofHandlers) HandleGetProofGovernance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "governance" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	levels, err := h.repos.ProofArtifacts.GetGovernanceProofLevels(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting governance levels: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve governance levels")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id":          proofID,
		"governance_levels": levels,
	})
}

// HandleGetProofAttestations handles GET /api/v1/proofs/{proof_id}/attestations
func (h *ProofHandlers) HandleGetProofAttestations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "attestations" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	attestations, err := h.repos.ProofArtifacts.GetProofAttestationsByProof(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting attestations: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve attestations")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id":     proofID,
		"attestations": attestations,
		"count":        len(attestations),
	})
}

// HandleGetProofVerifications handles GET /api/v1/proofs/{proof_id}/verifications
func (h *ProofHandlers) HandleGetProofVerifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "verifications" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	verifications, err := h.repos.ProofArtifacts.GetVerificationHistory(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting verifications: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve verifications")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id":      proofID,
		"verifications": verifications,
		"count":         len(verifications),
	})
}

// HandleVerifyProofIntegrity handles GET /api/v1/proofs/{proof_id}/integrity
func (h *ProofHandlers) HandleVerifyProofIntegrity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "integrity" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()
	valid, err := h.repos.ProofArtifacts.VerifyArtifactIntegrity(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error verifying integrity: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify integrity")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id":         proofID,
		"integrity_valid":  valid,
		"verified_at":      time.Now().UTC(),
	})
}

// ============================================================================
// BATCH STATISTICS ENDPOINTS
// ============================================================================

// HandleGetBatchStats handles GET /api/v1/batches/{batch_id}/stats
func (h *ProofHandlers) HandleGetBatchStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract batch ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/batches/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "stats" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	batchID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_BATCH_ID", "Invalid batch ID format")
		return
	}

	ctx := r.Context()
	stats, err := h.repos.ProofArtifacts.GetBatchProofStats(ctx, batchID)
	if err != nil {
		h.logger.Printf("Error getting batch stats: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve batch stats")
		return
	}

	h.writeJSON(w, http.StatusOK, stats)
}

// ============================================================================
// SYNC ENDPOINTS (For Auditing Nodes)
// ============================================================================

// HandleSyncProofs handles GET /api/v1/proofs/sync
func (h *ProofHandlers) HandleSyncProofs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Parse since timestamp
	sinceStr := r.URL.Query().Get("since")
	var since time.Time
	if sinceStr != "" {
		var err error
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_TIMESTAMP", "Invalid since timestamp format (use RFC3339)")
			return
		}
	} else {
		// Default to 24 hours ago
		since = time.Now().Add(-24 * time.Hour)
	}

	limit := h.parseIntParam(r, "limit", 1000)
	if limit > 1000 {
		limit = 1000
	}

	ctx := r.Context()
	proofs, err := h.repos.ProofArtifacts.GetProofsModifiedSince(ctx, since, limit)
	if err != nil {
		h.logger.Printf("Error syncing proofs: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to sync proofs")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"since":  since,
		"proofs": proofs,
		"count":  len(proofs),
		"limit":  limit,
	})
}

// ============================================================================
// HELPER METHODS
// ============================================================================

func (h *ProofHandlers) parseIntParam(r *http.Request, name string, defaultVal int) int {
	valStr := r.URL.Query().Get(name)
	if valStr == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return val
}

func (h *ProofHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("Error encoding response: %v", err)
	}
}

func (h *ProofHandlers) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
