// Copyright 2025 Certen Protocol
//
// Batch and Proof API Handlers
// Per Implementation Plan Phase 5: Provide API for on-demand anchoring and proof retrieval

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// BatchHandlers provides HTTP handlers for batch and proof operations
type BatchHandlers struct {
	repos       *database.Repositories
	validatorID string
	logger      *log.Logger
}

// NewBatchHandlers creates new batch operation handlers
func NewBatchHandlers(
	repos *database.Repositories,
	validatorID string,
	logger *log.Logger,
) *BatchHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[BatchAPI] ", log.LstdFlags)
	}
	return &BatchHandlers{
		repos:       repos,
		validatorID: validatorID,
		logger:      logger,
	}
}

// HandleBatchStatus handles GET /api/batches/:id
func (h *BatchHandlers) HandleBatchStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract batch ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/batches/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "batch ID required", http.StatusBadRequest)
		return
	}

	batchID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid batch ID", http.StatusBadRequest)
		return
	}

	// Get batch from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	batch, err := h.repos.Batches.GetBatch(ctx, batchID)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("batch not found: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(batch)
}

// ========================================
// Proof API
// ========================================

// HandleGetProof handles GET /api/proofs/:id
func (h *BatchHandlers) HandleGetProof(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/proofs/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "proof ID required", http.StatusBadRequest)
		return
	}

	proofID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid proof ID", http.StatusBadRequest)
		return
	}

	// Get proof from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	proof, err := h.repos.ProofArtifacts.GetProofByID(ctx, proofID)
	if err != nil || proof == nil {
		writeJSONError(w, fmt.Sprintf("proof not found: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(proof)
}

// HandleGetProofByTxHash handles GET /api/proofs/by-tx/:hash
func (h *BatchHandlers) HandleGetProofByTxHash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract tx hash from path
	path := strings.TrimPrefix(r.URL.Path, "/api/proofs/by-tx/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "transaction hash required", http.StatusBadRequest)
		return
	}

	// Get proof from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	proof, err := h.repos.ProofArtifacts.GetProofByTxHash(ctx, path)
	if err != nil || proof == nil {
		writeJSONError(w, fmt.Sprintf("proof not found: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(proof)
}

// HandleGetProofsByAccount handles GET /api/proofs/by-account/:url
func (h *BatchHandlers) HandleGetProofsByAccount(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract account URL from path (URL-encoded)
	path := strings.TrimPrefix(r.URL.Path, "/api/proofs/by-account/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "account URL required", http.StatusBadRequest)
		return
	}

	// Get proofs from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	proofs, err := h.repos.ProofArtifacts.GetProofsByAccount(ctx, path, 100, 0)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("failed to get proofs: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"account_url": path,
		"proofs":      proofs,
		"count":       len(proofs),
	})
}

// ========================================
// Anchor API
// ========================================

// HandleGetAnchor handles GET /api/anchors/:id
func (h *BatchHandlers) HandleGetAnchor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract anchor ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/anchors/")
	if path == "" || path == r.URL.Path || path == "on-demand" {
		writeJSONError(w, "anchor ID required", http.StatusBadRequest)
		return
	}

	anchorID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid anchor ID", http.StatusBadRequest)
		return
	}

	// Get anchor from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	anchor, err := h.repos.Anchors.GetAnchor(ctx, anchorID)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("anchor not found: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(anchor)
}

// HandleGetAnchorByBatch handles GET /api/anchors/by-batch/:batch_id
func (h *BatchHandlers) HandleGetAnchorByBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.repos == nil {
		writeJSONError(w, "database not available", http.StatusServiceUnavailable)
		return
	}

	// Extract batch ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/anchors/by-batch/")
	if path == "" || path == r.URL.Path {
		writeJSONError(w, "batch ID required", http.StatusBadRequest)
		return
	}

	batchID, err := uuid.Parse(path)
	if err != nil {
		writeJSONError(w, "invalid batch ID", http.StatusBadRequest)
		return
	}

	// Get anchor from database
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	anchor, err := h.repos.Anchors.GetAnchorByBatchID(ctx, batchID)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("anchor not found: %v", err), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(anchor)
}

// ========================================
// Cost API
// ========================================

// HandleGetCostStatistics handles GET /api/costs
func (h *BatchHandlers) HandleGetCostStatistics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return whitepaper-defined cost structure
	response := map[string]interface{}{
		"validator_id": h.validatorID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"cost_structure": map[string]interface{}{
			"on_cadence": map[string]interface{}{
				"per_proof_usd":  0.05,
				"batch_interval": "~15 minutes",
				"description":    "Amortized cost - transactions batched for cost efficiency",
			},
			"on_demand": map[string]interface{}{
				"per_proof_usd":  0.25,
				"batch_interval": "immediate",
				"description":    "Higher cost for immediate anchoring without waiting",
			},
		},
		"whitepaper_reference": "Section 3.4.2: Transaction Batching",
		"note":                 "Actual costs may vary based on gas prices and batch sizes",
	}

	json.NewEncoder(w).Encode(response)
}

// HandleEstimateCost handles GET /api/costs/estimate
func (h *BatchHandlers) HandleEstimateCost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	batchType := r.URL.Query().Get("type")
	if batchType == "" {
		batchType = "on-cadence"
	}

	txCountStr := r.URL.Query().Get("tx_count")
	txCount := 1
	if txCountStr != "" {
		if parsed, err := parseInt(txCountStr); err == nil && parsed > 0 {
			txCount = parsed
		}
	}

	// Calculate estimate
	var perProofCost float64
	switch batchType {
	case "on-demand":
		perProofCost = 0.25
	default:
		perProofCost = 0.05
	}

	totalCost := perProofCost * float64(txCount)

	response := map[string]interface{}{
		"batch_type":        batchType,
		"tx_count":          txCount,
		"per_proof_cost":    perProofCost,
		"total_cost_usd":    totalCost,
		"currency":          "USD",
		"estimate_validity": "Based on whitepaper Section 3.4.2",
	}

	json.NewEncoder(w).Encode(response)
}

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// ========================================
// Helper Functions
// ========================================

func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}
