// Copyright 2025 Certen Protocol
//
// Batch and Proof API Handlers
// Per Implementation Plan Phase 5: Provide API for on-demand anchoring and proof retrieval

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/batch"
	"github.com/certen/independant-validator/pkg/database"
)

// BatchHandlers provides HTTP handlers for batch and proof operations
type BatchHandlers struct {
	collector       *batch.Collector
	processor       *batch.Processor
	onDemandHandler *batch.OnDemandHandler
	repos           *database.Repositories
	validatorID     string
	logger          *log.Logger
}

// NewBatchHandlers creates new batch operation handlers
func NewBatchHandlers(
	collector *batch.Collector,
	processor *batch.Processor,
	onDemandHandler *batch.OnDemandHandler,
	repos *database.Repositories,
	validatorID string,
	logger *log.Logger,
) *BatchHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[BatchAPI] ", log.LstdFlags)
	}
	return &BatchHandlers{
		collector:       collector,
		processor:       processor,
		onDemandHandler: onDemandHandler,
		repos:           repos,
		validatorID:     validatorID,
		logger:          logger,
	}
}

// ========================================
// On-Demand Anchor API
// ========================================

// OnDemandAnchorRequest is the API request for on-demand anchoring
type OnDemandAnchorRequest struct {
	// Accumulate transaction hash (required)
	AccumTxHash string `json:"accum_tx_hash"`
	// Account URL (required)
	AccountURL string `json:"account_url"`
	// Pre-computed transaction hash for Merkle tree (optional, computed if not provided)
	TxHash string `json:"tx_hash,omitempty"`
	// Chained proof JSON (optional, from L1-L3 proof layers)
	ChainedProof json.RawMessage `json:"chained_proof,omitempty"`
	// Governance proof JSON (optional, G0-G2)
	GovProof json.RawMessage `json:"gov_proof,omitempty"`
	// Governance level (G0, G1, G2)
	GovLevel string `json:"gov_level,omitempty"`
	// Intent type (optional)
	IntentType string `json:"intent_type,omitempty"`
	// Intent data (optional)
	IntentData json.RawMessage `json:"intent_data,omitempty"`
}

// OnDemandAnchorResponse is the API response for on-demand anchoring
type OnDemandAnchorResponse struct {
	// Success indicator
	Success bool `json:"success"`
	// Transaction ID in the batch
	TransactionID int64 `json:"transaction_id,omitempty"`
	// Batch ID this transaction was added to
	BatchID string `json:"batch_id,omitempty"`
	// Tree index within the batch
	TreeIndex int `json:"tree_index"`
	// Current batch size
	BatchSize int `json:"batch_size"`
	// Whether an anchor was triggered
	AnchorTriggered bool `json:"anchor_triggered"`
	// Whether the anchor was successfully created on-chain
	Anchored bool `json:"anchored"`
	// Anchor transaction hash (if anchored)
	AnchorTxHash string `json:"anchor_tx_hash,omitempty"`
	// Anchor block number (if anchored)
	AnchorBlockNumber int64 `json:"anchor_block_number,omitempty"`
	// Merkle root (if batch was closed)
	MerkleRoot string `json:"merkle_root,omitempty"`
	// Estimated cost per proof
	EstimatedCost string `json:"estimated_cost"`
	// Error message (if any)
	Error string `json:"error,omitempty"`
}

// HandleOnDemandAnchor handles POST /api/anchors/on-demand
// Per whitepaper: On-demand anchoring at ~$0.25/proof for immediate confirmation
func (h *BatchHandlers) HandleOnDemandAnchor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.onDemandHandler == nil {
		writeJSONError(w, "on-demand anchoring not available", http.StatusServiceUnavailable)
		return
	}

	// Parse request
	var req OnDemandAnchorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.AccumTxHash == "" {
		writeJSONError(w, "accum_tx_hash is required", http.StatusBadRequest)
		return
	}
	if req.AccountURL == "" {
		writeJSONError(w, "account_url is required", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(req.AccountURL, "acc://") {
		writeJSONError(w, "account_url must start with acc://", http.StatusBadRequest)
		return
	}

	// Compute transaction hash if not provided
	var txHash []byte
	if req.TxHash != "" {
		var err error
		txHash, err = hex.DecodeString(req.TxHash)
		if err != nil {
			writeJSONError(w, "invalid tx_hash: must be hex-encoded", http.StatusBadRequest)
			return
		}
		if len(txHash) != 32 {
			writeJSONError(w, "invalid tx_hash: must be 32 bytes", http.StatusBadRequest)
			return
		}
	} else {
		// Compute hash from accum_tx_hash + account_url
		hasher := sha256.New()
		hasher.Write([]byte(req.AccumTxHash))
		hasher.Write([]byte(req.AccountURL))
		txHash = hasher.Sum(nil)
	}

	// Create transaction data
	txData := &batch.TransactionData{
		AccumTxHash:  req.AccumTxHash,
		AccountURL:   req.AccountURL,
		TxHash:       txHash,
		ChainedProof: req.ChainedProof,
		GovProof:     req.GovProof,
		GovLevel:     req.GovLevel,
		IntentType:   req.IntentType,
		IntentData:   req.IntentData,
	}

	// Process the on-demand transaction
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	result, err := h.onDemandHandler.ProcessTransaction(ctx, txData)
	if err != nil {
		h.logger.Printf("On-demand anchor failed: %v", err)
		writeJSONError(w, fmt.Sprintf("failed to process transaction: %v", err), http.StatusInternalServerError)
		return
	}

	// Build response
	resp := OnDemandAnchorResponse{
		Success:         true,
		EstimatedCost:   "$0.25", // Per whitepaper
		AnchorTriggered: result.AnchorTriggered,
		Anchored:        result.Anchored,
	}

	if result.TransactionResult != nil {
		resp.TransactionID = result.TransactionResult.TransactionID
		resp.BatchID = result.TransactionResult.BatchID.String()
		resp.TreeIndex = result.TransactionResult.TreeIndex
		resp.BatchSize = result.TransactionResult.BatchSize
	}

	if result.BatchResult != nil {
		resp.MerkleRoot = result.BatchResult.MerkleRootHex
	}

	h.logger.Printf("On-demand anchor processed: tx=%s, batch=%s, anchored=%v",
		req.AccumTxHash[:16]+"...", resp.BatchID, resp.Anchored)

	json.NewEncoder(w).Encode(resp)
}

// ========================================
// Batch Status API
// ========================================

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

// HandleBatchInfo handles GET /api/batches/current
// Returns info about the current on-cadence and on-demand batches
func (h *BatchHandlers) HandleBatchInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		writeJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"validator_id": h.validatorID,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}

	if h.collector != nil {
		if onCadence := h.collector.GetOnCadenceBatchInfo(); onCadence != nil {
			response["on_cadence_batch"] = map[string]interface{}{
				"batch_id":   onCadence.BatchID,
				"batch_type": onCadence.BatchType,
				"start_time": onCadence.StartTime,
				"tx_count":   onCadence.TxCount,
				"age":        onCadence.Age.String(),
			}
		}

		if onDemand := h.collector.GetOnDemandBatchInfo(); onDemand != nil {
			response["on_demand_batch"] = map[string]interface{}{
				"batch_id":   onDemand.BatchID,
				"batch_type": onDemand.BatchType,
				"start_time": onDemand.StartTime,
				"tx_count":   onDemand.TxCount,
				"age":        onDemand.Age.String(),
			}
		}
	}

	if h.onDemandHandler != nil {
		response["on_demand_stats"] = h.onDemandHandler.GetStats()
	}

	json.NewEncoder(w).Encode(response)
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

	proof, err := h.repos.Proofs.GetProof(ctx, proofID)
	if err != nil {
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

	proof, err := h.repos.Proofs.GetProofByAccumTxHash(ctx, path)
	if err != nil {
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

	proofs, err := h.repos.Proofs.GetProofsByAccountURL(ctx, path, 100)
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
