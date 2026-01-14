// Copyright 2025 Certen Protocol
//
// Ledger Query API Handlers
// Provides HTTP endpoints for system and anchor ledger queries

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/certen/independant-validator/pkg/ledger"
)

// LedgerHandlers provides HTTP handlers for ledger queries
type LedgerHandlers struct {
	ledgerStore *ledger.LedgerStore
	chainID     string
}

// NewLedgerHandlers creates new ledger query handlers
func NewLedgerHandlers(ledgerStore *ledger.LedgerStore, chainID string) *LedgerHandlers {
	return &LedgerHandlers{
		ledgerStore: ledgerStore,
		chainID:     chainID,
	}
}

// HandleSystemLedger handles GET /api/system-ledger requests
func (h *LedgerHandlers) HandleSystemLedger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.ledgerStore == nil {
		http.Error(w, `{"error":"ledger store not available"}`, http.StatusInternalServerError)
		return
	}

	// Check for height query parameter for historical queries
	heightParam := r.URL.Query().Get("height")

	var state *ledger.SystemLedgerState
	var err error

	if heightParam != "" {
		height, parseErr := strconv.ParseUint(heightParam, 10, 64)
		if parseErr != nil {
			http.Error(w, `{"error":"invalid height parameter"}`, http.StatusBadRequest)
			return
		}
		state, err = h.ledgerStore.GetSystemLedgerAtHeight(h.chainID, height)
	} else {
		state, err = h.ledgerStore.GetSystemLedgerLatest(h.chainID)
	}

	if err != nil {
		errorMsg := fmt.Sprintf(`{"error":"failed to load system ledger: %s"}`, err.Error())
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	if state == nil {
		http.Error(w, `{"error":"system ledger not found"}`, http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// HandleAnchorLedger handles GET /api/anchor-ledger requests
func (h *LedgerHandlers) HandleAnchorLedger(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.ledgerStore == nil {
		http.Error(w, `{"error":"ledger store not available"}`, http.StatusInternalServerError)
		return
	}

	state, err := h.ledgerStore.GetAnchorLedger(h.chainID)
	if err != nil {
		errorMsg := fmt.Sprintf(`{"error":"failed to load anchor ledger: %s"}`, err.Error())
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}

	if state == nil {
		http.Error(w, `{"error":"anchor ledger not found"}`, http.StatusNotFound)
		return
	}

	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// HandleLedgerStatus handles GET /api/ledger/status requests
func (h *LedgerHandlers) HandleLedgerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if h.ledgerStore == nil {
		http.Error(w, `{"error":"ledger store not available"}`, http.StatusInternalServerError)
		return
	}

	// Get both system and anchor ledger states for status
	systemState, systemErr := h.ledgerStore.GetSystemLedgerLatest(h.chainID)
	anchorState, anchorErr := h.ledgerStore.GetAnchorLedger(h.chainID)

	status := map[string]interface{}{
		"chainId": h.chainID,
		"timestamp": fmt.Sprintf("%d", h.getCurrentUnixTime()),
	}

	if systemErr == nil && systemState != nil {
		status["systemLedger"] = map[string]interface{}{
			"available": true,
			"latestHeight": systemState.Data.Index,
			"lastBlockTime": systemState.LastBlockTime,
			"executorVersion": systemState.Data.ExecutorVersion,
		}
	} else {
		status["systemLedger"] = map[string]interface{}{
			"available": false,
			"error": systemErr.Error(),
		}
	}

	if anchorErr == nil && anchorState != nil {
		status["anchorLedger"] = map[string]interface{}{
			"available": true,
			"sequenceNumber": anchorState.Data.MinorBlockSequenceNumber,
			"majorBlockIndex": anchorState.Data.MajorBlockIndex,
			"lastBlockTime": anchorState.LastBlockTime,
		}
	} else {
		status["anchorLedger"] = map[string]interface{}{
			"available": false,
			"error": anchorErr.Error(),
		}
	}

	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
	}
}

// getCurrentUnixTime returns current Unix timestamp
func (h *LedgerHandlers) getCurrentUnixTime() int64 {
	return time.Now().Unix()
}