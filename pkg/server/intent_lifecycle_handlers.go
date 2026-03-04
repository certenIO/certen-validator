// Copyright 2025 Certen Protocol
//
// Intent Lifecycle API Handlers
// Provides HTTP endpoints for querying intent lifecycle status

package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/database"
)

// IntentLifecycleHandlers provides HTTP handlers for intent lifecycle queries
type IntentLifecycleHandlers struct {
	repos  *database.Repositories
	logger *log.Logger
}

// NewIntentLifecycleHandlers creates new intent lifecycle handlers
func NewIntentLifecycleHandlers(repos *database.Repositories, logger *log.Logger) *IntentLifecycleHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[LifecycleAPI] ", log.LstdFlags)
	}
	return &IntentLifecycleHandlers{
		repos:  repos,
		logger: logger,
	}
}

// HandleGetByIntentID handles GET /api/v1/intent/{intent_id}/lifecycle
func (h *IntentLifecycleHandlers) HandleGetByIntentID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract intent_id from path: /api/v1/intent/{intent_id}/lifecycle
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/intent/")
	intentID := strings.TrimSuffix(path, "/lifecycle")
	intentID = strings.TrimSuffix(intentID, "/")
	if intentID == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_INTENT_ID", "Intent ID is required")
		return
	}

	ctx := r.Context()
	lc, err := h.repos.IntentLifecycle.GetByIntentID(ctx, intentID)
	if err != nil {
		if errors.Is(err, database.ErrIntentLifecycleNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "No lifecycle found for intent: "+intentID)
			return
		}
		h.logger.Printf("Error getting lifecycle by intent ID: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve lifecycle")
		return
	}

	h.writeJSON(w, http.StatusOK, lc)
}

// HandleGetByTxHash handles GET /api/v1/intent/tx/{tx_hash}/lifecycle
func (h *IntentLifecycleHandlers) HandleGetByTxHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract tx_hash from path: /api/v1/intent/tx/{tx_hash}/lifecycle
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/intent/tx/")
	txHash := strings.TrimSuffix(path, "/lifecycle")
	txHash = strings.TrimSuffix(txHash, "/")
	if txHash == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_TX_HASH", "Transaction hash is required")
		return
	}

	ctx := r.Context()
	lc, err := h.repos.IntentLifecycle.GetByTxHash(ctx, txHash)
	if err != nil {
		if errors.Is(err, database.ErrIntentLifecycleNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "No lifecycle found for tx hash: "+txHash)
			return
		}
		h.logger.Printf("Error getting lifecycle by tx hash: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve lifecycle")
		return
	}

	h.writeJSON(w, http.StatusOK, lc)
}

// HandleListByUser handles GET /api/v1/intent/user/{user_id}
func (h *IntentLifecycleHandlers) HandleListByUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/intent/user/")
	userID := strings.TrimSuffix(path, "/")
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_USER_ID", "User ID is required")
		return
	}

	limit := h.parseIntParam(r, "limit", 50)

	ctx := r.Context()
	items, err := h.repos.IntentLifecycle.ListByUserEnriched(ctx, userID, limit)
	if err != nil {
		h.logger.Printf("Error listing lifecycles by user: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list lifecycles")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"intents": items,
		"count":   len(items),
		"user_id": userID,
	})
}

// HandleListByStatus handles GET /api/v1/intent/status/{status}
func (h *IntentLifecycleHandlers) HandleListByStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/intent/status/")
	status := strings.TrimSuffix(path, "/")
	if status == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_STATUS", "Status is required")
		return
	}

	limit := h.parseIntParam(r, "limit", 50)

	ctx := r.Context()
	items, err := h.repos.IntentLifecycle.ListByStatus(ctx, database.IntentLifecycleStatus(status), limit)
	if err != nil {
		h.logger.Printf("Error listing lifecycles by status: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list lifecycles")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"intents": items,
		"count":   len(items),
		"status":  status,
	})
}

// HandleListRecent handles GET /api/v1/intent/recent
func (h *IntentLifecycleHandlers) HandleListRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	limit := h.parseIntParam(r, "limit", 50)

	ctx := r.Context()
	items, err := h.repos.IntentLifecycle.ListRecentEnriched(ctx, limit)
	if err != nil {
		h.logger.Printf("Error listing recent lifecycles: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list lifecycles")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"intents": items,
		"count":   len(items),
	})
}

func (h *IntentLifecycleHandlers) parseIntParam(r *http.Request, name string, defaultVal int) int {
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

func (h *IntentLifecycleHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("Error encoding response: %v", err)
	}
}

func (h *IntentLifecycleHandlers) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
