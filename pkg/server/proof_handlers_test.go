// Copyright 2025 Certen Protocol
//
// Unit tests for Proof Handlers
// Tests HTTP endpoints without requiring database connection

package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// Handler Construction Tests
// ============================================================================

func TestNewProofHandlers(t *testing.T) {
	handlers := NewProofHandlers(nil, "test-validator", nil)

	if handlers == nil {
		t.Fatal("Expected non-nil handlers")
	}
	if handlers.validatorID != "test-validator" {
		t.Errorf("Expected validatorID 'test-validator', got '%s'", handlers.validatorID)
	}
	if handlers.logger == nil {
		t.Error("Expected logger to be initialized")
	}
}

func TestNewProofHandlersWithLogger(t *testing.T) {
	customLogger := log.New(log.Writer(), "[CustomProof] ", log.LstdFlags)
	handlers := NewProofHandlers(nil, "validator-1", customLogger)

	if handlers.logger != customLogger {
		t.Error("Expected custom logger to be used")
	}
}

// ============================================================================
// Method Validation Tests (No Database Required)
// ============================================================================

func TestHandleGetProofByTxHash_MethodNotAllowed(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/v1/proofs/tx/abc123", nil)
		rr := httptest.NewRecorder()

		handlers.HandleGetProofByTxHash(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Expected %d for %s, got %d", http.StatusMethodNotAllowed, method, rr.Code)
		}

		var response map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
			continue
		}

		errObj, ok := response["error"].(map[string]interface{})
		if !ok {
			t.Error("Expected error object in response")
			continue
		}
		if errObj["code"] != "METHOD_NOT_ALLOWED" {
			t.Errorf("Expected error code 'METHOD_NOT_ALLOWED', got '%v'", errObj["code"])
		}
	}
}

func TestHandleGetProofByTxHash_MissingHash(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/tx/", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofByTxHash(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofByID_InvalidUUID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/not-a-uuid", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)
	errObj := response["error"].(map[string]interface{})
	if errObj["code"] != "INVALID_PROOF_ID" {
		t.Errorf("Expected INVALID_PROOF_ID, got %v", errObj["code"])
	}
}

func TestHandleGetProofsByAccount_MethodNotAllowed(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proofs/account/acc://test.acme", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofsByAccount(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestHandleGetProofsByAccount_MissingAccount(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/account/", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofsByAccount(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofsByBatch_InvalidBatchID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/batch/invalid-uuid", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofsByBatch(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofsByAnchor_MethodNotAllowed(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/proofs/anchor/0xabc123", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofsByAnchor(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestHandleGetProofsByAnchor_MissingAnchorHash(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/anchor/", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofsByAnchor(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleQueryProofs_MethodNotAllowed(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/query", nil)
	rr := httptest.NewRecorder()

	handlers.HandleQueryProofs(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d for GET, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestHandleQueryProofs_InvalidBody(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proofs/query", strings.NewReader("not valid json"))
	rr := httptest.NewRecorder()

	handlers.HandleQueryProofs(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// ============================================================================
// Path Extraction Tests
// ============================================================================

func TestHandleGetProofArtifact_InvalidPath(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	// Valid UUID but wrong sub-path
	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/550e8400-e29b-41d4-a716-446655440000/wrong", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofArtifact(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofLayers_InvalidPath(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/550e8400-e29b-41d4-a716-446655440000/notlayers", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofLayers(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofGovernance_InvalidPath(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/550e8400-e29b-41d4-a716-446655440000/notgovernance", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofGovernance(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofAttestations_InvalidProofID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/bad-uuid/attestations", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofAttestations(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetProofVerifications_InvalidProofID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/not-valid-uuid/verifications", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofVerifications(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleVerifyProofIntegrity_InvalidProofID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/invalid/integrity", nil)
	rr := httptest.NewRecorder()

	handlers.HandleVerifyProofIntegrity(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestHandleGetBatchStats_InvalidBatchID(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/batches/not-uuid/stats", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetBatchStats(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

// ============================================================================
// Sync Endpoint Tests
// ============================================================================

func TestHandleSyncProofs_MethodNotAllowed(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/proofs/sync", nil)
	rr := httptest.NewRecorder()

	handlers.HandleSyncProofs(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestHandleSyncProofs_InvalidTimestamp(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/sync?since=not-a-timestamp", nil)
	rr := httptest.NewRecorder()

	handlers.HandleSyncProofs(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected %d, got %d", http.StatusBadRequest, rr.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)
	errObj := response["error"].(map[string]interface{})
	if errObj["code"] != "INVALID_TIMESTAMP" {
		t.Errorf("Expected INVALID_TIMESTAMP, got %v", errObj["code"])
	}
}

// ============================================================================
// Helper Method Tests
// ============================================================================

func TestParseIntParam(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	tests := []struct {
		name       string
		query      string
		param      string
		defaultVal int
		expected   int
	}{
		{"empty query", "", "limit", 50, 50},
		{"valid value", "limit=100", "limit", 50, 100},
		{"invalid value", "limit=abc", "limit", 50, 50},
		{"negative value", "limit=-10", "limit", 50, -10},
		{"zero value", "limit=0", "limit", 50, 0},
		{"missing param", "offset=10", "limit", 50, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test?"+tt.query, nil)
			result := handlers.parseIntParam(req, tt.param, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	rr := httptest.NewRecorder()
	data := map[string]string{"message": "success"}

	handlers.writeJSON(rr, http.StatusOK, data)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}

	var response map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}
	if response["message"] != "success" {
		t.Errorf("Expected message 'success', got '%s'", response["message"])
	}
}

func TestWriteError(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	rr := httptest.NewRecorder()
	handlers.writeError(rr, http.StatusNotFound, "NOT_FOUND", "Resource not found")

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	errObj, ok := response["error"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected error object")
	}
	if errObj["code"] != "NOT_FOUND" {
		t.Errorf("Expected code 'NOT_FOUND', got '%v'", errObj["code"])
	}
	if errObj["message"] != "Resource not found" {
		t.Errorf("Expected message 'Resource not found', got '%v'", errObj["message"])
	}
}

// ============================================================================
// Response Structure Tests
// ============================================================================

func TestErrorResponseStructure(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	testCases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		path    string
		method  string
	}{
		{"GetProofByTxHash", handlers.HandleGetProofByTxHash, "/api/v1/proofs/tx/", http.MethodGet},
		{"GetProofByID", handlers.HandleGetProofByID, "/api/v1/proofs/bad-uuid", http.MethodGet},
		{"GetProofsByBatch", handlers.HandleGetProofsByBatch, "/api/v1/proofs/batch/bad-uuid", http.MethodGet},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rr := httptest.NewRecorder()

			tc.handler(rr, req)

			var response map[string]interface{}
			if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
				t.Errorf("Failed to decode response: %v", err)
				return
			}

			// Check error structure
			errObj, ok := response["error"].(map[string]interface{})
			if !ok {
				t.Error("Expected 'error' field in response")
				return
			}

			if _, ok := errObj["code"]; !ok {
				t.Error("Expected 'code' field in error")
			}
			if _, ok := errObj["message"]; !ok {
				t.Error("Expected 'message' field in error")
			}
		})
	}
}

// ============================================================================
// Content-Type Tests
// ============================================================================

func TestContentTypeJSON(t *testing.T) {
	handlers := NewProofHandlers(nil, "test", nil)

	// All error responses should have JSON content type
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proofs/tx/abc", nil)
	rr := httptest.NewRecorder()

	handlers.HandleGetProofByTxHash(rr, req)

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
	}
}

// ============================================================================
// Pagination Parameter Tests
// ============================================================================

func TestPaginationLimitCapping(t *testing.T) {
	// Test that limit is capped at 1000
	handlers := NewProofHandlers(nil, "test", nil)

	// When limit exceeds 1000, internal logic caps it
	// This tests the parseIntParam with high values
	req := httptest.NewRequest(http.MethodGet, "/api/v1/proofs/account/test?limit=5000", nil)
	limit := handlers.parseIntParam(req, "limit", 50)

	// parseIntParam returns the raw value - capping is done in handler
	if limit != 5000 {
		t.Errorf("parseIntParam should return raw value 5000, got %d", limit)
	}
}
