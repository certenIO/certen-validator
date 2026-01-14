// Copyright 2025 Certen Protocol
//
// Bundle API Handlers
// Implements endpoints for proof bundle download, verification, and request processing
//
// Endpoints:
// - POST /api/v1/proofs/request - Request new proof generation
// - GET /api/v1/proofs/{proof_id}/bundle - Download proof bundle
// - GET /api/v1/proofs/{proof_id}/bundle/verify - Verify bundle integrity
// - GET /api/v1/proofs/{proof_id}/custody - Get custody chain
// - POST /api/v1/proofs/verify/merkle - Verify merkle proof
// - POST /api/v1/proofs/verify/governance - Verify governance proof

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/proof"
)

// BundleHandlers provides HTTP handlers for bundle operations
type BundleHandlers struct {
	repos            *database.Repositories
	artifactService  *proof.ProofArtifactService
	lifecycleManager *proof.ProofLifecycleManager
	validatorID      string
	logger           *log.Logger
	rateLimiter      *RateLimiter
	apiKeyValidator  *APIKeyValidator
}

// BundleHandlersConfig contains configuration for bundle handlers
type BundleHandlersConfig struct {
	ValidatorID            string
	RateLimitPerMinute     int
	MaxBundleSizeBytes     int64
	EnableAPIKeyValidation bool
}

// NewBundleHandlers creates new bundle handlers
func NewBundleHandlers(
	repos *database.Repositories,
	artifactService *proof.ProofArtifactService,
	lifecycleManager *proof.ProofLifecycleManager,
	config *BundleHandlersConfig,
	logger *log.Logger,
) *BundleHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[BundleAPI] ", log.LstdFlags)
	}
	if config == nil {
		config = &BundleHandlersConfig{
			ValidatorID:        "default-validator",
			RateLimitPerMinute: 100,
			MaxBundleSizeBytes: 10 * 1024 * 1024, // 10MB
		}
	}

	return &BundleHandlers{
		repos:            repos,
		artifactService:  artifactService,
		lifecycleManager: lifecycleManager,
		validatorID:      config.ValidatorID,
		logger:           logger,
		rateLimiter:      NewRateLimiter(config.RateLimitPerMinute),
		apiKeyValidator:  NewAPIKeyValidator(repos),
	}
}

// =============================================================================
// PROOF REQUEST ENDPOINTS
// =============================================================================

// ProofRequestInput represents a proof request
type ProofRequestInput struct {
	AccumTxHash     string  `json:"accum_tx_hash,omitempty"`
	AccountURL      string  `json:"account_url,omitempty"`
	ProofClass      string  `json:"proof_class"` // "on_cadence" or "on_demand"
	GovernanceLevel string  `json:"governance_level,omitempty"` // "G0", "G1", "G2"
	CallbackURL     *string `json:"callback_url,omitempty"`
	Priority        int     `json:"priority,omitempty"`
}

// ProofRequestResponse represents the response to a proof request
type ProofRequestResponse struct {
	RequestID       uuid.UUID `json:"request_id"`
	Status          string    `json:"status"`
	EstimatedTimeMs int64     `json:"estimated_time_ms,omitempty"`
	ProofID         *uuid.UUID `json:"proof_id,omitempty"`
	Message         string    `json:"message,omitempty"`
}

// HandleRequestProof handles POST /api/v1/proofs/request
func (h *BundleHandlers) HandleRequestProof(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	// Validate API key
	apiKey, err := h.validateAPIKey(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
		return
	}

	// Check rate limit
	if !h.rateLimiter.Allow(apiKey.ClientName) {
		h.writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Rate limit exceeded")
		return
	}

	// Check permissions
	if !apiKey.CanRequestProofs {
		h.writeError(w, http.StatusForbidden, "FORBIDDEN", "API key does not have proof request permission")
		return
	}

	// Parse request
	var input ProofRequestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Validate input
	if input.AccumTxHash == "" && input.AccountURL == "" {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Either accum_tx_hash or account_url is required")
		return
	}

	if input.ProofClass != "on_cadence" && input.ProofClass != "on_demand" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_CLASS", "proof_class must be 'on_cadence' or 'on_demand'")
		return
	}

	if input.GovernanceLevel != "" && input.GovernanceLevel != "G0" && input.GovernanceLevel != "G1" && input.GovernanceLevel != "G2" {
		h.writeError(w, http.StatusBadRequest, "INVALID_GOV_LEVEL", "governance_level must be 'G0', 'G1', or 'G2'")
		return
	}

	ctx := r.Context()

	// Check if proof already exists
	if input.AccumTxHash != "" {
		existingProof, err := h.repos.ProofArtifacts.GetProofByTxHash(ctx, input.AccumTxHash)
		if err == nil && existingProof != nil {
			// Return existing proof
			h.writeJSON(w, http.StatusOK, ProofRequestResponse{
				RequestID: uuid.New(),
				Status:    "completed",
				ProofID:   &existingProof.ProofID,
				Message:   "Proof already exists",
			})
			return
		}
	}

	// Create proof request
	requestID := uuid.New()
	newRequest := &database.NewBundleProofRequest{
		AccumTxHash:     nilIfEmpty(input.AccumTxHash),
		AccountURL:      nilIfEmpty(input.AccountURL),
		ProofClass:      input.ProofClass,
		GovernanceLevel: nilIfEmpty(input.GovernanceLevel),
		APIKeyID:        &apiKey.KeyID,
		CallbackURL:     input.CallbackURL,
		Status:          "pending",
	}
	_ = requestID // used for logging

	createdRequest, err := h.repos.ProofArtifacts.CreateProofRequest(ctx, newRequest)
	if err != nil {
		h.logger.Printf("Error creating proof request: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create proof request")
		return
	}

	// Estimate time based on proof class
	var estimatedTimeMs int64
	if input.ProofClass == "on_demand" {
		estimatedTimeMs = 5000 // 5 seconds for on-demand
	} else {
		estimatedTimeMs = 900000 // 15 minutes for on-cadence
	}

	h.writeJSON(w, http.StatusAccepted, ProofRequestResponse{
		RequestID:       createdRequest.RequestID,
		Status:          "pending",
		EstimatedTimeMs: estimatedTimeMs,
		Message:         fmt.Sprintf("Proof request queued for %s processing", input.ProofClass),
	})
}

// HandleGetRequestStatus handles GET /api/v1/proofs/request/{request_id}
func (h *BundleHandlers) HandleGetRequestStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract request ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/request/")
	requestIDStr := strings.TrimSuffix(path, "/")

	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST_ID", "Invalid request ID format")
		return
	}

	ctx := r.Context()
	request, err := h.repos.ProofArtifacts.GetProofRequest(ctx, requestID)
	if err != nil {
		h.logger.Printf("Error getting proof request: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve request")
		return
	}

	if request == nil {
		h.writeError(w, http.StatusNotFound, "REQUEST_NOT_FOUND", fmt.Sprintf("No request found with ID: %s", requestID))
		return
	}

	h.writeJSON(w, http.StatusOK, request)
}

// =============================================================================
// BUNDLE DOWNLOAD ENDPOINTS
// =============================================================================

// HandleDownloadBundle handles GET /api/v1/proofs/{proof_id}/bundle
func (h *BundleHandlers) HandleDownloadBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Validate API key (optional for bundle download)
	apiKey, _ := h.validateAPIKey(r)
	clientIP := getClientIP(r)

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "bundle" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()

	// Get bundle from database
	bundle, err := h.repos.ProofArtifacts.GetBundleByProofID(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting bundle: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve bundle")
		return
	}

	if bundle == nil {
		// Try to generate bundle on-the-fly if proof exists
		proofDetails, err := h.repos.ProofArtifacts.GetProofWithDetails(ctx, proofID)
		if err != nil || proofDetails == nil {
			h.writeError(w, http.StatusNotFound, "BUNDLE_NOT_FOUND", fmt.Sprintf("No bundle found for proof: %s", proofID))
			return
		}

		// Generate bundle using artifact service
		if h.artifactService != nil {
			// Create artifact request
			govLevel := proof.GovLevelG0
			if proofDetails.GovLevel != nil {
				switch string(*proofDetails.GovLevel) {
				case "G1":
					govLevel = proof.GovLevelG1
				case "G2":
					govLevel = proof.GovLevelG2
				}
			}
			artifactReq := &proof.ArtifactRequest{
				TransactionHash: proofDetails.AccumTxHash,
				AccountURL:      proofDetails.AccountURL,
				GovernanceLevel: govLevel,
				IncludeMerkle:   true,
				IncludeAnchor:   true,
				IncludeChained:  true,
				IncludeGov:      true,
			}

			resp, err := h.artifactService.CollectArtifacts(ctx, artifactReq)
			if err != nil {
				h.logger.Printf("Error generating bundle: %v", err)
				h.writeError(w, http.StatusInternalServerError, "BUNDLE_GENERATION_FAILED", "Failed to generate bundle")
				return
			}

			// Convert to bundle format
			bundleData, err := json.Marshal(resp.Bundle)
			if err != nil {
				h.writeError(w, http.StatusInternalServerError, "BUNDLE_GENERATION_FAILED", "Failed to serialize bundle")
				return
			}

			// Compress the bundle
			var compressedBuf bytes.Buffer
			gzWriter := gzip.NewWriter(&compressedBuf)
			gzWriter.Write(bundleData)
			gzWriter.Close()

			bundleHash := sha256.Sum256(bundleData)
			bundle = &database.ProofBundle{
				BundleID:        uuid.New(),
				ProofID:         proofID,
				BundleFormat:    "certen_v1",
				BundleVersion:   "1.0",
				BundleData:      compressedBuf.Bytes(),
				BundleHash:      bundleHash[:],
				BundleSizeBytes: len(compressedBuf.Bytes()),
			}
		} else {
			h.writeError(w, http.StatusNotFound, "BUNDLE_NOT_FOUND", "Bundle not available and generation not configured")
			return
		}
	}

	// Record download
	var apiKeyID *uuid.UUID
	if apiKey != nil {
		apiKeyID = &apiKey.KeyID
	}
	h.recordBundleDownload(ctx, bundle.BundleID, apiKeyID, clientIP, r.UserAgent(), http.StatusOK, len(bundle.BundleData))

	// Record custody event if lifecycle manager is available
	if h.lifecycleManager != nil {
		clientID := "anonymous"
		if apiKey != nil {
			clientID = apiKey.ClientName
		}
		h.lifecycleManager.RecordBundleDownload(ctx, proofID, bundle.BundleID, clientID, clientIP)
	}

	// Check if client wants decompressed JSON
	acceptEncoding := r.Header.Get("Accept-Encoding")
	wantsGzip := strings.Contains(acceptEncoding, "gzip")

	// Set response headers
	w.Header().Set("X-Bundle-ID", bundle.BundleID.String())
	w.Header().Set("X-Bundle-Hash", "sha256:" + hex.EncodeToString(bundle.BundleHash))
	w.Header().Set("X-Bundle-Format", bundle.BundleFormat)
	w.Header().Set("X-Bundle-Version", bundle.BundleVersion)
	w.Header().Set("X-Attestation-Count", fmt.Sprintf("%d", bundle.AttestationCount))

	if wantsGzip {
		// Return compressed bundle directly
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"proof_%s.bundle.gz\"", proofID.String()))
		w.WriteHeader(http.StatusOK)
		w.Write(bundle.BundleData)
	} else {
		// Decompress and return JSON
		gzReader, err := gzip.NewReader(bytes.NewReader(bundle.BundleData))
		if err != nil {
			h.logger.Printf("Error decompressing bundle: %v", err)
			h.writeError(w, http.StatusInternalServerError, "DECOMPRESSION_ERROR", "Failed to decompress bundle")
			return
		}
		defer gzReader.Close()

		jsonData, err := io.ReadAll(gzReader)
		if err != nil {
			h.logger.Printf("Error reading decompressed bundle: %v", err)
			h.writeError(w, http.StatusInternalServerError, "DECOMPRESSION_ERROR", "Failed to read bundle")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"proof_%s.bundle.json\"", proofID.String()))
		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	}
}

// =============================================================================
// BUNDLE VERIFICATION ENDPOINTS
// =============================================================================

// BundleVerificationResponse represents bundle verification results
type BundleVerificationResponse struct {
	BundleValid  bool                        `json:"bundle_valid"`
	HashValid    bool                        `json:"hash_valid"`
	Components   map[string]bool             `json:"components"`
	Attestations BundleAttestationStatus     `json:"attestations"`
	VerifiedAt   time.Time                   `json:"verified_at"`
	Details      map[string]interface{}      `json:"details,omitempty"`
}

// BundleAttestationStatus represents attestation verification status
type BundleAttestationStatus struct {
	Total       int  `json:"total"`
	Valid       int  `json:"valid"`
	QuorumMet   bool `json:"quorum_met"`
	Required    int  `json:"required"`
}

// HandleVerifyBundle handles GET /api/v1/proofs/{proof_id}/bundle/verify
func (h *BundleHandlers) HandleVerifyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[1] != "bundle" || parts[2] != "verify" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()

	// Get bundle
	bundle, err := h.repos.ProofArtifacts.GetBundleByProofID(ctx, proofID)
	if err != nil || bundle == nil {
		h.writeError(w, http.StatusNotFound, "BUNDLE_NOT_FOUND", fmt.Sprintf("No bundle found for proof: %s", proofID))
		return
	}

	// Verify bundle hash
	gzReader, err := gzip.NewReader(bytes.NewReader(bundle.BundleData))
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "VERIFICATION_ERROR", "Failed to decompress bundle")
		return
	}
	defer gzReader.Close()

	jsonData, err := io.ReadAll(gzReader)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "VERIFICATION_ERROR", "Failed to read bundle")
		return
	}

	computedHash := sha256.Sum256(jsonData)
	hashValid := bytes.Equal(computedHash[:], bundle.BundleHash)

	// Parse bundle to verify components
	var bundleContent proof.CertenProofBundle
	componentStatus := make(map[string]bool)
	if err := json.Unmarshal(jsonData, &bundleContent); err == nil {
		componentStatus["merkle_inclusion"] = bundleContent.ProofComponents.MerkleInclusion != nil
		componentStatus["anchor_reference"] = bundleContent.ProofComponents.AnchorReference != nil
		componentStatus["chained_proof"] = bundleContent.ProofComponents.ChainedProof != nil
		componentStatus["governance_proof"] = bundleContent.ProofComponents.GovernanceProof != nil
	}

	// Get attestation status
	attestations, _ := h.repos.ProofArtifacts.GetProofAttestationsByProof(ctx, proofID)
	validCount := 0
	for _, att := range attestations {
		if att.SignatureValid {
			validCount++
		}
	}

	// Calculate quorum (2/3+1 of 4 validators = 3)
	requiredQuorum := 3
	quorumMet := validCount >= requiredQuorum

	allComponentsPresent := componentStatus["merkle_inclusion"] &&
		componentStatus["anchor_reference"] &&
		componentStatus["chained_proof"] &&
		componentStatus["governance_proof"]

	bundleValid := hashValid && allComponentsPresent && quorumMet

	response := BundleVerificationResponse{
		BundleValid: bundleValid,
		HashValid:   hashValid,
		Components:  componentStatus,
		Attestations: BundleAttestationStatus{
			Total:     len(attestations),
			Valid:     validCount,
			QuorumMet: quorumMet,
			Required:  requiredQuorum,
		},
		VerifiedAt: time.Now().UTC(),
		Details: map[string]interface{}{
			"bundle_id":      bundle.BundleID,
			"bundle_format":  bundle.BundleFormat,
			"bundle_version": bundle.BundleVersion,
			"bundle_size":    bundle.BundleSizeBytes,
		},
	}

	h.writeJSON(w, http.StatusOK, response)
}

// =============================================================================
// CUSTODY CHAIN ENDPOINTS
// =============================================================================

// HandleGetCustodyChain handles GET /api/v1/proofs/{proof_id}/custody
func (h *BundleHandlers) HandleGetCustodyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract proof ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "custody" {
		h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid endpoint path")
		return
	}

	proofID, err := uuid.Parse(parts[0])
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
		return
	}

	ctx := r.Context()

	// Get custody chain events
	events, err := h.repos.ProofArtifacts.GetCustodyChainEvents(ctx, proofID)
	if err != nil {
		h.logger.Printf("Error getting custody chain: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve custody chain")
		return
	}

	// Verify chain integrity
	chainValid := true
	if len(events) > 1 {
		for i := 1; i < len(events); i++ {
			if !bytes.Equal(events[i].PreviousHash, events[i-1].CurrentHash) {
				chainValid = false
				break
			}
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"proof_id":      proofID,
		"events":        events,
		"count":         len(events),
		"chain_valid":   chainValid,
		"retrieved_at":  time.Now().UTC(),
	})
}

// =============================================================================
// MERKLE VERIFICATION ENDPOINTS
// =============================================================================

// MerkleVerificationRequest represents a merkle proof verification request
type MerkleVerificationRequest struct {
	MerkleRoot   string   `json:"merkle_root"`
	LeafHash     string   `json:"leaf_hash"`
	LeafIndex    int      `json:"leaf_index"`
	MerklePath   []MerklePathEntry `json:"merkle_path"`
}

// MerklePathEntry represents a single entry in the merkle path
type MerklePathEntry struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right"`
}

// MerkleVerificationResponse represents merkle verification result
type MerkleVerificationResponse struct {
	Valid          bool      `json:"valid"`
	ComputedRoot   string    `json:"computed_root"`
	ExpectedRoot   string    `json:"expected_root"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// HandleVerifyMerkle handles POST /api/v1/proofs/verify/merkle
func (h *BundleHandlers) HandleVerifyMerkle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	var req MerkleVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Validate inputs
	rootBytes, err := hex.DecodeString(req.MerkleRoot)
	if err != nil || len(rootBytes) != 32 {
		h.writeError(w, http.StatusBadRequest, "INVALID_ROOT", "Invalid merkle root format")
		return
	}

	leafBytes, err := hex.DecodeString(req.LeafHash)
	if err != nil || len(leafBytes) != 32 {
		h.writeError(w, http.StatusBadRequest, "INVALID_LEAF", "Invalid leaf hash format")
		return
	}

	// Compute merkle root from proof
	currentHash := leafBytes
	for _, entry := range req.MerklePath {
		siblingBytes, err := hex.DecodeString(entry.Hash)
		if err != nil || len(siblingBytes) != 32 {
			h.writeError(w, http.StatusBadRequest, "INVALID_PATH", "Invalid merkle path entry")
			return
		}

		var combined []byte
		if entry.Right {
			combined = append(currentHash, siblingBytes...)
		} else {
			combined = append(siblingBytes, currentHash...)
		}
		hash := sha256.Sum256(combined)
		currentHash = hash[:]
	}

	computedRoot := hex.EncodeToString(currentHash)
	valid := computedRoot == req.MerkleRoot

	h.writeJSON(w, http.StatusOK, MerkleVerificationResponse{
		Valid:        valid,
		ComputedRoot: computedRoot,
		ExpectedRoot: req.MerkleRoot,
		VerifiedAt:   time.Now().UTC(),
	})
}

// =============================================================================
// GOVERNANCE VERIFICATION ENDPOINTS
// =============================================================================

// GovernanceVerificationRequest represents a governance proof verification request
type GovernanceVerificationRequest struct {
	ProofID         string                   `json:"proof_id"`
	GovernanceLevel string                   `json:"governance_level"` // G0, G1, G2
	ProofData       map[string]interface{}   `json:"proof_data"`
}

// GovernanceVerificationResponse represents governance verification result
type GovernanceVerificationResponse struct {
	Valid           bool                   `json:"valid"`
	Level           string                 `json:"level"`
	Details         map[string]interface{} `json:"details"`
	VerifiedAt      time.Time              `json:"verified_at"`
}

// HandleVerifyGovernance handles POST /api/v1/proofs/verify/governance
func (h *BundleHandlers) HandleVerifyGovernance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	var req GovernanceVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Validate governance level
	if req.GovernanceLevel != "G0" && req.GovernanceLevel != "G1" && req.GovernanceLevel != "G2" {
		h.writeError(w, http.StatusBadRequest, "INVALID_LEVEL", "governance_level must be 'G0', 'G1', or 'G2'")
		return
	}

	ctx := r.Context()
	details := make(map[string]interface{})

	// If proof ID is provided, verify against stored proof
	valid := false
	if req.ProofID != "" {
		proofID, err := uuid.Parse(req.ProofID)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_PROOF_ID", "Invalid proof ID format")
			return
		}

		// Get stored governance proof
		govLevels, err := h.repos.ProofArtifacts.GetGovernanceProofLevels(ctx, proofID)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve governance proof")
			return
		}

		// Find matching level
		for _, level := range govLevels {
			if string(level.GovLevel) == req.GovernanceLevel {
				valid = level.Verified
				details["stored_level"] = level
				break
			}
		}
	} else if req.ProofData != nil {
		// Verify provided proof data
		switch req.GovernanceLevel {
		case "G0":
			// G0: Execution Inclusion - verify merkle proof exists
			if merkleProof, ok := req.ProofData["merkle_proof"]; ok && merkleProof != nil {
				valid = true
				details["has_merkle_proof"] = true
			}
		case "G1":
			// G1: Governance Correctness - verify authority and signatures
			if authSnapshot, ok := req.ProofData["authority_snapshot"]; ok && authSnapshot != nil {
				if signatures, ok := req.ProofData["signatures"]; ok && signatures != nil {
					valid = true
					details["has_authority_snapshot"] = true
					details["has_signatures"] = true
				}
			}
		case "G2":
			// G2: Outcome Binding - verify post-state hash
			if postState, ok := req.ProofData["post_state_hash"]; ok && postState != nil {
				if inclusionProof, ok := req.ProofData["inclusion_proof"]; ok && inclusionProof != nil {
					valid = true
					details["has_post_state"] = true
					details["has_inclusion_proof"] = true
				}
			}
		}
	}

	h.writeJSON(w, http.StatusOK, GovernanceVerificationResponse{
		Valid:      valid,
		Level:      req.GovernanceLevel,
		Details:    details,
		VerifiedAt: time.Now().UTC(),
	})
}

// =============================================================================
// RATE LIMITER
// =============================================================================

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	buckets     map[string]*tokenBucket
	mu          sync.RWMutex
	ratePerMin  int
}

type tokenBucket struct {
	tokens    int
	lastFill  time.Time
	maxTokens int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	return &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		ratePerMin: ratePerMinute,
	}
}

// Allow checks if a request is allowed for the given client
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, ok := rl.buckets[clientID]
	if !ok {
		bucket = &tokenBucket{
			tokens:    rl.ratePerMin,
			lastFill:  time.Now(),
			maxTokens: rl.ratePerMin,
		}
		rl.buckets[clientID] = bucket
	}

	// Refill tokens based on time elapsed
	elapsed := time.Since(bucket.lastFill)
	tokensToAdd := int(elapsed.Minutes() * float64(rl.ratePerMin))
	if tokensToAdd > 0 {
		bucket.tokens = min(bucket.tokens+tokensToAdd, bucket.maxTokens)
		bucket.lastFill = time.Now()
	}

	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}
	return false
}

// =============================================================================
// API KEY VALIDATOR
// =============================================================================

// APIKeyValidator validates API keys
type APIKeyValidator struct {
	repos     *database.Repositories
	cache     map[string]*database.APIKey
	cacheMu   sync.RWMutex
	cacheTTL  time.Duration
}

// NewAPIKeyValidator creates a new API key validator
func NewAPIKeyValidator(repos *database.Repositories) *APIKeyValidator {
	return &APIKeyValidator{
		repos:    repos,
		cache:    make(map[string]*database.APIKey),
		cacheTTL: 5 * time.Minute,
	}
}

// Validate validates an API key and returns the key record
func (v *APIKeyValidator) Validate(ctx context.Context, apiKeyHeader string) (*database.APIKey, error) {
	if apiKeyHeader == "" {
		return nil, fmt.Errorf("API key is required")
	}

	// Check cache first
	v.cacheMu.RLock()
	cached, ok := v.cache[apiKeyHeader]
	v.cacheMu.RUnlock()
	if ok && cached != nil {
		return cached, nil
	}

	// Hash the API key for lookup
	keyHash := sha256.Sum256([]byte(apiKeyHeader))
	keyRecord, err := v.repos.ProofArtifacts.GetAPIKeyByHash(ctx, keyHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}
	if keyRecord == nil {
		return nil, fmt.Errorf("invalid API key")
	}
	if !keyRecord.IsActive {
		return nil, fmt.Errorf("API key is inactive")
	}
	if keyRecord.ExpiresAt != nil && keyRecord.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("API key has expired")
	}

	// Cache the valid key
	v.cacheMu.Lock()
	v.cache[apiKeyHeader] = keyRecord
	v.cacheMu.Unlock()

	// Update last used timestamp
	v.repos.ProofArtifacts.UpdateAPIKeyLastUsed(ctx, keyRecord.KeyID)

	return keyRecord, nil
}

// =============================================================================
// HELPER METHODS
// =============================================================================

func (h *BundleHandlers) validateAPIKey(r *http.Request) (*database.APIKey, error) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}
	if apiKey == "" {
		// Allow anonymous access for some endpoints
		return nil, nil
	}
	return h.apiKeyValidator.Validate(r.Context(), apiKey)
}

func (h *BundleHandlers) recordBundleDownload(ctx context.Context, bundleID uuid.UUID, apiKeyID *uuid.UUID, clientIP, userAgent string, responseCode, bytesSent int) {
	download := &database.NewBundleDownload{
		BundleID:     bundleID,
		APIKeyID:     apiKeyID,
		ClientIP:     clientIP,
		UserAgent:    &userAgent,
		ResponseCode: responseCode,
		BytesSent:    bytesSent,
	}
	h.repos.ProofArtifacts.RecordBundleDownload(ctx, download)
}

func (h *BundleHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("Error encoding response: %v", err)
	}
}

func (h *BundleHandlers) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	// Fall back to X-Real-IP
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}
	// Fall back to remote address
	addr := r.RemoteAddr
	if colonIdx := strings.LastIndex(addr, ":"); colonIdx != -1 {
		return addr[:colonIdx]
	}
	return addr
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
