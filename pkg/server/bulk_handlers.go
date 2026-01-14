// Copyright 2025 Certen Protocol
//
// Bulk Export API Handlers
// Implements endpoints for bulk proof export and audit operations
//
// Endpoints:
// - POST /api/v1/proofs/bulk/export - Export proofs in bulk
// - GET /api/v1/proofs/bulk/export/{job_id} - Get export job status
// - GET /api/v1/proofs/bulk/download/{job_id} - Download export file
// - POST /api/v1/proofs/bulk/verify - Bulk verification
// - GET /api/v1/stats/proofs - Get proof statistics
// - GET /api/v1/stats/system - Get system health

package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/database"
)

// BulkHandlers provides HTTP handlers for bulk operations
type BulkHandlers struct {
	repos           *database.Repositories
	validatorID     string
	logger          *log.Logger
	rateLimiter     *RateLimiter
	apiKeyValidator *APIKeyValidator
	exportJobs      map[uuid.UUID]*ExportJob
	exportMu        sync.RWMutex
	maxExportSize   int
}

// BulkHandlersConfig contains configuration for bulk handlers
type BulkHandlersConfig struct {
	ValidatorID        string
	RateLimitPerMinute int
	MaxExportSize      int // Maximum number of proofs in single export
}

// NewBulkHandlers creates new bulk handlers
func NewBulkHandlers(
	repos *database.Repositories,
	config *BulkHandlersConfig,
	logger *log.Logger,
) *BulkHandlers {
	if logger == nil {
		logger = log.New(log.Writer(), "[BulkAPI] ", log.LstdFlags)
	}
	if config == nil {
		config = &BulkHandlersConfig{
			ValidatorID:        "default-validator",
			RateLimitPerMinute: 10, // Lower rate limit for bulk operations
			MaxExportSize:      10000,
		}
	}

	return &BulkHandlers{
		repos:           repos,
		validatorID:     config.ValidatorID,
		logger:          logger,
		rateLimiter:     NewRateLimiter(config.RateLimitPerMinute),
		apiKeyValidator: NewAPIKeyValidator(repos),
		exportJobs:      make(map[uuid.UUID]*ExportJob),
		maxExportSize:   config.MaxExportSize,
	}
}

// =============================================================================
// EXPORT JOB TYPES
// =============================================================================

// ExportJob represents a bulk export job
type ExportJob struct {
	JobID          uuid.UUID              `json:"job_id"`
	Status         string                 `json:"status"` // pending, processing, completed, failed
	Format         string                 `json:"format"` // json_lines, csv, parquet
	Request        *BulkExportRequest     `json:"request"`
	TotalCount     int                    `json:"total_count"`
	ProcessedCount int                    `json:"processed_count"`
	FileSizeBytes  int64                  `json:"file_size_bytes"`
	FileData       []byte                 `json:"-"` // Not serialized
	Error          string                 `json:"error,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
	ExpiresAt      time.Time              `json:"expires_at"`
}

// BulkExportRequest represents a bulk export request
type BulkExportRequest struct {
	AccountURLs     []string               `json:"account_urls,omitempty"`
	DateRange       *DateRange             `json:"date_range,omitempty"`
	ProofTypes      []string               `json:"proof_types,omitempty"`
	GovernanceLevels []string              `json:"governance_levels,omitempty"`
	Status          []string               `json:"status,omitempty"`
	Format          string                 `json:"format"` // json_lines, csv
	IncludeArtifacts bool                  `json:"include_artifacts"`
	IncludeAttestations bool               `json:"include_attestations"`
	Limit           int                    `json:"limit,omitempty"`
}

// DateRange represents a date range for filtering
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// BulkExportResponse represents the response to a bulk export request
type BulkExportResponse struct {
	JobID          uuid.UUID `json:"job_id"`
	Status         string    `json:"status"`
	EstimatedCount int       `json:"estimated_count"`
	Message        string    `json:"message"`
}

// =============================================================================
// BULK EXPORT ENDPOINTS
// =============================================================================

// HandleBulkExport handles POST /api/v1/proofs/bulk/export
func (h *BulkHandlers) HandleBulkExport(w http.ResponseWriter, r *http.Request) {
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

	// Check permissions
	if !apiKey.CanBulkDownload {
		h.writeError(w, http.StatusForbidden, "FORBIDDEN", "API key does not have bulk download permission")
		return
	}

	// Check rate limit
	if !h.rateLimiter.Allow(apiKey.ClientName) {
		h.writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "Rate limit exceeded for bulk operations")
		return
	}

	// Parse request
	var req BulkExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	// Validate format
	if req.Format != "json_lines" && req.Format != "csv" {
		req.Format = "json_lines" // Default to JSON lines
	}

	// Apply limit
	if req.Limit <= 0 || req.Limit > h.maxExportSize {
		req.Limit = h.maxExportSize
	}

	ctx := r.Context()

	// Estimate count
	filter := h.buildFilter(&req)
	estimatedCount, err := h.repos.ProofArtifacts.CountProofs(ctx, filter)
	if err != nil {
		h.logger.Printf("Error counting proofs: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to estimate export size")
		return
	}

	// Create export job
	jobID := uuid.New()
	job := &ExportJob{
		JobID:      jobID,
		Status:     "pending",
		Format:     req.Format,
		Request:    &req,
		TotalCount: estimatedCount,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(24 * time.Hour), // Expire after 24 hours
	}

	h.exportMu.Lock()
	h.exportJobs[jobID] = job
	h.exportMu.Unlock()

	// Start async processing
	go h.processExportJob(job)

	h.writeJSON(w, http.StatusAccepted, BulkExportResponse{
		JobID:          jobID,
		Status:         "pending",
		EstimatedCount: estimatedCount,
		Message:        "Export job created and queued for processing",
	})
}

// HandleGetExportStatus handles GET /api/v1/proofs/bulk/export/{job_id}
func (h *BulkHandlers) HandleGetExportStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/bulk/export/")
	jobIDStr := strings.TrimSuffix(path, "/")

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JOB_ID", "Invalid job ID format")
		return
	}

	h.exportMu.RLock()
	job, ok := h.exportJobs[jobID]
	h.exportMu.RUnlock()

	if !ok {
		h.writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", fmt.Sprintf("No export job found with ID: %s", jobID))
		return
	}

	// Return job status (without file data)
	h.writeJSON(w, http.StatusOK, job)
}

// HandleDownloadExport handles GET /api/v1/proofs/bulk/download/{job_id}
func (h *BulkHandlers) HandleDownloadExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	// Extract job ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proofs/bulk/download/")
	jobIDStr := strings.TrimSuffix(path, "/")

	jobID, err := uuid.Parse(jobIDStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JOB_ID", "Invalid job ID format")
		return
	}

	h.exportMu.RLock()
	job, ok := h.exportJobs[jobID]
	h.exportMu.RUnlock()

	if !ok {
		h.writeError(w, http.StatusNotFound, "JOB_NOT_FOUND", fmt.Sprintf("No export job found with ID: %s", jobID))
		return
	}

	if job.Status != "completed" {
		h.writeError(w, http.StatusConflict, "JOB_NOT_READY", fmt.Sprintf("Export job status: %s", job.Status))
		return
	}

	if job.FileData == nil || len(job.FileData) == 0 {
		h.writeError(w, http.StatusGone, "FILE_EXPIRED", "Export file has expired or been deleted")
		return
	}

	// Set headers based on format
	var contentType, extension string
	switch job.Format {
	case "csv":
		contentType = "text/csv"
		extension = "csv"
	default:
		contentType = "application/x-ndjson"
		extension = "jsonl"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"export_%s.%s.gz\"", jobID.String(), extension))
	w.Header().Set("X-Total-Count", strconv.Itoa(job.TotalCount))
	w.Header().Set("X-Processed-Count", strconv.Itoa(job.ProcessedCount))
	w.WriteHeader(http.StatusOK)
	w.Write(job.FileData)
}

// =============================================================================
// BULK VERIFICATION ENDPOINTS
// =============================================================================

// BulkVerifyRequest represents a bulk verification request
type BulkVerifyRequest struct {
	ProofIDs []string `json:"proof_ids"`
}

// BulkVerifyResponse represents bulk verification results
type BulkVerifyResponse struct {
	Results     []ProofVerificationResult `json:"results"`
	TotalCount  int                       `json:"total_count"`
	ValidCount  int                       `json:"valid_count"`
	InvalidCount int                      `json:"invalid_count"`
	ErrorCount  int                       `json:"error_count"`
	VerifiedAt  time.Time                 `json:"verified_at"`
}

// ProofVerificationResult represents a single proof verification result
type ProofVerificationResult struct {
	ProofID       string `json:"proof_id"`
	Status        string `json:"status"` // valid, invalid, error
	IntegrityValid bool  `json:"integrity_valid"`
	QuorumMet     bool   `json:"quorum_met"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// HandleBulkVerify handles POST /api/v1/proofs/bulk/verify
func (h *BulkHandlers) HandleBulkVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	// Parse request
	var req BulkVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request format")
		return
	}

	if len(req.ProofIDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "At least one proof ID is required")
		return
	}

	if len(req.ProofIDs) > 100 {
		h.writeError(w, http.StatusBadRequest, "TOO_MANY_PROOFS", "Maximum 100 proofs per bulk verification request")
		return
	}

	ctx := r.Context()
	results := make([]ProofVerificationResult, 0, len(req.ProofIDs))
	validCount := 0
	invalidCount := 0
	errorCount := 0

	for _, proofIDStr := range req.ProofIDs {
		result := ProofVerificationResult{
			ProofID: proofIDStr,
		}

		proofID, err := uuid.Parse(proofIDStr)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = "Invalid proof ID format"
			errorCount++
			results = append(results, result)
			continue
		}

		// Verify integrity
		integrityValid, err := h.repos.ProofArtifacts.VerifyArtifactIntegrity(ctx, proofID)
		if err != nil {
			result.Status = "error"
			result.ErrorMessage = fmt.Sprintf("Verification failed: %v", err)
			errorCount++
			results = append(results, result)
			continue
		}
		result.IntegrityValid = integrityValid

		// Check attestation quorum
		attestations, err := h.repos.ProofArtifacts.GetProofAttestationsByProof(ctx, proofID)
		if err == nil {
			validAttestations := 0
			for _, att := range attestations {
				if att.SignatureValid {
					validAttestations++
				}
			}
			result.QuorumMet = validAttestations >= 3 // 2/3+1 of 4 validators
		}

		if result.IntegrityValid && result.QuorumMet {
			result.Status = "valid"
			validCount++
		} else {
			result.Status = "invalid"
			invalidCount++
		}

		results = append(results, result)
	}

	h.writeJSON(w, http.StatusOK, BulkVerifyResponse{
		Results:      results,
		TotalCount:   len(req.ProofIDs),
		ValidCount:   validCount,
		InvalidCount: invalidCount,
		ErrorCount:   errorCount,
		VerifiedAt:   time.Now().UTC(),
	})
}

// =============================================================================
// STATISTICS ENDPOINTS
// =============================================================================

// ProofStatistics represents proof statistics
type ProofStatistics struct {
	TotalProofs         int64                  `json:"total_proofs"`
	ProofsByStatus      map[string]int64       `json:"proofs_by_status"`
	ProofsByType        map[string]int64       `json:"proofs_by_type"`
	ProofsByGovLevel    map[string]int64       `json:"proofs_by_gov_level"`
	AttestationStats    AttestationStatistics  `json:"attestation_stats"`
	Last24HourStats     TimeWindowStats        `json:"last_24h"`
	Last7DayStats       TimeWindowStats        `json:"last_7d"`
	GeneratedAt         time.Time              `json:"generated_at"`
}

// AttestationStatistics represents attestation-related statistics
type AttestationStatistics struct {
	TotalAttestations   int64   `json:"total_attestations"`
	ValidAttestations   int64   `json:"valid_attestations"`
	QuorumReachedCount  int64   `json:"quorum_reached_count"`
	AveragePerProof     float64 `json:"average_per_proof"`
}

// TimeWindowStats represents statistics for a time window
type TimeWindowStats struct {
	ProofsCreated    int64 `json:"proofs_created"`
	ProofsVerified   int64 `json:"proofs_verified"`
	BundlesDownloaded int64 `json:"bundles_downloaded"`
}

// HandleGetProofStats handles GET /api/v1/stats/proofs
func (h *BulkHandlers) HandleGetProofStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx := r.Context()

	// Get total counts
	totalProofs, _ := h.repos.ProofArtifacts.CountProofs(ctx, nil)

	// Get proofs by status
	proofsByStatus := make(map[string]int64)
	for _, status := range []database.ProofStatus{
		database.ProofStatusPending,
		database.ProofStatusBatched,
		database.ProofStatusAnchored,
		database.ProofStatusAttested,
		database.ProofStatusVerified,
		database.ProofStatusFailed,
	} {
		statusCopy := status
		count, _ := h.repos.ProofArtifacts.CountProofs(ctx, &database.ProofArtifactFilter{Status: &statusCopy})
		proofsByStatus[string(status)] = int64(count)
	}

	// Get proofs by type
	proofsByType := make(map[string]int64)
	for _, proofType := range []database.ProofType{
		database.ProofTypeChained,
		database.ProofTypeGovernance,
		database.ProofTypeMerkle,
	} {
		typeCopy := proofType
		count, _ := h.repos.ProofArtifacts.CountProofs(ctx, &database.ProofArtifactFilter{ProofType: &typeCopy})
		proofsByType[string(proofType)] = int64(count)
	}

	// Get proofs by governance level
	proofsByGovLevel := make(map[string]int64)
	for _, level := range []database.GovernanceLevel{
		database.GovLevelG0,
		database.GovLevelG1,
		database.GovLevelG2,
	} {
		levelCopy := level
		count, _ := h.repos.ProofArtifacts.CountProofs(ctx, &database.ProofArtifactFilter{GovLevel: &levelCopy})
		proofsByGovLevel[string(level)] = int64(count)
	}

	// Get attestation stats
	attestationStats := h.getAttestationStats(ctx)

	// Get time window stats
	now := time.Now()
	last24h := now.Add(-24 * time.Hour)
	last7d := now.Add(-7 * 24 * time.Hour)

	last24hStats := h.getTimeWindowStats(ctx, last24h, now)
	last7dStats := h.getTimeWindowStats(ctx, last7d, now)

	stats := ProofStatistics{
		TotalProofs:      int64(totalProofs),
		ProofsByStatus:   proofsByStatus,
		ProofsByType:     proofsByType,
		ProofsByGovLevel: proofsByGovLevel,
		AttestationStats: attestationStats,
		Last24HourStats:  last24hStats,
		Last7DayStats:    last7dStats,
		GeneratedAt:      time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, stats)
}

// SystemHealth represents system health status
type SystemHealth struct {
	Status           string                 `json:"status"` // healthy, degraded, unhealthy
	ValidatorID      string                 `json:"validator_id"`
	DatabaseStatus   string                 `json:"database_status"`
	Services         map[string]ServiceStatus `json:"services"`
	Metrics          SystemMetrics          `json:"metrics"`
	LastCheckedAt    time.Time              `json:"last_checked_at"`
}

// ServiceStatus represents a service's health status
type ServiceStatus struct {
	Status      string `json:"status"`
	Message     string `json:"message,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`
}

// SystemMetrics represents system-level metrics
type SystemMetrics struct {
	ActiveExportJobs    int     `json:"active_export_jobs"`
	PendingProofRequests int    `json:"pending_proof_requests"`
	RequestsPerMinute   float64 `json:"requests_per_minute"`
	AverageLatencyMs    float64 `json:"average_latency_ms"`
}

// HandleGetSystemHealth handles GET /api/v1/stats/system
func (h *BulkHandlers) HandleGetSystemHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx := r.Context()

	// Check database connectivity
	dbStatus := "healthy"
	if _, err := h.repos.ProofArtifacts.CountProofs(ctx, nil); err != nil {
		dbStatus = "unhealthy"
	}

	// Count active export jobs
	h.exportMu.RLock()
	activeJobs := 0
	for _, job := range h.exportJobs {
		if job.Status == "pending" || job.Status == "processing" {
			activeJobs++
		}
	}
	h.exportMu.RUnlock()

	// Count pending proof requests
	pendingRequests, _ := h.repos.ProofArtifacts.CountPendingProofRequests(ctx)

	// Determine overall status
	overallStatus := "healthy"
	if dbStatus == "unhealthy" {
		overallStatus = "unhealthy"
	} else if activeJobs > 10 || pendingRequests > 100 {
		overallStatus = "degraded"
	}

	health := SystemHealth{
		Status:         overallStatus,
		ValidatorID:    h.validatorID,
		DatabaseStatus: dbStatus,
		Services: map[string]ServiceStatus{
			"proof_service": {
				Status:  "healthy",
				Message: "Operational",
			},
			"attestation_service": {
				Status:  "healthy",
				Message: "Collecting attestations",
			},
			"export_service": {
				Status:  "healthy",
				Message: fmt.Sprintf("%d active jobs", activeJobs),
			},
		},
		Metrics: SystemMetrics{
			ActiveExportJobs:     activeJobs,
			PendingProofRequests: pendingRequests,
		},
		LastCheckedAt: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, health)
}

// =============================================================================
// HELPER METHODS
// =============================================================================

func (h *BulkHandlers) buildFilter(req *BulkExportRequest) *database.ProofArtifactFilter {
	filter := &database.ProofArtifactFilter{
		Limit: req.Limit,
	}

	if len(req.AccountURLs) > 0 {
		filter.AccountURLs = req.AccountURLs
	}

	if req.DateRange != nil {
		filter.CreatedAfter = &req.DateRange.Start
		filter.CreatedBefore = &req.DateRange.End
	}

	if len(req.Status) > 0 {
		filter.Statuses = req.Status
	}

	if len(req.GovernanceLevels) > 0 {
		filter.GovernanceLevels = req.GovernanceLevels
	}

	return filter
}

func (h *BulkHandlers) processExportJob(job *ExportJob) {
	ctx := context.Background()

	// Update status to processing
	h.exportMu.Lock()
	job.Status = "processing"
	h.exportMu.Unlock()

	// Build filter
	filter := h.buildFilter(job.Request)

	// Query proofs (use full export query for complete artifact data)
	proofs, err := h.repos.ProofArtifacts.QueryProofsForExport(ctx, filter)
	if err != nil {
		h.exportMu.Lock()
		job.Status = "failed"
		job.Error = fmt.Sprintf("Failed to query proofs: %v", err)
		h.exportMu.Unlock()
		return
	}

	// Generate export file
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)

	switch job.Format {
	case "csv":
		h.writeCSVExport(gzWriter, proofs, job)
	default:
		h.writeJSONLinesExport(gzWriter, proofs, job)
	}

	gzWriter.Close()

	// Update job with results
	h.exportMu.Lock()
	job.FileData = buf.Bytes()
	job.FileSizeBytes = int64(len(job.FileData))
	job.ProcessedCount = len(proofs)
	job.Status = "completed"
	completedAt := time.Now()
	job.CompletedAt = &completedAt
	h.exportMu.Unlock()

	h.logger.Printf("Export job %s completed: %d proofs, %d bytes", job.JobID, len(proofs), job.FileSizeBytes)
}

func (h *BulkHandlers) writeJSONLinesExport(w io.Writer, proofs []database.ProofArtifact, job *ExportJob) {
	ctx := context.Background()
	encoder := json.NewEncoder(w)

	for _, proof := range proofs {
		record := map[string]interface{}{
			"proof_id":           proof.ProofID,
			"proof_type":         string(proof.ProofType),
			"accum_tx_hash":      proof.AccumTxHash,
			"account_url":        proof.AccountURL,
			"gov_level":          govLevelToString(proof.GovLevel),
			"status":             string(proof.Status),
			"created_at":         proof.CreatedAt,
			"anchored_at":        proof.AnchoredAt,
			"verified_at":        proof.VerifiedAt,
			"anchor_chain":       stringPtrOrEmpty(proof.AnchorChain),
			"anchor_tx_hash":     stringPtrOrEmpty(proof.AnchorTxHash),
			"anchor_block_number": int64PtrOrZero(proof.AnchorBlockNumber),
		}

		if job.Request.IncludeAttestations {
			attestations, _ := h.repos.ProofArtifacts.GetProofAttestationsByProof(ctx, proof.ProofID)
			record["attestations"] = attestations
		}

		encoder.Encode(record)
	}
}

func (h *BulkHandlers) writeCSVExport(w io.Writer, proofs []database.ProofArtifact, job *ExportJob) {
	csvWriter := csv.NewWriter(w)
	defer csvWriter.Flush()

	// Write header
	header := []string{
		"proof_id", "proof_type", "accum_tx_hash", "account_url",
		"gov_level", "status", "created_at", "anchored_at", "verified_at",
		"anchor_chain", "anchor_tx_hash", "anchor_block_number",
	}
	if job.Request.IncludeAttestations {
		header = append(header, "attestation_count", "quorum_met")
	}
	csvWriter.Write(header)

	ctx := context.Background()

	for _, proof := range proofs {
		record := []string{
			proof.ProofID.String(),
			string(proof.ProofType),
			proof.AccumTxHash,
			proof.AccountURL,
			govLevelToString(proof.GovLevel),
			string(proof.Status),
			proof.CreatedAt.Format(time.RFC3339),
			timeOrEmpty(proof.AnchoredAt),
			timeOrEmpty(proof.VerifiedAt),
			stringPtrOrEmpty(proof.AnchorChain),
			stringPtrOrEmpty(proof.AnchorTxHash),
			int64PtrToString(proof.AnchorBlockNumber),
		}

		if job.Request.IncludeAttestations {
			attestations, _ := h.repos.ProofArtifacts.GetProofAttestationsByProof(ctx, proof.ProofID)
			validCount := 0
			for _, att := range attestations {
				if att.SignatureValid {
					validCount++
				}
			}
			record = append(record, strconv.Itoa(len(attestations)))
			record = append(record, strconv.FormatBool(validCount >= 3))
		}

		csvWriter.Write(record)
	}
}

func (h *BulkHandlers) getAttestationStats(ctx context.Context) AttestationStatistics {
	stats := AttestationStatistics{}

	// Get all attestations count
	totalCount, _ := h.repos.ProofArtifacts.CountAttestations(ctx, nil)
	stats.TotalAttestations = int64(totalCount)

	// Get valid attestations count
	validOnly := true
	validCount, _ := h.repos.ProofArtifacts.CountAttestations(ctx, &validOnly)
	stats.ValidAttestations = int64(validCount)

	// Calculate average (simplified)
	totalProofs, _ := h.repos.ProofArtifacts.CountProofs(ctx, nil)
	if totalProofs > 0 {
		stats.AveragePerProof = float64(totalCount) / float64(totalProofs)
	}

	return stats
}

func (h *BulkHandlers) getTimeWindowStats(ctx context.Context, start, end time.Time) TimeWindowStats {
	stats := TimeWindowStats{}

	filter := &database.ProofArtifactFilter{
		CreatedAfter:  &start,
		CreatedBefore: &end,
	}

	count, _ := h.repos.ProofArtifacts.CountProofs(ctx, filter)
	stats.ProofsCreated = int64(count)

	verifiedStatus := database.ProofStatusVerified
	filter.Status = &verifiedStatus
	count, _ = h.repos.ProofArtifacts.CountProofs(ctx, filter)
	stats.ProofsVerified = int64(count)

	stats.BundlesDownloaded, _ = h.repos.ProofArtifacts.CountBundleDownloads(ctx, start, end)

	return stats
}

func (h *BulkHandlers) validateAPIKey(r *http.Request) (*database.APIKey, error) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		apiKey = r.URL.Query().Get("api_key")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required for bulk operations")
	}
	return h.apiKeyValidator.Validate(r.Context(), apiKey)
}

func (h *BulkHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("Error encoding response: %v", err)
	}
}

func (h *BulkHandlers) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func timeOrEmpty(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

func int64OrEmpty(i *int64) string {
	if i == nil {
		return ""
	}
	return strconv.FormatInt(*i, 10)
}

// stringPtrOrEmpty is an alias for stringOrEmpty for clarity
func stringPtrOrEmpty(s *string) string {
	return stringOrEmpty(s)
}

// int64PtrToString converts an int64 pointer to string
func int64PtrToString(i *int64) string {
	return int64OrEmpty(i)
}

// int64PtrOrZero returns the value or 0 if nil
func int64PtrOrZero(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

// govLevelToString converts a GovernanceLevel pointer to string
func govLevelToString(g *database.GovernanceLevel) string {
	if g == nil {
		return ""
	}
	return string(*g)
}
