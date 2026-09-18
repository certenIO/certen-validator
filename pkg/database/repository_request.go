// Copyright 2025 Certen Protocol
//
// Request Repository - CRUD operations for proof requests
// Handles incoming requests for on-cadence (~$0.05) and on-demand (~$0.25) proofs
// Per Whitepaper Section 3.4.2
//
// A request moves pending -> processing -> (batched ->) completed, or -> failed; a failed request can be
// reset to pending for another attempt, up to a retry limit. RequestFulfiller drives these transitions.

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// RequestRepository handles proof request operations
type RequestRepository struct {
	client *Client
}

// NewRequestRepository creates a new request repository
func NewRequestRepository(client *Client) *RequestRepository {
	return &RequestRepository{client: client}
}

const proofRequestColumns = `
	request_id, accum_tx_hash, account_url, proof_class, governance_level,
	priority, status, batch_id, proof_id, api_key_id, callback_url, created_at,
	processed_at, completed_at, requester_id, error_message, retry_count`

// priorityOrder sorts urgent work first and, within a priority, the oldest request first.
const priorityOrder = `
	CASE priority WHEN 'urgent' THEN 1 WHEN 'high' THEN 2 WHEN 'normal' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
	created_at ASC`

func scanProofRequest(scan func(...any) error) (*ProofRequest, error) {
	request := &ProofRequest{}
	if err := scan(
		&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType, &request.GovernanceLevel,
		&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.APIKeyID, &request.CallbackURL, &request.RequestedAt,
		&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
	); err != nil {
		return nil, err
	}
	return request, nil
}

// ============================================================================
// PROOF REQUEST OPERATIONS
// ============================================================================

// CreateRequest creates a new proof request
func (r *RequestRepository) CreateRequest(ctx context.Context, input *NewProofRequest) (*ProofRequest, error) {
	if input == nil {
		return nil, errors.New("proof request input is required")
	}
	if input.AccumTxHash == "" && input.AccountURL == "" {
		return nil, errors.New("a proof request needs a transaction hash or an account URL")
	}
	priority := input.Priority
	if priority == "" {
		if input.RequestType == RequestTypeOnDemand {
			priority = PriorityHigh
		} else {
			priority = PriorityNormal
		}
	}
	nullString := func(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
	row := r.client.QueryRowContext(ctx, `
		INSERT INTO proof_requests (
			accum_tx_hash, account_url, proof_class, governance_level,
			priority, status, requester_id, api_key_id, callback_url
		) VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8)
		RETURNING `+proofRequestColumns,
		nullString(input.AccumTxHash), nullString(input.AccountURL), input.RequestType, nullString(string(input.GovernanceLevel)),
		priority, nullString(input.RequesterID), uuid.NullUUID{UUID: input.APIKeyID, Valid: input.APIKeyID != uuid.Nil}, nullString(input.CallbackURL),
	)
	request, err := scanProofRequest(row.Scan)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	return request, nil
}

func (r *RequestRepository) getOne(ctx context.Context, where string, args ...any) (*ProofRequest, error) {
	row := r.client.QueryRowContext(ctx, `SELECT `+proofRequestColumns+` FROM proof_requests `+where, args...)
	request, err := scanProofRequest(row.Scan)
	if err == sql.ErrNoRows {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}
	return request, nil
}

func (r *RequestRepository) getMany(ctx context.Context, what, where string, args ...any) ([]*ProofRequest, error) {
	rows, err := r.client.QueryContext(ctx, `SELECT `+proofRequestColumns+` FROM proof_requests `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query %s: %w", what, err)
	}
	defer rows.Close()
	var requests []*ProofRequest
	for rows.Next() {
		request, err := scanProofRequest(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}
	return requests, rows.Err()
}

// GetRequest retrieves a request by ID
func (r *RequestRepository) GetRequest(ctx context.Context, requestID uuid.UUID) (*ProofRequest, error) {
	return r.getOne(ctx, `WHERE request_id = $1`, requestID)
}

// GetRequestByAccumTxHash retrieves the most recent request for an Accumulate transaction
func (r *RequestRepository) GetRequestByAccumTxHash(ctx context.Context, accumTxHash string) (*ProofRequest, error) {
	return r.getOne(ctx, `WHERE accum_tx_hash = $1 ORDER BY created_at DESC LIMIT 1`, accumTxHash)
}

// GetPendingRequests retrieves pending requests, most urgent first
func (r *RequestRepository) GetPendingRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "pending requests", `WHERE status = 'pending' ORDER BY `+priorityOrder+` LIMIT $1`, limit)
}

// GetPendingOnDemandRequests retrieves pending on-demand requests (higher priority)
func (r *RequestRepository) GetPendingOnDemandRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "on-demand requests", `WHERE status = 'pending' AND proof_class = 'on_demand' ORDER BY `+priorityOrder+` LIMIT $1`, limit)
}

// GetPendingOnCadenceRequests retrieves pending on-cadence requests
func (r *RequestRepository) GetPendingOnCadenceRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "on-cadence requests", `WHERE status = 'pending' AND proof_class = 'on_cadence' ORDER BY created_at ASC LIMIT $1`, limit)
}

// GetProcessingRequests retrieves requests that have been picked up and are awaiting their proof
func (r *RequestRepository) GetProcessingRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "processing requests", `WHERE status IN ('processing', 'batched') ORDER BY `+priorityOrder+` LIMIT $1`, limit)
}

// GetRequestsByBatch retrieves all requests assigned to a batch
func (r *RequestRepository) GetRequestsByBatch(ctx context.Context, batchID uuid.UUID) ([]*ProofRequest, error) {
	return r.getMany(ctx, "requests by batch", `WHERE batch_id = $1 ORDER BY created_at ASC`, batchID)
}

// ============================================================================
// STATUS UPDATE OPERATIONS
// ============================================================================

func (r *RequestRepository) execOne(ctx context.Context, what string, requestID uuid.UUID, query string, args ...any) error {
	result, err := r.client.ExecContext(ctx, query, append([]any{requestID}, args...)...)
	if err != nil {
		return fmt.Errorf("failed to %s: %w", what, err)
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return fmt.Errorf("%s: %w", what, ErrRequestNotFound)
	}
	return nil
}

// UpdateRequestStatus updates the status of a request
func (r *RequestRepository) UpdateRequestStatus(ctx context.Context, requestID uuid.UUID, status RequestStatus, errorMsg string) error {
	if errorMsg != "" {
		return r.execOne(ctx, "update request status", requestID, `
			UPDATE proof_requests SET status = $2, error_message = $3 WHERE request_id = $1`, status, errorMsg)
	}
	return r.execOne(ctx, "update request status", requestID, `
		UPDATE proof_requests SET status = $2 WHERE request_id = $1`, status)
}

// MarkProcessing claims a pending request. It only succeeds from 'pending', so two workers cannot both
// claim the same request.
func (r *RequestRepository) MarkProcessing(ctx context.Context, requestID uuid.UUID) error {
	return r.execOne(ctx, "mark request processing", requestID, `
		UPDATE proof_requests SET status = 'processing', processed_at = NOW()
		WHERE request_id = $1 AND status = 'pending'`)
}

// MarkBatched records the batch a request's transaction was placed in
func (r *RequestRepository) MarkBatched(ctx context.Context, requestID uuid.UUID, batchID uuid.UUID) error {
	return r.execOne(ctx, "mark request batched", requestID, `
		UPDATE proof_requests SET status = 'batched', batch_id = $2, processed_at = COALESCE(processed_at, NOW())
		WHERE request_id = $1 AND status IN ('pending', 'processing')`, batchID)
}

// MarkCompleted records the proof that fulfils a request
func (r *RequestRepository) MarkCompleted(ctx context.Context, requestID uuid.UUID, proofID uuid.UUID) error {
	return r.execOne(ctx, "mark request completed", requestID, `
		UPDATE proof_requests SET status = 'completed', proof_id = $2, completed_at = NOW(), error_message = NULL
		WHERE request_id = $1 AND status IN ('pending', 'processing', 'batched')`, proofID)
}

// MarkFailed records why a request could not be fulfilled and counts the attempt
func (r *RequestRepository) MarkFailed(ctx context.Context, requestID uuid.UUID, errorMsg string) error {
	return r.execOne(ctx, "mark request failed", requestID, `
		UPDATE proof_requests SET status = 'failed', error_message = $2, retry_count = retry_count + 1
		WHERE request_id = $1 AND status IN ('pending', 'processing', 'batched')`, errorMsg)
}

// ResetToRetry returns a failed request to the queue
func (r *RequestRepository) ResetToRetry(ctx context.Context, requestID uuid.UUID) error {
	return r.execOne(ctx, "reset request", requestID, `
		UPDATE proof_requests SET status = 'pending', processed_at = NULL, error_message = NULL
		WHERE request_id = $1 AND status = 'failed'`)
}

// ============================================================================
// STATISTICS
// ============================================================================

// CountPendingRequests returns the number of pending requests
func (r *RequestRepository) CountPendingRequests(ctx context.Context) (int64, error) {
	var count int64
	if err := r.client.QueryRowContext(ctx, `SELECT COUNT(*) FROM proof_requests WHERE status = 'pending'`).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count pending requests: %w", err)
	}
	return count, nil
}

// CountPendingByType returns the number of pending requests of one class
func (r *RequestRepository) CountPendingByType(ctx context.Context, requestType RequestType) (int64, error) {
	var count int64
	if err := r.client.QueryRowContext(ctx, `SELECT COUNT(*) FROM proof_requests WHERE status = 'pending' AND proof_class = $1`, requestType).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count pending requests by type: %w", err)
	}
	return count, nil
}

// CountByStatus returns the number of requests in a status
func (r *RequestRepository) CountByStatus(ctx context.Context, status RequestStatus) (int64, error) {
	var count int64
	if err := r.client.QueryRowContext(ctx, `SELECT COUNT(*) FROM proof_requests WHERE status = $1`, status).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count requests by status: %w", err)
	}
	return count, nil
}

// GetRecentRequests returns the most recent requests
func (r *RequestRepository) GetRecentRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "recent requests", `ORDER BY created_at DESC LIMIT $1`, limit)
}

// GetFailedRequestsForRetry returns failed requests that can be retried
func (r *RequestRepository) GetFailedRequestsForRetry(ctx context.Context, maxRetries int, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "failed requests", `WHERE status = 'failed' AND retry_count < $1 ORDER BY retry_count ASC, created_at ASC LIMIT $2`, maxRetries, limit)
}

// GetRequestsByRequester returns requests submitted by a specific requester
func (r *RequestRepository) GetRequestsByRequester(ctx context.Context, requesterID string, limit int) ([]*ProofRequest, error) {
	return r.getMany(ctx, "requests by requester", `WHERE requester_id = $1 ORDER BY created_at DESC LIMIT $2`, requesterID, limit)
}
