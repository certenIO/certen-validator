// Copyright 2025 Certen Protocol
//
// Request Repository - CRUD operations for proof requests
// Handles incoming requests for on-cadence (~$0.05) and on-demand (~$0.25) proofs
// Per Whitepaper Section 3.4.2

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

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

// ============================================================================
// PROOF REQUEST OPERATIONS
// ============================================================================

// CreateRequest creates a new proof request
func (r *RequestRepository) CreateRequest(ctx context.Context, input *NewProofRequest) (*ProofRequest, error) {
	request := &ProofRequest{
		RequestID:   uuid.New(),
		AccumTxHash: sql.NullString{String: input.AccumTxHash, Valid: input.AccumTxHash != ""},
		AccountURL:  sql.NullString{String: input.AccountURL, Valid: input.AccountURL != ""},
		RequestType: input.RequestType,
		Priority:    input.Priority,
		Status:      RequestStatusPending,
		RequestedAt: time.Now(),
		RequesterID: sql.NullString{String: input.RequesterID, Valid: input.RequesterID != ""},
		RetryCount:  0,
	}

	// Set default priority if not specified
	if request.Priority == "" {
		if request.RequestType == RequestTypeOnDemand {
			request.Priority = PriorityHigh
		} else {
			request.Priority = PriorityNormal
		}
	}

	query := `
		INSERT INTO proof_requests (
			request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, requested_at, requester_id, retry_count
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING request_id, requested_at`

	err := r.client.QueryRowContext(ctx, query,
		request.RequestID, request.AccumTxHash, request.AccountURL, request.RequestType,
		request.Priority, request.Status, request.RequestedAt, request.RequesterID, request.RetryCount,
	).Scan(&request.RequestID, &request.RequestedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	return request, nil
}

// GetRequest retrieves a request by ID
func (r *RequestRepository) GetRequest(ctx context.Context, requestID uuid.UUID) (*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE request_id = $1`

	request := &ProofRequest{}
	err := r.client.QueryRowContext(ctx, query, requestID).Scan(
		&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
		&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
		&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request: %w", err)
	}

	return request, nil
}

// GetRequestByAccumTxHash retrieves a request by Accumulate transaction hash
func (r *RequestRepository) GetRequestByAccumTxHash(ctx context.Context, accumTxHash string) (*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE accumulate_tx_hash = $1
		ORDER BY requested_at DESC
		LIMIT 1`

	request := &ProofRequest{}
	err := r.client.QueryRowContext(ctx, query, accumTxHash).Scan(
		&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
		&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
		&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get request by accum tx hash: %w", err)
	}

	return request, nil
}

// GetPendingRequests retrieves pending requests ordered by priority and time
func (r *RequestRepository) GetPendingRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE status = 'pending'
		ORDER BY
			CASE priority
				WHEN 'urgent' THEN 1
				WHEN 'high' THEN 2
				WHEN 'normal' THEN 3
				WHEN 'low' THEN 4
			END,
			requested_at ASC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending requests: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// GetPendingOnDemandRequests retrieves pending on-demand requests (higher priority)
func (r *RequestRepository) GetPendingOnDemandRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE status = 'pending' AND request_type = 'on_demand'
		ORDER BY
			CASE priority
				WHEN 'urgent' THEN 1
				WHEN 'high' THEN 2
				WHEN 'normal' THEN 3
				WHEN 'low' THEN 4
			END,
			requested_at ASC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query on-demand requests: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// GetPendingOnCadenceRequests retrieves pending on-cadence requests
func (r *RequestRepository) GetPendingOnCadenceRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE status = 'pending' AND request_type = 'on_cadence'
		ORDER BY requested_at ASC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query on-cadence requests: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// GetRequestsByBatch retrieves all requests assigned to a batch
func (r *RequestRepository) GetRequestsByBatch(ctx context.Context, batchID uuid.UUID) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE batch_id = $1
		ORDER BY requested_at ASC`

	rows, err := r.client.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query requests by batch: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// ============================================================================
// STATUS UPDATE OPERATIONS
// ============================================================================

// UpdateRequestStatus updates the status of a request
func (r *RequestRepository) UpdateRequestStatus(ctx context.Context, requestID uuid.UUID, status RequestStatus, errorMsg string) error {
	var query string
	var args []interface{}

	if errorMsg != "" {
		query = `
			UPDATE proof_requests
			SET status = $2, error_message = $3
			WHERE request_id = $1`
		args = []interface{}{requestID, status, errorMsg}
	} else {
		query = `
			UPDATE proof_requests
			SET status = $2
			WHERE request_id = $1`
		args = []interface{}{requestID, status}
	}

	_, err := r.client.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update request status: %w", err)
	}

	return nil
}

// MarkProcessing marks a request as being processed
func (r *RequestRepository) MarkProcessing(ctx context.Context, requestID uuid.UUID) error {
	query := `
		UPDATE proof_requests
		SET status = 'processing', processed_at = $2
		WHERE request_id = $1`

	_, err := r.client.ExecContext(ctx, query, requestID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to mark request processing: %w", err)
	}

	return nil
}

// MarkBatched marks a request as batched and assigns it to a batch
func (r *RequestRepository) MarkBatched(ctx context.Context, requestID uuid.UUID, batchID uuid.UUID) error {
	query := `
		UPDATE proof_requests
		SET status = 'batched', batch_id = $2, processed_at = COALESCE(processed_at, $3)
		WHERE request_id = $1`

	_, err := r.client.ExecContext(ctx, query, requestID, batchID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to mark request batched: %w", err)
	}

	return nil
}

// MarkCompleted marks a request as completed and assigns the proof ID
func (r *RequestRepository) MarkCompleted(ctx context.Context, requestID uuid.UUID, proofID uuid.UUID) error {
	query := `
		UPDATE proof_requests
		SET status = 'completed', proof_id = $2, completed_at = $3
		WHERE request_id = $1`

	_, err := r.client.ExecContext(ctx, query, requestID, proofID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to mark request completed: %w", err)
	}

	return nil
}

// MarkFailed marks a request as failed
func (r *RequestRepository) MarkFailed(ctx context.Context, requestID uuid.UUID, errorMsg string) error {
	query := `
		UPDATE proof_requests
		SET status = 'failed', error_message = $2, retry_count = retry_count + 1
		WHERE request_id = $1`

	_, err := r.client.ExecContext(ctx, query, requestID, errorMsg)
	if err != nil {
		return fmt.Errorf("failed to mark request failed: %w", err)
	}

	return nil
}

// ResetToRetry resets a failed request to pending for retry
func (r *RequestRepository) ResetToRetry(ctx context.Context, requestID uuid.UUID) error {
	query := `
		UPDATE proof_requests
		SET status = 'pending', processed_at = NULL, error_message = NULL
		WHERE request_id = $1 AND status = 'failed'`

	result, err := r.client.ExecContext(ctx, query, requestID)
	if err != nil {
		return fmt.Errorf("failed to reset request: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("request not found or not in failed status")
	}

	return nil
}

// ============================================================================
// QUERY/STATS OPERATIONS
// ============================================================================

// CountPendingRequests returns the number of pending requests
func (r *RequestRepository) CountPendingRequests(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM proof_requests WHERE status = 'pending'`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending requests: %w", err)
	}

	return count, nil
}

// CountPendingByType returns the count of pending requests by type
func (r *RequestRepository) CountPendingByType(ctx context.Context, requestType RequestType) (int64, error) {
	query := `SELECT COUNT(*) FROM proof_requests WHERE status = 'pending' AND request_type = $1`

	var count int64
	err := r.client.QueryRowContext(ctx, query, requestType).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count pending requests by type: %w", err)
	}

	return count, nil
}

// CountByStatus returns the count of requests by status
func (r *RequestRepository) CountByStatus(ctx context.Context, status RequestStatus) (int64, error) {
	query := `SELECT COUNT(*) FROM proof_requests WHERE status = $1`

	var count int64
	err := r.client.QueryRowContext(ctx, query, status).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count requests by status: %w", err)
	}

	return count, nil
}

// GetRecentRequests returns the most recent requests
func (r *RequestRepository) GetRecentRequests(ctx context.Context, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		ORDER BY requested_at DESC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent requests: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// GetFailedRequestsForRetry returns failed requests that can be retried
func (r *RequestRepository) GetFailedRequestsForRetry(ctx context.Context, maxRetries int, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE status = 'failed' AND retry_count < $1
		ORDER BY retry_count ASC, requested_at ASC
		LIMIT $2`

	rows, err := r.client.QueryContext(ctx, query, maxRetries, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed requests: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}

// GetRequestsByRequester returns requests submitted by a specific requester
func (r *RequestRepository) GetRequestsByRequester(ctx context.Context, requesterID string, limit int) ([]*ProofRequest, error) {
	query := `
		SELECT request_id, accumulate_tx_hash, account_url, request_type,
			priority, status, batch_id, proof_id, requested_at,
			processed_at, completed_at, requester_id, error_message, retry_count
		FROM proof_requests
		WHERE requester_id = $1
		ORDER BY requested_at DESC
		LIMIT $2`

	rows, err := r.client.QueryContext(ctx, query, requesterID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query requests by requester: %w", err)
	}
	defer rows.Close()

	var requests []*ProofRequest
	for rows.Next() {
		request := &ProofRequest{}
		err := rows.Scan(
			&request.RequestID, &request.AccumTxHash, &request.AccountURL, &request.RequestType,
			&request.Priority, &request.Status, &request.BatchID, &request.ProofID, &request.RequestedAt,
			&request.ProcessedAt, &request.CompletedAt, &request.RequesterID, &request.ErrorMessage, &request.RetryCount,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan request: %w", err)
		}
		requests = append(requests, request)
	}

	return requests, rows.Err()
}
