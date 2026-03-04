// Copyright 2025 Certen Protocol
//
// Intent Lifecycle Repository
// Provides CRUD operations for unified intent lifecycle status tracking

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// IntentLifecycleRepository handles database operations for intent lifecycle tracking
type IntentLifecycleRepository struct {
	client *Client
}

// NewIntentLifecycleRepository creates a new intent lifecycle repository
func NewIntentLifecycleRepository(client *Client) *IntentLifecycleRepository {
	return &IntentLifecycleRepository{client: client}
}

// UpdateOption is a functional option for UpdateStatus
type UpdateOption func(*updateOptions)

type updateOptions struct {
	errorMessage *string
	cycleID      *string
	writeBackTx  *string
}

// WithErrorMessage sets the error message on status update
func WithErrorMessage(msg string) UpdateOption {
	return func(o *updateOptions) {
		o.errorMessage = &msg
	}
}

// WithCycleID sets the cycle ID on status update
func WithCycleID(cycleID string) UpdateOption {
	return func(o *updateOptions) {
		o.cycleID = &cycleID
	}
}

// WithWriteBackTx sets the write-back transaction hash on status update
func WithWriteBackTx(txHash string) UpdateOption {
	return func(o *updateOptions) {
		o.writeBackTx = &txHash
	}
}

// UpsertOnDiscovery inserts a new lifecycle record when the validator first discovers an intent.
// Uses INSERT ON CONFLICT DO NOTHING to be idempotent — if the intent already exists, this is a no-op.
// Sets status=authorized since the validator only sees intents after Accumulate delivery (statusNo=201).
func (r *IntentLifecycleRepository) UpsertOnDiscovery(
	ctx context.Context,
	intentID string,
	txHash string,
	blockHeight int64,
	userID string,
	proofClass string,
	targetChain string,
) error {
	now := time.Now().UTC()

	query := `
		INSERT INTO intent_lifecycle (
			intent_id, accum_tx_hash, block_height, user_id, proof_class, target_chain,
			status, submitted_at, authorized_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (intent_id) DO NOTHING
	`

	var userIDPtr *string
	if userID != "" {
		userIDPtr = &userID
	}
	var proofClassPtr *string
	if proofClass != "" {
		proofClassPtr = &proofClass
	}
	var targetChainPtr *string
	if targetChain != "" {
		targetChainPtr = &targetChain
	}

	_, err := r.client.db.ExecContext(ctx, query,
		intentID,
		txHash,
		blockHeight,
		userIDPtr,
		proofClassPtr,
		targetChainPtr,
		string(IntentLifecycleAuthorized),
		now, // submitted_at
		now, // authorized_at
		now, // created_at
		now, // updated_at
	)
	if err != nil {
		return fmt.Errorf("upsert intent lifecycle: %w", err)
	}
	return nil
}

// UpdateStatus transitions an intent to a new lifecycle status.
// Guards against overwriting terminal states (complete, failed).
func (r *IntentLifecycleRepository) UpdateStatus(
	ctx context.Context,
	intentID string,
	newStatus IntentLifecycleStatus,
	opts ...UpdateOption,
) error {
	options := &updateOptions{}
	for _, opt := range opts {
		opt(options)
	}

	now := time.Now().UTC()

	// Build the SET clause dynamically based on the target status
	timestampCol := ""
	switch newStatus {
	case IntentLifecycleSubmitted:
		timestampCol = "submitted_at"
	case IntentLifecycleAuthorized:
		timestampCol = "authorized_at"
	case IntentLifecycleInProcess:
		timestampCol = "in_process_at"
	case IntentLifecycleComplete:
		timestampCol = "completed_at"
	case IntentLifecycleFailed:
		timestampCol = "failed_at"
	}

	// Build query: update status + phase timestamp + optional fields
	// Guard: don't overwrite terminal states
	query := fmt.Sprintf(`
		UPDATE intent_lifecycle
		SET status = $1,
		    updated_at = $2,
		    %s = $3,
		    error_message = COALESCE($4, error_message),
		    cycle_id = COALESCE($5, cycle_id),
		    write_back_tx = COALESCE($6, write_back_tx)
		WHERE intent_id = $7
		  AND status NOT IN ('complete', 'failed')
	`, timestampCol)

	result, err := r.client.db.ExecContext(ctx, query,
		string(newStatus),
		now,
		now,
		options.errorMessage,
		options.cycleID,
		options.writeBackTx,
		intentID,
	)
	if err != nil {
		return fmt.Errorf("update intent lifecycle status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// Either the intent doesn't exist or it's already in a terminal state
		_, getErr := r.GetByIntentID(ctx, intentID)
		if getErr != nil {
			return ErrIntentLifecycleNotFound
		}
		// Intent exists but is in a terminal state — not an error, just a no-op
		return nil
	}

	return nil
}

// GetByIntentID retrieves a lifecycle record by intent ID
func (r *IntentLifecycleRepository) GetByIntentID(ctx context.Context, intentID string) (*IntentLifecycle, error) {
	query := `
		SELECT id, intent_id, accum_tx_hash, user_id, status, target_chain, proof_class,
		       error_message, block_height, cycle_id, write_back_tx,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at
		FROM intent_lifecycle
		WHERE intent_id = $1
	`

	lc := &IntentLifecycle{}
	err := r.client.db.QueryRowContext(ctx, query, intentID).Scan(
		&lc.ID, &lc.IntentID, &lc.AccumTxHash, &lc.UserID, &lc.Status,
		&lc.TargetChain, &lc.ProofClass, &lc.ErrorMessage, &lc.BlockHeight,
		&lc.CycleID, &lc.WriteBackTx,
		&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
		&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrIntentLifecycleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get intent lifecycle by id: %w", err)
	}
	return lc, nil
}

// GetByTxHash retrieves a lifecycle record by Accumulate transaction hash
func (r *IntentLifecycleRepository) GetByTxHash(ctx context.Context, txHash string) (*IntentLifecycle, error) {
	query := `
		SELECT id, intent_id, accum_tx_hash, user_id, status, target_chain, proof_class,
		       error_message, block_height, cycle_id, write_back_tx,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at
		FROM intent_lifecycle
		WHERE accum_tx_hash = $1
	`

	lc := &IntentLifecycle{}
	err := r.client.db.QueryRowContext(ctx, query, txHash).Scan(
		&lc.ID, &lc.IntentID, &lc.AccumTxHash, &lc.UserID, &lc.Status,
		&lc.TargetChain, &lc.ProofClass, &lc.ErrorMessage, &lc.BlockHeight,
		&lc.CycleID, &lc.WriteBackTx,
		&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
		&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrIntentLifecycleNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get intent lifecycle by tx hash: %w", err)
	}
	return lc, nil
}

// ListByStatus returns lifecycle records filtered by status, ordered by created_at DESC
func (r *IntentLifecycleRepository) ListByStatus(ctx context.Context, status IntentLifecycleStatus, limit int) ([]*IntentLifecycle, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT id, intent_id, accum_tx_hash, user_id, status, target_chain, proof_class,
		       error_message, block_height, cycle_id, write_back_tx,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at
		FROM intent_lifecycle
		WHERE status = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	return r.scanRows(ctx, query, string(status), limit)
}

// ListByUser returns lifecycle records for a specific user, ordered by created_at DESC
func (r *IntentLifecycleRepository) ListByUser(ctx context.Context, userID string, limit int) ([]*IntentLifecycle, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT id, intent_id, accum_tx_hash, user_id, status, target_chain, proof_class,
		       error_message, block_height, cycle_id, write_back_tx,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at
		FROM intent_lifecycle
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	return r.scanRows(ctx, query, userID, limit)
}

// ListRecentEnriched returns recent lifecycle records joined with batch_transactions for UI display
func (r *IntentLifecycleRepository) ListRecentEnriched(ctx context.Context, limit int) ([]*IntentLifecycleEnriched, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT il.id, il.intent_id, il.accum_tx_hash, il.user_id, il.status,
		       il.target_chain, il.proof_class, il.error_message, il.block_height,
		       il.cycle_id, il.write_back_tx,
		       il.created_at, il.updated_at, il.submitted_at, il.authorized_at,
		       il.in_process_at, il.completed_at, il.failed_at,
		       bt.from_chain, bt.to_chain, bt.from_address, bt.to_address,
		       bt.amount, bt.token_symbol, bt.account_url
		FROM intent_lifecycle il
		LEFT JOIN batch_transactions bt ON bt.intent_id = il.intent_id
		ORDER BY il.created_at DESC
		LIMIT $1
	`

	return r.scanEnrichedRows(ctx, query, limit)
}

// ListByUserEnriched returns lifecycle records for a user joined with batch_transactions
func (r *IntentLifecycleRepository) ListByUserEnriched(ctx context.Context, userID string, limit int) ([]*IntentLifecycleEnriched, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT il.id, il.intent_id, il.accum_tx_hash, il.user_id, il.status,
		       il.target_chain, il.proof_class, il.error_message, il.block_height,
		       il.cycle_id, il.write_back_tx,
		       il.created_at, il.updated_at, il.submitted_at, il.authorized_at,
		       il.in_process_at, il.completed_at, il.failed_at,
		       bt.from_chain, bt.to_chain, bt.from_address, bt.to_address,
		       bt.amount, bt.token_symbol, bt.account_url
		FROM intent_lifecycle il
		LEFT JOIN batch_transactions bt ON bt.intent_id = il.intent_id
		WHERE il.user_id = $1
		ORDER BY il.created_at DESC
		LIMIT $2
	`

	return r.scanEnrichedRows(ctx, query, userID, limit)
}

// scanEnrichedRows scans rows from a joined lifecycle + batch_transactions query
func (r *IntentLifecycleRepository) scanEnrichedRows(ctx context.Context, query string, args ...interface{}) ([]*IntentLifecycleEnriched, error) {
	rows, err := r.client.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query enriched intent lifecycles: %w", err)
	}
	defer rows.Close()

	var results []*IntentLifecycleEnriched
	for rows.Next() {
		e := &IntentLifecycleEnriched{}
		if err := rows.Scan(
			&e.ID, &e.IntentID, &e.AccumTxHash, &e.UserID, &e.Status,
			&e.TargetChain, &e.ProofClass, &e.ErrorMessage, &e.BlockHeight,
			&e.CycleID, &e.WriteBackTx,
			&e.CreatedAt, &e.UpdatedAt, &e.SubmittedAt, &e.AuthorizedAt,
			&e.InProcessAt, &e.CompletedAt, &e.FailedAt,
			&e.FromChain, &e.ToChain, &e.FromAddress, &e.ToAddress,
			&e.Amount, &e.TokenSymbol, &e.AccountURL,
		); err != nil {
			return nil, fmt.Errorf("scan enriched intent lifecycle row: %w", err)
		}
		results = append(results, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate enriched intent lifecycle rows: %w", err)
	}

	return results, nil
}

// ListRecent returns the most recent lifecycle records regardless of user, ordered by created_at DESC
func (r *IntentLifecycleRepository) ListRecent(ctx context.Context, limit int) ([]*IntentLifecycle, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT id, intent_id, accum_tx_hash, user_id, status, target_chain, proof_class,
		       error_message, block_height, cycle_id, write_back_tx,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at
		FROM intent_lifecycle
		ORDER BY created_at DESC
		LIMIT $1
	`

	return r.scanRows(ctx, query, limit)
}

// scanRows is a helper that scans multiple lifecycle rows from a query result
func (r *IntentLifecycleRepository) scanRows(ctx context.Context, query string, args ...interface{}) ([]*IntentLifecycle, error) {
	rows, err := r.client.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query intent lifecycles: %w", err)
	}
	defer rows.Close()

	var results []*IntentLifecycle
	for rows.Next() {
		lc := &IntentLifecycle{}
		if err := rows.Scan(
			&lc.ID, &lc.IntentID, &lc.AccumTxHash, &lc.UserID, &lc.Status,
			&lc.TargetChain, &lc.ProofClass, &lc.ErrorMessage, &lc.BlockHeight,
			&lc.CycleID, &lc.WriteBackTx,
			&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
			&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt,
		); err != nil {
			return nil, fmt.Errorf("scan intent lifecycle row: %w", err)
		}
		results = append(results, lc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate intent lifecycle rows: %w", err)
	}

	return results, nil
}
