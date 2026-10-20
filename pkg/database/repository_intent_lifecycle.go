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

	"github.com/lib/pq"
)

// IntentLifecycleRepository handles database operations for intent lifecycle tracking
type IntentLifecycleRepository struct {
	client *Client
}

// NewIntentLifecycleRepository creates a new intent lifecycle repository
func NewIntentLifecycleRepository(client *Client) *IntentLifecycleRepository {
	return &IntentLifecycleRepository{client: client}
}

// lifecycleSettledStatuses are the states a row has reached on its own and that no later writer may alter: the terminal
// ones, and the ones only member outcomes derive (RB6). It is the set UpdateStatus guards, spelled once more here for the
// discovery fill (RB8-G); it is a SQL list, so it is a constant.
const lifecycleSettledStatuses = `('complete', 'failed', 'executed_proof_pending', 'executed_proof_unavailable', 'refused_pending_attestation')`

// UpdateOption is a functional option for UpdateStatus
type UpdateOption func(*updateOptions)

type updateOptions struct {
	errorMessage *string
	cycleID      *string
	writeBackTx  *string
	failureClass *string
}

// WithFailureClass records why a failed intent failed. Only a transition to failed takes one.
func WithFailureClass(class IntentFailureClass) UpdateOption {
	return func(o *updateOptions) {
		c := string(class)
		o.failureClass = &c
	}
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
// Idempotent: when the intent already has a row the write only FILLS what that row does not know (RB8-G) - a row the
// proof cycle created (EnsureOnProofCycle) has NULL block_height and authorized_at because its request could not say - and
// changes nothing else: never the status, never a row that has reached a state of its own (lifecycleSettledStatuses).
// Sets status=authorized since the validator only sees intents after Accumulate delivery (statusNo=201).
//
// executedBy is the consensus time of the partition block the intent executed in (discovery's BlockTime, RB4-F74). It
// is stored as authorized_at; zero (the block's time unknown) stores NULL. submitted_at is NULL: when the transaction was submitted is not on the chain and not known to a validator
// (RB4-F73). Both used to be the validator's own clock at discovery.
func (r *IntentLifecycleRepository) UpsertOnDiscovery(
	ctx context.Context,
	intentID string,
	txHash string,
	blockHeight int64,
	executedBy time.Time,
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
		ON CONFLICT (intent_id) DO UPDATE SET
		    block_height  = COALESCE(intent_lifecycle.block_height, NULLIF(EXCLUDED.block_height, 0)),
		    authorized_at = COALESCE(intent_lifecycle.authorized_at, EXCLUDED.authorized_at),
		    updated_at    = EXCLUDED.updated_at
		WHERE intent_lifecycle.status NOT IN ` + lifecycleSettledStatuses + `
		  AND ((intent_lifecycle.block_height IS NULL AND NULLIF(EXCLUDED.block_height, 0) IS NOT NULL)
		    OR (intent_lifecycle.authorized_at IS NULL AND EXCLUDED.authorized_at IS NOT NULL))
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
		nil,                       // submitted_at: not known to a validator (RB4-F73)
		executionTime(executedBy), // authorized_at: the partition block it executed in
		now,                       // created_at
		now,                       // updated_at
	)
	if err != nil {
		return fmt.Errorf("upsert intent lifecycle: %w", err)
	}
	return nil
}

// EnsureOnProofCycle creates the lifecycle row of an intent whose proof cycle has started without one (RB8-F, defect
// D4: discovery's write had failed). It writes what the proof cycle's own request carries and nothing it does not:
// the Accumulate transaction hash is required (the column is NOT NULL and a hash is never invented), the DN block
// height is stored only when the request knows it (NULL, not 0, otherwise), and authorized_at is NULL because the
// partition block's time is not in the request; the row is single-leg shaped (leg_count 1, no target_chains) because the
// request does not say otherwise. It is idempotent (ON CONFLICT DO NOTHING: a row discovery wrote is never altered by it)
// and reports whether this call created the row. Discovery's later write fills the unknowns (UpsertOnDiscovery*, RB8-G).
func (r *IntentLifecycleRepository) EnsureOnProofCycle(
	ctx context.Context,
	intentID string,
	txHash string,
	userID string,
	proofClass string,
	targetChain string,
	blockHeight int64,
) (bool, error) {
	if intentID == "" {
		return false, fmt.Errorf("ensure intent lifecycle: no intent id")
	}
	if txHash == "" {
		return false, fmt.Errorf("ensure intent lifecycle: intent %s: the proof cycle names no Accumulate transaction, so its row cannot be created without inventing one", intentID)
	}
	now := time.Now().UTC()
	var userIDPtr, proofClassPtr, targetChainPtr *string
	if userID != "" {
		userIDPtr = &userID
	}
	if proofClass != "" {
		proofClassPtr = &proofClass
	}
	if targetChain != "" {
		targetChainPtr = &targetChain
	}
	var heightPtr *int64
	if blockHeight > 0 {
		heightPtr = &blockHeight
	}
	res, err := r.client.db.ExecContext(ctx, `
		INSERT INTO intent_lifecycle (
			intent_id, accum_tx_hash, block_height, user_id, proof_class, target_chain,
			status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (intent_id) DO NOTHING
	`, intentID, txHash, heightPtr, userIDPtr, proofClassPtr, targetChainPtr, string(IntentLifecycleAuthorized), now, now)
	if err != nil {
		return false, fmt.Errorf("ensure intent lifecycle: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("ensure intent lifecycle: %w", err)
	}
	return n == 1, nil
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

	if options.failureClass != nil && newStatus != IntentLifecycleFailed {
		return fmt.Errorf("update intent lifecycle: a failure class (%s) is recorded only on failed, not %s", *options.failureClass, newStatus)
	}
	if newStatus == IntentLifecycleFailed && options.failureClass == nil {
		return fmt.Errorf("update intent lifecycle: %s fails without a failure class; say why (RB4-F13)", intentID)
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
	case IntentLifecycleSettling:
		// STAGE 1. Its own column, not a reuse of in_process_at: the gap between
		// "the proof cycle started" and "the chain write is still unresolved" is
		// the measurement this stage exists to make visible, and it is invisible if
		// both write the same timestamp. Added by migration 014.
		timestampCol = "settling_at"
	case IntentLifecycleComplete:
		timestampCol = "completed_at"
	case IntentLifecycleFailed:
		timestampCol = "failed_at"
	}

	// Build query: update status + phase timestamp + optional fields.
	// Guard: don't overwrite terminal states, nor the states only member outcomes derive (RB6): an intent whose action
	// executed with its proof owed, or whose refusal awaits attestation, moves on only through RecordMemberOutcome.
	//
	// The phase-timestamp clause is CONDITIONAL. Not every status has a column —
	// pending_signatures never did — and a status without one used to interpolate
	// an empty name straight into the SET list, producing `updated_at = $2, = $3`
	// and a syntax error at execution rather than at compile time. It has been
	// latent only because the statuses in use all happened to have a column;
	// adding one that does not would have surfaced it in production.
	var query string
	var args []interface{}
	if timestampCol != "" {
		query = fmt.Sprintf(`
		UPDATE intent_lifecycle
		SET status = $1,
		    updated_at = $2,
		    %s = $3,
		    error_message = COALESCE($4, error_message),
		    cycle_id = COALESCE($5, cycle_id),
		    write_back_tx = COALESCE($6, write_back_tx),
		    failure_class = $8
		WHERE intent_id = $7
		  AND status NOT IN ('complete', 'failed', 'executed_proof_pending', 'executed_proof_unavailable', 'refused_pending_attestation')
	`, timestampCol)
		args = []interface{}{
			string(newStatus), now, now,
			options.errorMessage, options.cycleID, options.writeBackTx, intentID, options.failureClass,
		}
	} else {
		query = `
		UPDATE intent_lifecycle
		SET status = $1,
		    updated_at = $2,
		    error_message = COALESCE($3, error_message),
		    cycle_id = COALESCE($4, cycle_id),
		    write_back_tx = COALESCE($5, write_back_tx),
		    failure_class = $7
		WHERE intent_id = $6
		  AND status NOT IN ('complete', 'failed', 'executed_proof_pending', 'executed_proof_unavailable', 'refused_pending_attestation')
	`
		args = []interface{}{
			string(newStatus), now,
			options.errorMessage, options.cycleID, options.writeBackTx, intentID, options.failureClass,
		}
	}

	result, err := r.client.db.ExecContext(ctx, query, args...)
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
		       target_chains, leg_count, execution_mode, legs_completed, legs_failed,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at, failure_class
		FROM intent_lifecycle
		WHERE intent_id = $1
	`

	lc := &IntentLifecycle{}
	err := r.client.db.QueryRowContext(ctx, query, intentID).Scan(
		&lc.ID, &lc.IntentID, &lc.AccumTxHash, &lc.UserID, &lc.Status,
		&lc.TargetChain, &lc.ProofClass, &lc.ErrorMessage, &lc.BlockHeight,
		&lc.CycleID, &lc.WriteBackTx,
		&lc.TargetChains, &lc.LegCount, &lc.ExecutionMode, &lc.LegsCompleted, &lc.LegsFailed,
		&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
		&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt, &lc.FailureClass,
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
		       target_chains, leg_count, execution_mode, legs_completed, legs_failed,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at, failure_class
		FROM intent_lifecycle
		WHERE accum_tx_hash = $1
	`

	lc := &IntentLifecycle{}
	err := r.client.db.QueryRowContext(ctx, query, TransactionHashKey(txHash)).Scan(
		&lc.ID, &lc.IntentID, &lc.AccumTxHash, &lc.UserID, &lc.Status,
		&lc.TargetChain, &lc.ProofClass, &lc.ErrorMessage, &lc.BlockHeight,
		&lc.CycleID, &lc.WriteBackTx,
		&lc.TargetChains, &lc.LegCount, &lc.ExecutionMode, &lc.LegsCompleted, &lc.LegsFailed,
		&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
		&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt, &lc.FailureClass,
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
		       target_chains, leg_count, execution_mode, legs_completed, legs_failed,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at, failure_class
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
		       target_chains, leg_count, execution_mode, legs_completed, legs_failed,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at, failure_class
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
		SELECT DISTINCT ON (il.intent_id)
		       il.id, il.intent_id, il.accum_tx_hash, il.user_id, il.status,
		       il.target_chain, il.proof_class, il.error_message, il.block_height,
		       il.cycle_id, il.write_back_tx,
		       il.target_chains, il.leg_count, il.execution_mode, il.legs_completed, il.legs_failed,
		       il.created_at, il.updated_at, il.submitted_at, il.authorized_at,
		       il.in_process_at, il.completed_at, il.failed_at, il.failure_class,
		       bt.from_chain, bt.to_chain, bt.from_address, bt.to_address,
		       bt.amount, bt.token_symbol, bt.account_url
		FROM intent_lifecycle il
		LEFT JOIN batch_transactions bt ON bt.intent_id = il.intent_id
		ORDER BY il.intent_id, il.created_at DESC
	`

	wrappedQuery := fmt.Sprintf(`SELECT * FROM (%s) sub ORDER BY created_at DESC LIMIT $1`, query)
	return r.scanEnrichedRows(ctx, wrappedQuery, limit)
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
		SELECT DISTINCT ON (il.intent_id)
		       il.id, il.intent_id, il.accum_tx_hash, il.user_id, il.status,
		       il.target_chain, il.proof_class, il.error_message, il.block_height,
		       il.cycle_id, il.write_back_tx,
		       il.target_chains, il.leg_count, il.execution_mode, il.legs_completed, il.legs_failed,
		       il.created_at, il.updated_at, il.submitted_at, il.authorized_at,
		       il.in_process_at, il.completed_at, il.failed_at, il.failure_class,
		       bt.from_chain, bt.to_chain, bt.from_address, bt.to_address,
		       bt.amount, bt.token_symbol, bt.account_url
		FROM intent_lifecycle il
		LEFT JOIN batch_transactions bt ON bt.intent_id = il.intent_id
		WHERE il.user_id = $1
		ORDER BY il.intent_id, il.created_at DESC
	`

	wrappedQuery := fmt.Sprintf(`SELECT * FROM (%s) sub ORDER BY created_at DESC LIMIT $2`, query)
	return r.scanEnrichedRows(ctx, wrappedQuery, userID, limit)
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
			&e.TargetChains, &e.LegCount, &e.ExecutionMode, &e.LegsCompleted, &e.LegsFailed,
			&e.CreatedAt, &e.UpdatedAt, &e.SubmittedAt, &e.AuthorizedAt,
			&e.InProcessAt, &e.CompletedAt, &e.FailedAt, &e.FailureClass,
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
		       target_chains, leg_count, execution_mode, legs_completed, legs_failed,
		       created_at, updated_at, submitted_at, authorized_at,
		       in_process_at, completed_at, failed_at, failure_class
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
			&lc.TargetChains, &lc.LegCount, &lc.ExecutionMode, &lc.LegsCompleted, &lc.LegsFailed,
			&lc.CreatedAt, &lc.UpdatedAt, &lc.SubmittedAt, &lc.AuthorizedAt,
			&lc.InProcessAt, &lc.CompletedAt, &lc.FailedAt, &lc.FailureClass,
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

// UpsertOnDiscoveryMultiLeg inserts a new lifecycle record for a multi-leg intent.
// Like UpsertOnDiscovery it is idempotent and, on an existing row, only fills (RB8-G): block_height and authorized_at when
// the row has none, and the multi-leg shape (target_chains, leg_count, execution_mode) only when the row is still in the
// single-leg shape the proof cycle gives the row it creates (target_chains NULL and leg_count 1). A shape discovery already
// wrote is never replaced, and neither is the status or any settled row.
// The targetChains slice and legCount capture multi-chain routing information.
func (r *IntentLifecycleRepository) UpsertOnDiscoveryMultiLeg(
	ctx context.Context,
	intentID string,
	txHash string,
	blockHeight int64,
	executedBy time.Time,
	userID string,
	proofClass string,
	targetChain string,
	targetChains []string,
	legCount int,
	executionMode string,
) error {
	now := time.Now().UTC()

	query := `
		INSERT INTO intent_lifecycle (
			intent_id, accum_tx_hash, block_height, user_id, proof_class, target_chain,
			target_chains, leg_count, execution_mode, legs_completed, legs_failed,
			status, submitted_at, authorized_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT (intent_id) DO UPDATE SET
		    block_height   = COALESCE(intent_lifecycle.block_height, NULLIF(EXCLUDED.block_height, 0)),
		    authorized_at  = COALESCE(intent_lifecycle.authorized_at, EXCLUDED.authorized_at),
		    target_chains  = CASE WHEN intent_lifecycle.target_chains IS NULL AND COALESCE(intent_lifecycle.leg_count, 1) = 1
		                          THEN EXCLUDED.target_chains ELSE intent_lifecycle.target_chains END,
		    leg_count      = CASE WHEN intent_lifecycle.target_chains IS NULL AND COALESCE(intent_lifecycle.leg_count, 1) = 1
		                          THEN EXCLUDED.leg_count ELSE intent_lifecycle.leg_count END,
		    execution_mode = CASE WHEN intent_lifecycle.target_chains IS NULL AND COALESCE(intent_lifecycle.leg_count, 1) = 1
		                          THEN EXCLUDED.execution_mode ELSE intent_lifecycle.execution_mode END,
		    updated_at     = EXCLUDED.updated_at
		WHERE intent_lifecycle.status NOT IN ` + lifecycleSettledStatuses + `
		  AND ((intent_lifecycle.block_height IS NULL AND NULLIF(EXCLUDED.block_height, 0) IS NOT NULL)
		    OR (intent_lifecycle.authorized_at IS NULL AND EXCLUDED.authorized_at IS NOT NULL)
		    OR (intent_lifecycle.target_chains IS NULL AND COALESCE(intent_lifecycle.leg_count, 1) = 1
		        AND EXCLUDED.target_chains IS NOT NULL))
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
	var executionModePtr *string
	if executionMode != "" {
		executionModePtr = &executionMode
	}

	_, err := r.client.db.ExecContext(ctx, query,
		intentID,
		txHash,
		blockHeight,
		userIDPtr,
		proofClassPtr,
		targetChainPtr,
		pq.StringArray(targetChains),
		legCount,
		executionModePtr,
		0, // legs_completed
		0, // legs_failed
		string(IntentLifecycleAuthorized),
		nil,                       // submitted_at: not known to a validator (RB4-F73)
		executionTime(executedBy), // authorized_at: the partition block it executed in
		now,                       // created_at
		now,                       // updated_at
	)
	if err != nil {
		return fmt.Errorf("upsert multi-leg intent lifecycle: %w", err)
	}
	return nil
}

// executionTime is an execution block time as stored: NULL when it is unknown, never the validator's clock.
func executionTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
