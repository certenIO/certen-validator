// Copyright 2025 Certen Protocol
//
// Batch Repository - CRUD operations for anchor batches and batch transactions

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BatchRepository handles anchor batch operations
type BatchRepository struct {
	client *Client
}

// NewBatchRepository creates a new batch repository
func NewBatchRepository(client *Client) *BatchRepository {
	return &BatchRepository{client: client}
}

// ============================================================================
// ANCHOR BATCH OPERATIONS
// ============================================================================

// CreateBatch creates a new anchor batch
func (r *BatchRepository) CreateBatch(ctx context.Context, input *NewAnchorBatch) (*AnchorBatch, error) {
	batch := &AnchorBatch{
		BatchID:     uuid.New(),
		BatchType:   input.BatchType,
		MerkleRoot:  make([]byte, 32), // Empty initially, filled when batch is closed
		TxCount:     0,
		StartTime:   time.Now(),
		ValidatorID: input.ValidatorID,
		Status:      BatchStatusPending,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `
		INSERT INTO anchor_batches (
			id, batch_type, merkle_root, transaction_count,
			batch_start_time, validator_id, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`

	err := r.client.QueryRowContext(ctx, query,
		batch.BatchID, batch.BatchType, batch.MerkleRoot, batch.TxCount,
		batch.StartTime, batch.ValidatorID, batch.Status, batch.CreatedAt, batch.UpdatedAt,
	).Scan(&batch.BatchID, &batch.CreatedAt, &batch.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create batch: %w", err)
	}

	return batch, nil
}

// GetBatch retrieves a batch by ID
func (r *BatchRepository) GetBatch(ctx context.Context, batchID uuid.UUID) (*AnchorBatch, error) {
	query := `
		SELECT id, batch_type, merkle_root, transaction_count,
			batch_start_time, batch_end_time, accumulate_block_height,
			accumulate_block_hash, validator_id, status, error_message,
			created_at, updated_at
		FROM anchor_batches
		WHERE id = $1`

	batch := &AnchorBatch{}
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(
		&batch.BatchID, &batch.BatchType, &batch.MerkleRoot, &batch.TxCount,
		&batch.StartTime, &batch.EndTime, &batch.AccumHeight,
		&batch.AccumHash, &batch.ValidatorID, &batch.Status, &batch.ErrorMessage,
		&batch.CreatedAt, &batch.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrBatchNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get batch: %w", err)
	}

	return batch, nil
}

// GetPendingBatch returns the current open batch for the validator (if any)
func (r *BatchRepository) GetPendingBatch(ctx context.Context, validatorID string, batchType BatchType) (*AnchorBatch, error) {
	query := `
		SELECT id, batch_type, merkle_root, transaction_count,
			batch_start_time, batch_end_time, accumulate_block_height,
			accumulate_block_hash, validator_id, status, error_message,
			created_at, updated_at
		FROM anchor_batches
		WHERE validator_id = $1 AND batch_type = $2 AND status = 'pending'
		ORDER BY created_at DESC
		LIMIT 1`

	batch := &AnchorBatch{}
	err := r.client.QueryRowContext(ctx, query, validatorID, batchType).Scan(
		&batch.BatchID, &batch.BatchType, &batch.MerkleRoot, &batch.TxCount,
		&batch.StartTime, &batch.EndTime, &batch.AccumHeight,
		&batch.AccumHash, &batch.ValidatorID, &batch.Status, &batch.ErrorMessage,
		&batch.CreatedAt, &batch.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrBatchNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get pending batch: %w", err)
	}

	return batch, nil
}

// GetBatchesReadyForAnchoring returns batches that are closed and ready to be anchored
func (r *BatchRepository) GetBatchesReadyForAnchoring(ctx context.Context) ([]*AnchorBatch, error) {
	query := `
		SELECT id, batch_type, merkle_root, transaction_count,
			batch_start_time, batch_end_time, accumulate_block_height,
			accumulate_block_hash, validator_id, status, error_message,
			created_at, updated_at
		FROM anchor_batches
		WHERE status = 'closed'
		ORDER BY created_at ASC`

	rows, err := r.client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query batches: %w", err)
	}
	defer rows.Close()

	var batches []*AnchorBatch
	for rows.Next() {
		batch := &AnchorBatch{}
		err := rows.Scan(
			&batch.BatchID, &batch.BatchType, &batch.MerkleRoot, &batch.TxCount,
			&batch.StartTime, &batch.EndTime, &batch.AccumHeight,
			&batch.AccumHash, &batch.ValidatorID, &batch.Status, &batch.ErrorMessage,
			&batch.CreatedAt, &batch.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch: %w", err)
		}
		batches = append(batches, batch)
	}

	return batches, rows.Err()
}

// CloseBatch closes a batch with the computed merkle root
func (r *BatchRepository) CloseBatch(ctx context.Context, batchID uuid.UUID, merkleRoot []byte, accumHeight int64, accumHash string) error {
	query := `
		UPDATE anchor_batches
		SET status = 'closed',
			merkle_root = $2,
			batch_end_time = $3,
			accumulate_block_height = $4,
			accumulate_block_hash = $5,
			updated_at = $6
		WHERE id = $1 AND status = 'pending'`

	result, err := r.client.ExecContext(ctx, query,
		batchID, merkleRoot, time.Now(), accumHeight, accumHash, time.Now())
	if err != nil {
		return fmt.Errorf("failed to close batch: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("batch not found or not in pending status")
	}

	return nil
}

// UpdateBatchStatus updates the batch status
func (r *BatchRepository) UpdateBatchStatus(ctx context.Context, batchID uuid.UUID, status BatchStatus, errorMsg string) error {
	var query string
	var args []interface{}

	if errorMsg != "" {
		query = `
			UPDATE anchor_batches
			SET status = $2, error_message = $3, updated_at = $4
			WHERE id = $1`
		args = []interface{}{batchID, status, errorMsg, time.Now()}
	} else {
		query = `
			UPDATE anchor_batches
			SET status = $2, updated_at = $3
			WHERE id = $1`
		args = []interface{}{batchID, status, time.Now()}
	}

	_, err := r.client.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update batch status: %w", err)
	}

	return nil
}

// IncrementTxCount increments the transaction count for a batch
func (r *BatchRepository) IncrementTxCount(ctx context.Context, batchID uuid.UUID) error {
	query := `
		UPDATE anchor_batches
		SET transaction_count = transaction_count + 1, updated_at = $2
		WHERE id = $1`

	_, err := r.client.ExecContext(ctx, query, batchID, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment tx count: %w", err)
	}

	return nil
}

// UpdateBatchPhase5 updates the Phase 5 consensus fields after quorum is reached
func (r *BatchRepository) UpdateBatchPhase5(ctx context.Context, batchID uuid.UUID, update *BatchPhase5Update) error {
	query := `
		UPDATE anchor_batches
		SET bpt_root = COALESCE($2, bpt_root),
			governance_root = COALESCE($3, governance_root),
			proof_data_included = $4,
			attestation_count = $5,
			aggregated_signature = COALESCE($6, aggregated_signature),
			aggregated_public_key = COALESCE($7, aggregated_public_key),
			quorum_reached = $8,
			consensus_completed_at = $9,
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.client.ExecContext(ctx, query,
		batchID,
		update.BPTRoot,
		update.GovernanceRoot,
		update.ProofDataIncluded,
		update.AttestationCount,
		update.AggregatedSignature,
		update.AggregatedPublicKey,
		update.QuorumReached,
		update.ConsensusCompletedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update batch Phase 5 fields: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("batch not found: %s", batchID)
	}

	return nil
}

// ============================================================================
// BATCH TRANSACTION OPERATIONS
// ============================================================================

// AddTransaction adds a transaction to a batch
func (r *BatchRepository) AddTransaction(ctx context.Context, input *NewBatchTransaction) (*BatchTransaction, error) {
	// Serialize merkle path
	merklePathJSON, err := json.Marshal(input.MerklePath)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize merkle path: %w", err)
	}

	// Build UserID and IntentID null strings
	var userID, intentID sql.NullString
	if input.UserID != nil {
		userID = sql.NullString{String: *input.UserID, Valid: true}
	}
	if input.IntentID != nil {
		intentID = sql.NullString{String: *input.IntentID, Valid: true}
	}

	tx := &BatchTransaction{
		BatchID:      input.BatchID,
		AccumTxHash:  input.AccumTxHash,
		AccountURL:   input.AccountURL,
		TreeIndex:    input.TreeIndex,
		MerklePath:   merklePathJSON,
		TxHash:       input.TxHash,
		ChainedProof: input.ChainedProof,
		ChainedValid: input.ChainedProof != nil,
		GovProof:     input.GovProof,
		GovLevel:     sql.NullString{String: string(input.GovLevel), Valid: input.GovLevel != ""},
		GovValid:     input.GovProof != nil,
		IntentType:   sql.NullString{String: input.IntentType, Valid: input.IntentType != ""},
		IntentData:   input.IntentData,
		CreatedAt:    time.Now(),
		UserID:       userID,
		IntentID:     intentID,
	}

	query := `
		INSERT INTO batch_transactions (
			batch_id, accumulate_tx_hash, account_url, tree_index,
			merkle_path, transaction_hash, chained_proof, chained_proof_valid,
			governance_proof, governance_level, governance_valid,
			intent_type, intent_data, user_id, intent_id, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, created_at`

	err = r.client.QueryRowContext(ctx, query,
		tx.BatchID, tx.AccumTxHash, tx.AccountURL, tx.TreeIndex,
		tx.MerklePath, tx.TxHash, tx.ChainedProof, tx.ChainedValid,
		tx.GovProof, tx.GovLevel, tx.GovValid,
		tx.IntentType, tx.IntentData, tx.UserID, tx.IntentID, tx.CreatedAt,
	).Scan(&tx.ID, &tx.CreatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to add transaction: %w", err)
	}

	// Increment the batch transaction count
	if err := r.IncrementTxCount(ctx, input.BatchID); err != nil {
		return nil, fmt.Errorf("failed to increment batch tx count: %w", err)
	}

	return tx, nil
}

// GetTransaction retrieves a transaction by ID
func (r *BatchRepository) GetTransaction(ctx context.Context, txID int64) (*BatchTransaction, error) {
	query := `
		SELECT id, batch_id, accumulate_tx_hash, account_url, tree_index,
			merkle_path, transaction_hash, chained_proof, chained_proof_valid,
			governance_proof, governance_level, governance_valid,
			intent_type, intent_data, created_at
		FROM batch_transactions
		WHERE id = $1`

	tx := &BatchTransaction{}
	err := r.client.QueryRowContext(ctx, query, txID).Scan(
		&tx.ID, &tx.BatchID, &tx.AccumTxHash, &tx.AccountURL, &tx.TreeIndex,
		&tx.MerklePath, &tx.TxHash, &tx.ChainedProof, &tx.ChainedValid,
		&tx.GovProof, &tx.GovLevel, &tx.GovValid,
		&tx.IntentType, &tx.IntentData, &tx.CreatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrTransactionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return tx, nil
}

// GetTransactionByAccumHash retrieves a transaction by Accumulate tx hash
func (r *BatchRepository) GetTransactionByAccumHash(ctx context.Context, accumTxHash string) (*BatchTransaction, error) {
	query := `
		SELECT id, batch_id, accumulate_tx_hash, account_url, tree_index,
			merkle_path, transaction_hash, chained_proof, chained_proof_valid,
			governance_proof, governance_level, governance_valid,
			intent_type, intent_data, created_at
		FROM batch_transactions
		WHERE accumulate_tx_hash = $1
		ORDER BY created_at DESC
		LIMIT 1`

	tx := &BatchTransaction{}
	err := r.client.QueryRowContext(ctx, query, accumTxHash).Scan(
		&tx.ID, &tx.BatchID, &tx.AccumTxHash, &tx.AccountURL, &tx.TreeIndex,
		&tx.MerklePath, &tx.TxHash, &tx.ChainedProof, &tx.ChainedValid,
		&tx.GovProof, &tx.GovLevel, &tx.GovValid,
		&tx.IntentType, &tx.IntentData, &tx.CreatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrTransactionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return tx, nil
}

// GetTransactionsInBatch retrieves all transactions in a batch
func (r *BatchRepository) GetTransactionsInBatch(ctx context.Context, batchID uuid.UUID) ([]*BatchTransaction, error) {
	query := `
		SELECT id, batch_id, accumulate_tx_hash, account_url, tree_index,
			merkle_path, transaction_hash, chained_proof, chained_proof_valid,
			governance_proof, governance_level, governance_valid,
			intent_type, intent_data, created_at
		FROM batch_transactions
		WHERE batch_id = $1
		ORDER BY tree_index ASC`

	rows, err := r.client.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query transactions: %w", err)
	}
	defer rows.Close()

	var txs []*BatchTransaction
	for rows.Next() {
		tx := &BatchTransaction{}
		err := rows.Scan(
			&tx.ID, &tx.BatchID, &tx.AccumTxHash, &tx.AccountURL, &tx.TreeIndex,
			&tx.MerklePath, &tx.TxHash, &tx.ChainedProof, &tx.ChainedValid,
			&tx.GovProof, &tx.GovLevel, &tx.GovValid,
			&tx.IntentType, &tx.IntentData, &tx.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		txs = append(txs, tx)
	}

	return txs, rows.Err()
}

// UpdateTransactionProofs updates the proof data for a transaction
func (r *BatchRepository) UpdateTransactionProofs(ctx context.Context, txID int64, chainedProof, govProof json.RawMessage, govLevel GovernanceLevel) error {
	query := `
		UPDATE batch_transactions
		SET chained_proof = $2,
			chained_proof_valid = $3,
			governance_proof = $4,
			governance_level = $5,
			governance_valid = $6
		WHERE id = $1`

	_, err := r.client.ExecContext(ctx, query,
		txID,
		chainedProof, chainedProof != nil,
		govProof, govLevel, govProof != nil,
	)
	if err != nil {
		return fmt.Errorf("failed to update transaction proofs: %w", err)
	}

	return nil
}

// GetNextTreeIndex returns the next tree index for a batch
func (r *BatchRepository) GetNextTreeIndex(ctx context.Context, batchID uuid.UUID) (int, error) {
	query := `SELECT COALESCE(MAX(tree_index), -1) + 1 FROM batch_transactions WHERE batch_id = $1`

	var nextIndex int
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(&nextIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to get next tree index: %w", err)
	}

	return nextIndex, nil
}

// UpdateMerklePath updates the merkle path for a transaction
// This is called when a batch is closed and merkle proofs are computed
func (r *BatchRepository) UpdateMerklePath(ctx context.Context, txID int64, merklePath json.RawMessage) error {
	query := `
		UPDATE batch_transactions
		SET merkle_path = $2
		WHERE id = $1`

	result, err := r.client.ExecContext(ctx, query, txID, merklePath)
	if err != nil {
		return fmt.Errorf("failed to update merkle path: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("transaction %d not found", txID)
	}

	return nil
}

// UpdateMerklePathByTreeIndex updates the merkle path for a transaction by batch ID and tree index
func (r *BatchRepository) UpdateMerklePathByTreeIndex(ctx context.Context, batchID uuid.UUID, treeIndex int, merklePath json.RawMessage) error {
	query := `
		UPDATE batch_transactions
		SET merkle_path = $3
		WHERE batch_id = $1 AND tree_index = $2`

	result, err := r.client.ExecContext(ctx, query, batchID, treeIndex, merklePath)
	if err != nil {
		return fmt.Errorf("failed to update merkle path: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("transaction with tree_index %d in batch %s not found", treeIndex, batchID)
	}

	return nil
}

// GetTransactionHashesByBatchID returns the Accumulate transaction hashes for a batch
// Used for Firestore sync to link confirmation updates back to user intents
func (r *BatchRepository) GetTransactionHashesByBatchID(ctx context.Context, batchID uuid.UUID) ([]string, error) {
	query := `
		SELECT accum_tx_hash
		FROM batch_transactions
		WHERE batch_id = $1
		ORDER BY tree_index`

	rows, err := r.client.QueryContext(ctx, query, batchID)
	if err != nil {
		return nil, fmt.Errorf("failed to query transaction hashes: %w", err)
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, fmt.Errorf("failed to scan transaction hash: %w", err)
		}
		hashes = append(hashes, hash)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating transaction hashes: %w", err)
	}

	return hashes, nil
}
