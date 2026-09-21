// Copyright 2025 Certen Protocol
//
// Batch Repository - CRUD operations for anchor batches and batch transactions

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

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

// ============================================================================
// BATCH TRANSACTION OPERATIONS
// ============================================================================

// GetTransaction retrieves a transaction by ID
func (r *BatchRepository) GetTransaction(ctx context.Context, txID int64) (*BatchTransaction, error) {
	query := `
		SELECT ` + batchTransactionColumns + `
		FROM batch_transactions
		WHERE id = $1`

	tx, err := scanBatchTransaction(r.client.QueryRowContext(ctx, query, txID).Scan)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrTransactionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	return tx, nil
}

// batchTransactionColumns is what the transaction readers select; scanBatchTransaction reads it.
const batchTransactionColumns = `id, batch_id, accumulate_tx_hash, account_url, tree_index,
			merkle_path, transaction_hash, chained_proof, chained_proof_valid,
			governance_proof, governance_level, governance_valid,
			intent_type, intent_data, created_at, user_id, intent_id`

// scanBatchTransaction reads one batch_transactions row. The proof, path and intent JSON columns and the
// two validity flags are nullable: a member written by the canonical anchor path has no chained proof
// yet, and scanning NULL straight into json.RawMessage or bool fails the whole read.
func scanBatchTransaction(scan func(...any) error) (*BatchTransaction, error) {
	tx := &BatchTransaction{}
	var chainedValid, govValid sql.NullBool
	if err := scan(
		&tx.ID, &tx.BatchID, &tx.AccumTxHash, &tx.AccountURL, &tx.TreeIndex,
		(*[]byte)(&tx.MerklePath), &tx.TxHash, (*[]byte)(&tx.ChainedProof), &chainedValid,
		(*[]byte)(&tx.GovProof), &tx.GovLevel, &govValid,
		&tx.IntentType, (*[]byte)(&tx.IntentData), &tx.CreatedAt, &tx.UserID, &tx.IntentID,
	); err != nil {
		return nil, err
	}
	tx.ChainedValid, tx.GovValid = chainedValid.Bool, govValid.Bool
	return tx, nil
}

// GetTransactionByAccumHash retrieves a transaction by Accumulate tx hash
func (r *BatchRepository) GetTransactionByAccumHash(ctx context.Context, accumTxHash string) (*BatchTransaction, error) {
	query := `
		SELECT ` + batchTransactionColumns + `
		FROM batch_transactions
		WHERE accumulate_tx_hash = $1
		ORDER BY created_at DESC
		LIMIT 1`

	tx, err := scanBatchTransaction(r.client.QueryRowContext(ctx, query, TransactionHashKey(accumTxHash)).Scan)

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
		SELECT ` + batchTransactionColumns + `
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
		tx, err := scanBatchTransaction(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}
		txs = append(txs, tx)
	}

	return txs, rows.Err()
}

// GetAccountURLByIntentID retrieves the account URL for an intent
// Used to populate proof_artifacts with the correct Accumulate account URL
func (r *BatchRepository) GetAccountURLByIntentID(ctx context.Context, intentID string) (string, error) {
	query := `
		SELECT COALESCE(account_url, adi_url, '')
		FROM batch_transactions
		WHERE intent_id = $1
		LIMIT 1`

	var accountURL string
	err := r.client.QueryRowContext(ctx, query, intentID).Scan(&accountURL)
	if err == sql.ErrNoRows {
		return "", nil // Not found, return empty string
	}
	if err != nil {
		return "", fmt.Errorf("failed to get account URL by intent: %w", err)
	}
	return accountURL, nil
}

// nullableJSON keeps the difference between "unknown" and "nothing was declared".
//
// A nil json.RawMessage handed to lib/pq becomes an empty STRING, which jsonb rejects — and a
// well-meaning fix is to substitute `[]`, which silently turns "we never found out" into "the intent
// committed to nothing". Those are different claims and migration 012 exists to keep them apart, so
// nil becomes a real SQL NULL here and nowhere else decides.
func nullableJSON(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	return []byte(raw)
}
