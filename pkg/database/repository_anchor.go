// Copyright 2025 Certen Protocol
//
// Anchor Repository - CRUD operations for external chain anchor records

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AnchorRepository handles external chain anchor record operations
type AnchorRepository struct {
	client *Client
}

// NewAnchorRepository creates a new anchor repository
func NewAnchorRepository(client *Client) *AnchorRepository {
	return &AnchorRepository{client: client}
}

// ============================================================================
// ANCHOR RECORD OPERATIONS
// ============================================================================

// CreateAnchor creates a new anchor record after successful external chain submission
func (r *AnchorRepository) CreateAnchor(ctx context.Context, input *NewAnchorRecord) (*AnchorRecord, error) {
	anchor := &AnchorRecord{
		AnchorID:             uuid.New(),
		BatchID:              input.BatchID,
		TargetChain:          input.TargetChain,
		ChainID:              sql.NullString{String: input.ChainID, Valid: input.ChainID != ""},
		NetworkName:          sql.NullString{String: input.NetworkName, Valid: input.NetworkName != ""},
		ContractAddress:      sql.NullString{String: input.ContractAddress, Valid: input.ContractAddress != ""},
		AnchorTxHash:         input.AnchorTxHash,
		AnchorBlockNumber:    input.AnchorBlockNumber,
		AnchorBlockHash:      sql.NullString{String: input.AnchorBlockHash, Valid: input.AnchorBlockHash != ""},
		MerkleRoot:           input.MerkleRoot,
		AccumHeight:          sql.NullInt64{Int64: input.AccumHeight, Valid: input.AccumHeight > 0},
		OperationCommitment:  input.OperationCommitment,
		CrossChainCommitment: input.CrossChainCommitment,
		GovernanceRoot:       input.GovernanceRoot,
		Confirmations:        0,
		RequiredConfirms:     getRequiredConfirmations(input.TargetChain),
		IsFinal:              false,
		GasUsed:              sql.NullInt64{Int64: input.GasUsed, Valid: input.GasUsed > 0},
		GasPriceWei:          sql.NullString{String: input.GasPriceWei, Valid: input.GasPriceWei != ""},
		TotalCostWei:         sql.NullString{String: input.TotalCostWei, Valid: input.TotalCostWei != ""},
		ValidatorID:          input.ValidatorID,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	query := `
		INSERT INTO anchor_records (
			anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			merkle_root, accumulate_height, operation_commitment, cross_chain_commitment,
			governance_root, confirmations, required_confirmations, is_final,
			gas_used, gas_price_wei, total_cost_wei, validator_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
		RETURNING anchor_id, created_at, updated_at`

	err := r.client.QueryRowContext(ctx, query,
		anchor.AnchorID, anchor.BatchID, anchor.TargetChain, anchor.ChainID, anchor.NetworkName,
		anchor.ContractAddress, anchor.AnchorTxHash, anchor.AnchorBlockNumber, anchor.AnchorBlockHash,
		anchor.MerkleRoot, anchor.AccumHeight, anchor.OperationCommitment, anchor.CrossChainCommitment,
		anchor.GovernanceRoot, anchor.Confirmations, anchor.RequiredConfirms, anchor.IsFinal,
		anchor.GasUsed, anchor.GasPriceWei, anchor.TotalCostWei, anchor.ValidatorID,
		anchor.CreatedAt, anchor.UpdatedAt,
	).Scan(&anchor.AnchorID, &anchor.CreatedAt, &anchor.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create anchor: %w", err)
	}

	return anchor, nil
}

// getRequiredConfirmations returns the required confirmations for a chain
func getRequiredConfirmations(chain TargetChain) int {
	switch chain {
	case TargetChainEthereum:
		return 12 // ~3 minutes on PoS Ethereum
	case TargetChainBitcoin:
		return 6 // ~60 minutes on Bitcoin
	default:
		return 12
	}
}

// GetAnchor retrieves an anchor by ID
func (r *AnchorRepository) GetAnchor(ctx context.Context, anchorID uuid.UUID) (*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		WHERE anchor_id = $1`

	anchor := &AnchorRecord{}
	err := r.client.QueryRowContext(ctx, query, anchorID).Scan(
		&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
		&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
		&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
		&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
		&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
		&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAnchorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get anchor: %w", err)
	}

	return anchor, nil
}

// GetAnchorByTxHash retrieves an anchor by external chain transaction hash
func (r *AnchorRepository) GetAnchorByTxHash(ctx context.Context, txHash string) (*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		WHERE anchor_tx_hash = $1`

	anchor := &AnchorRecord{}
	err := r.client.QueryRowContext(ctx, query, txHash).Scan(
		&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
		&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
		&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
		&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
		&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
		&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAnchorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get anchor by tx hash: %w", err)
	}

	return anchor, nil
}

// GetAnchorByBatchID retrieves the anchor for a specific batch
func (r *AnchorRepository) GetAnchorByBatchID(ctx context.Context, batchID uuid.UUID) (*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		WHERE batch_id = $1`

	anchor := &AnchorRecord{}
	err := r.client.QueryRowContext(ctx, query, batchID).Scan(
		&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
		&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
		&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
		&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
		&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
		&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// F.4 remediation: Return explicit error instead of nil, nil
		return nil, ErrAnchorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get anchor by batch ID: %w", err)
	}

	return anchor, nil
}

// GetUnconfirmedAnchors returns anchors that haven't reached required confirmations
func (r *AnchorRepository) GetUnconfirmedAnchors(ctx context.Context) ([]*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		WHERE is_final = false
		ORDER BY created_at ASC`

	rows, err := r.client.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unconfirmed anchors: %w", err)
	}
	defer rows.Close()

	var anchors []*AnchorRecord
	for rows.Next() {
		anchor := &AnchorRecord{}
		err := rows.Scan(
			&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
			&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
			&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
			&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
			&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
			&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan anchor: %w", err)
		}
		anchors = append(anchors, anchor)
	}

	return anchors, rows.Err()
}

// UpdateConfirmations updates the confirmation count for an anchor
func (r *AnchorRepository) UpdateConfirmations(ctx context.Context, anchorID uuid.UUID, confirmations int, blockHash string, blockTimestamp time.Time) error {
	query := `
		UPDATE anchor_records
		SET confirmations = $2,
			anchor_block_hash = $3,
			anchor_timestamp = $4,
			updated_at = $5
		WHERE anchor_id = $1`

	_, err := r.client.ExecContext(ctx, query,
		anchorID, confirmations,
		sql.NullString{String: blockHash, Valid: blockHash != ""},
		sql.NullTime{Time: blockTimestamp, Valid: !blockTimestamp.IsZero()},
		time.Now())
	if err != nil {
		return fmt.Errorf("failed to update confirmations: %w", err)
	}

	return nil
}

// MarkAnchorFinal marks an anchor as having sufficient confirmations
func (r *AnchorRepository) MarkAnchorFinal(ctx context.Context, anchorID uuid.UUID) error {
	query := `
		UPDATE anchor_records
		SET is_final = true,
			confirmed_at = $2,
			updated_at = $3
		WHERE anchor_id = $1`

	result, err := r.client.ExecContext(ctx, query, anchorID, time.Now(), time.Now())
	if err != nil {
		return fmt.Errorf("failed to mark anchor final: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("anchor not found")
	}

	return nil
}

// UpdateAnchorCostUSD updates the USD cost for an anchor (after price lookup)
func (r *AnchorRepository) UpdateAnchorCostUSD(ctx context.Context, anchorID uuid.UUID, costUSD float64) error {
	query := `
		UPDATE anchor_records
		SET total_cost_usd = $2, updated_at = $3
		WHERE anchor_id = $1`

	_, err := r.client.ExecContext(ctx, query, anchorID, costUSD, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update anchor cost USD: %w", err)
	}

	return nil
}

// GetAnchorsByChain returns all anchors for a specific chain
func (r *AnchorRepository) GetAnchorsByChain(ctx context.Context, chain TargetChain, limit int) ([]*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		WHERE target_chain = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.client.QueryContext(ctx, query, chain, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query anchors by chain: %w", err)
	}
	defer rows.Close()

	var anchors []*AnchorRecord
	for rows.Next() {
		anchor := &AnchorRecord{}
		err := rows.Scan(
			&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
			&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
			&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
			&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
			&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
			&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan anchor: %w", err)
		}
		anchors = append(anchors, anchor)
	}

	return anchors, rows.Err()
}

// GetRecentAnchors returns the most recent anchors across all chains
func (r *AnchorRepository) GetRecentAnchors(ctx context.Context, limit int) ([]*AnchorRecord, error) {
	query := `
		SELECT anchor_id, batch_id, target_chain, chain_id, network_name,
			contract_address, anchor_tx_hash, anchor_block_number, anchor_block_hash,
			anchor_timestamp, merkle_root, accumulate_height, operation_commitment,
			cross_chain_commitment, governance_root, confirmations, required_confirmations,
			confirmed_at, is_final, gas_used, gas_price_wei, total_cost_wei, total_cost_usd,
			validator_id, created_at, updated_at
		FROM anchor_records
		ORDER BY created_at DESC
		LIMIT $1`

	rows, err := r.client.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent anchors: %w", err)
	}
	defer rows.Close()

	var anchors []*AnchorRecord
	for rows.Next() {
		anchor := &AnchorRecord{}
		err := rows.Scan(
			&anchor.AnchorID, &anchor.BatchID, &anchor.TargetChain, &anchor.ChainID, &anchor.NetworkName,
			&anchor.ContractAddress, &anchor.AnchorTxHash, &anchor.AnchorBlockNumber, &anchor.AnchorBlockHash,
			&anchor.AnchorTimestamp, &anchor.MerkleRoot, &anchor.AccumHeight, &anchor.OperationCommitment,
			&anchor.CrossChainCommitment, &anchor.GovernanceRoot, &anchor.Confirmations, &anchor.RequiredConfirms,
			&anchor.ConfirmedAt, &anchor.IsFinal, &anchor.GasUsed, &anchor.GasPriceWei, &anchor.TotalCostWei,
			&anchor.TotalCostUSD, &anchor.ValidatorID, &anchor.CreatedAt, &anchor.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan anchor: %w", err)
		}
		anchors = append(anchors, anchor)
	}

	return anchors, rows.Err()
}

// CountAnchors returns the total number of anchors
func (r *AnchorRepository) CountAnchors(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM anchor_records`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count anchors: %w", err)
	}

	return count, nil
}

// CountFinalAnchors returns the number of finalized anchors
func (r *AnchorRepository) CountFinalAnchors(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM anchor_records WHERE is_final = true`

	var count int64
	err := r.client.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count final anchors: %w", err)
	}

	return count, nil
}
