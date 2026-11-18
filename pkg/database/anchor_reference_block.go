// Copyright 2025 Certen Protocol
//
// Rows whose anchor block hash or time was never recorded (AGT-F11), and the guarded fill of them. Used by
// `validator repair anchor-block-fields`; the decision (read the chain, refuse a mismatch) is execution's.

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AnchorReferenceBlockRow is an anchor reference that lacks its anchor block hash or time.
type AnchorReferenceBlockRow struct {
	ProofID           uuid.UUID
	ChainID           string
	AnchorTxHash      string
	AnchorBlockNumber int64
	CreatedAt         time.Time
}

// ListAnchorReferencesMissingBlock returns the anchor references created at or after since whose anchor_block_hash or
// anchor_timestamp is empty, oldest first.
func (r *ProofArtifactRepository) ListAnchorReferencesMissingBlock(ctx context.Context, since time.Time) ([]AnchorReferenceBlockRow, error) {
	const q = `
		SELECT proof_id, COALESCE(chain_id, ''), COALESCE(anchor_tx_hash, ''), COALESCE(anchor_block_number, 0), created_at
		FROM anchor_references
		WHERE created_at >= $1
		  AND (anchor_block_hash IS NULL OR anchor_block_hash = '' OR anchor_timestamp IS NULL)
		ORDER BY created_at, proof_id`
	rows, err := r.db.QueryContext(ctx, q, since)
	if err != nil {
		return nil, fmt.Errorf("list anchor references missing their block: %w", err)
	}
	defer rows.Close()
	var out []AnchorReferenceBlockRow
	for rows.Next() {
		var a AnchorReferenceBlockRow
		if err := rows.Scan(&a.ProofID, &a.ChainID, &a.AnchorTxHash, &a.AnchorBlockNumber, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan anchor reference: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// FillAnchorReferenceBlock records the anchor block hash and time on the proof's anchor reference, and on the canonical
// anchor_records rows of the same anchor transaction and block, only where they are still empty and only when the
// stored block number is the one given. It reports whether the anchor reference changed (false: already filled, or the
// row no longer matches - nothing is overwritten).
func (r *ProofArtifactRepository) FillAnchorReferenceBlock(ctx context.Context, row AnchorReferenceBlockRow, blockHash string, blockTime time.Time) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE anchor_references
		SET anchor_block_hash = COALESCE(NULLIF(anchor_block_hash, ''), $4),
		    anchor_timestamp  = COALESCE(anchor_timestamp, $5)
		WHERE proof_id = $1 AND LOWER(anchor_tx_hash) = LOWER($2) AND anchor_block_number = $3
		  AND (anchor_block_hash IS NULL OR anchor_block_hash = '' OR anchor_timestamp IS NULL)
		  AND (anchor_block_hash IS NULL OR anchor_block_hash = '' OR LOWER(anchor_block_hash) = LOWER($4))`,
		row.ProofID, row.AnchorTxHash, row.AnchorBlockNumber, blockHash, blockTime.UTC())
	if err != nil {
		return false, fmt.Errorf("fill anchor reference of proof %s: %w", row.ProofID, err)
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
		UPDATE anchor_records
		SET anchor_block_hash = COALESCE(NULLIF(anchor_block_hash, ''), $3),
		    anchor_timestamp  = COALESCE(anchor_timestamp, $4),
		    updated_at        = NOW()
		WHERE LOWER(anchor_tx_hash) = LOWER($1) AND anchor_block_number = $2
		  AND (anchor_block_hash IS NULL OR anchor_block_hash = '' OR anchor_timestamp IS NULL)
		  AND (anchor_block_hash IS NULL OR anchor_block_hash = '' OR LOWER(anchor_block_hash) = LOWER($3))`,
		row.AnchorTxHash, row.AnchorBlockNumber, blockHash, blockTime.UTC()); err != nil {
		return false, fmt.Errorf("fill canonical anchor record of %s: %w", row.AnchorTxHash, err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return n > 0, nil
}
