// Copyright 2026 Certen Protocol
//
// Stage 3 — the joins that were never written.
//
// The pieces of an external-anchor proof mostly existed and were UNJOINED.
// Measured against production, 2026-08-25:
//
//	batch_transactions.merkle_path      70,253 / 70,253  ✅ the leaf->root path
//	batch_transactions.tree_index       70,253 / 70,253  ✅ the leaf index
//	anchor_batches.merkle_root          67,847 / 67,847  ✅ the batch root
//	proof_artifacts.anchor_tx_hash         410 / 418     ✅ external coordinates
//	proof_artifacts.batch_id                 0 / 418     ❌ proof -> batch
//	proof_artifacts.merkle_path              0 / 418     ❌ per-proof path
//	anchor_batches.anchor_tx_hash            0 / 67,847  ❌ batch -> external tx
//
// Every ❌ is a JOIN, not a missing measurement. The path proving a given proof
// is in a given anchored batch was computed, stored under the batch, and never
// connected to the proof — so "we have a tx hash somewhere" could not be turned
// into "here is the path proving this proof is in that anchored batch". These
// three columns are the actual plumbing defect, and they are worth more than the
// new layer on their own.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Layer5Binding is everything the leaf->batchRoot half of L5 needs, joined from
// the rows that already held it.
type Layer5Binding struct {
	BatchID     uuid.UUID
	TreeIndex   int
	MerklePath  []MerklePathNode // leaf -> batch root; EMPTY is legitimate for a one-member batch
	BatchRoot   []byte           // anchor_batches.merkle_root, 32 bytes
	TargetChain string

	// AnchorTxHash / AnchorBlockNum are the batch's own external coordinates,
	// when the batch already carries them. Usually empty, because
	// anchor_batches.anchor_tx_hash is the third unwritten join.
	AnchorTxHash   string
	AnchorBlockNum int64
}

// ErrNoBatchBinding reports that no batch row covers this transaction.
//
// Not an error condition in itself: an intent settled outside the batch path has
// no batch row, and its proof is then a one-member case where the leaf IS the
// root. Callers distinguish that from a real failure with errors.Is, because
// treating "settled alone" as "lookup failed" would suppress L5 for exactly the
// proofs where it is simplest to produce.
var ErrNoBatchBinding = errors.New("no batch_transactions row for this accumulate transaction")

// GetLayer5Binding joins batch_transactions to anchor_batches for one Accumulate
// transaction.
//
// The join is on accumulate_tx_hash for the same reason ProofBlob's is:
// batch_transactions predates proof_artifacts and carries no proof_id.
//
// Ordered newest-first and limited to one. A transaction can appear in more than
// one batch row across re-runs, and the most recent row is the one whose batch
// actually anchored — picking arbitrarily would sometimes return a path to a
// root that was never published.
func (r *ProofArtifactRepository) GetLayer5Binding(ctx context.Context, accumTxHash string) (*Layer5Binding, error) {
	const q = `
		SELECT bt.batch_id,
		       COALESCE(bt.tree_index, 0),
		       bt.merkle_path,
		       ab.merkle_root,
		       COALESCE(ab.target_chain, ''),
		       COALESCE(ab.anchor_tx_hash, ''),
		       COALESCE(ab.anchor_block_num, 0)
		FROM batch_transactions bt
		JOIN anchor_batches ab ON ab.id = bt.batch_id
		WHERE bt.accumulate_tx_hash = $1
		ORDER BY bt.created_at DESC
		LIMIT 1`

	var (
		b       Layer5Binding
		rawPath []byte
		root    []byte
	)
	err := r.db.QueryRowContext(ctx, q, accumTxHash).Scan(
		&b.BatchID, &b.TreeIndex, &rawPath, &root, &b.TargetChain, &b.AnchorTxHash, &b.AnchorBlockNum)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("tx %s: %w", accumTxHash, ErrNoBatchBinding)
	}
	if err != nil {
		return nil, fmt.Errorf("look up layer-5 binding for %s: %w", accumTxHash, err)
	}
	b.BatchRoot = root

	if len(rawPath) > 0 {
		if err := json.Unmarshal(rawPath, &b.MerklePath); err != nil {
			// A path that will not parse is a corrupt record, not an absent one.
			// Returning it as "no path" would turn a corruption into a
			// single-leaf claim, which is the one shape that passes vacuously.
			return nil, fmt.Errorf("tx %s: batch_transactions.merkle_path does not parse: %w",
				accumTxHash, err)
		}
	}
	return &b, nil
}

// BindProofToBatch writes the two per-proof joins that were never populated:
// proof_artifacts.batch_id and proof_artifacts.merkle_path.
//
// Idempotent and non-destructive. An empty path is written as SQL NULL rather
// than as '[]', because those mean different things: NULL is "no path was
// recorded", '[]' is "the path is empty, and the leaf is therefore the root".
// Conflating them would let a proof with no recorded evidence read as a
// single-leaf batch, which verifies whenever leaf == root and is exactly the
// vacuous pass L5 is written to refuse.
func (r *ProofArtifactRepository) BindProofToBatch(
	ctx context.Context, proofID, batchID uuid.UUID, leafIndex int, path []MerklePathNode,
) error {
	var pathJSON interface{}
	if path != nil {
		data, err := json.Marshal(path)
		if err != nil {
			return fmt.Errorf("marshal merkle_path: %w", err)
		}
		pathJSON = data
	}

	const q = `
		UPDATE proof_artifacts
		SET batch_id    = $2,
		    merkle_path = COALESCE($3, merkle_path),
		    leaf_index  = COALESCE(leaf_index, $4)
		WHERE proof_id = $1`
	if _, err := r.db.ExecContext(ctx, q, proofID, batchID, pathJSON, leafIndex); err != nil {
		return fmt.Errorf("bind proof %s to batch %s: %w", proofID, batchID, err)
	}
	return nil
}

// SetAnchorBatchTxHash records which external transaction published a batch's
// merkle root — the batch -> external chain join, 0 of 67,847 before Stage 3.
//
// Without it the batch root is a number in a table that nobody can point at a
// chain, and the whole L5 claim degenerates to "this leaf is under some root".
//
// Deliberately does NOT overwrite an existing hash. A batch is anchored once;
// a second, different hash arriving later means either a re-anchor or a bug, and
// silently replacing the first would erase the evidence needed to tell which.
func (r *ProofArtifactRepository) SetAnchorBatchTxHash(
	ctx context.Context, batchID uuid.UUID, txHash string, blockNum int64,
) error {
	if txHash == "" {
		return fmt.Errorf("refusing to record an empty anchor tx hash for batch %s", batchID)
	}
	const q = `
		UPDATE anchor_batches
		SET anchor_tx_hash   = $2,
		    anchor_block_num = COALESCE(anchor_block_num, $3),
		    anchored_at      = COALESCE(anchored_at, NOW()),
		    updated_at       = NOW()
		WHERE id = $1
		  AND (anchor_tx_hash IS NULL OR anchor_tx_hash = '')`
	res, err := r.db.ExecContext(ctx, q, batchID, txHash, blockNum)
	if err != nil {
		return fmt.Errorf("record anchor tx for batch %s: %w", batchID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Not an error. Either the batch already carries a hash (the common
		// case on a replay) or the batch is gone. Reported so a caller that
		// expected to write one can say so, rather than assuming it did.
		return ErrAnchorTxAlreadyRecorded
	}
	return nil
}

// ErrAnchorTxAlreadyRecorded reports that the batch already had an anchor
// transaction, so nothing was overwritten.
var ErrAnchorTxAlreadyRecorded = errors.New("anchor batch already carries an anchor tx hash; not overwritten")
