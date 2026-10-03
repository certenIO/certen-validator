package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// =============================================================================
// A member proof's recorded batch outcome (RB5-F15): chained_proof_layers layer 6
// =============================================================================

// ErrOutcomeLayerContradiction: a proof already carries outcome evidence that differs from the evidence being attached.
var ErrOutcomeLayerContradiction = errors.New("a proof's batch outcome evidence contradicts the evidence already attached to it")

// OutcomeLayerNumber is the chained_proof_layers row a proof's outcome evidence is stored in.
const OutcomeLayerNumber = 6

func bareLowerHex(s string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X"))
}

// ProofsOfAnchorLeaf lists the proofs whose standing layer 5 places them at leaf leafHash under batchRoot on chainID -
// and, where that layer records its anchor's commitment, under the anchor bundleID.
func (r *ProofArtifactRepository) ProofsOfAnchorLeaf(ctx context.Context, chainID int64, bundleID, batchRoot, leafHash string) ([]uuid.UUID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT proof_id FROM chained_proof_layers
		WHERE layer_number = 5 AND superseded_at IS NULL AND proof_id IS NOT NULL
		  AND (layer_json->>'chainId')::bigint = $1
		  AND regexp_replace(lower(layer_json->>'batchRoot'), '^0x', '') = $2
		  AND regexp_replace(lower(layer_json->>'leafHash'), '^0x', '') = $3
		  AND (layer_json->'commitment' IS NULL OR jsonb_typeof(layer_json->'commitment') = 'null'
		       OR regexp_replace(lower(layer_json->'commitment'->>'bundleId'), '^0x', '') = $4)
		ORDER BY proof_id`, chainID, bareLowerHex(batchRoot), bareLowerHex(leafHash), bareLowerHex(bundleID))
	if err != nil {
		return nil, fmt.Errorf("the proofs of anchor %s leaf %s: %w", bundleID, leafHash, err)
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// OutcomeLayerDecision is what to do with a proof's standing outcome evidence when other evidence is attached.
type OutcomeLayerDecision int

const (
	// OutcomeLayerKeep: the standing row states the same outcome and is kept; nothing is written.
	OutcomeLayerKeep OutcomeLayerDecision = iota
	// OutcomeLayerSupersede: the new evidence states the same outcome and more of its evidence; the standing row is
	// superseded (kept, marked, never deleted) and the new one written.
	OutcomeLayerSupersede
)

// AttachOutcomeLayer stores a proof's outcome evidence as its layer-6 row. With no standing row it writes one and
// returns true. With one, decide compares the standing evidence with the new: keep it (false), supersede it with the
// new (true, the old row marked with supersededReason), or refuse with an error - evidence is never overwritten.
// Concurrent writers of one proof are serialized.
func (r *ProofArtifactRepository) AttachOutcomeLayer(ctx context.Context, proofID uuid.UUID, layerName string, layerJSON []byte,
	decide func(standing []byte) (OutcomeLayerDecision, string, error)) (bool, error) {
	if len(layerJSON) == 0 || decide == nil {
		return false, fmt.Errorf("proof %s: no outcome evidence to attach", proofID)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('certen:outcome-layer:' || $1::text))`, proofID.String()); err != nil {
		return false, fmt.Errorf("proof %s: %w", proofID, err)
	}
	var standingID uuid.UUID
	var standing []byte
	err = tx.QueryRowContext(ctx, `
		SELECT layer_id, layer_json FROM chained_proof_layers
		WHERE proof_id = $1 AND layer_number = $2 AND superseded_at IS NULL
		ORDER BY created_at LIMIT 1`, proofID, OutcomeLayerNumber).Scan(&standingID, &standing)
	switch {
	case err == nil:
		d, reason, derr := decide(standing)
		if derr != nil {
			return false, fmt.Errorf("%w: proof %s: %v", ErrOutcomeLayerContradiction, proofID, derr)
		}
		if d == OutcomeLayerKeep {
			return false, tx.Commit()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE chained_proof_layers SET superseded_at = NOW(), superseded_reason = $2
			WHERE layer_id = $1`, standingID, reason); err != nil {
			return false, fmt.Errorf("proof %s: supersede its outcome evidence: %w", proofID, err)
		}
	case !errors.Is(err, sql.ErrNoRows):
		return false, fmt.Errorf("proof %s: %w", proofID, err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO chained_proof_layers (proof_id, layer_number, layer_name, layer_json, verified, verified_at, created_at)
		VALUES ($1, $2, $3, $4::jsonb, true, NOW(), NOW())`, proofID, OutcomeLayerNumber, layerName, string(layerJSON)); err != nil {
		return false, fmt.Errorf("proof %s: write its outcome evidence: %w", proofID, err)
	}
	return true, tx.Commit()
}
