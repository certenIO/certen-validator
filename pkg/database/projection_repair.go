// Copyright 2026 Certen Protocol
//
// Moving the settlement out of the anchor columns (RB3-F135, migration 00011). proof_artifacts,
// anchor_references and validator_attestations stated the member's settlement transaction as anchor_tx_hash.
// Each proof's value is classified from chain facts by the caller; these operations move it, conditional
// on the value read, in one transaction with its correction records.

package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Correction record types for the projections (migration 00011).
const (
	CorrectionRecordProofArtifact        = "proof_artifact"
	CorrectionRecordAnchorReference      = "anchor_reference"
	CorrectionRecordValidatorAttestation = "validator_attestation"
)

// ProofProjection is a proof whose anchor columns have not been classified: what they state, and what the
// proof's standing layer 5 says was the anchor (empty when it has none).
type ProofProjection struct {
	ProofID     uuid.UUID
	Chain       string // proof_artifacts.anchor_chain: the chain id, as stored
	StatedTx    string
	StatedBlock int64
	L5AnchorTx  string
	L5Block     int64
	L5BlockHash string
}

// ListUnclassifiedProjections returns the proofs on the given chains whose anchor_tx_hash is set and whose
// settlement has not been recorded - the rows written before migration 00011.
func (r *EvidenceRepair) ListUnclassifiedProjections(ctx context.Context, chains []string) ([]ProofProjection, error) {
	rows, err := r.client.QueryContext(ctx, `
		SELECT pa.proof_id, pa.anchor_chain, pa.anchor_tx_hash, COALESCE(pa.anchor_block_number, 0),
		       COALESCE(l5.layer_json->>'anchorTx', ''), COALESCE((l5.layer_json->>'blockNumber')::bigint, 0),
		       COALESCE(l5.layer_json->>'blockHash', '')
		FROM proof_artifacts pa
		LEFT JOIN chained_proof_layers l5
		       ON l5.proof_id = pa.proof_id AND l5.layer_number = 5 AND l5.superseded_at IS NULL
		WHERE pa.anchor_tx_hash IS NOT NULL
		  AND pa.settlement_tx_hash IS NULL
		  AND pa.anchor_chain = ANY($1)
		ORDER BY pa.created_at, pa.proof_id`, pq.Array(chains))
	if err != nil {
		return nil, fmt.Errorf("list unclassified projections: %w", err)
	}
	defer rows.Close()
	var out []ProofProjection
	for rows.Next() {
		var p ProofProjection
		if err := rows.Scan(&p.ProofID, &p.Chain, &p.StatedTx, &p.StatedBlock, &p.L5AnchorTx, &p.L5Block, &p.L5BlockHash); err != nil {
			return nil, fmt.Errorf("scan projection: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SettlementMove is what the chain established about a proof's stated transaction: it is the settlement
// (mined in SettlementBlock), and the anchor is layer 5's (AnchorTx, empty when the proof has none).
type SettlementMove struct {
	SettlementBlock int64
	AnchorTx        string
	AnchorBlock     int64
	AnchorBlockHash string
	Reason          string
	Evidence        AnchorChainFacts
}

// MoveSettlementOutOfAnchor moves p.StatedTx from the anchor columns of the proof's artifact, anchor
// reference and validator attestations to their settlement columns and states the anchor in its place,
// conditional on each still holding p.StatedTx; one correction record per table.
func (r *EvidenceRepair) MoveSettlementOutOfAnchor(ctx context.Context, p ProofProjection, m SettlementMove, by string) error {
	tx, err := r.client.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	anchorTx := sql.NullString{String: m.AnchorTx, Valid: m.AnchorTx != ""}
	anchorBlock := sql.NullInt64{Int64: m.AnchorBlock, Valid: m.AnchorTx != "" && m.AnchorBlock > 0}
	anchorHash := sql.NullString{String: m.AnchorBlockHash, Valid: m.AnchorTx != "" && m.AnchorBlockHash != ""}

	res, err := tx.Tx().ExecContext(ctx, `
		UPDATE proof_artifacts
		SET settlement_tx_hash = anchor_tx_hash, settlement_block_number = $3,
		    anchor_tx_hash = $4, anchor_block_number = $5
		WHERE proof_id = $1 AND anchor_tx_hash = $2 AND settlement_tx_hash IS NULL`,
		p.ProofID, p.StatedTx, m.SettlementBlock, anchorTx, anchorBlock)
	if err != nil {
		return fmt.Errorf("move settlement of proof %s: %w", p.ProofID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrEvidenceChanged
	}
	if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordProofArtifact, p.ProofID.String(), m.Reason,
		map[string]any{"anchor_tx_hash": p.StatedTx, "anchor_block_number": p.StatedBlock, "settlement_tx_hash": nil},
		map[string]any{"anchor_tx_hash": nullable(anchorTx), "anchor_block_number": nullableInt(anchorBlock),
			"settlement_tx_hash": p.StatedTx, "settlement_block_number": m.SettlementBlock},
		m.Evidence, by); err != nil {
		return err
	}

	// The anchor reference: every anchor_* column described the settlement.
	var prevRef []byte
	err = tx.Tx().QueryRowContext(ctx, `
		SELECT to_jsonb(ar) FROM anchor_references ar WHERE proof_id = $1 AND LOWER(anchor_tx_hash) = LOWER($2) FOR UPDATE`,
		p.ProofID, p.StatedTx).Scan(&prevRef)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		return fmt.Errorf("read anchor reference of proof %s: %w", p.ProofID, err)
	default:
		if _, err := tx.Tx().ExecContext(ctx, `
			UPDATE anchor_references
			SET settlement_tx_hash = anchor_tx_hash, settlement_block_number = anchor_block_number,
			    settlement_block_hash = anchor_block_hash, settlement_timestamp = anchor_timestamp,
			    settlement_gas_used = gas_used,
			    anchor_tx_hash = $3::text, anchor_block_number = $4, anchor_block_hash = $5, anchor_timestamp = NULL,
			    gas_used = NULL, gas_price_wei = NULL, total_cost_wei = NULL,
			    confirmations = CASE WHEN $3::text IS NULL THEN 0 ELSE confirmations END,
			    is_confirmed = CASE WHEN $3::text IS NULL THEN FALSE ELSE is_confirmed END
			WHERE proof_id = $1 AND LOWER(anchor_tx_hash) = LOWER($2)`,
			p.ProofID, p.StatedTx, anchorTx, anchorBlock, anchorHash); err != nil {
			return fmt.Errorf("move settlement of anchor reference for proof %s: %w", p.ProofID, err)
		}
		if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordAnchorReference, p.ProofID.String(), m.Reason,
			json.RawMessage(prevRef), map[string]any{"anchor_tx_hash": nullable(anchorTx), "anchor_block_number": nullableInt(anchorBlock),
				"settlement_tx_hash": p.StatedTx}, m.Evidence, by); err != nil {
			return err
		}
	}

	// The validator attestations: the message they signed names the settlement.
	res, err = tx.Tx().ExecContext(ctx, `
		UPDATE validator_attestations
		SET settlement_tx_hash = anchor_tx_hash, settlement_block_number = block_number,
		    anchor_tx_hash = $3, block_number = $4
		WHERE proof_id = $1 AND LOWER(anchor_tx_hash) = LOWER($2) AND settlement_tx_hash IS NULL`,
		p.ProofID, p.StatedTx, anchorTx, anchorBlock)
	if err != nil {
		return fmt.Errorf("move settlement of attestations for proof %s: %w", p.ProofID, err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if _, err := recordCorrection(ctx, tx.Tx(), CorrectionRecordValidatorAttestation, p.ProofID.String(), m.Reason,
			map[string]any{"anchor_tx_hash": p.StatedTx, "rows": n},
			map[string]any{"anchor_tx_hash": nullable(anchorTx), "block_number": nullableInt(anchorBlock), "settlement_tx_hash": p.StatedTx, "rows": n},
			m.Evidence, by); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func nullable(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

func nullableInt(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return n.Int64
}
