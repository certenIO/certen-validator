package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// ProofV2ShadowRepository keeps what the proof v2 shadow captured, built and verified (migration 00022).
type ProofV2ShadowRepository struct {
	client *Client
}

func NewProofV2ShadowRepository(client *Client) *ProofV2ShadowRepository {
	return &ProofV2ShadowRepository{client: client}
}

// RecordCapture stores the pages captured at discovery, or the named reason none could be. A capture that holds pages
// is never replaced: a retried intent is re-discovered after its block may have left retention, and its later attempt
// must not erase the pages read while they were servable.
func (r *ProofV2ShadowRepository) RecordCapture(ctx context.Context, intentID, txHash, account string, block uint64, captured any, captureErr string) error {
	var raw []byte
	if captured != nil {
		var err error
		if raw, err = json.Marshal(captured); err != nil {
			return fmt.Errorf("encode captured pages: %w", err)
		}
	}
	_, err := r.client.DB().ExecContext(ctx, `
		INSERT INTO proof_v2_shadow (intent_id, accum_tx_hash, account_url, captured_block, captured, captured_at, capture_error)
		VALUES ($1, $2, $3, NULLIF($4, 0), $5, now(), NULLIF($6, ''))
		ON CONFLICT (intent_id) DO UPDATE SET captured_block = EXCLUDED.captured_block, captured = EXCLUDED.captured,
			captured_at = EXCLUDED.captured_at, capture_error = EXCLUDED.capture_error, updated_at = now()
		WHERE proof_v2_shadow.captured IS NULL`,
		intentID, txHash, account, int64(block), nullJSON(raw), captureErr)
	return err
}

// Captured returns the pages captured for an intent (JSON), and whether a capture was recorded.
func (r *ProofV2ShadowRepository) Captured(ctx context.Context, intentID string) ([]byte, bool, error) {
	var raw []byte
	err := r.client.DB().QueryRowContext(ctx, `SELECT captured FROM proof_v2_shadow WHERE intent_id = $1`, intentID).Scan(&raw)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// ProofV2Result is what one shadow build established.
type ProofV2Result struct {
	IntentID, TxHash, Account string
	Evidence                  any    // proofv2.Evidence, nil when the build failed
	Verdict                   string // the verifier's set verdict, or "failed"
	Error                     string // why it failed; required when Verdict is "failed"
	AnchorBlock               uint64
	CertifiedBlock            uint64
	Pages                     int
}

// RecordBuild stores a shadow build's evidence and verdict.
func (r *ProofV2ShadowRepository) RecordBuild(ctx context.Context, res ProofV2Result) error {
	if res.Verdict == "failed" && res.Error == "" {
		return fmt.Errorf("a failed shadow build must name why")
	}
	var raw []byte
	if res.Evidence != nil {
		var err error
		if raw, err = json.Marshal(res.Evidence); err != nil {
			return fmt.Errorf("encode evidence: %w", err)
		}
	}
	_, err := r.client.DB().ExecContext(ctx, `
		INSERT INTO proof_v2_shadow (intent_id, accum_tx_hash, account_url, evidence, built_at, verdict, error, anchor_block, certified_block, pages)
		VALUES ($1, $2, $3, $4, now(), $5, NULLIF($6, ''), NULLIF($7, 0), NULLIF($8, 0), $9)
		ON CONFLICT (intent_id) DO UPDATE SET evidence = EXCLUDED.evidence, built_at = EXCLUDED.built_at, verdict = EXCLUDED.verdict,
			error = EXCLUDED.error, anchor_block = EXCLUDED.anchor_block, certified_block = EXCLUDED.certified_block,
			pages = EXCLUDED.pages, updated_at = now()`,
		res.IntentID, res.TxHash, res.Account, nullJSON(raw), res.Verdict, res.Error, int64(res.AnchorBlock), int64(res.CertifiedBlock), res.Pages)
	return err
}

// SaveSpine stores major records from first (1-based) on; a stored record must not change.
func (r *ProofV2ShadowRepository) SaveSpine(ctx context.Context, first uint64, records [][]byte) error {
	for i, rec := range records {
		idx := int64(first) + int64(i)
		res, err := r.client.DB().ExecContext(ctx, `
			INSERT INTO proof_v2_spine (major_index, record) VALUES ($1, $2)
			ON CONFLICT (major_index) DO NOTHING`, idx, rec)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var stored []byte
			if err := r.client.DB().QueryRowContext(ctx, `SELECT record FROM proof_v2_spine WHERE major_index = $1`, idx).Scan(&stored); err != nil {
				return err
			}
			if string(stored) != string(rec) {
				return fmt.Errorf("major block %d: the stored record differs from the one just verified", idx)
			}
		}
	}
	return nil
}

// Spine returns every stored major record in order.
func (r *ProofV2ShadowRepository) Spine(ctx context.Context) ([][]byte, error) {
	rows, err := r.client.DB().QueryContext(ctx, `SELECT major_index, record FROM proof_v2_spine ORDER BY major_index`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var idx int64
		var rec []byte
		if err := rows.Scan(&idx, &rec); err != nil {
			return nil, err
		}
		if idx != int64(len(out))+1 {
			return nil, fmt.Errorf("the stored spine skips from major block %d to %d", len(out), idx)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func nullJSON(raw []byte) any {
	if raw == nil {
		return nil
	}
	return raw
}
