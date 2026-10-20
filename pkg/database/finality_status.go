// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// FinalityStatusRepository holds the builder status of each leg's target levels (migration 00028, V2_SPEC_S7 2.7): the last
// state the upgrader judged, shown by the gateway as "level reached / next / eta". The table is MUTABLE by design - a later
// pass replaces the row - and is outside the addendum chain: no verifier reads it, and nothing here can add, change or remove
// an addendum. It implements finality.BuilderStatusStore.
type FinalityStatusRepository struct {
	client *Client
}

func NewFinalityStatusRepository(client *Client) *FinalityStatusRepository {
	return &FinalityStatusRepository{client: client}
}

var _ finality.BuilderStatusStore = (*FinalityStatusRepository)(nil)

// UpsertStatus writes the row of (proof, target level), replacing the previous judgement.
func (r *FinalityStatusRepository) UpsertStatus(ctx context.Context, s finality.BuilderStatus) error {
	if _, err := finality.ParseProofID(s.ProofID); err != nil {
		return err
	}
	doc, err := s.Document()
	if err != nil {
		return err
	}
	at := s.JudgedAt
	if at.IsZero() {
		at = time.Now()
	}
	_, err = r.client.DB().ExecContext(ctx, `INSERT INTO proof_finality_status (proof_id, chain, target_level, state, judged_at)
		VALUES ($1::uuid, $2, $3, $4::jsonb, $5)
		ON CONFLICT (proof_id, target_level) DO UPDATE SET chain = EXCLUDED.chain, state = EXCLUDED.state, judged_at = EXCLUDED.judged_at`,
		s.ProofID, int64(s.Chain), int16(s.TargetLevel), string(doc), at.UTC())
	return err
}

// GetStatus returns the stored row of (proof, target level), or ok=false when nothing was judged.
func (r *FinalityStatusRepository) GetStatus(ctx context.Context, proofID string, target finality.Level) (finality.BuilderStatusView, bool, error) {
	if _, err := finality.ParseProofID(proofID); err != nil {
		return finality.BuilderStatusView{}, false, err
	}
	var chain int64
	var doc []byte
	var at time.Time
	err := r.client.DB().QueryRowContext(ctx, `SELECT chain, state, judged_at FROM proof_finality_status
		WHERE proof_id = $1::uuid AND target_level = $2`, proofID, int16(target)).Scan(&chain, &doc, &at)
	if err == sql.ErrNoRows {
		return finality.BuilderStatusView{}, false, nil
	}
	if err != nil {
		return finality.BuilderStatusView{}, false, err
	}
	v, err := finality.ParseBuilderStatusDocument(doc)
	if err != nil {
		return finality.BuilderStatusView{}, false, fmt.Errorf("status of %s level %s: %w", proofID, target, err)
	}
	v.ProofID, v.Chain, v.TargetLevel, v.JudgedAt = proofID, uint64(chain), target, at.UTC()
	return v, true, nil
}
