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
// pass replaces the row, but never a verified row and never a newer judgement with an older one (UpsertStatus) - and is outside the addendum chain: no verifier reads it, and nothing here can add, change or remove
// an addendum. It implements finality.BuilderStatusStore.
type FinalityStatusRepository struct {
	client *Client
}

func NewFinalityStatusRepository(client *Client) *FinalityStatusRepository {
	return &FinalityStatusRepository{client: client}
}

var _ finality.BuilderStatusStore = (*FinalityStatusRepository)(nil)

// UpsertStatus writes the row of (proof, target level) under the rules that make the table safe for several validators sharing
// one database (RB11-DBFIX D1). One statement, atomic against every other writer:
//
//   - a claim of a stored level must be FOUNDED: a verified row, or any row whose levelReached is l1_posted or finalized, is
//     written only if the proof holds the addendum at that level (and, for a verified row, with that seq and chain). An unfounded
//     claim is refused with the named state finality_guard_refused and nothing is written;
//   - a verified row is final: the addendum it names is immutable, so nothing replaces it, whatever the time of the writer;
//   - any other row replaces the stored one only if it was judged at or after it (an older judgement, written later by a slower
//     validator, never replaces a newer one); a verified row replaces a stored non-verified row whatever their times, because it is
//     a fact derived from the addendum and not a judgement of the moment (validators' clocks differ).
//
// A write that a newer judgement or a verified row supersedes is not a failure: nil is returned and the row that stands is the
// newer one.
func (r *FinalityStatusRepository) UpsertStatus(ctx context.Context, s finality.BuilderStatus) error {
	if _, err := finality.ParseProofID(s.ProofID); err != nil {
		return err
	}
	if s.Class == finality.BuilderVerified && (s.Seq == 0 || s.LevelReached != s.TargetLevel) {
		return finality.NewState(finality.CodeGuardRefused, "proof_id", s.ProofID, "seq", s.Seq,
			"cause", fmt.Sprintf("a verified status names the addendum of its own level (seq > 0, levelReached %s = target %s)", s.LevelReached, s.TargetLevel))
	}
	doc, err := s.Document()
	if err != nil {
		return err
	}
	at := s.JudgedAt
	if at.IsZero() {
		at = time.Now()
	}
	// the founding addendum: the verified level itself, or the level a non-verified row says the leg has reached
	foundLevel, foundSeq := int16(0), int64(0)
	switch {
	case s.Class == finality.BuilderVerified:
		foundLevel, foundSeq = int16(s.TargetLevel), int64(s.Seq)
	case s.LevelReached.Stored():
		foundLevel = int16(s.LevelReached)
	}
	var founded bool
	var written int
	err = r.client.DB().QueryRowContext(ctx, `WITH claim AS (
			SELECT $6::smallint = 0 OR EXISTS (SELECT 1 FROM proof_finality_addenda a
				WHERE a.proof_id = $1::uuid AND a.level = $6 AND a.chain = $2 AND ($7::bigint = 0 OR a.seq = $7)) AS founded
		), written AS (
			INSERT INTO proof_finality_status (proof_id, chain, target_level, state, judged_at)
			SELECT $1::uuid, $2, $3, $4::jsonb, $5 FROM claim WHERE claim.founded
			ON CONFLICT (proof_id, target_level) DO UPDATE
				SET chain = EXCLUDED.chain, state = EXCLUDED.state, judged_at = EXCLUDED.judged_at
				WHERE proof_finality_status.state->>'class' <> 'verified'
				  AND (proof_finality_status.judged_at <= EXCLUDED.judged_at OR EXCLUDED.state->>'class' = 'verified')
			RETURNING 1
		) SELECT (SELECT founded FROM claim), (SELECT count(*) FROM written)`,
		s.ProofID, int64(s.Chain), int16(s.TargetLevel), string(doc), at.UTC(), foundLevel, foundSeq).Scan(&founded, &written)
	if err != nil {
		return err
	}
	if !founded {
		return finality.NewState(finality.CodeGuardRefused, "proof_id", s.ProofID, "seq", s.Seq,
			"cause", fmt.Sprintf("a %s status for %s claims level %s, which the proof does not hold as an addendum", s.Class, s.TargetLevel, finality.Level(foundLevel)))
	}
	return nil
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
