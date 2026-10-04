package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Resolving intents left in `authorized` with nothing executed (RB6-F12; owner decision 2026-10-04: every intent ends in
// a named state).
//
// An intent the validators authorized and then never processed to an outcome stayed `authorized` for good - 108 on
// 2026-10-04, dated 2026-03-08 … 2026-10-02, most from before member outcomes were recorded. Each is resolved only on
// facts the database itself holds at the moment of the change, all in one transaction: still authorized past the horizon,
// no member outcome, none of its batches ever anchored (a CERTEN settlement cannot execute without its anchor on chain),
// and no chain execution recorded for it. Then it fails as processing_failed - CERTEN did not complete processing it,
// nothing of it executed anywhere - and the state it replaces is kept as a correction with that evidence.

// StaleIntent is one intent the resolution would change, with its evidence.
type StaleIntent struct {
	IntentID      string    `json:"intent_id"`
	AuthorizedAt  time.Time `json:"authorized_at"`
	Batches       int       `json:"batches"`
	AnchoredBatch int       `json:"anchored_batches"`
	Executions    int       `json:"chain_executions"`
}

// staleIntentsSQL selects every intent that may be resolved: the conditions are restated inside the update, so a row that
// changed in between is left alone.
const staleIntentsSQL = `
	SELECT l.intent_id, COALESCE(l.authorized_at, l.created_at),
	       (SELECT count(DISTINCT b.batch_id) FROM batch_transactions b WHERE b.intent_id = l.intent_id),
	       (SELECT count(DISTINCT b.batch_id) FROM batch_transactions b JOIN anchor_batches a ON a.id = b.batch_id
	         WHERE b.intent_id = l.intent_id AND a.anchor_tx_hash IS NOT NULL),
	       (SELECT count(*) FROM proof_artifacts p JOIN chain_execution_results c ON c.result_id = p.chain_execution_id
	         WHERE p.intent_id = l.intent_id)
	FROM intent_lifecycle l
	WHERE l.status = 'authorized' AND COALESCE(l.authorized_at, l.created_at) < $1
	  AND NOT EXISTS (SELECT 1 FROM intent_member_outcomes m WHERE m.intent_id = l.intent_id)
	ORDER BY 2`

// StaleIntents lists the intents authorized before horizon that ResolveStaleIntent may resolve, with their evidence;
// an intent with an anchored batch or a recorded chain execution is listed so it can be seen, and is never resolved.
func (r *IntentLifecycleRepository) StaleIntents(ctx context.Context, horizon time.Time) ([]StaleIntent, error) {
	rows, err := r.client.db.QueryContext(ctx, staleIntentsSQL, horizon)
	if err != nil {
		return nil, fmt.Errorf("read stale intents: %w", err)
	}
	defer rows.Close()
	var out []StaleIntent
	for rows.Next() {
		var s StaleIntent
		if err := rows.Scan(&s.IntentID, &s.AuthorizedAt, &s.Batches, &s.AnchoredBatch, &s.Executions); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ResolveStaleIntent fails one stale intent as processing_failed, re-checking every condition under the intent's row lock,
// and records the replaced state as a correction with the evidence. It reports whether the intent was resolved; one that
// no longer qualifies (it moved on, executed, or was anchored) is left alone.
func (r *IntentLifecycleRepository) ResolveStaleIntent(ctx context.Context, s StaleIntent, horizon time.Time, by string) (bool, error) {
	if s.AnchoredBatch != 0 || s.Executions != 0 {
		return false, nil
	}
	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // a committed transaction ignores it
	var before lifecycleOutcome
	err = tx.QueryRowContext(ctx, `
		SELECT status, legs_completed, legs_failed, failed_at, completed_at, error_message, failure_class, write_back_tx
		FROM intent_lifecycle WHERE intent_id = $1 FOR UPDATE`, s.IntentID).
		Scan(&before.Status, &before.LegsCompleted, &before.LegsFailed, &before.FailedAt, &before.CompletedAt,
			&before.ErrorMessage, &before.FailureClass, &before.WriteBackTx)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lock %s: %w", s.IntentID, err)
	}
	var still StaleIntent
	err = tx.QueryRowContext(ctx, `SELECT intent_id, authorized_at, batches, anchored, executions FROM (`+staleIntentsSQL+`) q(intent_id, authorized_at, batches, anchored, executions)
		WHERE intent_id = $2`, horizon, s.IntentID).Scan(&still.IntentID, &still.AuthorizedAt, &still.Batches, &still.AnchoredBatch, &still.Executions)
	if err == sql.ErrNoRows || still.AnchoredBatch != 0 || still.Executions != 0 {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("re-check %s: %w", s.IntentID, err)
	}
	message := fmt.Sprintf("processing_failed: authorized at %s and never processed to an outcome; nothing of it executed on any chain "+
		"(%d batch(es), none ever anchored; no chain execution recorded) - resolved from the stale state", still.AuthorizedAt.UTC().Format(time.RFC3339),
		still.Batches)
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `
		UPDATE intent_lifecycle SET status = 'failed', failure_class = 'processing_failed', failed_at = $2, error_message = $3, updated_at = $2
		WHERE intent_id = $1 AND status = 'authorized'`, s.IntentID, now, message); err != nil {
		return false, fmt.Errorf("resolve %s: %w", s.IntentID, err)
	}
	after := before
	after.Status = sql.NullString{String: "failed", Valid: true}
	after.FailureClass = sql.NullString{String: "processing_failed", Valid: true}
	after.ErrorMessage = sql.NullString{String: message, Valid: true}
	after.FailedAt = sql.NullTime{Time: now, Valid: true}
	if _, err := recordCorrection(ctx, tx, "intent_lifecycle", s.IntentID, "stale authorized intent resolved (RB6-F12)", before.view(),
		after.view(), still, by); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
