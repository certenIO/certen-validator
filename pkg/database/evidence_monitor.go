// Copyright 2026 Certen Protocol
//
// Standing checks over the evidence tables.

package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// EvidenceReport is one pass of the standing checks.
type EvidenceReport struct {
	// SettledWithoutCanonicalRow counts intents that settled in the window with no canonical anchor row.
	// Non-zero means a batch was proven and its evidence never landed — the original 70,236-row outage.
	SettledWithoutCanonicalRow int

	// ContradictedLayer5Rows counts STANDING layer-5 rows naming a root other than the one the canonical
	// anchor for that intent holds. Non-zero means a published claim disagrees with the chain-backed row
	// sitting beside it — the d2d24ab3 shape.
	ContradictedLayer5Rows int
}

// EvidenceQueries runs the standing checks. Read-only.
//
// These are deliberately whole-table questions rather than per-write assertions. Every defect they look
// for was introduced by code that believed it was correct, so a check that shares that code's assumptions
// would have agreed with it. Asking the database "is anything inconsistent right now" does not.
type EvidenceQueries struct {
	DB *sql.DB
	// Window bounds SettledWithoutCanonicalRow. Zero means one hour.
	Window time.Duration
}

// Run executes every check. A failure of ANY check returns an error: a partial report whose zero values
// look like health is worse than no report.
func (q EvidenceQueries) Run(ctx context.Context) (*EvidenceReport, error) {
	if q.DB == nil {
		return nil, fmt.Errorf("evidence checks require a database")
	}
	window := q.Window
	if window <= 0 {
		window = time.Hour
	}

	rep := &EvidenceReport{}

	// An intent is covered if ANY of its member rows belongs to a canonical anchor. The retired shadow
	// pipeline writes one row per validator for the same intent, so "this row is not canonical" proves
	// nothing on its own — the question is whether a canonical row exists anywhere for that intent.
	const settledQ = `
		SELECT count(DISTINCT bt.intent_id)
		  FROM batch_transactions bt
		 WHERE bt.created_at > NOW() - $1::interval
		   AND bt.intent_id IS NOT NULL
		   AND NOT EXISTS (
		       SELECT 1 FROM batch_transactions b2
		         JOIN anchor_batches a2 ON a2.id = b2.batch_id
		        WHERE b2.intent_id = bt.intent_id AND a2.bundle_id IS NOT NULL)`
	if err := q.DB.QueryRowContext(ctx, settledQ, fmt.Sprintf("%d seconds", int(window.Seconds()))).
		Scan(&rep.SettledWithoutCanonicalRow); err != nil {
		return nil, fmt.Errorf("settled-without-canonical check: %w", err)
	}

	// Migration 020's rule, kept as a standing check rather than a one-shot: the migration cleaned what
	// existed, this catches anything new. superseded_at IS NULL means the claim still stands.
	const contradictedQ = `
		SELECT count(*)
		  FROM chained_proof_layers cpl
		  JOIN proof_artifacts pa ON pa.proof_id = cpl.proof_id
		  JOIN batch_transactions bt ON bt.intent_id = pa.intent_id
		  JOIN anchor_batches ab ON ab.id = bt.batch_id AND ab.bundle_id IS NOT NULL
		 WHERE cpl.layer_number = 5
		   AND cpl.superseded_at IS NULL
		   AND cpl.layer_json ? 'batchRoot'
		   AND LOWER(cpl.layer_json->>'batchRoot') <> encode(ab.merkle_root, 'hex')`
	if err := q.DB.QueryRowContext(ctx, contradictedQ).Scan(&rep.ContradictedLayer5Rows); err != nil {
		return nil, fmt.Errorf("contradicted-layer5 check: %w", err)
	}

	return rep, nil
}
