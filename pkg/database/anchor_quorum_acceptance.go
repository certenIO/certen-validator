// Copyright 2026 Certen Protocol
//
// The acceptance gate for anchor quorum evidence: §4.E and §4.D of the runbook, as code.

package database

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// AnchorQuorumCheck is one acceptance check and what it found.
type AnchorQuorumCheck struct {
	// ID is the runbook's label for this check (E1…E8, D3, D4).
	ID string
	// Name says what is being asserted, in the terms the runbook uses.
	Name string
	// Passed is the gate. A check that could not be evaluated is NOT passed.
	Passed bool
	// Detail is the observed value, present whether the check passed or failed, so a passing run is
	// evidence rather than a row of ticks.
	Detail string
}

// AnchorQuorumAcceptance is one run of the gate over one anchor.
type AnchorQuorumAcceptance struct {
	ChainID  int64
	BundleID string
	Checks   []AnchorQuorumCheck
}

// Passed reports whether every check passed. This is the sign-off condition: the runbook requires all of
// them, so a partial pass is a fail.
func (a *AnchorQuorumAcceptance) Passed() bool {
	if len(a.Checks) == 0 {
		return false
	}
	for _, c := range a.Checks {
		if !c.Passed {
			return false
		}
	}
	return true
}

// Failures returns only the checks that did not pass.
func (a *AnchorQuorumAcceptance) Failures() []AnchorQuorumCheck {
	var out []AnchorQuorumCheck
	for _, c := range a.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

func (a *AnchorQuorumAcceptance) add(id, name string, passed bool, format string, args ...interface{}) {
	a.Checks = append(a.Checks, AnchorQuorumCheck{
		ID: id, Name: name, Passed: passed, Detail: fmt.Sprintf(format, args...),
	})
}

// AnchorQuorumOnChain is what the chain says about an anchor, supplied by the caller.
//
// The database cannot answer E3 by itself — "the row agrees with the chain" is only meaningful if someone
// reads the chain. A nil value means the chain was not consulted, and E3 is recorded as NOT passed rather
// than quietly skipped: a gate that drops the checks it cannot run reports a clean sheet for an anchor
// nobody verified.
type AnchorQuorumOnChain struct {
	// VerifyTx is the transaction that proved the anchor.
	VerifyTx string
	// Root is the merkle root the anchor holds on-chain.
	Root []byte
	// ProofExecuted is anchors(bundleId).proofExecuted.
	ProofExecuted bool
}

// AnchorQuorumAcceptanceOptions bounds one run.
type AnchorQuorumAcceptanceOptions struct {
	// ExpectedSigners is the fleet size the runbook's E2/E4 name (7). Zero accepts whatever the row
	// records, still requiring signed == total voting power and distinct signers.
	ExpectedSigners int
	// OnChain is the chain's own account of this anchor. Nil leaves E3 failed.
	OnChain *AnchorQuorumOnChain
	// SettledWindow bounds E8. Zero means one hour.
	SettledWindow time.Duration
	// QuarantinedEntries is how many outbox entries are set aside on this node (E7). Negative means the
	// outbox was not inspected, which leaves E7 failed.
	QuarantinedEntries int
}

// RunAnchorQuorumAcceptance evaluates the runbook's live end-to-end gate against one anchor.
//
// Every check is phrased as a question to the database rather than an assertion by the writer that just
// ran. That distinction is the whole point: the defect this gate exists for was introduced by code that
// believed it was correct, and a check sharing its assumptions would have agreed with it.
func RunAnchorQuorumAcceptance(
	ctx context.Context,
	db *sql.DB,
	chainID int64,
	bundleID string,
	opts AnchorQuorumAcceptanceOptions,
) (*AnchorQuorumAcceptance, error) {
	if db == nil {
		return nil, fmt.Errorf("anchor quorum acceptance: a database is required")
	}
	if chainID == 0 || bundleID == "" {
		return nil, fmt.Errorf("anchor quorum acceptance: chain id and bundle id are required")
	}
	res := &AnchorQuorumAcceptance{ChainID: chainID, BundleID: bundleID}

	// ─── E1: exactly one canonical row ──────────────────────────────────────────────────────────────
	var rowCount int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM anchor_batches WHERE chain_id = $1 AND bundle_id = $2`,
		chainID, bundleID).Scan(&rowCount); err != nil {
		return nil, fmt.Errorf("E1: %w", err)
	}
	res.add("E1", "exactly one canonical row for (chain_id, bundle_id)", rowCount == 1,
		"found %d row(s)", rowCount)
	if rowCount == 0 {
		// Nothing further is answerable about a row that does not exist. Record the remaining checks as
		// failed rather than erroring out, so the report names every unmet condition at once.
		for _, c := range []struct{ id, name string }{
			{"E2", "quorum_reached, attestation_count and voting power"},
			{"E3", "verify_tx and proofExecuted agree with the chain"},
			{"E4", "one attestation row per distinct signer"},
			{"E5", "proofs_service reports batch_quorum_met=true"},
			{"E6", "layer 5 binds the anchor-create tx and the published root"},
		} {
			res.add(c.id, c.name, false, "no canonical row exists")
		}
		appendFleetChecks(ctx, db, res, opts)
		return res, nil
	}

	// ─── E2: the quorum the row claims ──────────────────────────────────────────────────────────────
	var (
		quorumReached    bool
		attestationCount int
		signedPower      sql.NullString
		totalPower       sql.NullString
		storedRoot       []byte
		verifyTx         sql.NullString
		anchorCreateTx   sql.NullString
		evidenceSource   sql.NullString
	)
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(quorum_reached, FALSE), COALESCE(attestation_count, 0),
		       signed_voting_power::text, total_voting_power::text, merkle_root,
		       anchor_create_tx, verify_tx, evidence_source
		  FROM anchor_batches WHERE chain_id = $1 AND bundle_id = $2`,
		chainID, bundleID).Scan(&quorumReached, &attestationCount, &signedPower, &totalPower,
		&storedRoot, &anchorCreateTx, &verifyTx, &evidenceSource)
	if err != nil {
		return nil, fmt.Errorf("E2: %w", err)
	}

	powersMatch := signedPower.Valid && totalPower.Valid && signedPower.String == totalPower.String
	countOK := opts.ExpectedSigners == 0 || attestationCount == opts.ExpectedSigners
	res.add("E2", "quorum_reached, attestation_count and voting power",
		quorumReached && powersMatch && countOK,
		"quorum_reached=%t attestation_count=%d signed=%s total=%s",
		quorumReached, attestationCount, nullOr(signedPower, "NULL"), nullOr(totalPower, "NULL"))

	// ─── E3: the chain agrees ───────────────────────────────────────────────────────────────────────
	switch {
	case opts.OnChain == nil:
		res.add("E3", "verify_tx and proofExecuted agree with the chain", false,
			"the chain was not consulted; this check cannot pass without it")
	default:
		txMatches := verifyTx.Valid &&
			strings.EqualFold(strings.TrimSpace(verifyTx.String), strings.TrimSpace(opts.OnChain.VerifyTx))
		rootMatches := len(opts.OnChain.Root) > 0 && hex.EncodeToString(storedRoot) == hex.EncodeToString(opts.OnChain.Root)
		res.add("E3", "verify_tx and proofExecuted agree with the chain",
			txMatches && rootMatches && opts.OnChain.ProofExecuted,
			"stored verify_tx=%s chain verify_tx=%s root_matches=%t proofExecuted=%t",
			nullOr(verifyTx, "NULL"), opts.OnChain.VerifyTx, rootMatches, opts.OnChain.ProofExecuted)
	}

	// ─── E4: one attestation per distinct signer ────────────────────────────────────────────────────
	var attRows, distinctAddrs int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*), count(DISTINCT ba.evm_address)
		  FROM batch_attestations ba
		  JOIN anchor_batches ab ON ab.id = ba.batch_id
		 WHERE ab.chain_id = $1 AND ab.bundle_id = $2`,
		chainID, bundleID).Scan(&attRows, &distinctAddrs); err != nil {
		return nil, fmt.Errorf("E4: %w", err)
	}
	// Distinctness is the property that matters: seven rows naming one address is one signature claimed
	// seven times, which is exactly the shape a forged quorum would take.
	e4 := attRows > 0 && attRows == distinctAddrs &&
		(opts.ExpectedSigners == 0 || attRows == opts.ExpectedSigners)
	res.add("E4", "one attestation row per distinct signer", e4,
		"%d attestation row(s), %d distinct evm_address", attRows, distinctAddrs)

	// ─── E5: what proofs_service will report ────────────────────────────────────────────────────────
	//
	// The same expression proofs_service reads, run here rather than trusted. If this disagrees with the
	// UI, the UI is reading a different row, which is itself the finding.
	var quorumMet sql.NullBool
	err = db.QueryRowContext(ctx, `
		SELECT COALESCE(ab.quorum_reached AND ab.bundle_id IS NOT NULL, FALSE)
		  FROM anchor_batches ab WHERE ab.chain_id = $1 AND ab.bundle_id = $2`,
		chainID, bundleID).Scan(&quorumMet)
	if err != nil {
		return nil, fmt.Errorf("E5: %w", err)
	}
	res.add("E5", "proofs_service reports batch_quorum_met=true", quorumMet.Valid && quorumMet.Bool,
		"batch_quorum_met=%t", quorumMet.Valid && quorumMet.Bool)

	// ─── E6: layer 5 binds the anchor-create tx and the published root ──────────────────────────────
	//
	// This is the d2d24ab3 check. A standing layer-5 row for any member of this anchor must name the
	// anchor-create transaction and the root the anchor actually holds — never the settlement tx, and
	// never a root computed locally.
	var l5Total, l5Agreeing int
	err = db.QueryRowContext(ctx, `
		SELECT count(*),
		       count(*) FILTER (
		           WHERE LOWER(cpl.layer_json->>'batchRoot') = encode(ab.merkle_root, 'hex')
		             AND (
		                   ab.anchor_create_tx IS NULL
		                OR LOWER(COALESCE(cpl.layer_json->>'anchorTx', '')) = LOWER(ab.anchor_create_tx)
		             ))
		  FROM chained_proof_layers cpl
		  JOIN proof_artifacts pa ON pa.proof_id = cpl.proof_id
		  JOIN batch_transactions bt ON bt.intent_id = pa.intent_id
		  JOIN anchor_batches ab ON ab.id = bt.batch_id
		 WHERE cpl.layer_number = 5
		   AND cpl.superseded_at IS NULL
		   AND cpl.layer_json ? 'batchRoot'
		   AND ab.chain_id = $1 AND ab.bundle_id = $2`,
		chainID, bundleID).Scan(&l5Total, &l5Agreeing)
	if err != nil {
		return nil, fmt.Errorf("E6: %w", err)
	}
	// No layer-5 row yet is not a failure: the binding is written when the proof is built, which may be
	// after the anchor is recorded. A row that DISAGREES is always a failure.
	res.add("E6", "layer 5 binds the anchor-create tx and the published root", l5Total == l5Agreeing,
		"%d standing layer-5 row(s) for this anchor, %d agreeing", l5Total, l5Agreeing)

	appendFleetChecks(ctx, db, res, opts)
	return res, nil
}

// appendFleetChecks adds the two checks that are about the fleet rather than this one anchor.
func appendFleetChecks(
	ctx context.Context,
	db *sql.DB,
	res *AnchorQuorumAcceptance,
	opts AnchorQuorumAcceptanceOptions,
) {
	// ─── E7: nothing is in conflict on this node ────────────────────────────────────────────────────
	//
	// A conflict quarantines its evidence rather than overwriting a row, so a non-empty quarantine is the
	// durable form of "anchor_quorum_conflict was logged".
	switch {
	case opts.QuarantinedEntries < 0:
		res.add("E7", "no anchor quorum conflict on this node", false,
			"the outbox quarantine was not inspected; this check cannot pass without it")
	default:
		res.add("E7", "no anchor quorum conflict on this node", opts.QuarantinedEntries == 0,
			"%d quarantined outbox entr(ies)", opts.QuarantinedEntries)
	}

	// ─── E8: nothing settled recently without a canonical row ───────────────────────────────────────
	window := opts.SettledWindow
	if window <= 0 {
		window = time.Hour
	}
	rep, err := (EvidenceQueries{DB: db, Window: window}).Run(ctx)
	if err != nil {
		res.add("E8", "no settled intent lacks a canonical anchor row", false,
			"the standing check could not run: %v", err)
		return
	}
	res.add("E8", "no settled intent lacks a canonical anchor row", rep.SettledWithoutCanonicalRow == 0,
		"%d settled intent(s) with no canonical row in the last %s; %d contradicted layer-5 row(s)",
		rep.SettledWithoutCanonicalRow, window, rep.ContradictedLayer5Rows)
}

// AnchorQuorumBackfillGate is §4.D: the whole-table conditions a backfill must leave true.
type AnchorQuorumBackfillGate struct {
	// BackfilledRows is D3: rows whose evidence came from the chain.
	BackfilledRows int
	// ShadowRowsClaimingQuorum is D4, and must be ZERO. A shadow row is a per-validator copy over a root
	// nobody published; quorum_reached on one of them would republish the original defect.
	ShadowRowsClaimingQuorum int
	// CanonicalRowsWithoutBundle must be zero: quorum_reached is meaningful only on a canonical row.
	CanonicalRowsWithoutBundle int
	// ContradictedLayer5Rows must be zero.
	ContradictedLayer5Rows int
}

// Passed reports whether the backfill left the tables in the state §4.D requires.
func (g *AnchorQuorumBackfillGate) Passed() bool {
	return g.ShadowRowsClaimingQuorum == 0 &&
		g.CanonicalRowsWithoutBundle == 0 &&
		g.ContradictedLayer5Rows == 0
}

// RunAnchorQuorumBackfillGate evaluates D3 and D4 over the whole table.
func RunAnchorQuorumBackfillGate(ctx context.Context, db *sql.DB) (*AnchorQuorumBackfillGate, error) {
	if db == nil {
		return nil, fmt.Errorf("anchor quorum backfill gate: a database is required")
	}
	g := &AnchorQuorumBackfillGate{}

	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM anchor_batches
		 WHERE COALESCE(quorum_reached, FALSE) AND evidence_source = 'chain_backfill'`).
		Scan(&g.BackfilledRows); err != nil {
		return nil, fmt.Errorf("D3: %w", err)
	}

	// D4. The wording matters: NOT "no shadow rows" — they are kept, labelled, and ignored by readers —
	// but "no shadow row asserts a quorum".
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM anchor_batches
		 WHERE COALESCE(quorum_reached, FALSE) AND evidence_source = 'legacy_shadow'`).
		Scan(&g.ShadowRowsClaimingQuorum); err != nil {
		return nil, fmt.Errorf("D4: %w", err)
	}

	// The same defect stated without relying on the label being right: quorum on a row that has no
	// bundle id is a quorum over a root the contract never keyed.
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM anchor_batches
		 WHERE COALESCE(quorum_reached, FALSE) AND bundle_id IS NULL`).
		Scan(&g.CanonicalRowsWithoutBundle); err != nil {
		return nil, fmt.Errorf("D4 (unlabelled): %w", err)
	}

	rep, err := (EvidenceQueries{DB: db}).Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("D: standing checks: %w", err)
	}
	g.ContradictedLayer5Rows = rep.ContradictedLayer5Rows
	return g, nil
}

func nullOr(s sql.NullString, fallback string) string {
	if !s.Valid {
		return fallback
	}
	return s.String
}
