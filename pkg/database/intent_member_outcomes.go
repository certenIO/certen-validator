// Copyright 2026 Certen Protocol
//
// An intent's status, derived from every chain member's outcome.

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

// MemberSettlement is what a member's chain shows for it.
type MemberSettlement string

const (
	// MemberSettlementSettled: the member's settlement transaction executed (status 1).
	MemberSettlementSettled MemberSettlement = "settled"
	// MemberSettlementReverted: the settlement transaction was mined and reverted (final).
	MemberSettlementReverted MemberSettlement = "reverted"
	// MemberSettlementUnobserved: the proof cycle could not observe the settlement.
	MemberSettlementUnobserved MemberSettlement = "unobserved"
	// MemberSettlementNone: no settlement transaction reached the chain.
	MemberSettlementNone MemberSettlement = "none"
)

// MemberProofCycle is whether a member's outcome was written back to Accumulate.
type MemberProofCycle string

const (
	// MemberProofCycleWritten: written back under a quorum attestation.
	MemberProofCycleWritten MemberProofCycle = "written"
	// MemberProofCycleFailed: the proof cycle ended without a write-back.
	MemberProofCycleFailed MemberProofCycle = "failed"
)

// MemberOutcome is one chain member's terminal outcome.
type MemberOutcome struct {
	IntentID string
	ChainID  int64
	// MemberChains is the intent's full member set - every chain it was split into. The same on every
	// report for an intent; the first report records it.
	MemberChains []int64
	Settlement   MemberSettlement
	ProofCycle   MemberProofCycle
	// Legs is how many of the intent's legs this member carries.
	Legs         int
	SettlementTx string
	WriteBackTx  string
	CycleID      string
	Reason       string
	// EffectsProven says whether the member's committed contract-call effects were proven: nil when it
	// committed none (a native transfer) or they were not assessed, true proven, false provably absent -
	// the member settled but did not do what the intent committed to, and counts as failed (RB3-F67).
	EffectsProven *bool
	// ReportedBy is the validator reporting the outcome. A report that replaces a recorded outcome is recorded
	// as a correction under its name (RB4-F58).
	ReportedBy string
}

// RecordedMemberOutcome is a member's outcome as recorded.
type RecordedMemberOutcome struct {
	Settlement   MemberSettlement
	ProofCycle   MemberProofCycle
	SettlementTx string
	WriteBackTx  string
	CycleID      string
	RecordedAt   time.Time
}

// MemberOutcomeOf returns the recorded outcome of an intent's member on a chain, or nil when none is
// recorded. A recorded outcome is terminal: the batch path never queues that member again (RB3-F141).
func (r *IntentLifecycleRepository) MemberOutcomeOf(ctx context.Context, intentID string, chainID int64) (*RecordedMemberOutcome, error) {
	var o RecordedMemberOutcome
	var settlement, cycle string
	var settlementTx, writeBackTx, cycleID sql.NullString
	err := r.client.db.QueryRowContext(ctx, `
		SELECT settlement, proof_cycle, settlement_tx, write_back_tx, cycle_id, recorded_at
		FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = $2`, intentID, chainID).
		Scan(&settlement, &cycle, &settlementTx, &writeBackTx, &cycleID, &o.RecordedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the outcome of %s on chain %d: %w", intentID, chainID, err)
	}
	o.Settlement, o.ProofCycle = MemberSettlement(settlement), MemberProofCycle(cycle)
	o.SettlementTx, o.WriteBackTx, o.CycleID = settlementTx.String, writeBackTx.String, cycleID.String
	return &o, nil
}

// ErrMemberOutcomeInvalid is a report that cannot be recorded as given.
var ErrMemberOutcomeInvalid = errors.New("invalid member outcome")

func (o *MemberOutcome) validate() error {
	switch {
	case o.IntentID == "":
		return fmt.Errorf("%w: no intent id", ErrMemberOutcomeInvalid)
	case o.ChainID == 0:
		return fmt.Errorf("%w: no chain id", ErrMemberOutcomeInvalid)
	case o.Legs <= 0:
		return fmt.Errorf("%w: a member carries at least one leg", ErrMemberOutcomeInvalid)
	case o.ReportedBy == "":
		return fmt.Errorf("%w: no reporting validator", ErrMemberOutcomeInvalid)
	}
	inSet := false
	for _, c := range o.MemberChains {
		if c == o.ChainID {
			inSet = true
		}
	}
	if !inSet {
		return fmt.Errorf("%w: chain %d is not in the intent's member set %v", ErrMemberOutcomeInvalid, o.ChainID, o.MemberChains)
	}
	switch o.Settlement {
	case MemberSettlementSettled, MemberSettlementReverted, MemberSettlementUnobserved, MemberSettlementNone:
	default:
		return fmt.Errorf("%w: settlement %q", ErrMemberOutcomeInvalid, o.Settlement)
	}
	switch o.ProofCycle {
	case MemberProofCycleWritten, MemberProofCycleFailed:
	default:
		return fmt.Errorf("%w: proof cycle %q", ErrMemberOutcomeInvalid, o.ProofCycle)
	}
	return nil
}

// DerivedIntentStatus is what RecordMemberOutcome derived for the intent.
type DerivedIntentStatus struct {
	// Found is false when the intent has no lifecycle row; the member row is still recorded.
	Found bool
	// Terminal is true once every member in the intent's member set has an outcome.
	Terminal bool
	Status   IntentLifecycleStatus
	// Summary names each chain's outcome, in chain order.
	Summary string
}

// RecordMemberOutcome records one chain member's terminal outcome and derives the intent's status
// from every member's, in one transaction serialized on the intent row (RB3-F50).
//
// Each member used to write the whole intent's status, so whichever finished first decided it and the
// terminal guard froze it there. Now the intent is in progress while any member of its member set has
// no outcome; complete only when every member settled and was written back; failed otherwise, with
// every chain's outcome in error_message. A member's row is replaced by a later report for the same
// chain (a retried write-back), and the intent is derived again.
func (r *IntentLifecycleRepository) RecordMemberOutcome(ctx context.Context, o MemberOutcome) (DerivedIntentStatus, error) {
	var derived DerivedIntentStatus
	if err := o.validate(); err != nil {
		return derived, err
	}
	chains := append([]int64(nil), o.MemberChains...)
	sort.Slice(chains, func(i, j int) bool { return chains[i] < chains[j] })

	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return derived, fmt.Errorf("begin member outcome: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // a committed transaction ignores it

	// Lock the intent row first: every report for this intent derives in turn. Its terminal outcome is read
	// with it, so a change to it can be recorded (RB4-F58).
	var stored pq.Int64Array
	var before lifecycleOutcome
	err = tx.QueryRowContext(ctx, `
		SELECT member_chains, status, legs_completed, legs_failed, failed_at, completed_at, error_message, failure_class, write_back_tx
		FROM intent_lifecycle WHERE intent_id = $1 FOR UPDATE`, o.IntentID).
		Scan(&stored, &before.Status, &before.LegsCompleted, &before.LegsFailed, &before.FailedAt, &before.CompletedAt,
			&before.ErrorMessage, &before.FailureClass, &before.WriteBackTx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		derived.Found = false
	case err != nil:
		return derived, fmt.Errorf("lock intent %s: %w", o.IntentID, err)
	default:
		derived.Found = true
	}

	if derived.Found {
		if len(stored) == 0 {
			if _, err := tx.ExecContext(ctx,
				`UPDATE intent_lifecycle SET member_chains = $1 WHERE intent_id = $2`,
				pq.Int64Array(chains), o.IntentID); err != nil {
				return derived, fmt.Errorf("record member set of %s: %w", o.IntentID, err)
			}
		} else if !sameChains(stored, chains) {
			return derived, fmt.Errorf("%w: intent %s was recorded with members %v, this report names %v",
				ErrMemberOutcomeInvalid, o.IntentID, []int64(stored), chains)
		}
	}

	// The member's recorded outcome, if any. A member written back under a quorum attestation is never replaced by a
	// report that it was not: the write-back is on Accumulate, so that report can only be stale (a broken cycle's
	// outbox entry replayed after a repair). Any other change is recorded as a correction.
	prior, err := recordedMemberRow(ctx, tx, o.IntentID, o.ChainID)
	if err != nil {
		return derived, err
	}
	next := memberRowOf(o)
	if prior != nil && prior.ProofCycle == string(MemberProofCycleWritten) && o.ProofCycle != MemberProofCycleWritten {
		return derived, fmt.Errorf("%w: intent %s member %d was written back by cycle %s (%s); a later report that it was not (cycle %s) is stale",
			ErrMemberOutcomeInvalid, o.IntentID, o.ChainID, prior.CycleID, prior.WriteBackTx, o.CycleID)
	}
	if prior != nil && !prior.sameAs(next) {
		reason := fmt.Sprintf("member outcome replaced by a later report: cycle %s replaces cycle %s", o.CycleID, prior.CycleID)
		evidence := map[string]any{"settlement_tx": o.SettlementTx, "write_back_tx": o.WriteBackTx, "cycle_id": o.CycleID}
		if _, err := recordCorrection(ctx, tx, "intent_member_outcome", fmt.Sprintf("%s/%d", o.IntentID, o.ChainID),
			reason, prior, next, evidence, o.ReportedBy); err != nil {
			return derived, fmt.Errorf("record the replaced outcome of %s/%d: %w", o.IntentID, o.ChainID, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO intent_member_outcomes
			(intent_id, chain_id, settlement, proof_cycle, legs, settlement_tx, write_back_tx, cycle_id, reason, effects_proven, recorded_at)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''), $10, now())
		ON CONFLICT (intent_id, chain_id) DO UPDATE SET
			settlement = EXCLUDED.settlement, proof_cycle = EXCLUDED.proof_cycle, legs = EXCLUDED.legs,
			settlement_tx = EXCLUDED.settlement_tx, write_back_tx = EXCLUDED.write_back_tx,
			cycle_id = EXCLUDED.cycle_id, reason = EXCLUDED.reason, effects_proven = EXCLUDED.effects_proven,
			recorded_at = now()`,
		o.IntentID, o.ChainID, string(o.Settlement), string(o.ProofCycle), o.Legs,
		o.SettlementTx, o.WriteBackTx, o.CycleID, o.Reason, o.EffectsProven); err != nil {
		return derived, fmt.Errorf("record member outcome %s/%d: %w", o.IntentID, o.ChainID, err)
	}

	if !derived.Found {
		return derived, tx.Commit()
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT chain_id, settlement, proof_cycle, legs, COALESCE(settlement_tx, ''), COALESCE(write_back_tx, ''), COALESCE(reason, ''),
		       effects_proven
		FROM intent_member_outcomes WHERE intent_id = $1 ORDER BY chain_id`, o.IntentID)
	if err != nil {
		return derived, fmt.Errorf("read member outcomes of %s: %w", o.IntentID, err)
	}
	type row struct {
		settlement, proofCycle, settlementTx, writeBackTx, reason string
		legs                                                      int
		effectsProven                                             sql.NullBool
	}
	got := map[int64]row{}
	for rows.Next() {
		var c int64
		var rr row
		if err := rows.Scan(&c, &rr.settlement, &rr.proofCycle, &rr.legs, &rr.settlementTx, &rr.writeBackTx, &rr.reason, &rr.effectsProven); err != nil {
			rows.Close()
			return derived, fmt.Errorf("scan member outcome: %w", err)
		}
		got[c] = rr
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return derived, fmt.Errorf("read member outcomes of %s: %w", o.IntentID, err)
	}

	complete := true
	var legsDone, legsFailed int
	parts := make([]string, 0, len(chains))
	lastWriteBack := ""
	for _, c := range chains {
		rr, ok := got[c]
		if !ok {
			derived.Terminal = false
			parts = append(parts, strconv.FormatInt(c, 10)+": pending")
			complete = false
			continue
		}
		part := fmt.Sprintf("%d: %s, %s", c, rr.settlement, map[string]string{"written": "written back", "failed": "not written back"}[rr.proofCycle])
		if rr.settlementTx != "" {
			part += " (tx " + rr.settlementTx + ")"
		}
		// Settled but a committed effect provably absent: it did not do what the intent committed to.
		unproven := rr.effectsProven.Valid && !rr.effectsProven.Bool
		if unproven {
			part += ", committed effects NOT proven"
		}
		if rr.reason != "" {
			part += " - " + rr.reason
		}
		parts = append(parts, part)
		if rr.settlement == string(MemberSettlementSettled) && !unproven {
			legsDone += rr.legs
		} else {
			legsFailed += rr.legs
		}
		if rr.settlement != string(MemberSettlementSettled) || unproven || rr.proofCycle != string(MemberProofCycleWritten) {
			complete = false
		}
		if rr.writeBackTx != "" {
			lastWriteBack = rr.writeBackTx
		}
	}
	derived.Summary = strings.Join(parts, "; ")
	derived.Terminal = len(got) >= len(chains) && allPresent(got, chains)

	now := time.Now().UTC()
	if !derived.Terminal {
		// Still in progress: counts only. The status stays what the running cycles set it to.
		if _, err := tx.ExecContext(ctx, `
			UPDATE intent_lifecycle SET legs_completed = $1, legs_failed = $2, updated_at = $3 WHERE intent_id = $4`,
			legsDone, legsFailed, now, o.IntentID); err != nil {
			return derived, fmt.Errorf("update progress of %s: %w", o.IntentID, err)
		}
		derived.Status = ""
		return derived, tx.Commit()
	}

	if complete {
		derived.Status = IntentLifecycleComplete
		_, err = tx.ExecContext(ctx, `
			UPDATE intent_lifecycle SET status = $1, legs_completed = $2, legs_failed = $3,
				completed_at = COALESCE(completed_at, $4), failed_at = NULL, error_message = NULL, failure_class = NULL,
				write_back_tx = COALESCE(NULLIF($5, ''), write_back_tx), updated_at = $4
			WHERE intent_id = $6`,
			string(IntentLifecycleComplete), legsDone, legsFailed, now, lastWriteBack, o.IntentID)
	} else {
		derived.Status = IntentLifecycleFailed
		_, err = tx.ExecContext(ctx, `
			UPDATE intent_lifecycle SET status = $1, legs_completed = $2, legs_failed = $3,
				failed_at = COALESCE(failed_at, $4), completed_at = NULL, error_message = $5,
				failure_class = 'settlement_failed',
				write_back_tx = COALESCE(NULLIF($6, ''), write_back_tx), updated_at = $4
			WHERE intent_id = $7`,
			string(IntentLifecycleFailed), legsDone, legsFailed, now, derived.Summary, lastWriteBack, o.IntentID)
	}
	if err != nil {
		return derived, fmt.Errorf("derive status of %s: %w", o.IntentID, err)
	}

	// A terminal outcome that changes is a correction of a published outcome (RB4-F58): keep what it was.
	if before.terminal() {
		var after lifecycleOutcome
		if err := tx.QueryRowContext(ctx, `
			SELECT status, legs_completed, legs_failed, failed_at, completed_at, error_message, failure_class, write_back_tx
			FROM intent_lifecycle WHERE intent_id = $1`, o.IntentID).
			Scan(&after.Status, &after.LegsCompleted, &after.LegsFailed, &after.FailedAt, &after.CompletedAt,
				&after.ErrorMessage, &after.FailureClass, &after.WriteBackTx); err != nil {
			return derived, fmt.Errorf("read the derived status of %s: %w", o.IntentID, err)
		}
		if before.Status != after.Status || before.ErrorMessage != after.ErrorMessage || before.FailureClass != after.FailureClass {
			reason := fmt.Sprintf("intent outcome derived again after member %d's outcome was replaced (cycle %s)", o.ChainID, o.CycleID)
			evidence := map[string]any{"chain_id": o.ChainID, "settlement_tx": o.SettlementTx, "write_back_tx": o.WriteBackTx, "cycle_id": o.CycleID}
			if _, err := recordCorrection(ctx, tx, "intent_lifecycle", o.IntentID, reason, before.view(), after.view(), evidence, o.ReportedBy); err != nil {
				return derived, fmt.Errorf("record the replaced outcome of %s: %w", o.IntentID, err)
			}
		}
	}
	return derived, tx.Commit()
}

// memberRow is a member outcome as stored, as a correction records it.
type memberRow struct {
	Settlement    string `json:"settlement"`
	ProofCycle    string `json:"proof_cycle"`
	Legs          int    `json:"legs"`
	SettlementTx  string `json:"settlement_tx"`
	WriteBackTx   string `json:"write_back_tx"`
	CycleID       string `json:"cycle_id"`
	Reason        string `json:"reason"`
	EffectsProven *bool  `json:"effects_proven"`
}

func memberRowOf(o MemberOutcome) memberRow {
	return memberRow{Settlement: string(o.Settlement), ProofCycle: string(o.ProofCycle), Legs: o.Legs,
		SettlementTx: o.SettlementTx, WriteBackTx: o.WriteBackTx, CycleID: o.CycleID, Reason: o.Reason, EffectsProven: o.EffectsProven}
}

func (m *memberRow) sameAs(n memberRow) bool {
	sameEffects := (m.EffectsProven == nil) == (n.EffectsProven == nil) &&
		(m.EffectsProven == nil || *m.EffectsProven == *n.EffectsProven)
	return m.Settlement == n.Settlement && m.ProofCycle == n.ProofCycle && m.Legs == n.Legs && m.SettlementTx == n.SettlementTx &&
		m.WriteBackTx == n.WriteBackTx && m.CycleID == n.CycleID && m.Reason == n.Reason && sameEffects
}

// recordedMemberRow reads (and locks) a member's recorded outcome, or nil when none is recorded.
func recordedMemberRow(ctx context.Context, tx *sql.Tx, intentID string, chainID int64) (*memberRow, error) {
	var m memberRow
	var settlementTx, writeBackTx, cycleID, reason sql.NullString
	var effects sql.NullBool
	err := tx.QueryRowContext(ctx, `
		SELECT settlement, proof_cycle, legs, settlement_tx, write_back_tx, cycle_id, reason, effects_proven
		FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = $2 FOR UPDATE`, intentID, chainID).
		Scan(&m.Settlement, &m.ProofCycle, &m.Legs, &settlementTx, &writeBackTx, &cycleID, &reason, &effects)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the recorded outcome of %s/%d: %w", intentID, chainID, err)
	}
	m.SettlementTx, m.WriteBackTx, m.CycleID, m.Reason = settlementTx.String, writeBackTx.String, cycleID.String, reason.String
	if effects.Valid {
		v := effects.Bool
		m.EffectsProven = &v
	}
	return &m, nil
}

// lifecycleOutcome is an intent's recorded outcome, as a correction records it.
type lifecycleOutcome struct {
	Status                    sql.NullString
	LegsCompleted, LegsFailed sql.NullInt64
	FailedAt, CompletedAt     sql.NullTime
	ErrorMessage              sql.NullString
	FailureClass              sql.NullString
	WriteBackTx               sql.NullString
}

func (l lifecycleOutcome) terminal() bool {
	return l.Status.String == string(IntentLifecycleComplete) || l.Status.String == string(IntentLifecycleFailed)
}

func (l lifecycleOutcome) view() map[string]any {
	opt := func(v sql.NullString) any {
		if v.Valid {
			return v.String
		}
		return nil
	}
	optTime := func(v sql.NullTime) any {
		if v.Valid {
			return v.Time.UTC().Format(time.RFC3339Nano)
		}
		return nil
	}
	optInt := func(v sql.NullInt64) any {
		if v.Valid {
			return v.Int64
		}
		return nil
	}
	return map[string]any{
		"status": opt(l.Status), "legs_completed": optInt(l.LegsCompleted), "legs_failed": optInt(l.LegsFailed),
		"failed_at": optTime(l.FailedAt), "completed_at": optTime(l.CompletedAt), "error_message": opt(l.ErrorMessage),
		"failure_class": opt(l.FailureClass), "write_back_tx": opt(l.WriteBackTx),
	}
}

func sameChains(a pq.Int64Array, b []int64) bool {
	x := append([]int64(nil), a...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	if len(x) != len(b) {
		return false
	}
	for i := range x {
		if x[i] != b[i] {
			return false
		}
	}
	return true
}

func allPresent[T any](got map[int64]T, chains []int64) bool {
	for _, c := range chains {
		if _, ok := got[c]; !ok {
			return false
		}
	}
	return true
}
