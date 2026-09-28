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

	// Lock the intent row first: every report for this intent derives in turn.
	var stored pq.Int64Array
	err = tx.QueryRowContext(ctx,
		`SELECT member_chains FROM intent_lifecycle WHERE intent_id = $1 FOR UPDATE`, o.IntentID).Scan(&stored)
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
				completed_at = COALESCE(completed_at, $4), failed_at = NULL, error_message = NULL,
				write_back_tx = COALESCE(NULLIF($5, ''), write_back_tx), updated_at = $4
			WHERE intent_id = $6`,
			string(IntentLifecycleComplete), legsDone, legsFailed, now, lastWriteBack, o.IntentID)
	} else {
		derived.Status = IntentLifecycleFailed
		_, err = tx.ExecContext(ctx, `
			UPDATE intent_lifecycle SET status = $1, legs_completed = $2, legs_failed = $3,
				failed_at = COALESCE(failed_at, $4), completed_at = NULL, error_message = $5,
				write_back_tx = COALESCE(NULLIF($6, ''), write_back_tx), updated_at = $4
			WHERE intent_id = $7`,
			string(IntentLifecycleFailed), legsDone, legsFailed, now, derived.Summary, lastWriteBack, o.IntentID)
	}
	if err != nil {
		return derived, fmt.Errorf("derive status of %s: %w", o.IntentID, err)
	}
	return derived, tx.Commit()
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
