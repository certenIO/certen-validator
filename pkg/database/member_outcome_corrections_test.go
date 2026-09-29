package database

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// RB4-F58. A member's recorded outcome is replaced by a later report for the same chain, and the intent's status is
// derived again (RecordMemberOutcome). Replacing it overwrote the member row and, when the intent went from failed
// to complete, erased failed_at, error_message and failure_class - a published failure rewritten with no record.
// Production 2026-09-29: intent 000ac79a's base member was recorded failed by a proof cycle a restart broke (RB4-F55)
// although its settlement landed; its repair must replace that record, and the replacement must be on record.
//
// Every replacement that changes a member row, and every change of an intent's terminal status, now leaves an
// evidence_corrections row in the same transaction: what was recorded, what replaced it, the evidence, and who.
// A member already written back is never replaced by a report that it was not: that report can only be stale.

type correctionRow struct {
	RecordType, RecordID, Reason, CorrectedBy string
	Previous, Corrected, Evidence             map[string]any
}

func correctionsFor(t *testing.T, ctx context.Context, recordType, recordID string) []correctionRow {
	t.Helper()
	rows, err := testDB.QueryContext(ctx, `
		SELECT record_type, record_id, reason, corrected_by, previous, corrected, chain_evidence
		FROM evidence_corrections WHERE record_type = $1 AND record_id = $2 ORDER BY corrected_at`, recordType, recordID)
	if err != nil {
		t.Fatalf("read corrections: %v", err)
	}
	defer rows.Close()
	var out []correctionRow
	for rows.Next() {
		var c correctionRow
		var prev, next, ev []byte
		if err := rows.Scan(&c.RecordType, &c.RecordID, &c.Reason, &c.CorrectedBy, &prev, &next, &ev); err != nil {
			t.Fatalf("scan correction: %v", err)
		}
		for _, p := range []struct {
			b []byte
			m *map[string]any
		}{{prev, &c.Previous}, {next, &c.Corrected}, {ev, &c.Evidence}} {
			if err := json.Unmarshal(p.b, p.m); err != nil {
				t.Fatalf("decode correction json: %v", err)
			}
		}
		out = append(out, c)
	}
	return out
}

func newTwoMemberIntent(t *testing.T, ctx context.Context) string {
	t.Helper()
	id := "f58-" + uuid.NewString()
	if _, err := testDB.ExecContext(ctx, `INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status) VALUES ($1, $2, 'settling')`,
		id, uuid.NewString()[:16]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = testDB.ExecContext(bg, `DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
		_, _ = testDB.ExecContext(bg, `DELETE FROM intent_lifecycle WHERE intent_id = $1`, id)
	})
	return id
}

func TestARepairedMemberLeavesTheFailureOnRecord(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	id := newTwoMemberIntent(t, ctx)
	members := []int64{84532, 421614}

	// Arbitrum settled and was written back; base was recorded failed by a cycle a restart broke.
	if _, err := repo.RecordMemberOutcome(ctx, MemberOutcome{IntentID: id, ChainID: 421614, MemberChains: members, Legs: 1,
		Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, SettlementTx: "0xarb", WriteBackTx: "acc://wb-arb",
		CycleID: "cycle-arb", ReportedBy: "validator-1"}); err != nil {
		t.Fatal(err)
	}
	failed := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1,
		Settlement: MemberSettlementUnobserved, ProofCycle: MemberProofCycleFailed, CycleID: "cycle-broken",
		Reason: "phase 7 failed: persist chain execution 0xc409: duplicate key", ReportedBy: "validator-6"}
	d, err := repo.RecordMemberOutcome(ctx, failed)
	if err != nil || d.Status != IntentLifecycleFailed {
		t.Fatalf("the broken cycle's report: %v %+v", err, d)
	}
	if got := correctionsFor(t, ctx, "intent_member_outcome", id+"/84532"); len(got) != 0 {
		t.Fatalf("a member's FIRST outcome is not a correction: %d recorded", len(got))
	}
	if got := correctionsFor(t, ctx, "intent_lifecycle", id); len(got) != 0 {
		t.Fatalf("an intent's first terminal status is not a correction: %d recorded", len(got))
	}

	// The repair: the member's proof cycle re-run, settled and written back.
	repaired := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1,
		Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, SettlementTx: "0xc409", WriteBackTx: "acc://wb-base",
		CycleID: "cycle-repair", ReportedBy: "validator-6"}
	d, err = repo.RecordMemberOutcome(ctx, repaired)
	if err != nil || d.Status != IntentLifecycleComplete {
		t.Fatalf("the repair: %v %+v", err, d)
	}

	member := correctionsFor(t, ctx, "intent_member_outcome", id+"/84532")
	if len(member) != 1 {
		t.Fatalf("THE regression: the replaced member outcome left %d corrections, want 1", len(member))
	}
	m := member[0]
	if m.CorrectedBy != "validator-6" || m.Previous["proof_cycle"] != "failed" || m.Previous["cycle_id"] != "cycle-broken" ||
		m.Previous["reason"] != failed.Reason || m.Corrected["proof_cycle"] != "written" || m.Corrected["cycle_id"] != "cycle-repair" ||
		m.Evidence["settlement_tx"] != "0xc409" || m.Evidence["write_back_tx"] != "acc://wb-base" || m.Reason == "" {
		t.Fatalf("the member correction does not state what was replaced, by what and on what evidence: %+v", m)
	}

	lifecycle := correctionsFor(t, ctx, "intent_lifecycle", id)
	if len(lifecycle) != 1 {
		t.Fatalf("THE regression: failed -> complete erased the failure with %d corrections, want 1", len(lifecycle))
	}
	l := lifecycle[0]
	if l.Previous["status"] != "failed" || l.Previous["failure_class"] != "settlement_failed" || l.Previous["error_message"] == nil ||
		l.Previous["failed_at"] == nil || l.Corrected["status"] != "complete" || l.CorrectedBy != "validator-6" {
		t.Fatalf("the lifecycle correction does not keep the failure it replaced: %+v", l)
	}

	// The same report again (an outbox replay) changes nothing and records nothing.
	if _, err := repo.RecordMemberOutcome(ctx, repaired); err != nil {
		t.Fatal(err)
	}
	if n := len(correctionsFor(t, ctx, "intent_member_outcome", id+"/84532")); n != 1 {
		t.Fatalf("an identical report was recorded as a correction: %d", n)
	}
	if n := len(correctionsFor(t, ctx, "intent_lifecycle", id)); n != 1 {
		t.Fatalf("an unchanged status was recorded as a correction: %d", n)
	}
}

func TestAWrittenBackMemberIsNeverReplacedByAStaleFailure(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	id := newTwoMemberIntent(t, ctx)
	members := []int64{84532}

	written := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1,
		Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, SettlementTx: "0xc409", WriteBackTx: "acc://wb",
		CycleID: "cycle-repair", ReportedBy: "validator-6"}
	if _, err := repo.RecordMemberOutcome(ctx, written); err != nil {
		t.Fatal(err)
	}
	// A failure report of the same member left in an outbox by the broken cycle, replayed after the repair.
	stale := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1,
		Settlement: MemberSettlementUnobserved, ProofCycle: MemberProofCycleFailed, CycleID: "cycle-broken",
		Reason: "phase 7 failed", ReportedBy: "validator-6"}
	_, err := repo.RecordMemberOutcome(ctx, stale)
	if !errors.Is(err, ErrMemberOutcomeInvalid) {
		t.Fatalf("a stale failure over a written-back member: want ErrMemberOutcomeInvalid, got %v", err)
	}
	var cycle, status string
	if err := testDB.QueryRowContext(ctx, `SELECT m.proof_cycle, l.status FROM intent_member_outcomes m JOIN intent_lifecycle l USING (intent_id)
		WHERE m.intent_id = $1 AND m.chain_id = 84532`, id).Scan(&cycle, &status); err != nil {
		t.Fatal(err)
	}
	if cycle != "written" || status != "complete" {
		t.Fatalf("the stale report replaced the written-back member: %s / %s", cycle, status)
	}
}

func TestAMemberOutcomeNamesItsReporter(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	id := newTwoMemberIntent(t, ctx)
	_, err := repo.RecordMemberOutcome(ctx, MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: []int64{84532}, Legs: 1,
		Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, CycleID: "c"})
	if !errors.Is(err, ErrMemberOutcomeInvalid) {
		t.Fatalf("an outcome without its reporter: want ErrMemberOutcomeInvalid, got %v", err)
	}
}
