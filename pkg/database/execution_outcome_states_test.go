package database

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// RB6 execution outcome states (DESIGN_RB6_execution_outcome_states.md, owner decision 2026-10-04): an action that
// executed is never reported failed - its proof bundle is pending, written, or (declared) unavailable - and a refusal
// before any chain transaction is named, then fails the intent as refused.
func TestAnExecutedActionIsNeverReportedFailed(t *testing.T) {
	if testDB == nil {
		t.Fatal("test database not configured")
	}
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	newIntent := func() string {
		id := "rb6-" + uuid.NewString()
		if _, err := testDB.ExecContext(ctx, `INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status) VALUES ($1, $2, 'settling')`,
			id, uuid.NewString()[:16]); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			testDB.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
			testDB.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, id)
		})
		return id
	}
	read := func(id string) (status string, class *string, completed, failed bool, msg string) {
		var c, f, m *string
		if err := testDB.QueryRowContext(ctx, `SELECT status, failure_class, completed_at::text, failed_at::text, error_message
			FROM intent_lifecycle WHERE intent_id = $1`, id).Scan(&status, &class, &c, &f, &m); err != nil {
			t.Fatal(err)
		}
		if m != nil {
			msg = *m
		}
		return status, class, c != nil, f != nil, msg
	}
	member := func(id string, chain int64, chains []int64, s MemberSettlement, p MemberProofCycle, refusal string) MemberOutcome {
		o := MemberOutcome{IntentID: id, ReportedBy: "validator-3", ChainID: chain, MemberChains: chains, Settlement: s, ProofCycle: p,
			Legs: 1, Refusal: refusal}
		if s == MemberSettlementSettled || s == MemberSettlementReverted {
			o.SettlementTx = "0x" + strings.ReplaceAll(uuid.NewString(), "-", "")
		}
		return o
	}
	record := func(o MemberOutcome) {
		t.Helper()
		if _, err := repo.RecordMemberOutcome(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	// 1. An executed member can never be recorded failed - by the store, and by the schema beneath it.
	id := newIntent()
	if _, err := repo.RecordMemberOutcome(ctx, member(id, 84532, []int64{84532}, MemberSettlementSettled, MemberProofCycleFailed, "")); err == nil {
		t.Fatal("THE regression: the store recorded an executed member failed")
	}
	record(member(id, 84532, []int64{84532}, MemberSettlementSettled, MemberProofCyclePending, ""))
	if _, err := testDB.ExecContext(ctx, `UPDATE intent_member_outcomes SET proof_cycle = 'failed' WHERE intent_id = $1`, id); err == nil {
		t.Fatal("THE regression: the schema accepted an executed member recorded failed")
	}
	if _, err := repo.RecordMemberOutcome(ctx, member(id, 84532, []int64{84532}, MemberSettlementNone, MemberProofCyclePending, "")); err == nil {
		t.Fatal("a member nothing executed for was recorded proof_pending")
	}

	// 2. Executed, bundle owed: executed_proof_pending - open, no failure, no class. Its bundle lands: complete.
	if st, class, completed, failed, msg := read(id); st != "executed_proof_pending" || class != nil || completed || failed ||
		!strings.Contains(msg, "executed, proof pending") {
		t.Fatalf("executed with its bundle owed: %s / %v completed=%v failed=%v %q", st, class, completed, failed, msg)
	}
	var next *string
	if err := testDB.QueryRowContext(ctx, `SELECT next_proof_attempt_at::text FROM intent_member_outcomes WHERE intent_id = $1`, id).Scan(&next); err != nil || next == nil {
		t.Fatalf("a proof_pending member has no recovery scheduled (%v)", err)
	}
	record(member(id, 84532, []int64{84532}, MemberSettlementSettled, MemberProofCycleWritten, ""))
	if st, class, completed, _, _ := read(id); st != "complete" || class != nil || !completed {
		t.Fatalf("after its bundle was written: %s / %v completed=%v", st, class, completed)
	}

	// 3. One member's bundle owed decides over another member's failure: the intent is still open.
	id = newIntent()
	record(member(id, 84532, []int64{84532, 421614}, MemberSettlementSettled, MemberProofCyclePending, ""))
	record(member(id, 421614, []int64{84532, 421614}, MemberSettlementUnobserved, MemberProofCycleFailed, ""))
	if st, _, _, failed, _ := read(id); st != "executed_proof_pending" || failed {
		t.Fatalf("an owed bundle beside a failed member: %s failed=%v", st, failed)
	}

	// 4. Declared unavailable: terminal, completed, not failed, no class; the message says it.
	id = newIntent()
	record(member(id, 84532, []int64{84532}, MemberSettlementSettled, MemberProofCycleUnavailable, ""))
	if st, class, completed, failed, msg := read(id); st != "executed_proof_unavailable" || class != nil || !completed || failed ||
		!strings.Contains(msg, "proof unavailable") {
		t.Fatalf("declared unavailable: %s / %v completed=%v failed=%v %q", st, class, completed, failed, msg)
	}

	// 5. Refused by name before any chain transaction: open while its attestation is pending; attested, failed as refused.
	id = newIntent()
	if _, err := repo.RecordMemberOutcome(ctx, member(id, 421614, []int64{421614}, MemberSettlementNone, MemberProofCycleRefused, "")); err == nil {
		t.Fatal("a refusal was recorded without its cause")
	}
	if _, err := repo.RecordMemberOutcome(ctx, member(id, 421614, []int64{421614}, MemberSettlementSettled, MemberProofCyclePending, "account unusable")); err == nil {
		t.Fatal("an executed member was recorded refused")
	}
	record(member(id, 421614, []int64{421614}, MemberSettlementNone, MemberProofCycleRefused, "account unusable: leaf v1, chain on v3"))
	if st, class, _, failed, msg := read(id); st != "refused_pending_attestation" || class != nil || failed || !strings.Contains(msg, "refused: account unusable") {
		t.Fatalf("refused, attestation pending: %s / %v failed=%v %q", st, class, failed, msg)
	}
	record(member(id, 421614, []int64{421614}, MemberSettlementNone, MemberProofCycleWritten, ""))
	if st, class, _, failed, _ := read(id); st != "failed" || class == nil || *class != "refused" || !failed {
		t.Fatalf("an attested refusal: %s / %v failed=%v", st, class, failed)
	}

	// 6. A non-settlement that was not a refusal stays a failed settlement.
	id = newIntent()
	record(member(id, 84532, []int64{84532}, MemberSettlementNone, MemberProofCycleWritten, ""))
	if st, class, _, _, _ := read(id); st != "failed" || class == nil || *class != "settlement_failed" {
		t.Fatalf("a non-settlement: %s / %v", st, class)
	}

	// 7. A phase update from a running cycle never overwrites an owed bundle's state.
	id = newIntent()
	record(member(id, 84532, []int64{84532}, MemberSettlementSettled, MemberProofCyclePending, ""))
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleSettling); err == nil {
		if st, _, _, _, _ := read(id); st != "executed_proof_pending" {
			t.Fatalf("a running cycle's update moved an owed bundle to %s", st)
		}
	}
}
