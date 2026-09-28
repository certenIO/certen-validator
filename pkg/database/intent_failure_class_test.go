package database

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// RB4-F13: a failed intent says why, as a class a client can act on. It was status 'failed' with message text
// only, so an intent's own defect, a governance verdict, a missing entitlement, a chain member that did not settle
// and CERTEN failing to process it all read the same.
func TestAFailedIntentCarriesItsFailureClass(t *testing.T) {
	if testDB == nil {
		t.Fatal("test database not configured")
	}
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	newIntent := func() string {
		id := "f13-" + uuid.NewString()
		if _, err := testDB.ExecContext(ctx, `INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status) VALUES ($1, $2, 'submitted')`,
			id, uuid.NewString()[:16]); err != nil {
			t.Fatal(err)
		}
		return id
	}
	read := func(id string) (status string, class *string) {
		if err := testDB.QueryRowContext(ctx, `SELECT status, failure_class FROM intent_lifecycle WHERE intent_id = $1`, id).Scan(&status, &class); err != nil {
			t.Fatal(err)
		}
		return
	}

	id := newIntent()
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleFailed, WithErrorMessage("boom")); err == nil {
		t.Fatal("an intent was failed without saying why")
	}
	if st, _ := read(id); st != "submitted" {
		t.Fatalf("a refused write changed the status to %s", st)
	}
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleInProcess, WithFailureClass(FailureRefused)); err == nil {
		t.Fatal("a failure class was recorded on an intent that did not fail")
	}
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleFailed, WithErrorMessage("G1 threshold not met"), WithFailureClass(FailureGovernanceUnsatisfied)); err != nil {
		t.Fatal(err)
	}
	if st, class := read(id); st != "failed" || class == nil || *class != "governance_unsatisfied" {
		t.Fatalf("recorded %s / %v", st, class)
	}
	lc, err := repo.GetByIntentID(ctx, id)
	if err != nil || lc.FailureClass == nil || *lc.FailureClass != "governance_unsatisfied" {
		t.Fatalf("the lifecycle read does not carry the class: %v %+v", err, lc)
	}

	// The schema holds it: only a failed intent has a class, and only a known one.
	other := newIntent()
	if _, err := testDB.ExecContext(ctx, `UPDATE intent_lifecycle SET failure_class = 'refused' WHERE intent_id = $1`, other); err == nil {
		t.Fatal("the schema accepted a failure class on an intent that has not failed")
	}
	if _, err := testDB.ExecContext(ctx, `UPDATE intent_lifecycle SET status = 'failed', failure_class = 'bad luck' WHERE intent_id = $1`, other); err == nil {
		t.Fatal("the schema accepted an unknown failure class")
	}

	// A chain member that did not settle fails its intent as settlement_failed; settling it after clears the class.
	m := newIntent()
	if _, err := repo.RecordMemberOutcome(ctx, MemberOutcome{IntentID: m, ChainID: 84532, MemberChains: []int64{84532},
		Settlement: MemberSettlementReverted, ProofCycle: MemberProofCycleWritten, Legs: 1, SettlementTx: "0x" + uuid.NewString()[:8], Reason: "reverted"}); err != nil {
		t.Fatal(err)
	}
	if st, class := read(m); st != "failed" || class == nil || *class != "settlement_failed" {
		t.Fatalf("a reverted member left the intent %s / %v", st, class)
	}
	if _, err := repo.RecordMemberOutcome(ctx, MemberOutcome{IntentID: m, ChainID: 84532, MemberChains: []int64{84532},
		Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, Legs: 1, SettlementTx: "0x" + uuid.NewString()[:8]}); err != nil {
		t.Fatal(err)
	}
	if st, class := read(m); st != "complete" || class != nil {
		t.Fatalf("a settled intent reads %s / %v", st, class)
	}
}
