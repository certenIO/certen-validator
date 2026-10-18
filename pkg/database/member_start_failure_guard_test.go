package database

import (
	"context"
	"errors"
	"testing"
)

// A start failure says only that no proof cycle began for the member. It must not replace a member that is already beyond start
// (executed on its chain, written back, proof owed, or refused): nothing it states is true of that member, and replacing it
// turned a settled / proof_pending row into unobserved / failed (V-A note 2).
func TestAStartFailureNeverReplacesAMemberBeyondStart(t *testing.T) {
	requireTestDB(t)
	ctx := context.Background()
	repo := NewIntentLifecycleRepository(NewClientFromDB(testDB))
	members := []int64{84532}

	priors := map[string]MemberOutcome{
		"settled, proof pending":       {Settlement: MemberSettlementSettled, ProofCycle: MemberProofCyclePending, SettlementTx: "0xaa"},
		"settled, written back":        {Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleWritten, SettlementTx: "0xbb", WriteBackTx: "acc://wb"},
		"settled, proof unavailable":   {Settlement: MemberSettlementSettled, ProofCycle: MemberProofCycleUnavailable, SettlementTx: "0xcc"},
		"reverted, proof pending":      {Settlement: MemberSettlementReverted, ProofCycle: MemberProofCyclePending, SettlementTx: "0xdd"},
		"refused, attestation pending": {Settlement: MemberSettlementNone, ProofCycle: MemberProofCycleRefused, Refusal: "not entitled"},
	}
	for name, prior := range priors {
		t.Run(name, func(t *testing.T) {
			id := newTwoMemberIntent(t, ctx)
			prior.IntentID, prior.ChainID, prior.MemberChains, prior.Legs, prior.CycleID, prior.ReportedBy = id, 84532, members, 1, "cycle-first", "validator-1"
			if _, err := repo.RecordMemberOutcome(ctx, prior); err != nil {
				t.Fatalf("seed the prior outcome: %v", err)
			}
			startFailure := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1,
				Settlement: MemberSettlementUnobserved, ProofCycle: MemberProofCycleFailed, CycleID: "cycle-second",
				Reason: "proof cycle not started: boom", ReportedBy: "validator-1", NotStarted: true}
			_, err := repo.RecordMemberOutcome(ctx, startFailure)
			if !errors.Is(err, ErrMemberBeyondStart) {
				t.Fatalf("a start failure over a member that is %s: err = %v, want ErrMemberBeyondStart", name, err)
			}
			var settlement, cycle string
			if err := testDB.QueryRowContext(ctx, `SELECT settlement, proof_cycle FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = 84532`, id).
				Scan(&settlement, &cycle); err != nil {
				t.Fatal(err)
			}
			if settlement != string(prior.Settlement) || cycle != string(prior.ProofCycle) {
				t.Fatalf("the member was overwritten: now %s / %s, was %s / %s", settlement, cycle, prior.Settlement, prior.ProofCycle)
			}
			if got := correctionsFor(t, ctx, "intent_member_outcome", id+"/84532"); len(got) != 0 {
				t.Fatalf("a refused start failure left %d corrections", len(got))
			}
		})
	}

	t.Run("a start failure over a member that never started is still recorded", func(t *testing.T) {
		id := newTwoMemberIntent(t, ctx)
		first := MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: members, Legs: 1, Settlement: MemberSettlementUnobserved,
			ProofCycle: MemberProofCycleFailed, CycleID: "cycle-first", Reason: "phase 3 failed", ReportedBy: "validator-1"}
		if _, err := repo.RecordMemberOutcome(ctx, first); err != nil {
			t.Fatal(err)
		}
		second := first
		second.CycleID, second.Reason, second.NotStarted = "cycle-second", "proof cycle not started: boom", true
		if _, err := repo.RecordMemberOutcome(ctx, second); err != nil {
			t.Fatalf("a start failure over a failed, unobserved member was refused: %v", err)
		}
		var reason string
		if err := testDB.QueryRowContext(ctx, `SELECT reason FROM intent_member_outcomes WHERE intent_id = $1 AND chain_id = 84532`, id).Scan(&reason); err != nil || reason != second.Reason {
			t.Fatalf("the later start failure was not recorded: reason %q err %v", reason, err)
		}
	})
}
