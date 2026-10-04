// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F65: a proof cycle that fails AFTER Phase 7 read the settlement's receipt records the settlement it
// read. Live on intent 3b990fe3: both members settled with status 1, the contract-call gate then refused
// to attest, and the member was recorded as "unobserved" - contradicting the receipt Phase 7 had read.
func TestPhaseFailureRecordsTheSettlementItObserved(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)

	outcome := func(intentID string) (settlement, proofCycle, reason string) {
		t.Helper()
		if err := db.QueryRow(`SELECT settlement, proof_cycle, COALESCE(reason, '') FROM intent_member_outcomes WHERE intent_id = $1`,
			intentID).Scan(&settlement, &proofCycle, &reason); err != nil {
			t.Fatalf("read outcome of %s: %v", intentID, err)
		}
		return
	}
	cleanup := func(id string) {
		t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
	}
	gate := errors.New("RB contract-call verification gate failed: contract-call leg committed no events")

	// RB6: an action that executed (settled or reverted) is never recorded failed - its bundle is owed (proof_pending).
	for _, tc := range []struct {
		name      string
		obs       []*chain.ObservationResult
		phase     int
		want      database.MemberSettlement
		wantCycle database.MemberProofCycle
	}{
		{"settled, then the gate refused", []*chain.ObservationResult{settledObs("0xe9b9")}, 7, database.MemberSettlementSettled, database.MemberProofCyclePending},
		{"reverted, then attestation failed", []*chain.ObservationResult{revertedObs("0xdead")}, 8, database.MemberSettlementReverted, database.MemberProofCyclePending},
		{"nothing observed", nil, 7, database.MemberSettlementUnobserved, database.MemberProofCycleFailed},
		{"only an empty observation slot", []*chain.ObservationResult{nil}, 7, database.MemberSettlementUnobserved, database.MemberProofCycleFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "f65-" + strings.ReplaceAll(tc.name, " ", "-")
			s1Seed(ctx, t, db, id)
			cleanup(id)
			c := memberCycle(id, "11155111", []int64{11155111}, 1, nil)
			c.Result.ObservationResults = tc.obs
			o.recordPhaseFailure(ctx, c, tc.phase, gate)

			settlement, proofCycle, reason := outcome(id)
			if settlement != string(tc.want) || proofCycle != string(tc.wantCycle) {
				t.Fatalf("recorded settlement=%s proof_cycle=%s; want %s / %s", settlement, proofCycle, tc.want, tc.wantCycle)
			}
			if !strings.Contains(reason, "phase") || !strings.Contains(reason, "committed no events") {
				t.Fatalf("reason %q does not say which phase failed and why", reason)
			}
			if c.Result.FailPhase != tc.phase || c.Result.Error != reason {
				t.Fatalf("cycle result not marked: phase %d error %q", c.Result.FailPhase, c.Result.Error)
			}
		})
	}
}

// RB6-F9: Phase 7 read the settlement's final receipt but could not prove it in its block (settled_unproven). The member
// is recorded as the chain holds it - settled (or reverted), with its settlement transaction - and the reason names the
// state and the proof's refusal; it is never "unobserved" with no settlement transaction.
func TestAnUnprovenSettlementIsRecordedAsTheChainHoldsIt(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	for _, tc := range []struct {
		name   string
		status uint64
		want   database.MemberSettlement
	}{
		{"executed", 1, database.MemberSettlementSettled},
		{"reverted", 0, database.MemberSettlementReverted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "rb6f9-" + tc.name
			s1Seed(ctx, t, db, id)
			t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
			c := memberCycle(id, "421614", []int64{421614}, 1, nil)
			tx := "0x1d16f2799d263a3a58d72e9e16c13e65cbf6fbd0ba4bd1b01a58bdfc38600d67"
			unproven := &chain.UnprovenSettlementError{ChainID: 421614, TxHash: tx, BlockHash: "0xc5087e23", BlockNumber: 315690738,
				Status: tc.status, Err: errors.New("no inclusion proof: transaction type 0x7d has no encoder here")}
			o.recordPhaseFailure(ctx, c, 7, fmt.Errorf("observe transaction 0 (%s): %w", tx, unproven))

			var settlement, proofCycle, settlementTx, reason string
			if err := db.QueryRow(`SELECT settlement, proof_cycle, COALESCE(settlement_tx, ''), COALESCE(reason, '') FROM intent_member_outcomes
				WHERE intent_id = $1`, id).Scan(&settlement, &proofCycle, &settlementTx, &reason); err != nil {
				t.Fatal(err)
			}
			if settlement != string(tc.want) || proofCycle != string(database.MemberProofCyclePending) {
				t.Fatalf("THE regression: recorded settlement=%s proof_cycle=%s for a final receipt of status %d; want %s / proof_pending",
					settlement, proofCycle, tc.status, tc.want)
			}
			if !strings.EqualFold(settlementTx, tx) {
				t.Fatalf("THE regression: settlement transaction %q recorded; the receipt read was %s", settlementTx, tx)
			}
			if !strings.Contains(reason, "settled_unproven") || !strings.Contains(reason, "0x7d") {
				t.Fatalf("reason %q does not name the state and the refusal", reason)
			}
		})
	}
}
