// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
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

	for _, tc := range []struct {
		name  string
		obs   []*chain.ObservationResult
		phase int
		want  database.MemberSettlement
	}{
		{"settled, then the gate refused", []*chain.ObservationResult{settledObs("0xe9b9")}, 7, database.MemberSettlementSettled},
		{"reverted, then attestation failed", []*chain.ObservationResult{revertedObs("0xdead")}, 8, database.MemberSettlementReverted},
		{"nothing observed", nil, 7, database.MemberSettlementUnobserved},
		{"only an empty observation slot", []*chain.ObservationResult{nil}, 7, database.MemberSettlementUnobserved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "f65-" + strings.ReplaceAll(tc.name, " ", "-")
			s1Seed(ctx, t, db, id)
			cleanup(id)
			c := memberCycle(id, "11155111", []int64{11155111}, 1, nil)
			c.Result.ObservationResults = tc.obs
			o.recordPhaseFailure(ctx, c, tc.phase, gate)

			settlement, proofCycle, reason := outcome(id)
			if settlement != string(tc.want) || proofCycle != string(database.MemberProofCycleFailed) {
				t.Fatalf("recorded settlement=%s proof_cycle=%s; want %s / failed", settlement, proofCycle, tc.want)
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
