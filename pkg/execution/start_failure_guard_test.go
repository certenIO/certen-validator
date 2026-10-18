// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// V-A note 2: a start failure must not overwrite a member beyond start. Here the member's action settled and its proof is owed
// (settled / proof_pending); a second cycle for the same member that cannot start must leave that row as it is.
func TestAStartFailureLeavesAMemberBeyondStartAsItIs(t *testing.T) {
	db := s1OpenDB(t)
	o := s1Orchestrator(t, db)
	ctx := context.Background()
	id := fmt.Sprintf("va-note2-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
		db.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, id)
	})
	s1Seed(ctx, t, db, id)

	first := memberCycle(id, "84532", []int64{84532}, 1, settledObs("0xfeed"))
	if err := o.recordMemberOutcome(ctx, first, database.MemberSettlementSettled, database.MemberProofCyclePending, "proof owed"); err != nil {
		t.Fatalf("seed the settled member: %v", err)
	}

	second := memberCycle(id, "84532", []int64{84532}, 1, nil)
	second.Request.CycleID = "cycle-second"
	o.recordStartFailure(ctx, second.Request, nil, errors.New("boom"))

	var settlement, proofCycle string
	var cycle *string
	if err := db.QueryRow(`SELECT settlement, proof_cycle, cycle_id FROM intent_member_outcomes WHERE intent_id = $1`, id).
		Scan(&settlement, &proofCycle, &cycle); err != nil {
		t.Fatal(err)
	}
	if settlement != "settled" || proofCycle != "proof_pending" {
		t.Fatalf("a start failure overwrote a settled member: now %s / %s (cycle %v), want settled / proof_pending", settlement, proofCycle, cycle)
	}
}
