// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// RB6: a member whose action executed with its proof bundle owed (proof_pending) is re-driven automatically by the
// validator that reported it, through the member repair, with backoff, until its bundle is written - never failed.
func TestAProofPendingMemberIsRecoveredAutomatically(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	seed := func(id, chain string, reporter string) *activeCycle {
		s1Seed(ctx, t, db, id)
		t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
		c := memberCycle(id, chain, []int64{84532}, 1, settledObs("0x"+run))
		o.config.ValidatorID = reporter
		if err := o.recordMemberOutcome(ctx, c, database.MemberSettlementSettled, database.MemberProofCyclePending, "phase 9 failed: quorum not met"); err != nil {
			t.Fatal(err)
		}
		return c
	}
	mine := "rb6-rec-mine-" + run
	theirs := "rb6-rec-theirs-" + run
	seed(mine, "84532", "validator-3")
	seed(theirs, "84532", "validator-5")

	var asked []MemberRepairRequest
	outcome := MemberRepairFailed
	p := &ProofRecovery{DB: db, ValidatorID: "validator-3", Logf: t.Logf, Repair: func(_ context.Context, req MemberRepairRequest) *MemberRepairResult {
		asked = append(asked, req)
		if outcome == MemberRepairRepaired {
			// The re-driven proof cycle writes the bundle back: the member is written.
			c := memberCycle(req.IntentID, "84532", []int64{84532}, 1, settledObs(req.SettlementTx))
			o.config.ValidatorID = "validator-3"
			if err := o.recordMemberOutcome(ctx, c, database.MemberSettlementSettled, database.MemberProofCycleWritten, ""); err != nil {
				t.Fatal(err)
			}
		}
		return &MemberRepairResult{Outcome: outcome, Reason: "quorum not met again"}
	}}
	due := func(id string) (attempts int, next time.Time, cycle string) {
		if err := db.QueryRow(`SELECT proof_attempts, COALESCE(next_proof_attempt_at, 'epoch'), proof_cycle FROM intent_member_outcomes WHERE intent_id = $1`,
			id).Scan(&attempts, &next, &cycle); err != nil {
			t.Fatal(err)
		}
		return
	}

	// 1. Its own due member is re-driven, applied, on its settlement; another validator's is not.
	if _, err := p.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 || asked[0].IntentID != mine || !asked[0].Apply || asked[0].SettlementTx != "0x"+run || asked[0].ChainID != 84532 {
		t.Fatalf("THE regression: recovery asked %+v", asked)
	}
	attempts, next, cycle := due(mine)
	if attempts != 1 || cycle != "proof_pending" || time.Until(next) < 50*time.Second || time.Until(next) > 70*time.Second {
		t.Fatalf("after a failed attempt: attempts %d, next in %s, %s", attempts, time.Until(next), cycle)
	}
	if a, _, c := due(theirs); a != 0 || c != "proof_pending" {
		t.Fatalf("another validator's member was touched: attempts %d %s", a, c)
	}

	// 2. Not due yet: not re-driven.
	if _, err := p.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 1 {
		t.Fatalf("a member not due was re-driven: %d asks", len(asked))
	}

	// 3. Due again, and this time its bundle is written: the member is written and the intent complete; no more attempts.
	db.Exec(`UPDATE intent_member_outcomes SET next_proof_attempt_at = now() - interval '1 second' WHERE intent_id = $1`, mine)
	outcome = MemberRepairRepaired
	if _, err := p.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, next, cycle := due(mine); cycle != "written" || next.Unix() != 0 {
		t.Fatalf("after recovery: %s, next attempt still scheduled at %s", cycle, next)
	}
	if status, _, _, _ := lifecycleRow(t, db, mine); status != "complete" {
		t.Fatalf("after recovery the intent is %s", status)
	}
	before := len(asked)
	if _, err := p.RunOnce(ctx); err != nil || len(asked) != before {
		t.Fatalf("a recovered member was re-driven again (%v)", err)
	}
}

func TestProofRecoveryBacksOff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 7: time.Hour, 50: time.Hour} {
		if got := proofRecoveryBackoff(n); got != want {
			t.Fatalf("backoff after %d attempts = %s, want %s", n, got, want)
		}
	}
}
