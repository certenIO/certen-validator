// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// RB6 state 3 (owner decision 2026-10-04): an executed member's proof is declared unavailable only by an operator, with
// evidence, after it has been owed for ProofUnavailableMinPending, and only when its block cannot be proven now. The
// intent then reads executed_proof_unavailable - completed, not failed - and its owed state is kept as a correction.
func TestAProofIsDeclaredUnavailableOnlyWithEvidenceAndOnlyWhenUnprovable(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	repo := database.NewIntentLifecycleRepository(database.NewClientFromDB(db))
	id := fmt.Sprintf("rb6-unavail-%d", time.Now().UnixNano())
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
		db.Exec(`DELETE FROM evidence_corrections WHERE record_id LIKE $1`, id+"%")
	})
	tx := "0x" + strings.Repeat("ab", 32)
	o.config.ValidatorID = "validator-3"
	if err := o.recordMemberOutcome(ctx, memberCycle(id, "84532", []int64{84532}, 1, settledObs(tx)), database.MemberSettlementSettled,
		database.MemberProofCyclePending, "settled_unproven: no inclusion proof"); err != nil {
		t.Fatal(err)
	}
	provable := false
	probe := func(context.Context, int64, string) (bool, []string, error) {
		return provable, []string{"p1: receipt served, block 0x.. not found", "agreed proof: too few providers answered"}, nil
	}
	req := ProofUnavailableRequest{IntentID: id, ChainID: 84532, SettlementTx: tx, Operator: "operator-jkg", Evidence: "pruned on every provider", Apply: true}
	declare := func(r ProofUnavailableRequest, at time.Time) *ProofUnavailableResult {
		t.Helper()
		res, err := DeclareProofUnavailable(ctx, db, repo, probe, r, at)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	cycle := func() string {
		var c string
		db.QueryRow(`SELECT proof_cycle FROM intent_member_outcomes WHERE intent_id = $1`, id).Scan(&c)
		return c
	}

	if res := declare(req, time.Now()); !strings.Contains(res.Refused, "may be declared unavailable after") || cycle() != "proof_pending" {
		t.Fatalf("THE regression: declared before the pending bound: %+v (%s)", res, cycle())
	}
	later := time.Now().Add(ProofUnavailableMinPending + time.Hour)
	other := req
	other.SettlementTx = "0x" + strings.Repeat("cd", 32)
	if res := declare(other, later); !strings.Contains(res.Refused, "records settlement") {
		t.Fatalf("another transaction: %+v", res)
	}
	provable = true
	if res := declare(req, later); !strings.Contains(res.Refused, "CAN be proven now") || cycle() != "proof_pending" {
		t.Fatalf("THE regression: a provable block was declared unavailable: %+v (%s)", res, cycle())
	}
	provable = false
	dry := req
	dry.Apply = false
	if res := declare(dry, later); res.Refused != "" || res.Declared || cycle() != "proof_pending" {
		t.Fatalf("a dry run: %+v (%s)", res, cycle())
	}
	if _, err := DeclareProofUnavailable(ctx, db, repo, probe, ProofUnavailableRequest{IntentID: id, ChainID: 84532, SettlementTx: tx,
		Operator: "operator-jkg", Apply: true}, later); err == nil {
		t.Fatal("a declaration without evidence was accepted")
	}

	res := declare(req, later)
	if !res.Declared || cycle() != "proof_unavailable" || !strings.Contains(res.Reason, "pruned on every provider") ||
		!strings.Contains(res.Reason, "agreed proof: too few providers answered") {
		t.Fatalf("declaration: %+v (%s)", res, cycle())
	}
	if status, _, _, msg := lifecycleRow(t, db, id); status != "executed_proof_unavailable" || !strings.Contains(msg, "proof unavailable") {
		t.Fatalf("the intent reads %s %q", status, msg)
	}
	var kept int
	db.QueryRow(`SELECT count(*) FROM evidence_corrections WHERE record_type = 'intent_member_outcome' AND record_id = $1
		AND previous->>'proof_cycle' = 'proof_pending' AND corrected->>'proof_cycle' = 'proof_unavailable'`, id+"/84532").Scan(&kept)
	if kept != 1 {
		t.Fatalf("the owed state was not kept as a correction (%d)", kept)
	}
	if res := declare(req, later); !strings.Contains(res.Refused, "only an executed member whose proof is pending") {
		t.Fatalf("declared twice: %+v", res)
	}
}
