// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F78: a member outcome the lifecycle store refuses is kept until the store takes it.

func TestARefusedMemberOutcomeIsRecordedOnceTheStoreRecovers(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	intentID := fmt.Sprintf("f78-%d", time.Now().UnixNano())
	s1Seed(ctx, t, db, intentID)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, intentID) })

	outbox, err := NewFileMemberOutcomeOutbox(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	repos := database.NewRepositories(database.NewClientFromDB(db))
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{Repos: repos, MemberOutcomes: outbox}}

	if _, err := db.Exec(`CREATE OR REPLACE FUNCTION f78_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'f78: store unavailable'; END $$;
		CREATE TRIGGER f78_refuse BEFORE INSERT ON intent_member_outcomes FOR EACH ROW EXECUTE FUNCTION f78_refuse();`); err != nil {
		t.Fatal(err)
	}
	dropped := false
	drop := func() {
		if !dropped {
			db.Exec(`DROP TRIGGER IF EXISTS f78_refuse ON intent_member_outcomes; DROP FUNCTION IF EXISTS f78_refuse();`)
			dropped = true
		}
	}
	t.Cleanup(drop)

	c := memberCycle(intentID, "84532", []int64{84532}, 1, settledObs("0xbase"))
	c.Result.WriteBackTxHash, c.Result.WriteBackState = "wb", WriteBackWritten
	if err := o.recordMemberOutcome(ctx, c, database.MemberSettlementSettled, database.MemberProofCycleWritten, ""); err != nil {
		t.Fatalf("a refused outcome that was queued is not a failure: %v", err)
	}
	if n, _ := outbox.Depth(); n != 1 {
		t.Fatalf("the refused outcome was not kept: outbox depth %d", n)
	}

	drop()
	rep, err := (&MemberOutcomeReconciler{Outbox: outbox, Store: repos.IntentLifecycle, Logf: t.Logf}).RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recorded != 1 || rep.Remaining != 0 {
		t.Fatalf("reconcile %+v", rep)
	}
	if status, _, _, _ := lifecycleRow(t, db, intentID); status != "complete" {
		t.Fatalf("the intent's status after its outcome was recorded: %q, want complete", status)
	}
}

type refusingRecorder struct{ err error }

func (r refusingRecorder) RecordMemberOutcome(context.Context, database.MemberOutcome) (database.DerivedIntentStatus, error) {
	return database.DerivedIntentStatus{}, r.err
}

func TestAContradictedMemberOutcomeIsQuarantinedAndATransientOneWaits(t *testing.T) {
	outbox, err := NewFileMemberOutcomeOutbox(filepath.Join(t.TempDir(), "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	out := database.MemberOutcome{IntentID: "i", ChainID: 84532, CycleID: "c", MemberChains: []int64{84532}, Legs: 1}
	if err := outbox.Put(out); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rep, err := (&MemberOutcomeReconciler{Outbox: outbox, Store: refusingRecorder{fmt.Errorf("connection refused")}, Logf: t.Logf}).RunOnce(ctx)
	if err != nil || rep.Deferred != 1 || rep.Remaining != 1 {
		t.Fatalf("a transient refusal waits: %+v %v", rep, err)
	}
	rep, err = (&MemberOutcomeReconciler{Outbox: outbox, Store: refusingRecorder{fmt.Errorf("%w: member set differs", database.ErrMemberOutcomeInvalid)}, Logf: t.Logf}).RunOnce(ctx)
	if err != nil || rep.Quarantined != 1 || rep.Remaining != 0 {
		t.Fatalf("a contradiction is quarantined, not retried forever or deleted: %+v %v", rep, err)
	}
}

func TestACycleWithoutItsMemberSetIsRefusedBeforeItRuns(t *testing.T) {
	o := &UnifiedOrchestrator{config: &UnifiedOrchestratorConfig{}}
	for name, req := range map[string]*UnifiedProofCycleRequest{
		"no member set":        {TxHashes: []string{"0xaa"}, ProofClass: "on_demand", TargetChain: "84532"},
		"a chain name, not id": {TxHashes: []string{"0xaa"}, ProofClass: "on_demand", TargetChain: "base-sepolia", CommitmentData: map[string]interface{}{"memberChains": []int64{84532}, "memberLegs": 1}},
	} {
		if err := o.validateRequest(req); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	ok := &UnifiedProofCycleRequest{TxHashes: []string{"0xaa"}, ProofClass: "on_demand", TargetChain: "84532",
		CommitmentData: map[string]interface{}{"memberChains": []int64{84532}, "memberLegs": 1}}
	if err := o.validateRequest(ok); err != nil && !strings.Contains(err.Error(), "member") {
		t.Fatal(err)
	} else if err != nil {
		t.Fatalf("a request with its member set: %v", err)
	}
}
