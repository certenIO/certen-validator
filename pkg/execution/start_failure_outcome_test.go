// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB3-F103: a proof cycle that cannot start records its member's outcome - not observed, proof cycle
// failed, with why. It used to be a log line ("Failed to start proof cycle"), and the intent stayed
// "settling" with nothing recorded to say why.
func TestAProofCycleThatCannotStartIsRecordedAsTheMembersOutcome(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	o.config.Registry = strategy.NewRegistry() // real, and with no strategy for chain 999999

	outcome := func(intentID string) (settlement, proofCycle, reason string) {
		t.Helper()
		if err := db.QueryRow(`SELECT settlement, proof_cycle, COALESCE(reason, '') FROM intent_member_outcomes WHERE intent_id = $1`,
			intentID).Scan(&settlement, &proofCycle, &reason); err != nil {
			t.Fatalf("no outcome recorded for %s: %v", intentID, err)
		}
		return
	}
	forget := func(id string) {
		t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
	}
	check := func(id, why string) {
		t.Helper()
		settlement, proofCycle, reason := outcome(id)
		if settlement != string(database.MemberSettlementUnobserved) || proofCycle != string(database.MemberProofCycleFailed) {
			t.Fatalf("%s: recorded %s / %s; want unobserved / failed", id, settlement, proofCycle)
		}
		if !strings.Contains(reason, "not started") || !strings.Contains(reason, why) {
			t.Fatalf("%s: reason %q does not say the cycle did not start, nor why (%q)", id, reason, why)
		}
	}

	// Inside the orchestrator: a chain it has no strategies for.
	run := fmt.Sprintf("%d", time.Now().UnixNano())
	id := "f103-strategies-" + run
	s1Seed(ctx, t, db, id)
	forget(id)
	req := memberCycle(id, "999999", []int64{999999}, 1, nil).Request
	req.ProofClass = string(LaneOnCadence)
	req.TxHashes = []string{"0x" + strings.Repeat("ab", 32)}
	if _, err := o.StartProofCycle(ctx, req); err == nil {
		t.Fatal("a cycle on a chain with no strategies started")
	}
	check(id, "strategies")

	// In the adapter: a cycle that names no settlement lane.
	id = "f103-lane-" + run
	s1Seed(ctx, t, db, id)
	forget(id)
	err := NewUnifiedOrchestratorAdapter(o).StartProofCycleWithAccumulateRef(ctx, id, "", [32]byte{1},
		[]string{"0x" + strings.Repeat("cd", 32)},
		map[string]interface{}{"targetChain": "11155111", "memberChains": []int64{11155111}, "memberLegs": 1, "proofClass": "express"},
		"acc://harbor.acme/data", strings.Repeat("ef", 32), "bvn1")
	if err == nil {
		t.Fatal("a cycle naming no settlement lane started")
	}
	check(id, "settlement lane")
}

// RB3-F108: an orchestrator with no strategy registry refuses the cycle by name and records it; it used
// to dereference nil inside the adapter's goroutine and panic the validator.
func TestNoRegistryIsARefusalNotAPanic(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	id := fmt.Sprintf("f108-%d", time.Now().UnixNano())
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id) })
	req := memberCycle(id, "11155111", []int64{11155111}, 1, nil).Request
	req.ProofClass = string(LaneOnCadence)
	req.TxHashes = []string{"0x" + strings.Repeat("ab", 32)}
	if _, err := o.StartProofCycle(ctx, req); err == nil || !strings.Contains(err.Error(), "no strategy registry") {
		t.Fatalf("no registry: %v", err)
	}
	var reason string
	if err := db.QueryRow(`SELECT COALESCE(reason,'') FROM intent_member_outcomes WHERE intent_id=$1`, id).Scan(&reason); err != nil ||
		!strings.Contains(reason, "no strategy registry") {
		t.Fatalf("not recorded: %q %v", reason, err)
	}
}
