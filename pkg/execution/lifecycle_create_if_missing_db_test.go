// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
)

// RB8-F (defect D4) against the REAL repository and a REAL PostgreSQL (CERTEN_TEST_DB, migrated through the production
// runner): an intent with no lifecycle row is moved to in_process by its proof cycle, which creates the row from the
// request; the created row carries what the request knew and NULL for what it did not.
func TestRB8F_ProofCycleCreatesTheMissingLifecycleRowInPostgres(t *testing.T) {
	db := openMigratedTestDB(t, "RB8-F")
	ctx := context.Background()
	o := s1Orchestrator(t, db)

	const intentID = "rb8f-missing-row-1c152f20"
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, intentID) })
	req := cycleRequest(intentID)
	req.AccumulateHeight = 0 // the adapter does not carry the DN block: the row says so with NULL, not 0

	if err := o.updateLifecycleInProcessFor(ctx, req, "cycle-rb8f"); err != nil {
		t.Fatalf("the proof cycle of an intent with no row was refused: %v", err)
	}
	var status, tx, class, chain, user string
	var height, authorizedAt, cycle interface{}
	if err := db.QueryRow(`SELECT status, accum_tx_hash, proof_class, target_chain, user_id, block_height, authorized_at, cycle_id
		FROM intent_lifecycle WHERE intent_id = $1`, intentID).Scan(&status, &tx, &class, &chain, &user, &height, &authorizedAt, &cycle); err != nil {
		t.Fatalf("the row was not created: %v", err)
	}
	if status != string(database.IntentLifecycleInProcess) || tx != req.AccumulateTxHash || class != "on_demand" || chain != "base_sepolia" || user != "gateway-user" {
		t.Fatalf("created row: status=%q tx=%q class=%q chain=%q user=%q", status, tx, class, chain, user)
	}
	if height != nil || authorizedAt != nil {
		t.Fatalf("unknown values were invented: block_height=%v authorized_at=%v (must be NULL)", height, authorizedAt)
	}
	if cycle == nil {
		t.Fatal("the cycle id was not recorded")
	}

	// Idempotent: discovery's own write for the same intent is a no-op on the existing row, and a second ensure creates nothing.
	repo := database.NewIntentLifecycleRepository(database.NewClientFromDB(db))
	created, err := repo.EnsureOnProofCycle(ctx, intentID, req.AccumulateTxHash, "gateway-user", "on_demand", "base_sepolia", 11243840)
	if err != nil || created {
		t.Fatalf("a second ensure created=%v err=%v", created, err)
	}
}
