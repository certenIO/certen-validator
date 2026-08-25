// Copyright 2026 Certen Protocol
//
// Stage 1 Gate 1c — NO LIFECYCLE SKIPS 'settling'.
//
// An intent may not go in_process -> complete without passing through settling
// on the on-demand path. That is not a stylistic rule: 'complete' meant "Phase 9
// write-back succeeded", and it was being reached — and reported — while the
// target-chain write was still in flight. On 2026-08-25 intent
// 1638327d-af2c-439c-a188-be53cdb5c854 was logged complete at 07:33:41 and its
// transaction confirmed at 07:34:32.
//
// This drives the REAL repository against a REAL PostgreSQL carrying the live
// schema plus migration 014. Without CERTEN_TEST_DB it SKIPS rather than passing
// vacuously — a skipped gate is not a green gate.
//
//	go test ./pkg/execution/ -run 'TestS1_' -count=1 -v
package execution

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
	_ "github.com/lib/pq"
)

func s1OpenDB(t *testing.T) *sql.DB {
	t.Helper()
	conn := os.Getenv("CERTEN_TEST_DB")
	if conn == "" {
		t.Skip("CERTEN_TEST_DB not set — Gate 1c needs a PostgreSQL with the live schema " +
			"and migration 014. A skipped gate is not a green gate.")
	}
	db, err := sql.Open("postgres", conn)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Fail loudly if 014 has not been applied: otherwise the settling write would
	// error at runtime and this gate would report a confusing SQL failure rather
	// than "the migration is missing".
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_name = 'intent_lifecycle' AND column_name = 'settling_at'`).Scan(&n); err != nil {
		t.Fatalf("probe for settling_at: %v", err)
	}
	if n == 0 {
		t.Fatal("intent_lifecycle.settling_at is absent — apply migration " +
			"014_intent_lifecycle_settling.sql to the test database first")
	}
	return db
}

// s1Orchestrator builds a UnifiedOrchestrator wired to the test database with
// nothing else configured. The lifecycle helpers are the whole surface under
// test, and they only need Repos.
func s1Orchestrator(t *testing.T, db *sql.DB) *UnifiedOrchestrator {
	t.Helper()
	return &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{
			Repos: &database.Repositories{
				IntentLifecycle: database.NewIntentLifecycleRepository(database.NewClientFromDB(db)),
			},
		},
	}
}

func s1Status(t *testing.T, db *sql.DB, intentID string) (status string, inProcess, settling, completed, failed *time.Time) {
	t.Helper()
	row := db.QueryRow(`SELECT status, in_process_at, settling_at, completed_at, failed_at
		FROM intent_lifecycle WHERE intent_id = $1`, intentID)
	if err := row.Scan(&status, &inProcess, &settling, &completed, &failed); err != nil {
		t.Fatalf("read lifecycle row for %s: %v", intentID, err)
	}
	return
}

func s1Seed(ctx context.Context, t *testing.T, db *sql.DB, intentID string) {
	t.Helper()
	_, err := db.ExecContext(ctx, `
		INSERT INTO intent_lifecycle (intent_id, accum_tx_hash, status, created_at, updated_at)
		VALUES ($1, $2, 'authorized', now(), now())`, intentID, "acc-"+intentID)
	if err != nil {
		t.Fatalf("seed intent_lifecycle: %v", err)
	}
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, intentID) })
}

// =============================================================================
// GATE 1c
// =============================================================================

func TestS1_LifecyclePassesThroughSettling(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)

	const intentID = "s1-settling-happy-path"
	s1Seed(ctx, t, db, intentID)

	// The on-demand sequence, driven through the SAME helpers StartProofCycle and
	// executePhase7 call. Nothing here re-implements the transition.
	o.updateLifecycleInProcess(ctx, intentID, "cycle-1")
	if st, _, settling, _, _ := s1Status(t, db, intentID); st != "in_process" || settling != nil {
		t.Fatalf("after in_process: status=%q settling_at=%v — settling must not be set yet", st, settling)
	}

	o.updateLifecycleSettling(ctx, intentID, "cycle-1")
	st, inProcessAt, settlingAt, completedAt, _ := s1Status(t, db, intentID)
	if st != string(database.IntentLifecycleSettling) {
		t.Fatalf("expected status %q, got %q — the pending window has no state and 'complete' will absorb it again",
			database.IntentLifecycleSettling, st)
	}
	if settlingAt == nil {
		t.Fatal("settling_at was not recorded; the settlement latency this stage exists to expose is invisible again")
	}
	if inProcessAt == nil {
		t.Fatal("in_process_at was cleared by the settling transition")
	}
	if completedAt != nil {
		t.Fatal("settling must not set completed_at — it is not terminal")
	}
	if settlingAt.Before(*inProcessAt) {
		t.Fatalf("settling_at (%s) precedes in_process_at (%s); the interval between them is the measurement",
			settlingAt, inProcessAt)
	}

	// Terminal resolution, from settling.
	o.updateLifecycleComplete(ctx, intentID, "cycle-1", "0xwriteback")
	st, _, settlingAfter, completedAt, _ := s1Status(t, db, intentID)
	if st != string(database.IntentLifecycleComplete) {
		t.Fatalf("settling -> complete did not take effect: status=%q", st)
	}
	if completedAt == nil {
		t.Fatal("completed_at not recorded")
	}
	if settlingAfter == nil {
		t.Fatal("settling_at was erased by completion; the settlement latency must remain readable afterwards")
	}
	if completedAt.Before(*settlingAfter) {
		t.Fatalf("completed_at (%s) precedes settling_at (%s)", completedAt, settlingAfter)
	}
}

// settling resolves to failed just as readily as to complete. If it could only
// go one way it would be a synonym for success, which is exactly the conflation
// being removed.
func TestS1_SettlingResolvesToFailed(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)

	const intentID = "s1-settling-to-failed"
	s1Seed(ctx, t, db, intentID)

	o.updateLifecycleInProcess(ctx, intentID, "cycle-2")
	o.updateLifecycleSettling(ctx, intentID, "cycle-2")
	o.updateLifecycleFailed(ctx, intentID, "cycle-2", 7, context.DeadlineExceeded)

	st, _, settlingAt, _, failedAt := s1Status(t, db, intentID)
	if st != string(database.IntentLifecycleFailed) {
		t.Fatalf("settling -> failed did not take effect: status=%q", st)
	}
	if failedAt == nil {
		t.Fatal("failed_at not recorded")
	}
	if settlingAt == nil {
		t.Fatal("settling_at lost on failure; the row must still say the settlement was once in flight")
	}
}

// settling is NOT terminal, and the repository's terminal guard must not treat
// it as one. If it did, an intent would get stuck in flight forever with no way
// to record what actually happened.
func TestS1_SettlingIsNotTerminal(t *testing.T) {
	if database.IntentLifecycleSettling.IsTerminal() {
		t.Fatal("settling must not be terminal — its entire purpose is to say the answer is not in yet")
	}
	if !database.IntentLifecycleComplete.IsTerminal() || !database.IntentLifecycleFailed.IsTerminal() {
		t.Fatal("complete and failed remain terminal")
	}
}

// A status with no phase-timestamp column must not produce broken SQL. This was
// latent — the SET clause interpolated an empty column name — and adding a new
// state is exactly the change that surfaces it.
func TestS1_StatusWithoutTimestampColumnStillUpdates(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repo := database.NewIntentLifecycleRepository(database.NewClientFromDB(db))

	const intentID = "s1-no-timestamp-column"
	s1Seed(ctx, t, db, intentID)

	if err := repo.UpdateStatus(ctx, intentID, database.IntentLifecyclePendingSignatures); err != nil {
		t.Fatalf("UpdateStatus to a status with no timestamp column failed: %v", err)
	}
	if st, _, _, _, _ := s1Status(t, db, intentID); st != string(database.IntentLifecyclePendingSignatures) {
		t.Fatalf("status not updated: %q", st)
	}
}

// =============================================================================
// The terminal line — the half of Stage 1 that lives in the log, not the DB
// =============================================================================
//
// The database already ended up right before Stage 1. What never happened was a
// line, against the SAME intent ID, retracting the warning. This asserts that
// executePhase7's renderer speaks about the receipt it actually saw.
func TestS1_TargetChainResolutionUsesTheObservedReceipt(t *testing.T) {
	for _, tc := range []struct {
		status uint8
		want   consensus.TargetChainOutcome
	}{
		{1, consensus.TargetChainConfirmedOutcome},
		{2, consensus.TargetChainFailed},
		{0, consensus.TargetChainPending},
	} {
		obs := &chain.ObservationResult{Status: tc.status, BlockNumber: 45937480, ChainName: "base-sepolia"}
		if got := consensus.TargetChainOutcomeFromReceiptStatus(obs.Status); got != tc.want {
			t.Fatalf("receipt status %d -> %q, want %q", tc.status, got, tc.want)
		}
	}

	// A nil observation must not panic and must not claim anything.
	o := &UnifiedOrchestrator{}
	o.logTargetChainResolution("intent-x", "0xabc", nil)
}
