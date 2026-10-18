package database

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// RB8-G (verifier defect 2). A row the proof cycle created (EnsureOnProofCycle) is single-leg shaped with NULL block
// height and authorized_at. When it wins the race against discovery's queued or retried write, that write must FILL what
// the row does not know - and only that: never the status, never a terminal row, never a shape discovery already wrote.

func lifecycleShapeFixture(t *testing.T, label string) (*IntentLifecycleRepository, string, string) {
	t.Helper()
	requireTestDB(t)
	run := time.Now().UnixNano()
	id := fmt.Sprintf("rb8g-%s-%d", label, run)
	t.Cleanup(func() { testDB.Exec(`DELETE FROM intent_lifecycle WHERE intent_id = $1`, id) })
	return NewIntentLifecycleRepository(NewClientFromDB(testDB)), id, id + "-tx"
}

func TestAQueuedMultiLegWriteFillsTheShapeOfARowTheProofCycleCreated(t *testing.T) {
	repo, id, tx := lifecycleShapeFixture(t, "multi")
	ctx := context.Background()
	executed := time.Date(2026, 10, 18, 0, 37, 40, 0, time.UTC)

	if created, err := repo.EnsureOnProofCycle(ctx, id, tx, "gateway-user", "on_demand", "base-sepolia", 0); err != nil || !created {
		t.Fatalf("proof cycle ensure: created=%v err=%v", created, err)
	}
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleInProcess, WithCycleID("cycle-1")); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertOnDiscoveryMultiLeg(ctx, id, tx, 11243840, executed, "gateway-user", "on_demand", "base-sepolia",
		[]string{"84532", "421614"}, 2, "sequential"); err != nil {
		t.Fatal(err)
	}
	lc, err := repo.GetByIntentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if lc.BlockHeight == nil || *lc.BlockHeight != 11243840 || lc.AuthorizedAt == nil || !lc.AuthorizedAt.Equal(executed) {
		t.Errorf("block_height %v / authorized_at %v were not filled", lc.BlockHeight, lc.AuthorizedAt)
	}
	if len(lc.TargetChains) != 2 || lc.LegCount == nil || *lc.LegCount != 2 || lc.ExecutionMode == nil || *lc.ExecutionMode != "sequential" {
		t.Errorf("the multi-leg shape was not filled: chains %v legs %v mode %v", lc.TargetChains, lc.LegCount, lc.ExecutionMode)
	}
	if lc.Status != IntentLifecycleInProcess || lc.CycleID == nil || *lc.CycleID != "cycle-1" {
		t.Errorf("the status/cycle of the running proof cycle was touched: %s %v", lc.Status, lc.CycleID)
	}
}

func TestAQueuedSingleLegWriteFillsTheHeightAndTimeOfARowTheProofCycleCreated(t *testing.T) {
	repo, id, tx := lifecycleShapeFixture(t, "single")
	ctx := context.Background()
	executed := time.Date(2026, 10, 18, 0, 37, 40, 0, time.UTC)

	if _, err := repo.EnsureOnProofCycle(ctx, id, tx, "", "on_demand", "base-sepolia", 0); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateStatus(ctx, id, IntentLifecycleInProcess, WithCycleID("cycle-1")); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertOnDiscovery(ctx, id, tx, 11243840, executed, "", "on_demand", "base-sepolia"); err != nil {
		t.Fatal(err)
	}
	lc, err := repo.GetByIntentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if lc.BlockHeight == nil || *lc.BlockHeight != 11243840 || lc.AuthorizedAt == nil || !lc.AuthorizedAt.Equal(executed) {
		t.Errorf("block_height %v / authorized_at %v were not filled", lc.BlockHeight, lc.AuthorizedAt)
	}
	if lc.Status != IntentLifecycleInProcess || len(lc.TargetChains) != 0 {
		t.Errorf("status %s or shape %v was touched by a single-leg fill", lc.Status, lc.TargetChains)
	}
}

// A terminal row is never touched by a later discovery write: not its status, not its outcome, not even its NULLs.
func TestATerminalRowIsNotTouchedByALaterDiscoveryWrite(t *testing.T) {
	for _, terminal := range []IntentLifecycleStatus{IntentLifecycleComplete, IntentLifecycleFailed} {
		t.Run(string(terminal), func(t *testing.T) {
			repo, id, tx := lifecycleShapeFixture(t, "terminal-"+string(terminal))
			ctx := context.Background()
			if _, err := repo.EnsureOnProofCycle(ctx, id, tx, "", "on_demand", "base-sepolia", 0); err != nil {
				t.Fatal(err)
			}
			var opts []UpdateOption
			if terminal == IntentLifecycleFailed {
				opts = append(opts, WithFailureClass(FailureProcessingFailed))
			}
			if err := repo.UpdateStatus(ctx, id, terminal, opts...); err != nil {
				t.Fatal(err)
			}
			before, err := repo.GetByIntentID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.UpsertOnDiscovery(ctx, id, tx, 7, time.Now(), "", "on_demand", "base-sepolia"); err != nil {
				t.Fatal(err)
			}
			if err := repo.UpsertOnDiscoveryMultiLeg(ctx, id, tx, 7, time.Now(), "", "on_demand", "base-sepolia", []string{"84532", "421614"}, 2, "sequential"); err != nil {
				t.Fatal(err)
			}
			after, err := repo.GetByIntentID(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if after.Status != terminal || after.BlockHeight != nil || after.AuthorizedAt != nil || len(after.TargetChains) != 0 ||
				(after.LegCount == nil) != (before.LegCount == nil) || (after.LegCount != nil && *after.LegCount != *before.LegCount) ||
				!after.UpdatedAt.Equal(before.UpdatedAt) {
				t.Fatalf("a terminal row was touched: before %+v after %+v", before, after)
			}
		})
	}
}

// A row discovery wrote keeps what it wrote: a later proof-cycle ensure creates nothing, and a later discovery write
// fills nothing already known (a different height, time or shape does not replace it).
func TestADiscoveryWrittenMultiLegRowIsNotAlteredByALaterWriter(t *testing.T) {
	repo, id, tx := lifecycleShapeFixture(t, "keep")
	ctx := context.Background()
	executed := time.Date(2026, 10, 18, 0, 37, 40, 0, time.UTC)
	if err := repo.UpsertOnDiscoveryMultiLeg(ctx, id, tx, 11243840, executed, "u", "on_demand", "base-sepolia", []string{"84532", "421614"}, 2, "sequential"); err != nil {
		t.Fatal(err)
	}
	if created, err := repo.EnsureOnProofCycle(ctx, id, tx, "other", "scheduled", "arbitrum-sepolia", 99); err != nil || created {
		t.Fatalf("a proof cycle ensure on a discovery-written row: created=%v err=%v", created, err)
	}
	if err := repo.UpsertOnDiscoveryMultiLeg(ctx, id, tx, 5, time.Now(), "u", "on_demand", "base-sepolia", []string{"1"}, 1, "parallel"); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertOnDiscovery(ctx, id, tx, 6, time.Now(), "u", "on_demand", "base-sepolia"); err != nil {
		t.Fatal(err)
	}
	lc, err := repo.GetByIntentID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if lc.BlockHeight == nil || *lc.BlockHeight != 11243840 || lc.AuthorizedAt == nil || !lc.AuthorizedAt.Equal(executed) ||
		len(lc.TargetChains) != 2 || lc.LegCount == nil || *lc.LegCount != 2 || *lc.ExecutionMode != "sequential" ||
		*lc.ProofClass != "on_demand" || *lc.TargetChain != "base-sepolia" || lc.Status != IntentLifecycleAuthorized {
		t.Fatalf("a discovery-written row was altered: %+v", lc)
	}
}
