// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"
)

// RB11-DBFIX D1: all validators share one database, so a level can be stored by ANOTHER validator while this one's status row for
// it still says pending or unavailable (the other validator crashed between its append and its status write, or its verified write
// lost a race with an older judgement). A level the chain holds is never a target again, so without convergence that row would stay
// wrong for ever. The upgrader writes the verified row of every stored level whose row is not verified.

func staleFixture(t *testing.T, stored ...Level) (*upgraderFixture, *memStatus) {
	t.Helper()
	status := newMemStatus()
	f := newFixture(t, allLevels(t), UpgraderConfig{Status: status}, nil)
	settlement := f.src.settlements[legID]
	pid, _ := ParseProofID(legID)
	var chain []Addendum
	for _, l := range stored { // appended by another validator
		a, err := NewAddendum(f.d0(), pid, chain, ChainBaseSepolia, l, baseKinds[l], built(t, settlement.Included, l, "theirs").Evidence)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, a)
	}
	f.store.chains[legID] = chain
	return f, status
}

func TestUpgraderConvergesAStalePendingRowOfALevelAnotherValidatorStored(t *testing.T) {
	f, status := staleFixture(t, LevelL1Posted)
	stale := BuilderStatusOf(legID, ChainBaseSepolia, LevelL1Posted, LevelIncluded,
		&PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: LevelL1Posted, Reason: "awaiting_batch_post"}, nil, false, f.clock.Now().Add(-time.Hour))
	if err := status.UpsertStatus(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 1 { // this validator stores the other level, finalized
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	l1 := status.row(legID, LevelL1Posted)
	if l1.Class != BuilderVerified || l1.Seq != 1 || l1.State != nil || l1.LevelReached != LevelL1Posted {
		t.Fatalf("the stored level's stale pending row was not converged to verified: %+v", l1)
	}
	if fin := status.row(legID, LevelFinalized); fin.Class != BuilderVerified || fin.Seq != 2 {
		t.Fatalf("the level this validator stored: %+v", fin)
	}
}

func TestUpgraderConvergesStaleRowsOfACompleteLegAndWritesTheMissingOnes(t *testing.T) {
	f, status := staleFixture(t, LevelFinalized, LevelL1Posted)
	ctx := context.Background()
	// finalized: an unavailable row; l1_posted: no row at all
	st := BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelIncluded, nil, NewState(CodeBuildTimeout, "chain", uint64(ChainBaseSepolia), "after", time.Minute, "cause", "x"), false, f.clock.Now())
	if err := status.UpsertStatus(ctx, st); err != nil {
		t.Fatal(err)
	}
	rep := f.u.RunOnce(ctx)
	if rep.Appended != 0 {
		t.Fatalf("a leg that holds every level builds nothing: %+v", rep)
	}
	if fin := status.row(legID, LevelFinalized); fin.Class != BuilderVerified || fin.Seq != 1 {
		t.Fatalf("finalized: %+v", fin)
	}
	if l1 := status.row(legID, LevelL1Posted); l1.Class != BuilderVerified || l1.Seq != 2 {
		t.Fatalf("l1_posted had no row and the chain holds it: %+v", l1)
	}
	// converged rows are not written again: the next pass reads them and leaves them (the leg is complete and skipped)
	before := status.row(legID, LevelL1Posted).JudgedAt
	f.clock.Advance(time.Hour)
	f.u.RunOnce(ctx)
	if !status.row(legID, LevelL1Posted).JudgedAt.Equal(before) {
		t.Fatal("a verified row was rewritten")
	}
}
