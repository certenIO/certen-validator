// Copyright 2026 Certen Protocol

package database

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D1: the status table is mutable by design, but it is read by the gateway as "level reached / next / eta" and all
// seven validators write it into ONE database. A write may therefore never (a) replace a newer judgement with an older one,
// (b) replace a verified row with anything, or (c) claim a stored level the proof does not hold.

func pendingFor(pid string, target, reached finality.Level, at time.Time) finality.BuilderStatus {
	pd := &finality.PendingState{Chain: finality.ChainBaseSepolia, LevelReached: reached, NextLevel: target, Reason: "game_unresolved"}
	return finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, target, reached, pd, nil, false, at)
}

func unavailableFor(pid string, target, reached finality.Level, at time.Time) finality.BuilderStatus {
	return finality.BuilderStatusOf(pid, finality.ChainBaseSepolia, target, reached, nil,
		finality.NewState(finality.CodeBuildTimeout, "chain", uint64(finality.ChainBaseSepolia), "after", time.Minute, "cause", "x"), false, at)
}

func TestFinalityStatusAnOlderJudgementNeverReplacesANewerOne(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	pid := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)

	if err := repo.UpsertStatus(ctx, pendingFor(pid, finality.LevelFinalized, finality.LevelIncluded, now)); err != nil {
		t.Fatal(err)
	}
	// a judgement made an hour EARLIER, written later (a slow validator), must not replace it
	if err := repo.UpsertStatus(ctx, unavailableFor(pid, finality.LevelFinalized, finality.LevelIncluded, now.Add(-time.Hour))); err != nil {
		t.Fatalf("a superseded write is not a failure: %v", err)
	}
	got, ok, err := repo.GetStatus(ctx, pid, finality.LevelFinalized)
	if err != nil || !ok || got.Class != finality.BuilderPending || !got.JudgedAt.Equal(now) {
		t.Fatalf("the older judgement replaced the newer: %+v %v %v", got, ok, err)
	}
	// the same instant replaces (the later writer of equal time wins), a later one replaces
	if err := repo.UpsertStatus(ctx, unavailableFor(pid, finality.LevelFinalized, finality.LevelIncluded, now)); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := repo.GetStatus(ctx, pid, finality.LevelFinalized); got.Class != finality.BuilderUnavailable {
		t.Fatalf("a judgement of the same instant did not replace: %+v", got)
	}
	if err := repo.UpsertStatus(ctx, pendingFor(pid, finality.LevelFinalized, finality.LevelIncluded, now.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := repo.GetStatus(ctx, pid, finality.LevelFinalized); got.Class != finality.BuilderPending || !got.JudgedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("a newer judgement did not replace: %+v", got)
	}
}

func TestFinalityStatusAVerifiedRowIsFinalAndOnlyTheStoredAddendumCanMakeOne(t *testing.T) {
	ctx := context.Background()
	repo := NewFinalityStatusRepository(NewClientFromDB(testDB))
	addenda := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	now := time.Now().UTC().Truncate(time.Microsecond)

	t.Run("verified and level-reached claims need the addendum", func(t *testing.T) {
		pid := uuid.NewString() // a proof with ZERO addenda
		for name, s := range map[string]finality.BuilderStatus{
			"verified l1_posted":                         finality.VerifiedBuilderStatus(pid, finality.ChainBaseSepolia, finality.LevelL1Posted, 1, now),
			"verified finalized":                         finality.VerifiedBuilderStatus(pid, finality.ChainBaseSepolia, finality.LevelFinalized, 1, now),
			"pending claiming finalized was reached":     pendingFor(pid, finality.LevelFinalized, finality.LevelFinalized, now),
			"pending claiming l1_posted was reached":     pendingFor(pid, finality.LevelFinalized, finality.LevelL1Posted, now),
			"unavailable claiming l1_posted was reached": unavailableFor(pid, finality.LevelFinalized, finality.LevelL1Posted, now),
		} {
			err := repo.UpsertStatus(ctx, s)
			st, named := finality.AsNamed(err)
			if !named || st.Code != finality.CodeGuardRefused {
				t.Fatalf("%s: want the named state %s, got %v", name, finality.CodeGuardRefused, err)
			}
			for _, l := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
				if _, ok, _ := repo.GetStatus(ctx, pid, l); ok {
					t.Fatalf("%s: a row was stored at %s", name, l)
				}
			}
		}
		// the ordinary states that claim nothing above included are still accepted for a proof with no addendum
		if err := repo.UpsertStatus(ctx, pendingFor(pid, finality.LevelL1Posted, finality.LevelIncluded, now)); err != nil {
			t.Fatalf("pending at included: %v", err)
		}
	})

	t.Run("a verified row must name the stored seq and chain of that level", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		reg := kindRegistry(t, nil)
		a, err := addenda.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelL1Posted, "x"))
		if err != nil {
			t.Fatal(err)
		}
		for name, bad := range map[string]finality.BuilderStatus{
			"another seq":                        finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelL1Posted, a.Seq+1, now),
			"another chain":                      finality.VerifiedBuilderStatus(proofID, finality.ChainArbitrumSepolia, finality.LevelL1Posted, a.Seq, now),
			"the other level that is not stored": finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelFinalized, a.Seq, now),
		} {
			if st, named := finality.AsNamed(repo.UpsertStatus(ctx, bad)); !named || st.Code != finality.CodeGuardRefused {
				t.Fatalf("%s: want %s, got %v", name, finality.CodeGuardRefused, st)
			}
		}
		if err := repo.UpsertStatus(ctx, finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelL1Posted, a.Seq, now)); err != nil {
			t.Fatalf("the founded verified row was refused: %v", err)
		}
		// a pending row of the OTHER level may state that l1_posted was reached, because it was
		if err := repo.UpsertStatus(ctx, pendingFor(proofID, finality.LevelFinalized, finality.LevelL1Posted, now)); err != nil {
			t.Fatalf("a founded level-reached claim was refused: %v", err)
		}
	})

	t.Run("nothing replaces a verified row, whatever its time", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		reg := kindRegistry(t, nil)
		a, err := addenda.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelL1Posted, "x"))
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.UpsertStatus(ctx, finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelL1Posted, a.Seq, now)); err != nil {
			t.Fatal(err)
		}
		// a validator that judged BEFORE the append and writes its pending row an hour AFTER the verified one (the reviewer's probe)
		for _, later := range []finality.BuilderStatus{
			pendingFor(proofID, finality.LevelL1Posted, finality.LevelIncluded, now.Add(time.Hour)),
			unavailableFor(proofID, finality.LevelL1Posted, finality.LevelIncluded, now.Add(2*time.Hour)),
			pendingFor(proofID, finality.LevelL1Posted, finality.LevelIncluded, now.Add(-time.Hour)),
		} {
			if err := repo.UpsertStatus(ctx, later); err != nil {
				t.Fatalf("a superseded write is not a failure: %v", err)
			}
			got, ok, err := repo.GetStatus(ctx, proofID, finality.LevelL1Posted)
			if err != nil || !ok || got.Class != finality.BuilderVerified || got.Seq != a.Seq {
				t.Fatalf("a verified row was replaced by %s: %+v", later.Class, got)
			}
		}
	})

	t.Run("a verified row converges a stale pending row even when the pending row carries a later time", func(t *testing.T) {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		reg := kindRegistry(t, nil)
		if err := repo.UpsertStatus(ctx, pendingFor(proofID, finality.LevelL1Posted, finality.LevelIncluded, now.Add(time.Hour))); err != nil { // a validator whose clock is fast
			t.Fatal(err)
		}
		a, err := addenda.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelL1Posted, "x"))
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.UpsertStatus(ctx, finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelL1Posted, a.Seq, now)); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := repo.GetStatus(ctx, proofID, finality.LevelL1Posted); got.Class != finality.BuilderVerified {
			t.Fatalf("the stored level's stale pending row was not converged: %+v", got)
		}
	})
}

// Two validators of one database: one appends and records the verified row, the other judged before the append and writes a
// pending row with a later clock reading, at the same moment. Whatever the interleaving, the verified row stands.
func TestFinalityStatusTwoValidatorsRacingNeverLeaveAStaleRowOverAVerifiedOne(t *testing.T) {
	ctx := context.Background()
	addenda := NewFinalityAddendaRepository(NewClientFromDB(testDB))
	reg := kindRegistry(t, nil)
	const rounds = 24
	var wg sync.WaitGroup
	errs := make(chan error, rounds*2)
	for i := 0; i < rounds; i++ {
		proofID, s := storeLeg(t, "base_sepolia_47368146")
		a, err := addenda.Append(ctx, appendRequest(t, reg, proofID, s, finality.LevelL1Posted, "x"))
		if err != nil {
			t.Fatal(err)
		}
		validatorA := NewFinalityStatusRepository(NewClientFromDB(testDB))
		validatorB := NewFinalityStatusRepository(NewClientFromDB(testDB))
		now := time.Now().UTC()
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errs <- validatorA.UpsertStatus(ctx, finality.VerifiedBuilderStatus(proofID, finality.ChainBaseSepolia, finality.LevelL1Posted, a.Seq, now))
		}()
		go func() {
			defer wg.Done()
			<-start
			errs <- validatorB.UpsertStatus(ctx, pendingFor(proofID, finality.LevelL1Posted, finality.LevelIncluded, now.Add(time.Second)))
		}()
		close(start)
		wg.Wait()
		got, ok, err := validatorA.GetStatus(ctx, proofID, finality.LevelL1Posted)
		if err != nil || !ok || got.Class != finality.BuilderVerified {
			t.Fatalf("round %d: the row is %+v (ok=%v err=%v), want verified", i, got, ok, err)
		}
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a racing write failed: %v", err)
		}
	}
}
