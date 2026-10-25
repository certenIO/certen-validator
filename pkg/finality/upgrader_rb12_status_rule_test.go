// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12 OPS-A2 items 7 and 8 (ledger P0-1): which prover's status the status row of a level keeps when several provers answer. The rule, in
// upgradeLeg: a prover that returns nothing never replaces a status; a pending answer replaces the kept status only if the kept one is not a
// pending one or the new wait is strictly SHORTER (the earliest pending is kept, a tie keeps the first). The mutation entry that said
// `w < wait` -> `w <= wait` was equivalent (when w equals wait the assignment leaves it unchanged) described an older shape of the code; in
// the current code the comparison selects the status, so a tie is observable and is pinned here.

func rb12PendingProver(reason string, eta time.Time) *finalProver {
	return &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, _ *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelIncluded, NextLevel: target, Reason: reason, ETA: eta}, nil
	}}
}

func rb12NothingProver() *finalProver {
	return &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, nil
	}}
}

// rb12KeptReason runs one pass with the given provers (the first is registered by the fixture, the rest after it) and returns the reason of
// the pending state kept in the status row of the first stored level.
func rb12KeptReason(t *testing.T, provers ...*finalProver) string {
	t.Helper()
	f := newFixture(t, provers[0], UpgraderConfig{}, nil)
	for _, p := range provers[1:] {
		if err := f.reg.RegisterProver(p); err != nil {
			t.Fatal(err)
		}
	}
	status := newRB12Status()
	f.u.cfg.Status = status
	f.u.RunOnce(context.Background())
	row, ok := status.row(legID, LevelL1Posted)
	if !ok || row.Class != BuilderPending || row.State == nil {
		t.Fatalf("no pending status row: %+v ok=%v", row, ok)
	}
	return fmt.Sprint(row.State.Fields["reason"])
}

func TestRB12AProverThatReturnsNothingNeverReplacesAnEarlierProversStatus(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if got := rb12KeptReason(t, rb12PendingProver("game_unresolved", now.Add(10*time.Minute)), rb12NothingProver()); got != "game_unresolved" {
		t.Fatalf("the second prover returned nothing and the status row has reason %q", got)
	}
}

func TestRB12EqualWaitsKeepTheFirstProversPendingStatusAndAShorterWaitReplacesIt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0) // the fixture's clock
	eta := now.Add(10 * time.Minute)
	// a tie keeps the first prover's status
	if got := rb12KeptReason(t, rb12PendingProver("game_unresolved", eta), rb12PendingProver("awaiting_assertion_confirmation", eta)); got != "game_unresolved" {
		t.Fatalf("equal waits: the status row has reason %q, the first prover's was game_unresolved", got)
	}
	// a strictly shorter wait replaces it
	if got := rb12KeptReason(t, rb12PendingProver("game_unresolved", eta), rb12PendingProver("awaiting_assertion_confirmation", eta.Add(-time.Minute))); got != "awaiting_assertion_confirmation" {
		t.Fatalf("a shorter wait: the status row has reason %q", got)
	}
	// a longer wait does not
	if got := rb12KeptReason(t, rb12PendingProver("game_unresolved", eta), rb12PendingProver("awaiting_assertion_confirmation", eta.Add(time.Minute))); got != "game_unresolved" {
		t.Fatalf("a longer wait: the status row has reason %q", got)
	}
}

// The row of a level whose first prover was held by the environment and whose later prover answered pending with a shorter wait is that
// later prover's pending row, and it carries no retry note: the note is for a row that IS the environment's state. (Mutation entry 11-14 of
// upgrader.go described a condition that F17 rewrote; this pins the part of the new condition that `held && ...` -> `held || ...` breaks.)
func TestRB12ALaterPendingAnswerReplacingAHoldCarriesNoRetryNote(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	hold := &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, rb12Hold()
	}}
	f := newFixture(t, hold, UpgraderConfig{}, nil)
	if err := f.reg.RegisterProver(rb12PendingProver("game_unresolved", now.Add(30*time.Second))); err != nil {
		t.Fatal(err)
	}
	status := newRB12Status()
	f.u.cfg.Status = status
	f.u.RunOnce(context.Background())
	row, ok := status.row(legID, LevelL1Posted)
	if !ok || row.Class != BuilderPending || row.State == nil || fmt.Sprint(row.State.Fields["reason"]) != "game_unresolved" {
		t.Fatalf("the later pending answer (shorter wait) should be the row: %+v ok=%v", row, ok)
	}
	if v, has := row.State.Fields[FieldNextAttemptAt]; has {
		t.Fatalf("a pending row that is not the environment's state carries a retry note: %v", v)
	}
}
