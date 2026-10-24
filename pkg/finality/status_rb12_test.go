// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-P0LIVE-FIX D4 (independent verifier V-RB12-P0-LIVE, 2026-10-23).

// D4: finality_verifier_failed means "evidence was built and failed verification". An error with no name (a capture row that vanished,
// a database error, a provider error) is neither: it is the named builder-side state finality_builder_error with the stage it came
// from, and the class is unavailable.
func TestRB12AnUnnamedBuilderErrorIsNamedAndIsNeverAVerifierFailure(t *testing.T) {
	reg := loadRegistry(t)
	at := time.Unix(1_800_000_000, 0)
	for name, err := range map[string]error{
		"a capture row that vanished":     fmt.Errorf("baseposted: capture row %s vanished", "inbox"),
		"a database error":                errors.New("pq: connection reset by peer"),
		"a provider error":                errors.New("Get \"https://rpc.example/v1/key\": EOF"),
		"a wrapped error with a cause":    fmt.Errorf("loading the window: %w", errors.New("bad row")),
		"an error that is only a message": errors.New("x"),
	} {
		s := BuilderStatusOf("p", 84532, LevelL1Posted, LevelIncluded, nil, err, false, at)
		if s.State == nil || s.State.Code == CodeVerifierFailed {
			t.Fatalf("%s: an unnamed builder error is not a verifier failure: %+v", name, s.State)
		}
		if s.State.Code != "finality_builder_error" || s.Class != BuilderUnavailable {
			t.Fatalf("%s: want class unavailable and finality_builder_error, got %s %+v", name, s.Class, s.State)
		}
		if s.State.Fields["chain"] != uint64(84532) || s.State.Fields["stage"] == nil || s.State.Fields["cause"] == nil {
			t.Fatalf("%s: the state carries chain, stage and cause: %v", name, s.State.Fields)
		}
		if msg := conforms(reg, s.State); msg != "" {
			t.Fatalf("%s: %s", name, msg)
		}
	}
	// a state that already has a name keeps it, and evidence that was built and refused stays a verifier failure of class refused
	named := NewState(CodeVerifierFailed, "chain", uint64(84532), "kind", "base_posted", "cause", "x")
	if s := BuilderStatusOf("p", 84532, LevelL1Posted, LevelIncluded, nil, named, true, at); s.State.Code != CodeVerifierFailed || s.Class != BuilderRefused {
		t.Fatalf("%s %+v", s.Class, s.State)
	}
}

// D4 end to end: a prover that returns a plain error is reported by the upgrader as finality_builder_error, stage build, with the
// attempt notes the failure path adds.
func TestRB12AProverThatReturnsAPlainErrorIsAStoredBuilderError(t *testing.T) {
	u, src, clock, rec, _ := rb12Fixture(t, UpgraderConfig{HeapInUse: func() uint64 { return 0 }},
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
				return nil, nil, fmt.Errorf("baseposted: capture row %s vanished", "inbox")
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	src.add(leg(1))
	if rep := u.RunOnce(context.Background()); rep.Failed != 1 {
		t.Fatalf("%+v", rep)
	}
	row, ok := status.row(leg(1), LevelL1Posted)
	if !ok || row.Class != BuilderUnavailable || row.State == nil || row.State.Code != "finality_builder_error" || row.State.Fields["stage"] != "build" {
		t.Fatalf("%+v", row)
	}
	if msg := conforms(loadRegistry(t), row.State); msg != "" {
		t.Fatal(msg)
	}
	if rec.failures["finality_builder_error"] < 1 || rec.failures["unnamed_error"] != 0 {
		t.Fatalf("the failure metric carries the name: %v", rec.failures)
	}
	_ = clock
}
