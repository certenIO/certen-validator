// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"testing"
	"time"
)

// settlementSource answers every LegSettlement with a fixed error and lists the fixture's legs.
type settlementSource struct {
	*memSource
	err error
}

func (s settlementSource) LegSettlement(context.Context, LegRef) (Settlement, error) {
	return Settlement{}, s.err
}

// A leg whose bundle holds no execution proof has no settlement (yet): the named finality_included_unavailable state is neither
// a failure nor an unusable leg, writes no log line and no failure metric, and the leg is asked again on the pending schedule.
func TestUpgraderStaysQuietForALegWithoutASettlementAndAsksAgainOnThePendingSchedule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.u.src = settlementSource{f.src, IncludedUnavailable(IncludedNoExecutionProof, "proof_id", legID)}

	rep := f.u.RunOnce(ctx)
	if rep.NoSettlement != 1 || rep.Attempts != 1 || rep.Unusable != 0 || rep.Failed != 0 || rep.Appended != 0 || rep.Broken != 0 {
		t.Fatalf("%+v", rep)
	}
	if len(f.rec.failures) != 0 {
		t.Fatalf("a failure was recorded for a leg that is only not settled yet: %v", f.rec.failures)
	}
	if out := f.logs.Joined(); out != "" {
		t.Fatalf("the upgrader logged for a leg that is only not settled yet:\n%s", out)
	}
	if got, want := f.nextAt(t), f.clock.Now().Add(2*time.Minute); !got.Equal(want) {
		t.Fatalf("next ask %v, want the pending retry %v", got, want)
	}
	// not asked before the schedule, asked again after it, never taken for complete
	f.clock.Advance(time.Minute)
	if rep := f.u.RunOnce(ctx); rep.NotDue != 1 || rep.Attempts != 0 {
		t.Fatalf("asked again before its schedule: %+v", rep)
	}
	f.clock.Advance(2 * time.Minute)
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Complete != 0 {
		t.Fatalf("not asked again after its schedule: %+v", rep)
	}
}

// Only the named unavailable state is quiet: a plain source error and a named invalid state are still counted, recorded and logged.
func TestUpgraderIsLoudForEveryOtherSettlementError(t *testing.T) {
	ctx := context.Background()
	for name, err := range map[string]error{
		"a plain error":         errors.New("db down"),
		"a named invalid state": NewState(CodeIncludedInvalid, "cause", "bundle is not gzip"),
	} {
		f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
		f.u.src = settlementSource{f.src, err}
		rep := f.u.RunOnce(ctx)
		if rep.Unusable != 1 || rep.NoSettlement != 0 {
			t.Fatalf("%s: %+v", name, rep)
		}
		if f.logs.Joined() == "" {
			t.Fatalf("%s: nothing was logged", name)
		}
		if got, want := f.nextAt(t), f.clock.Now().Add(time.Hour); !got.Equal(want) {
			t.Fatalf("%s: next ask %v, want %v", name, got, want)
		}
	}
}
