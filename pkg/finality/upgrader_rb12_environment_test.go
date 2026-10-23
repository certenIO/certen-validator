// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-GO-INT F17 (INDEX-A finding): the state of a leg whose sequencer window holds blocks the capture has not captured yet
// (l1_capture_gap) is a fact about the capture STORE, not a verdict on the leg. The upgrader treated it as a builder failure, so after
// the backfill closed the hole the leg waited out a back-off of 5 minutes doubling to 6 hours. These tests use only the configuration
// surface and the API of the merged base, so they run there and fail by their assertion.

// rb12GapState is the state the Base l1_posted builder returns for a leg inside a recorded gap (pkg/finality/baseposted/gaps.go).
func rb12GapState() *StateError {
	return NewState("l1_capture_gap", "chain", uint64(ChainBaseSepolia), "kind", "l1_posted", "from", uint64(110), "to", uint64(120), "gap_state", "open",
		"ranges", 1, "blocks", uint64(11), "epoch_l1_block", uint64(100), "window_end_l1_block", uint64(130), "archive_provider", "unset")
}

func rb12GapCfg() UpgraderConfig {
	return UpgraderConfig{HeapInUse: func() uint64 { return 0 }, BuildTimeout: 20 * time.Second}
}

// A leg in a gap is asked again at PendingRetry, every time, whatever the number of earlier asks; it is no suspect, no failure is counted
// and the row says when it is asked next. When the hole is closed the leg is built at the next ask, which is within one retry interval.
func TestRB12F17ALegInACaptureGapIsRebuiltWithinOneRetryIntervalOfTheGapClosing(t *testing.T) {
	var gapOpen atomic.Bool
	gapOpen.Store(true)
	u, src, clock, rec, logs := rb12Fixture(t, rb12GapCfg(),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
				if gapOpen.Load() {
					return nil, nil, rb12GapState()
				}
				return built(t, s, target, "evidence"), nil, nil
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	src.add(leg(1))
	reg := loadRegistry(t)
	retry := 2 * time.Minute // the default PendingRetry

	for pass := 1; pass <= 8; pass++ {
		at := clock.Now()
		rep := u.RunOnce(context.Background())
		if rep.Attempts != 1 || rep.Failed != 0 || rep.Appended != 0 {
			t.Fatalf("pass %d: a leg in a capture gap is held, not failed: %+v\n%s", pass, rep, logs.Joined())
		}
		if u.isSuspect(leg(1)) {
			t.Fatalf("pass %d: a capture gap made the leg a suspect", pass)
		}
		if n := rec.failures["l1_capture_gap"]; n != 0 {
			t.Fatalf("pass %d: the gap was counted as a build failure %d times", pass, n)
		}
		for _, lv := range []Level{LevelL1Posted, LevelFinalized} {
			row, ok := status.row(leg(1), lv)
			if !ok || row.State == nil || row.State.Code != "l1_capture_gap" {
				t.Fatalf("pass %d: the %s row names the gap: %+v", pass, lv, row)
			}
			if _, has := row.State.Fields["attempt"]; has {
				t.Fatalf("pass %d: a hold is no failed attempt and carries no attempt ordinal: %v", pass, row.State.Fields)
			}
			want := at.Add(retry).UTC().Format(time.RFC3339)
			if got := row.State.Fields["next_attempt_at"]; got != want {
				t.Fatalf("pass %d: %s next_attempt_at=%v want %s (PendingRetry, never an exponent)", pass, lv, got, want)
			}
			if msg := conforms(reg, row.State); msg != "" {
				t.Fatalf("pass %d: the stored state is not in the registry: %s", pass, msg)
			}
		}
		// not asked before the time the row states
		clock.Advance(retry - time.Second)
		if rep := u.RunOnce(context.Background()); rep.Attempts != 0 {
			t.Fatalf("pass %d: asked again before next_attempt_at: %+v", pass, rep)
		}
		if pass < 8 {
			clock.Advance(time.Second)
		}
	}

	// the backfill closes the hole; the row said the leg is asked one retry interval after its last ask, which is now
	closedAt := clock.Now()
	gapOpen.Store(false)
	clock.Advance(time.Second)
	rep := u.RunOnce(context.Background())
	if rep.Appended != 2 || rep.Failed != 0 {
		t.Fatalf("the leg was not rebuilt within one retry interval of the gap closing (closed at %s, now %s): %+v\n%s", closedAt, clock.Now(), rep, logs.Joined())
	}
	if d := clock.Now().Sub(closedAt); d > retry {
		t.Fatalf("the rebuild came %s after the gap closed, more than one retry interval (%s)", d, retry)
	}
	for _, lv := range []Level{LevelL1Posted, LevelFinalized} {
		if row, ok := status.row(leg(1), lv); !ok || row.Class != BuilderVerified {
			t.Fatalf("%s: the row after the rebuild: %+v", lv, row)
		}
	}
}

// A gap leaves the back-off exponent of the leg where it was: after eight asks inside the hole, the first REAL failure waits the first
// back-off (5 minutes, attempt 1), the second waits twice that.
func TestRB12F17AnEnvironmentHoldAdvancesNoFailureExponent(t *testing.T) {
	var mode atomic.Int32 // 0: gap, 1: a provider error
	u, src, clock, _, logs := rb12Fixture(t, rb12GapCfg(),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(_ context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				if mode.Load() == 0 {
					return nil, nil, rb12GapState()
				}
				return nil, nil, errors.New("provider unreachable")
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	src.add(leg(1))
	for i := 0; i < 8; i++ {
		u.RunOnce(context.Background())
		clock.Advance(2 * time.Minute)
	}
	mode.Store(1)
	for n, wantWait := range []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute} {
		at := clock.Now()
		rep := u.RunOnce(context.Background())
		if rep.Failed != 1 {
			t.Fatalf("failure %d: %+v\n%s", n+1, rep, logs.Joined())
		}
		row, _ := status.row(leg(1), LevelL1Posted)
		if row.State == nil || row.State.Code != CodeBuilderError {
			t.Fatalf("failure %d: %+v", n+1, row)
		}
		if got := row.State.Fields["attempt"]; got != uint64(n+1) {
			t.Fatalf("failure %d: attempt=%v: the eight asks inside the gap must not count", n+1, got)
		}
		if got, want := row.State.Fields["next_attempt_at"], at.Add(wantWait).UTC().Format(time.RFC3339); got != want {
			t.Fatalf("failure %d: next_attempt_at=%v want %s", n+1, got, want)
		}
		clock.Advance(wantWait)
	}
}

// The held ask is counted: certen_finality_build_held_total{chain,code} (the failure counter no longer sees it, and a gap that is held
// for ever must still be visible to an alert).
func TestRB12F17AHeldAskIsCountedByCode(t *testing.T) {
	metrics.RegisterMetrics()
	u, src, _, rec, _ := rb12Fixture(t, rb12GapCfg(),
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
				return nil, nil, rb12GapState()
			}
		})
	u.cfg.Recorder = MetricsRecorder{}
	src.add(leg(1))
	before := rb12Counter(t, "certen_finality_build_held_total", map[string]string{"chain": "84532", "code": "l1_capture_gap"})
	failedBefore := rb12Counter(t, "certen_finality_build_failures_total", map[string]string{"chain": "84532", "code": "l1_capture_gap"})
	u.RunOnce(context.Background())
	if got := rb12Counter(t, "certen_finality_build_held_total", map[string]string{"chain": "84532", "code": "l1_capture_gap"}); got != before+2 {
		t.Fatalf("held counter %v -> %v, want +2 (one per level asked)", before, got)
	}
	if got := rb12Counter(t, "certen_finality_build_failures_total", map[string]string{"chain": "84532", "code": "l1_capture_gap"}); got != failedBefore {
		t.Fatalf("the failure counter moved for a hold: %v -> %v", failedBefore, got)
	}
	if rec.failures["l1_capture_gap"] != 0 {
		t.Fatal("unreachable: the fixture recorder was replaced")
	}
}

// rb12Counter reads one labelled counter series of the default registry (0 when the series does not exist yet: a vector with no series
// is not gathered).
func rb12Counter(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			match := true
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					match = false
				}
			}
			if match {
				return m.GetCounter().GetValue()
			}
		}
		return 0
	}
	return 0
}
