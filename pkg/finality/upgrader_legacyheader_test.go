// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"
)

// A bundle that holds no execution proof is read once and remembered against its bundle id. A bundle whose execution proof lacks only
// its header is NOT: the header is reconstructed in the background (pkg/finality/legacyhdr) and appears in the capture store without
// the bundle changing, so the leg is read again every HeaderRetry (RB12-LEGACY-191).
func TestUpgraderReadsALegWithoutABlockHeaderAgainEveryHeaderRetry(t *testing.T) {
	for _, reason := range []IncludedReason{IncludedNoBlockHeader, IncludedLegacyHeaderUnserved} {
		t.Run(string(reason), func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
			g := &gapRec{recSink: f.rec}
			f.u.cfg.Recorder = g
			src := newSettlementSource(f.src, IncludedUnavailable(reason, "proof_id", legID))
			f.u.src = src
			f.src.legs[0].BundleID = "bundle-1"

			rep := f.u.RunOnce(ctx)
			if rep.NoSettlement != 1 || rep.Attempts != 1 || rep.Unusable != 0 || rep.Failed != 0 || src.total() != 1 {
				t.Fatalf("first pass: %+v calls %d", rep, src.total())
			}
			if len(f.rec.failures) != 0 || f.logs.Joined() != "" {
				t.Fatalf("a leg waiting for its reconstructed header was reported: %v %q", f.rec.failures, f.logs.Joined())
			}
			if g.quietOn(ChainBaseSepolia) != 1 {
				t.Fatalf("the leg is not counted as quiet: %v", g.quiet)
			}
			if got, want := f.nextAt(t), f.clock.Now().Add(10*time.Minute); !got.Equal(want) {
				t.Fatalf("next read %v, want HeaderRetry (10m) %v", got, want)
			}
			// exact: one nanosecond early it is not read, on time it is read again (it is not remembered against its bundle id)
			f.clock.Advance(10*time.Minute - time.Nanosecond)
			if rep := f.u.RunOnce(ctx); rep.NotDue != 1 || rep.Attempts != 0 || src.total() != 1 {
				t.Fatalf("read before HeaderRetry: %+v calls %d", rep, src.total())
			}
			f.clock.Advance(time.Nanosecond)
			if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Attempts != 1 || src.total() != 2 {
				t.Fatalf("not read again at HeaderRetry: %+v calls %d", rep, src.total())
			}
			// the header appears: the leg is served, leaves the quiet gauge and is no longer a leg waiting
			src.err = nil
			f.clock.Advance(10 * time.Minute)
			rep = f.u.RunOnce(ctx)
			if rep.NoSettlement != 0 || rep.Attempts != 1 || rep.Unusable != 0 {
				t.Fatalf("pass after the header appeared: %+v", rep)
			}
			if g.quietOn(ChainBaseSepolia) != 0 {
				t.Fatalf("the leg is still counted as quiet: %v", g.quiet)
			}
		})
	}
}

// The remembered state of a bundle without an execution proof is unchanged: it is still read once.
func TestUpgraderStillReadsABundleWithoutAnExecutionProofOnce(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	src := newSettlementSource(f.src, errNoComponent)
	f.u.src = src
	f.src.legs[0].BundleID = "bundle-1"
	f.u.RunOnce(ctx)
	f.clock.Advance(24 * time.Hour)
	if rep := f.u.RunOnce(ctx); rep.Attempts != 0 || src.total() != 1 {
		t.Fatalf("a bundle without an execution proof was read again: %+v calls %d", rep, src.total())
	}
}

func TestUpgraderConfigHeaderRetryDefaultAndFloor(t *testing.T) {
	if got := (UpgraderConfig{}).withDefaults().HeaderRetry; got != 10*time.Minute {
		t.Fatalf("default HeaderRetry = %s", got)
	}
	if got := (UpgraderConfig{HeaderRetry: time.Nanosecond}).withDefaults().HeaderRetry; got != MinPoll {
		t.Fatalf("HeaderRetry below the floor = %s, want MinPoll %s", got, MinPoll)
	}
	if got := (UpgraderConfig{HeaderRetry: time.Hour}).withDefaults().HeaderRetry; got != time.Hour {
		t.Fatalf("HeaderRetry = %s", got)
	}
}
