// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-INDEX-FIX (F17 follow-up): the leg of an index_inconsistent state is held or backed off by the REASON. A missing row is a fact about
// the capture store that clears (the reconcile or a backfill writes it): the leg is asked again at PendingRetry and no failure is counted.
// Any other reason is persistent until a new generation: the leg backs off (5 minutes, doubling) and is asked ever less often.
func TestRB12F17IndexInconsistentIsHeldOnlyForAMissingRow(t *testing.T) {
	for _, c := range []struct {
		reason string
		held   bool
	}{
		{IndexRowMissing, true},
		{IndexEntryCorrupt, false},
		{IndexSelfCheckMismatch, false},
		{IndexCoverageOverflow, false},
		{IndexPinsChanged, false},
		{IndexRowsDisagree, false},
		{IndexDuplicateAfterOpen, false},
	} {
		t.Run(c.reason, func(t *testing.T) {
			u, src, clock, _, logs := rb12Fixture(t, rb12GapCfg(),
				func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
					return func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
						return nil, nil, IndexInconsistent(uint64(ChainBaseSepolia), "bi", c.reason, "item", "idx/g1/bi/c/1/2/ab", "l1_block", uint64(10))
					}
				})
			status := newRB12Status()
			u.cfg.Status = status
			src.add(leg(1))
			var failed, attempts int
			for pass := 0; pass < 3; pass++ {
				rep := u.RunOnce(context.Background())
				failed += rep.Failed
				attempts += rep.Attempts
				clock.Advance(2 * time.Minute) // PendingRetry; the failure back-off is 5 minutes, so the third ask (4 minutes) is still inside it
			}
			if c.held && (failed != 0 || attempts != 3) {
				t.Fatalf("a missing row is held and asked again at every PendingRetry: attempts=%d failed=%d\n%s", attempts, failed, logs.Joined())
			}
			if !c.held && (failed != 1 || attempts != 1) {
				t.Fatalf("%s is persistent until a new generation: one failure, then the back-off holds the leg off: attempts=%d failed=%d\n%s", c.reason, attempts, failed, logs.Joined())
			}
		})
	}
}
