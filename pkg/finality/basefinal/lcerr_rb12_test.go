// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

type pendingCarrier struct{ p *finality.PendingState }

func (e *pendingCarrier) Error() string                        { return "ledger incomplete" }
func (e *pendingCarrier) PendingState() *finality.PendingState { return e.p }

// RB12 OPS-A2 item 6: every kind of error the light-client source can return is reported by its own pending reason. A ledger that is too far
// behind the head (runtime.LedgerIncompleteError) is finality_ledger_incomplete with its periods and the eta of the next publication; every
// other error is the generic finality_lc_unavailable.
func TestEveryLightClientErrorKindIsReportedByItsOwnPendingReason(t *testing.T) {
	ctx := context.Background()
	eta := time.Unix(1_900_000_000, 0)
	incomplete := &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: "finality_ledger_incomplete", ETA: eta, Judged: map[string]any{"needed_period": uint64(1400), "max_links": uint64(64), "missing_period": uint64(1443)}}
	for _, c := range []struct {
		name   string
		err    error
		reason string
		own    bool
	}{
		{"a plain error", errors.New("lodestar down"), "finality_lc_unavailable", false},
		{"a cancelled context", context.Canceled, "finality_lc_unavailable", false},
		{"the named unavailable state", finality.NewState("finality_lc_unavailable", "endpoints", []string{"https://lc.example"}), "finality_lc_unavailable", false},
		{"an incomplete ledger", &pendingCarrier{incomplete}, "finality_ledger_incomplete", true},
		{"an incomplete ledger, wrapped", fmt.Errorf("light client: %w", &pendingCarrier{incomplete}), "finality_ledger_incomplete", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := loadLive(t)
			b := w.builder(t, w.store(t))
			b.LC = errLC{err: c.err}
			_, p, err := b.buildLeg(ctx, w.leg, haveIncluded)
			p = wantPendingReason(t, p, err, c.reason)
			if p.Chain != uint64(Chain) {
				t.Errorf("the pending state is of chain %d, not the builder's %d", p.Chain, Chain)
			}
			if c.own && (!p.ETA.Equal(eta) || p.Judged["needed_period"] != uint64(1400) || p.Judged["missing_period"] != uint64(1443) || p.Judged["max_links"] != uint64(64)) {
				t.Errorf("the periods and the eta of the ledger are lost: %v %v", p.ETA, p.Judged)
			}
			if !c.own && p.Judged["endpoints"] == nil {
				t.Errorf("%+v", p.Judged)
			}
		})
	}
}
