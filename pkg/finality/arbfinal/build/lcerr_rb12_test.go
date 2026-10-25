// Copyright 2026 Certen Protocol

package build

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

type pendingCarrier struct{ p *finality.PendingState }

func (e *pendingCarrier) Error() string                        { return "ledger incomplete" }
func (e *pendingCarrier) PendingState() *finality.PendingState { return e.p }

// RB12 OPS-A2 item 6: every kind of error the light-client source can return is reported by its own pending reason (see basefinal).
func TestEveryLightClientErrorKindIsReportedByItsOwnPendingReason(t *testing.T) {
	eta := time.Unix(1_900_000_000, 0)
	incomplete := &finality.PendingState{Chain: finality.ChainSepolia, LevelReached: finality.LevelIncluded, NextLevel: finality.LevelFinalized,
		Reason: "finality_ledger_incomplete", ETA: eta, Judged: map[string]any{"needed_period": uint64(1400), "max_links": uint64(64), "missing_period": uint64(1443)}}
	for _, c := range []struct {
		name   string
		err    error
		reason string
		own    bool
	}{
		{"a plain error", errors.New("beacon down"), PendingL1State, false},
		{"the named unavailable state", finality.NewState("finality_lc_unavailable", "endpoints", []string{"https://lc.example"}), PendingL1State, false},
		{"an incomplete ledger", &pendingCarrier{incomplete}, "finality_ledger_incomplete", true},
		{"an incomplete ledger, wrapped", fmt.Errorf("light client: %w", &pendingCarrier{incomplete}), "finality_ledger_incomplete", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.lc.err = c.err
			_, pend, err := w.build(t)
			wantPending(t, pend, err, c.reason)
			if pend.Chain != finality.ChainArbitrumSepolia {
				t.Errorf("the pending state is of chain %d", pend.Chain)
			}
			if c.own && (!pend.ETA.Equal(eta) || pend.Judged["needed_period"] != uint64(1400) || pend.Judged["missing_period"] != uint64(1443) || pend.Judged["max_links"] != uint64(64)) {
				t.Errorf("the periods and the eta of the ledger are lost: %v %v", pend.ETA, pend.Judged)
			}
			if !c.own && pend.ETA != (time.Time{}) {
				t.Errorf("an unavailable source has no eta: %v", pend.ETA)
			}
		})
	}
}
