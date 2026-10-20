// Copyright 2026 Certen Protocol

package basefinal

import (
	"fmt"
	"testing"
	"time"
)

// A capture inside the finality delay waits until the resolution time plus the delay: with a pinned delay that is not zero, the end of
// the wait is after the resolution.
func TestTheWaitInsideTheFinalityDelayEndsAtTheResolutionPlusTheDelay(t *testing.T) {
	w := loadLive(t)
	m := baseSection(t)
	for _, v := range m["impl_pins"].(map[string]any) {
		row := v.(map[string]any)
		if row["role"] == RoleASRImpl {
			row["finality_delay_seconds"] = 1000
		}
	}
	pins := pinsWith(t, m)
	st := w.store(t)
	b := w.builder(t, st)
	b.Pins = pins
	resolved := uint64(0)
	if _, err := fmt.Sscan(w.expect["resolved_at"], &resolved); err != nil {
		t.Fatal(err)
	}
	a := aOf(w)
	a.Timestamp = resolved + 1000 // the last second of the delay
	w.headers[a.Hash] = a
	_, p, err := w.built(t, b)
	p = wantPendingReason(t, p, err, "within_finality_delay")
	if !p.ETA.Equal(time.Unix(int64(resolved+1000), 0)) {
		t.Errorf("eta %v, want %d", p.ETA, resolved+1000)
	}
}
