// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

type carrierErr struct{ p *PendingState }

func (e *carrierErr) Error() string               { return "carrier" }
func (e *carrierErr) PendingState() *PendingState { return e.p }

// RB12 OPS-A2 item 6: PendingOf finds the pending state an error carries, also when it is wrapped; JudgedPairs is in key order.
func TestPendingOfFindsACarriedPendingStateThroughWrapping(t *testing.T) {
	p := &PendingState{Reason: "finality_ledger_incomplete", ETA: time.Unix(5, 0), Judged: map[string]any{"b": 2, "a": 1}}
	for name, err := range map[string]error{
		"direct":  &carrierErr{p},
		"wrapped": fmt.Errorf("light client: %w", &carrierErr{p}),
		"joined":  errors.Join(errors.New("x"), &carrierErr{p}),
	} {
		if got := PendingOf(err); got != p {
			t.Errorf("%s: %v", name, got)
		}
	}
	for name, err := range map[string]error{"nil": nil, "plain": errors.New("lodestar down"), "named": NewState("finality_lc_unavailable", "endpoints", []string{"x"})} {
		if got := PendingOf(err); got != nil {
			t.Errorf("%s: carries %v", name, got)
		}
	}
	if kv := p.JudgedPairs(); len(kv) != 4 || kv[0] != "a" || kv[1] != 1 || kv[2] != "b" || kv[3] != 2 {
		t.Fatalf("pairs %v", kv)
	}
	if kv := (&PendingState{}).JudgedPairs(); len(kv) != 0 {
		t.Fatalf("empty: %v", kv)
	}
}
