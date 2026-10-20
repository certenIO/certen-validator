// Copyright 2026 Certen Protocol

package basefinal

import (
	"fmt"
	"math"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The finality delay is a pin added to a proven resolution time; a delay near 2^64 must not wrap the sum to a small number and let a
// game that resolved a moment ago through.
func TestAFinalityDelayNearTheUint64LimitDoesNotWrapTheDelayCheck(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{})
	if err != nil {
		t.Fatal(err)
	}
	var asrHash [32]byte
	for h, r := range p.Impl {
		if r.Role == RoleASRImpl {
			asrHash = h
		}
	}
	for _, delay := range []uint64{math.MaxUint64, math.MaxUint64 - 1000, 1 << 63} {
		q := clonePins(p)
		r := q.Impl[asrHash]
		d := delay
		r.FinalityDelaySeconds = &d
		q.Impl[asrHash] = r
		_, err := Judge(q, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
		se, ok := finality.AsNamed(err)
		if !ok || se.Code != CodeGameWithinDelay || fmt.Sprint(se.Fields["delay"]) != fmt.Sprint(delay) {
			t.Errorf("delay %d: %v", delay, err)
		}
	}
}
