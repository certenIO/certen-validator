// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// newScaleBuilder is the builder under test over the metered store: the capture index is built over the raw store first (the indexer
// run to completion, outside the measurement) and the builder answers from it.
func newScaleBuilder(t testing.TB, raw finality.CaptureStore, meter *meterStore, bp *Pins, upTo uint64, l2 fixedL2) *Builder {
	t.Helper()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndexer(raw, bp, 0, IndexConfig{BlocksPerStep: 1 << 30, StepBudget: time.Hour})
	for i := 0; i < 8; i++ {
		rep, err := ix.Step(context.Background(), upTo)
		if err != nil {
			t.Fatal(err)
		}
		if rep.StoppedByCap == "" {
			break
		}
	}
	return &Builder{Pins: pins, Store: meter, L2: l2, Index: NewIndexReader(meter, bp, 0)}
}
