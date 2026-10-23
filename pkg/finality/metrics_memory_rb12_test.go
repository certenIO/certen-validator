// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-F12 (the deployed f555588 on validator-2, 2026-10-23T14:00Z): certen_finality_heap_inuse_bytes, certen_finality_memory_budget_bytes
// and certen_finality_memory_reserved_bytes were all 0 seven minutes after start, while the startup line said memory_budget=2147483648
// and the Go heap was 1.2 GB: they were written only at the end of a pass, and a pass lasts as long as its slowest non-suspect leg. An
// alert on the heap would never have fired. The budget is published when the upgrader starts, the heap on a ticker of its own, and the
// reserved bytes on every reservation and release.

func rb12Gauge(t *testing.T, name string) float64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			for _, m := range f.GetMetric() {
				return m.GetGauge().GetValue()
			}
		}
	}
	t.Fatalf("metric %s is not registered", name)
	return 0
}

func rb12WaitGauge(t *testing.T, name string, ok func(float64) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		v := rb12Gauge(t, name)
		if ok(v) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %v: %s", name, v, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A pass that has not finished (it waits for a slow leg) must not keep the gauges at zero.
func TestRB12TheMemoryGaugesAreLiveWhileAPassIsStillRunning(t *testing.T) {
	metrics.RegisterMetrics() // what the validator process does once at start
	metrics.SetFinalityHeap(0, 0, 0)
	const heap = 1_234_567_890
	budget := NewMemoryBudget(3 << 29)
	gate := make(chan struct{})
	u, src, _, _, _ := rb12Fixture(t, UpgraderConfig{Memory: budget, HeapInUse: func() uint64 { return heap }, BuildTimeout: time.Minute},
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				<-gate // a slow, non-suspect leg: the pass waits for it
				return nil, nil, ctx.Err()
			}
		})
	src.add(leg(1))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	defer func() {
		close(gate)
		cancel()
		<-done
	}()

	rb12WaitGauge(t, "certen_finality_memory_budget_bytes", func(v float64) bool { return v == float64(3<<29) }, "the budget is published when the upgrader starts, not at the end of its first pass")
	rb12WaitGauge(t, "certen_finality_heap_inuse_bytes", func(v float64) bool { return v == heap }, "the heap is published on a ticker of its own, not at the end of a pass")
	// the pass is still running: the slow leg has not returned
	select {
	case <-done:
		t.Fatal("the run ended")
	default:
	}
}

// The reserved bytes follow every reservation and release at once.
func TestRB12TheReservedGaugeFollowsEveryReservationAndRelease(t *testing.T) {
	metrics.RegisterMetrics() // what the validator process does once at start
	metrics.SetFinalityHeap(0, 0, 0)
	b := NewMemoryBudget(10_000)
	rel, err := b.Reserve(84532, "x", 700)
	if err != nil {
		t.Fatal(err)
	}
	if v := rb12Gauge(t, "certen_finality_memory_reserved_bytes"); v != 700 {
		t.Fatalf("reserved gauge %v after Reserve(700)", v)
	}
	h := NewHold(WithMemoryBudget(context.Background(), b), 84532, "y")
	if err := h.Add(300); err != nil {
		t.Fatal(err)
	}
	if v := rb12Gauge(t, "certen_finality_memory_reserved_bytes"); v != 1000 {
		t.Fatalf("reserved gauge %v after Add(300)", v)
	}
	rel()
	if v := rb12Gauge(t, "certen_finality_memory_reserved_bytes"); v != 300 {
		t.Fatalf("reserved gauge %v after the release", v)
	}
	h.Release()
	if v := rb12Gauge(t, "certen_finality_memory_reserved_bytes"); v != 0 {
		t.Fatalf("reserved gauge %v after Release", v)
	}
}
