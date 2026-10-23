// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

func TestRB12TheMemoryBudgetReservesReleasesAndRefusesByName(t *testing.T) {
	b := NewMemoryBudget(1000)
	r1, err := b.Reserve(84532, "base_posted_window", 600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Reserve(84532, "base_posted_window", 401)
	se, ok := AsNamed(err)
	if !ok || se.Code != CodeMemoryBudget || se.Fields["requested"] != uint64(401) || se.Fields["in_use"] != uint64(600) || se.Fields["limit"] != uint64(1000) || se.Fields["what"] != "base_posted_window" {
		t.Fatalf("want finality_memory_budget_exceeded carrying what was asked, held and allowed: %v", err)
	}
	r2, err := b.Reserve(84532, "x", 400)
	if err != nil || b.Used() != 1000 {
		t.Fatalf("the exact remainder fits: %v %d", err, b.Used())
	}
	r1()
	r1() // releasing twice gives nothing back twice
	if b.Used() != 400 {
		t.Fatalf("used %d", b.Used())
	}
	r2()
	if b.Used() != 0 {
		t.Fatalf("used %d", b.Used())
	}
	// concurrent reservers never overshoot
	var wg sync.WaitGroup
	var peak atomic.Int64
	c := NewMemoryBudget(10_000)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := c.Reserve(1, "c", 100)
			if err != nil {
				return
			}
			if u := c.Used(); u > peak.Load() {
				peak.Store(u)
			}
			time.Sleep(time.Millisecond)
			rel()
		}()
	}
	wg.Wait()
	if peak.Load() > 10_000 || c.Used() != 0 {
		t.Fatalf("peak %d used %d", peak.Load(), c.Used())
	}
	// a nil budget reserves nothing (tests and recorders)
	var nb *MemoryBudget
	if rel, err := nb.Reserve(1, "x", 1<<40); err != nil {
		t.Fatal(err)
	} else {
		rel()
	}
}

func TestRB12TheMemoryBudgetEnvironmentValue(t *testing.T) {
	t.Setenv(EnvMemoryBudget, "")
	if v, err := MemoryBudgetFromEnv(); err != nil || v != DefaultMemoryBudget {
		t.Fatalf("default: %d %v", v, err)
	}
	t.Setenv(EnvMemoryBudget, "1073741824")
	if v, err := MemoryBudgetFromEnv(); err != nil || v != 1<<30 {
		t.Fatalf("%d %v", v, err)
	}
	for _, bad := range []string{"lots", "1024", "-5", "1.5"} {
		t.Setenv(EnvMemoryBudget, bad)
		if _, err := MemoryBudgetFromEnv(); err == nil {
			t.Errorf("%q must refuse startup by name", bad)
		}
	}
}

// A generic row loader reserves what it reads against the build's hold and stops with the named state.
func TestRB12TheGenericRowLoaderStopsAtTheBuildsBudget(t *testing.T) {
	st := NewMemCaptureStore()
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		if err := st.Put(ctx, CaptureKey{Chain: 84532, L1Block: uint64(100 + i), Item: "game/x"}, make([]byte, 100_000)); err != nil {
			t.Fatal(err)
		}
	}
	budget := NewMemoryBudget(1 << 20) // 1 MiB: seven rows of 150,000
	h := NewHold(WithMemoryBudget(ctx, budget), 84532, "build")
	_, err := CaptureRowsOfItem(WithHold(WithMemoryBudget(ctx, budget), h), st, 84532, "game/x")
	if se, ok := AsNamed(err); !ok || se.Code != CodeMemoryBudget {
		t.Fatalf("want finality_memory_budget_exceeded, got %v", err)
	}
	h.Release()
	if budget.Used() != 0 {
		t.Fatalf("used %d after the hold was released", budget.Used())
	}
	if rows, err := CaptureRowsOfItem(ctx, st, 84532, "game/x"); err != nil || len(rows) != 20 {
		t.Fatalf("without a hold the loader is unbounded (recorders): %d %v", len(rows), err)
	}
}

// The heap gate holds due legs back by name while the heap is above twice the budget, collects once, and starts them when it is down.
func TestRB12TheUpgraderHoldsLegsBackWhileTheHeapIsAboveTheGate(t *testing.T) {
	var heap atomic.Uint64
	var gcs atomic.Int64
	budget := NewMemoryBudget(1 << 30)
	heap.Store(uint64(3 << 30)) // above the gate (2 GiB)
	prover := allLevels(t)
	f := newFixture(t, prover, UpgraderConfig{Memory: budget, HeapInUse: heap.Load, GC: func() { gcs.Add(1) }}, nil)

	rep := f.u.RunOnce(context.Background())
	if rep.Attempts != 0 || rep.MemoryHeld != 1 || prover.calls.Load() != 0 {
		t.Fatalf("the leg must be held back by name, not attempted: %+v calls=%d", rep, prover.calls.Load())
	}
	if gcs.Load() != 1 {
		t.Fatalf("the gate collects once before holding legs back: %d", gcs.Load())
	}
	if !contains(f.logs.Joined(), "finality_memory_budget_exceeded{what=attempt,heap_in_use=") {
		t.Fatalf("the held-back legs are logged with the named state:\n%s", f.logs.Joined())
	}
	// still over, and collected a moment ago: held again without collecting again
	rep = f.u.RunOnce(context.Background())
	if rep.MemoryHeld != 1 || gcs.Load() != 1 {
		t.Fatalf("%+v gcs=%d", rep, gcs.Load())
	}
	// the heap comes down: the leg is started
	heap.Store(uint64(512 << 20))
	rep = f.u.RunOnce(context.Background())
	if rep.Attempts != 1 || rep.Appended != 2 || rep.MemoryHeld != 0 {
		t.Fatalf("%+v", rep)
	}
	// a collection that brings the heap down lets the pass go on
	heap.Store(uint64(3 << 30))
	f2 := newFixture(t, allLevels(t), UpgraderConfig{Memory: NewMemoryBudget(1 << 30), HeapInUse: heap.Load, GC: func() { heap.Store(uint64(100 << 20)) }}, nil)
	if rep := f2.u.RunOnce(context.Background()); rep.Attempts != 1 || rep.MemoryHeld != 0 {
		t.Fatalf("the collected heap is under the gate: %+v", rep)
	}
}

// Every build runs under the process budget: a prover that reads through the generic loaders is bounded by it.
func TestRB12ABuildRunsUnderTheProcessBudget(t *testing.T) {
	budget := NewMemoryBudget(1 << 20)
	var seen atomic.Pointer[MemoryBudget]
	prover := &finalProver{chain: ChainBaseSepolia, mode: func(ctx context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		seen.Store(MemoryBudgetOf(ctx))
		return nil, nil, ReserveRow(ctx, 10<<20) // 15 MiB against a 1 MiB budget
	}}
	f := newFixture(t, prover, UpgraderConfig{Memory: budget, HeapInUse: func() uint64 { return 0 }}, nil)
	rep := f.u.RunOnce(context.Background())
	if seen.Load() != budget {
		t.Fatalf("the build did not run under the configured budget")
	}
	if rep.Failed != 0 || rep.BuildHeld != 1 || f.rec.failures[CodeMemoryBudget] != 0 {
		t.Fatalf("a refused reservation is a named hold of the process (BuildHeld), not a failure of the leg: %+v %v", rep, f.rec.failures)
	}
	if budget.Used() != 0 {
		t.Fatalf("used %d after the attempt", budget.Used())
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
