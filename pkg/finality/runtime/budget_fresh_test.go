// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX (D7 completion): the bound of a captured block counts what the durable store holds AT THE CALL, not what this process saw
// the first time it touched the block, so rows another validator adds to the same database after that are counted.

func TestRTBudgetRowsAnotherValidatorAddsAfterThisProcessFirstTouchedTheBlockAreCounted(t *testing.T) {
	ctx := context.Background()
	mem := finality.NewMemCaptureStore()
	one, two := NewBudgetedStore(mem, 100), NewBudgetedStore(mem, 100) // two validators, one database
	for _, s := range []*BudgetedStore{one, two} {
		s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	}
	if err := one.Put(ctx, rtKey(10, 1, "a"), make([]byte, 30)); err != nil {
		t.Fatal(err)
	}
	if err := two.Put(ctx, rtKey(10, 1, "a"), make([]byte, 30)); err != nil { // the same capture, identical bytes: a no-op that touches the block
		t.Fatal(err)
	}
	if err := one.Put(ctx, rtKey(10, 1, "b"), make([]byte, 40)); err != nil { // the store holds 70 now
		t.Fatal(err)
	}
	// the second validator first touched the block when it held 30; the store holds 70, so 60 more crosses the bound
	st, ok := finality.AsNamed(two.Put(ctx, rtKey(10, 1, "c"), make([]byte, 60)))
	if !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.block" || st.Fields["count"] != uint64(130) || st.Fields["limit"] != uint64(100) {
		t.Fatalf("a row another validator's rows push over the bound: %v", st)
	}
	if _, found, _ := mem.Get(ctx, rtKey(10, 1, "c")); found {
		t.Fatal("the crossing row was stored")
	}
	if err := two.Put(ctx, rtKey(10, 1, "c"), make([]byte, 30)); err != nil {
		t.Fatalf("the remaining 30 bytes: %v", err)
	}
}

// holdStore is an inner store whose PutBlock calls run a per-call hook first (call i runs hooks[i]; an error from the hook is the
// store's error), so a test can hold calls in flight and release them in an order of its choosing.
type holdStore struct {
	mem   *finality.MemCaptureStore
	mu    sync.Mutex
	calls int
	hooks []func() error
}

func (h *holdStore) PutBlock(ctx context.Context, rows []finality.CaptureRow) error {
	h.mu.Lock()
	i := h.calls
	h.calls++
	h.mu.Unlock()
	if i < len(h.hooks) && h.hooks[i] != nil {
		if err := h.hooks[i](); err != nil {
			return err
		}
	}
	return h.mem.PutBlock(ctx, rows)
}
func (h *holdStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	return h.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: k, Bytes: b}})
}
func (h *holdStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return h.mem.Get(ctx, k)
}
func (h *holdStore) ListByBlock(ctx context.Context, c, b uint64) ([]finality.CaptureRow, error) {
	return h.mem.ListByBlock(ctx, c, b)
}
func (h *holdStore) ListByRange(ctx context.Context, c, from, to uint64, p string) ([]finality.CaptureKey, error) {
	return h.mem.ListByRange(ctx, c, from, to, p)
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// Two calls of one process write the same row: the first reserves it, the second joins it. When the first fails, the row is still
// the second's to write, so it stays counted until the second has finished - a third call must not be admitted into its space.
func TestRTBudgetARowAJoinedWriterStillMeansToWriteStaysCountedWhenTheFirstReserverFails(t *testing.T) {
	ctx := context.Background()
	aIn, relA, bIn, relB := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	inner := &holdStore{mem: finality.NewMemCaptureStore(), hooks: []func() error{
		func() error { close(aIn); <-relA; return errors.New("disk full") }, // A: in flight, then fails
		func() error { close(bIn); <-relB; return nil },                     // B: in flight, then succeeds
	}}
	s := NewBudgetedStore(inner, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	x := finality.CaptureRow{CaptureKey: rtKey(10, 1, "x"), Bytes: make([]byte, 40)}
	var wg sync.WaitGroup
	var errA, errB error
	doneA := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); defer close(doneA); errA = s.PutBlock(ctx, []finality.CaptureRow{x}) }()
	waitFor(t, aIn, "A in flight")
	go func() { defer wg.Done(); errB = s.PutBlock(ctx, []finality.CaptureRow{x}) }()
	waitFor(t, bIn, "B in flight")
	close(relA) // A fails; B has not written yet
	waitFor(t, doneA, "A to return")
	// C wants 61 bytes beside the 40 that B is about to write: 101 > 100
	st, ok := finality.AsNamed(s.Put(ctx, rtKey(10, 1, "z"), make([]byte, 61)))
	if !ok || st.Code != finality.CodeEvidenceTooLarge {
		t.Fatalf("a row beside a row another call of this process is about to write was admitted: %v", st)
	}
	close(relB)
	wg.Wait()
	if errA == nil || errB != nil {
		t.Fatalf("A %v, B %v", errA, errB)
	}
	if err := s.Put(ctx, rtKey(10, 1, "z"), make([]byte, 60)); err != nil {
		t.Fatalf("the 60 bytes left beside the stored 40: %v", err)
	}
	if st, ok := finality.AsNamed(s.Put(ctx, rtKey(10, 1, "w"), make([]byte, 1))); !ok || st.Code != finality.CodeEvidenceTooLarge {
		t.Fatalf("the block is full: %v", st)
	}
}

func TestRTBudgetAFailedCallLeavesNoReservationBehind(t *testing.T) {
	ctx := context.Background()
	inner := &holdStore{mem: finality.NewMemCaptureStore(), hooks: []func() error{func() error { return errors.New("disk full") }}}
	s := NewBudgetedStore(inner, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	if err := s.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: rtKey(10, 1, "x"), Bytes: make([]byte, 90)}}); err == nil {
		t.Fatal("the store failure was swallowed")
	}
	s.mu.Lock()
	n := len(s.inflight)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d blocks keep a reservation after the call failed", n)
	}
	if err := s.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: rtKey(10, 1, "y"), Bytes: make([]byte, 100)}}); err != nil {
		t.Fatalf("the failed call kept its 90 bytes: %v", err)
	}
}
