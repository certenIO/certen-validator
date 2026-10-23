// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB11-DBFIX D7: the budget of a captured block is atomic (a check-then-Put that two writers can both pass is not a bound) and is
// seeded from the durable store (a restart, or another validator's rows in the same database, count).

// gateStore holds every Put until `want` Puts have entered it (or a deadline passes), which makes a check-then-Put race certain
// instead of likely: a store that reserves before it writes lets fewer than `want` writers through and the gate times out.
type gateStore struct {
	*finality.MemCaptureStore
	want    int32
	entered atomic.Int32
	release chan struct{}
	once    sync.Once
}

func newGateStore(want int) *gateStore {
	return &gateStore{MemCaptureStore: finality.NewMemCaptureStore(), want: int32(want), release: make(chan struct{})}
}

func (g *gateStore) Put(ctx context.Context, k finality.CaptureKey, data []byte) error {
	if g.entered.Add(1) >= g.want {
		g.once.Do(func() { close(g.release) })
	}
	select {
	case <-g.release:
	case <-time.After(400 * time.Millisecond):
	}
	return g.MemCaptureStore.Put(ctx, k, data)
}

func TestRTBudgetConcurrentWritersOfOneBlockNeverExceedTheBound(t *testing.T) {
	const writers, rowBytes, limit = 8, 30, 100 // 8 x 30 = 240 offered; 3 rows (90) fit
	gate := newGateStore(writers)
	s := NewBudgetedStore(gate, limit)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	var wg sync.WaitGroup
	var ok, refused atomic.Int32
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := s.Put(context.Background(), rtKey(10, 1, fmt.Sprintf("row-%d", i)), make([]byte, rowBytes))
			switch st, named := finality.AsNamed(err); {
			case err == nil:
				ok.Add(1)
			case named && st.Code == finality.CodeEvidenceTooLarge:
				refused.Add(1)
			default:
				t.Errorf("writer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	rows, err := gate.ListByBlock(context.Background(), 84532, 10)
	if err != nil {
		t.Fatal(err)
	}
	var total int
	for _, r := range rows {
		total += len(r.Bytes)
	}
	if total > limit || ok.Load() != 3 || refused.Load() != writers-3 || len(rows) != 3 {
		t.Fatalf("stored %d bytes in %d rows (%d accepted, %d refused) for a bound of %d: the check-then-Put was not atomic", total, len(rows), ok.Load(), refused.Load(), limit)
	}
}

func TestRTBudgetARestartRecountsTheBlockFromTheStoreAndOtherValidatorsRowsCount(t *testing.T) {
	ctx := context.Background()
	mem := finality.NewMemCaptureStore()
	// rows an earlier process (or another validator) already wrote for the block: 60 + 30 = 90 of 100
	for item, n := range map[string]int{"a": 60, "b": 30} {
		if err := mem.Put(ctx, rtKey(10, 1, item), make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	restarted := NewBudgetedStore(mem, 100)
	restarted.OnPut, restarted.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	st, ok := finality.AsNamed(restarted.Put(ctx, rtKey(10, 1, "c"), make([]byte, 30)))
	if !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.block" || st.Fields["count"] != uint64(120) || st.Fields["limit"] != uint64(100) {
		t.Fatalf("a restarted process must count the 90 bytes the store already holds: %v", st)
	}
	if _, found, _ := mem.Get(ctx, rtKey(10, 1, "c")); found {
		t.Fatal("the row that crosses the bound after a restart was stored")
	}
	// what the store holds is not recounted: an identical re-put is a no-op and the remaining 10 bytes are still available
	if err := restarted.Put(ctx, rtKey(10, 1, "a"), make([]byte, 60)); err != nil {
		t.Fatalf("an identical re-put after a restart: %v", err)
	}
	if err := restarted.Put(ctx, rtKey(10, 1, "d"), make([]byte, 10)); err != nil {
		t.Fatalf("a row that fits the remaining budget after a restart: %v", err)
	}
	// another block of the same chain, and the same height under another hash, are seeded on their own
	if err := restarted.Put(ctx, rtKey(11, 1, "c"), make([]byte, 100)); err != nil {
		t.Fatalf("another block: %v", err)
	}
	if err := restarted.Put(ctx, rtKey(10, 2, "c"), make([]byte, 100)); err != nil {
		t.Fatalf("the same height under another hash: %v", err)
	}
}
