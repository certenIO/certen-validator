// Copyright 2026 Certen Protocol

package runtime

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-DBFIX-FIX (verifier V-RB12-DBFIX V1, V2): the read of what a block holds, the decision and the reservation are ONE critical
// section, and a reservation ends with its call even when the inner store panics.

// gatedSizer is a store whose first BlockSizes call returns its answer and then waits (a call "held after its read"); later calls
// are not held. Everything else is the in-memory store.
type gatedSizer struct {
	*finality.MemCaptureStore
	mu     sync.Mutex
	calls  int
	afterA chan struct{} // closed when the first call has read
	hold   chan struct{} // the first call returns when this is closed
}

func (g *gatedSizer) BlockSizes(ctx context.Context, chain, l1Block uint64, l1Hash [32]byte) (map[string]int64, error) {
	out, err := g.MemCaptureStore.BlockSizes(ctx, chain, l1Block, l1Hash)
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	g.mu.Unlock()
	if first {
		close(g.afterA)
		<-g.hold
	}
	return out, err
}

// Bound 100. Call X wants to write a 60-byte row and is held right after it read the block's sizes (the block was empty). Call Y of
// the same process writes its own 60-byte row of the same block meanwhile. X must not be admitted on its stale read: before the
// read, the decision and the reservation were separate steps, Y wrote and released between them, and 120 bytes were stored.
func TestRTBudgetACallHeldAfterItsReadCannotBeAdmittedOnAStaleViewOfTheBlock(t *testing.T) {
	ctx := context.Background()
	g := &gatedSizer{MemCaptureStore: finality.NewMemCaptureStore(), afterA: make(chan struct{}), hold: make(chan struct{})}
	s := NewBudgetedStore(g, 100)
	s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
	var wg sync.WaitGroup
	var errX, errY error
	wg.Add(1)
	go func() {
		defer wg.Done()
		errX = s.Put(ctx, rtKey(10, 1, "x"), make([]byte, 60))
	}()
	waitFor(t, g.afterA, "X to have read the block")
	yDone := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(yDone)
		errY = s.Put(ctx, rtKey(10, 1, "y"), make([]byte, 60))
	}()
	select { // before the fix Y completes here; after it, Y waits for X's critical section
	case <-yDone:
	case <-time.After(300 * time.Millisecond):
	}
	close(g.hold)
	wg.Wait()

	rows, err := g.MemCaptureStore.ListByBlock(ctx, 84532, 10)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, r := range rows {
		total += int64(len(r.Bytes))
	}
	if total > 100 {
		t.Fatalf("x err=%v y err=%v: stored rows=%d total bytes=%d for a bound of 100", errX, errY, len(rows), total)
	}
	accepted := 0
	for _, e := range []error{errX, errY} {
		if e == nil {
			accepted++
			continue
		}
		if st, ok := finality.AsNamed(e); !ok || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "capture.block" {
			t.Fatalf("the refused call must say finality_evidence_too_large{capture.block}: %v", e)
		}
	}
	if accepted != 1 || len(rows) != 1 {
		t.Fatalf("exactly one of the two 60-byte rows fits 100 bytes: accepted=%d stored=%d (x %v, y %v)", accepted, len(rows), errX, errY)
	}
}

// A panic out of the inner store (a recovered one: the capture loops recover and name it unavailable) must not leave the call's
// reservation behind: nothing was stored, so the block is as empty as before.
func TestRTBudgetAPanickingInnerStoreLeavesNoReservationBehind(t *testing.T) {
	ctx := context.Background()
	blockPutter := &holdStore{mem: finality.NewMemCaptureStore(), hooks: []func() error{func() error { panic("provider decoder blew up") }}}
	for name, inner := range map[string]finality.CaptureStore{
		"a store that is a BlockPutter":       blockPutter,
		"a store that is only a CaptureStore": &panicPutStore{mem: finality.NewMemCaptureStore()},
	} {
		inner := inner
		t.Run(name, func(t *testing.T) {
			s := NewBudgetedStore(inner, 100)
			s.OnPut, s.OnRefused = func(uint64, int) {}, func(uint64, string) {}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("the inner panic was swallowed")
					}
				}()
				_ = s.PutBlock(ctx, []finality.CaptureRow{{CaptureKey: rtKey(10, 1, "big"), Bytes: make([]byte, 90)}})
			}()
			s.mu.Lock()
			n := len(s.inflight)
			s.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d blocks keep a reservation after the call panicked", n)
			}
			if err := s.Put(ctx, rtKey(10, 1, "next"), make([]byte, 60)); err != nil {
				t.Fatalf("a 60-byte row of a block nothing was stored in: %v", err)
			}
		})
	}
}

// panicPutStore is a CaptureStore that is not a BlockPutter (no PutBlock method) and whose first Put panics.
type panicPutStore struct {
	mem   *finality.MemCaptureStore
	mu    sync.Mutex
	calls int
}

func (p *panicPutStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	p.mu.Lock()
	p.calls++
	first := p.calls == 1
	p.mu.Unlock()
	if first {
		panic("provider decoder blew up")
	}
	return p.mem.Put(ctx, k, b)
}
func (p *panicPutStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	return p.mem.Get(ctx, k)
}
func (p *panicPutStore) ListByBlock(ctx context.Context, c, b uint64) ([]finality.CaptureRow, error) {
	return p.mem.ListByBlock(ctx, c, b)
}
func (p *panicPutStore) ListByRange(ctx context.Context, c, from, to uint64, pre string) ([]finality.CaptureKey, error) {
	return p.mem.ListByRange(ctx, c, from, to, pre)
}
