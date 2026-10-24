// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// RB12-ARCHIVE-BACKFILL (V-ARCHIVE D4a): the budget of the prefix windows is read and then written. The upgrader runs several builds at
// once in one process, so the read and the write of one request must be one step within a process; across processes the bound is one
// window per concurrent validator, stated in the PR.

// raceStore pauses the first write of a prefix row until a second reader has listed the store (or a deadline passes), which is the
// interleaving that lets two requests both see room for one more window.
type raceStore struct {
	CaptureStore
	lists   atomic.Int64
	writing atomic.Bool
}

func (r *raceStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]CaptureKey, error) {
	r.lists.Add(1)
	return r.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

func (r *raceStore) Put(ctx context.Context, k CaptureKey, b []byte) error {
	if r.writing.CompareAndSwap(false, true) {
		before := r.lists.Load()
		deadline := time.Now().Add(300 * time.Millisecond)
		for r.lists.Load() <= before && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}
	return r.CaptureStore.Put(ctx, k, b)
}

func TestRB12PrefixConcurrentRequestsOfOneProcessNeverExceedTheBudget(t *testing.T) {
	s := &raceStore{CaptureStore: NewMemCaptureStore()}
	pol := PrefixPolicy{MaxBlocks: 200} // room for exactly two disjoint windows of 100 blocks
	var wg sync.WaitGroup
	verdicts := make(chan PrefixVerdict, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			from := uint64(1000 * (i + 1))
			v, err := RequestPrefix(pxCtx(), s, pxChain, from, from+99, pol)
			if err != nil {
				t.Error(err)
			}
			verdicts <- v
		}(i)
	}
	wg.Wait()
	close(verdicts)
	recorded := 0
	for v := range verdicts {
		if v == PrefixRecorded {
			recorded++
		}
	}
	ws, _ := PrefixWindowsOf(pxCtx(), s, pxChain)
	if recorded != 2 || PrefixBlocks(MergePrefixWindows(ws)) != 200 {
		t.Fatalf("a budget of two windows takes exactly two: recorded %d, blocks %d (%s)", recorded, PrefixBlocks(MergePrefixWindows(ws)), fmt.Sprint(ws))
	}
}
