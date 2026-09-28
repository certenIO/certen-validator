package intent

import (
	"context"
	"io"
	"log"
	"sort"
	"sync"
	"testing"
	"time"
)

func drainHeights(ch chan *BlockProcessJob) []uint64 {
	var out []uint64
	for {
		select {
		case j := <-ch:
			out = append(out, j.BlockHeight)
		default:
			sort.Slice(out, func(i, k int) bool { return out[i] < out[k] })
			return out
		}
	}
}

// RB3-F151: while the workers are behind, every tick used to queue the whole range from the watermark to the
// head again, so each block was queued once per tick and new blocks waited behind the duplicates. A height
// in flight is queued once.
func TestATickQueuesNoBlockThatIsInFlight(t *testing.T) {
	id := &IntentDiscovery{client: tipClient{tip: 120}, logger: log.New(io.Discard, "", 0), lastProcessedBlock: 100,
		blockProcessCh: make(chan *BlockProcessJob, 1000), stopCh: make(chan struct{}), processedBlocks: map[uint64]bool{}}
	for i := 0; i < 3; i++ {
		if err := id.checkForNewBlocks(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got := drainHeights(id.blockProcessCh)
	if len(got) != 20 || got[0] != 101 || got[19] != 120 {
		t.Fatalf("three ticks queued %d jobs (%v...), want each of 101-120 once", len(got), got[:min(5, len(got))])
	}
}

// The tip is still searched again: a block searched while above the finalize ceiling is re-queued on the next
// tick, so an intent whose block became queryable a tick later is found. Blocks at or below the ceiling are
// finalized and not searched again.
func TestTheUnconfirmedTipIsSearchedAgain(t *testing.T) {
	id := &IntentDiscovery{client: tipClient{tip: 120}, logger: log.New(io.Discard, "", 0), lastProcessedBlock: 100,
		blockProcessCh: make(chan *BlockProcessJob, 1000), stopCh: make(chan struct{}), processedBlocks: map[uint64]bool{}}
	if err := id.checkForNewBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, h := range drainHeights(id.blockProcessCh) {
		id.advanceWatermark(h) // every block searched
	}
	if id.lastProcessedBlock != 118 {
		t.Fatalf("watermark %d, want the ceiling 118", id.lastProcessedBlock)
	}
	if err := id.checkForNewBlocks(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := drainHeights(id.blockProcessCh); len(got) != 2 || got[0] != 119 || got[1] != 120 {
		t.Fatalf("re-queued %v, want the unconfirmed tip 119-120", got)
	}
}

type recordingUnsearched struct {
	mu   sync.Mutex
	kept []uint64
}

func (r *recordingUnsearched) Put(h uint64, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kept = append(r.kept, h)
	return nil
}
func (r *recordingUnsearched) List() ([]UnsearchedBlock, error) { return nil, nil }
func (r *recordingUnsearched) Remove(uint64) error              { return nil }
func (r *recordingUnsearched) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.kept)
}

// A search that panics is a failed search: the block is kept for another search and leaves flight, and the
// worker goes on to the next job. It used to end the worker.
func TestAPanickingSearchIsAFailedSearchAndTheWorkerGoesOn(t *testing.T) {
	store := &recordingUnsearched{}
	id := &IntentDiscovery{client: tipClient{tip: 120}, // SearchCertenTransactions is not implemented: it panics
		logger: log.New(io.Discard, "", 0), lastProcessedBlock: 100, lastQueuedBlock: 120, finalizeCeiling: 118,
		blockProcessCh: make(chan *BlockProcessJob, 4), stopCh: make(chan struct{}), processedBlocks: map[uint64]bool{},
		inFlight: map[uint64]bool{101: true, 102: true}, unsearched: store}
	defer close(id.stopCh)
	go id.blockProcessor("w")
	id.blockProcessCh <- &BlockProcessJob{BlockHeight: 101}
	id.blockProcessCh <- &BlockProcessJob{BlockHeight: 102}
	deadline := time.Now().Add(5 * time.Second)
	for store.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if store.count() != 2 {
		t.Fatalf("%d blocks kept after panicking searches, want 2 (the worker must survive the first)", store.count())
	}
	id.watermarkMu.Lock()
	inFlight := len(id.inFlight)
	id.watermarkMu.Unlock()
	if inFlight != 0 {
		t.Fatalf("%d heights still in flight after their jobs finished", inFlight)
	}
}
