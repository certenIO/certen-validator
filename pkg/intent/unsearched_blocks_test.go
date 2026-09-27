// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB3-F125: a block whose search failed is kept and searched again until it is searched; the watermark
// never passes a block that is neither searched nor kept. It used to pass it "to prevent getting stuck",
// on the theory that the block "will appear again on a future polling cycle" - it never did.

type searchClient struct {
	accumulate.Client
	mu   sync.Mutex
	fail map[int64]bool
	seen map[int64]int
}

func (c *searchClient) SearchCertenTransactions(_ context.Context, h int64) ([]*accumulate.CertenTransaction, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[h]++
	if c.fail[h] {
		return nil, errors.New("DN block: failed to read response body: unexpected EOF")
	}
	return nil, nil
}

func workerDiscovery(t *testing.T, c *searchClient, store UnsearchedBlockStore) *IntentDiscovery {
	t.Helper()
	id := &IntentDiscovery{
		client: c, logger: log.New(io.Discard, "", 0), config: &IntentDiscoveryConfig{},
		stopCh: make(chan struct{}), blockProcessCh: make(chan *BlockProcessJob, 16),
		processedBlocks: map[uint64]bool{}, lastProcessedBlock: 9, lastQueuedBlock: 12, finalizeCeiling: 12,
		unsearched: store,
	}
	go id.blockProcessor("w1")
	t.Cleanup(func() { close(id.stopCh) })
	return id
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAnUnsearchableBlockIsKeptAndSearchedAgain(t *testing.T) {
	store, err := OpenFileUnsearchedBlocks(filepath.Join(t.TempDir(), "unsearched.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := &searchClient{fail: map[int64]bool{11: true}, seen: map[int64]int{}}
	id := workerDiscovery(t, c, store)
	for _, h := range []uint64{10, 11, 12} {
		id.blockProcessCh <- &BlockProcessJob{BlockHeight: h}
	}
	// The watermark moves on - block 11 is kept, not lost.
	waitFor(t, "the watermark to pass the kept block", func() bool { return id.Status().Watermark == 12 })
	kept, err := store.List()
	if err != nil || len(kept) != 1 || kept[0].Height != 11 || kept[0].Attempts != 1 {
		t.Fatalf("kept %+v (%v)", kept, err)
	}
	if st := id.Status(); st.Unsearched != 1 || st.OldestUnsearched != 11 {
		t.Fatalf("status %+v", st)
	}

	// Still unreadable: kept, one more attempt.
	id.searchUnsearchedOnce()
	if kept, _ := store.List(); len(kept) != 1 || kept[0].Attempts != 2 {
		t.Fatalf("after a failed retry: %+v", kept)
	}
	// Readable now: searched and removed.
	c.mu.Lock()
	c.fail[11] = false
	c.mu.Unlock()
	id.searchUnsearchedOnce()
	if kept, _ := store.List(); len(kept) != 0 {
		t.Fatalf("a searched block is still kept: %+v", kept)
	}
	if c.seen[11] != 3 {
		t.Fatalf("block 11 searched %d times, want 3", c.seen[11])
	}
}

// With nowhere to keep it, a block that could not be searched is never passed.
func TestAnUnsearchableBlockThatCannotBeKeptIsNotPassed(t *testing.T) {
	c := &searchClient{fail: map[int64]bool{10: true}, seen: map[int64]int{}}
	id := workerDiscovery(t, c, nil)
	id.blockProcessCh <- &BlockProcessJob{BlockHeight: 10}
	id.blockProcessCh <- &BlockProcessJob{BlockHeight: 11}
	waitFor(t, "block 11 to be searched", func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.seen[11] > 0
	})
	time.Sleep(50 * time.Millisecond)
	if w := id.Status().Watermark; w != 9 {
		t.Fatalf("the watermark passed a block that was neither searched nor kept: %d", w)
	}
}

func TestTheUnsearchedStoreSurvivesARestartAndRefusesAnUnreadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsearched.json")
	s, err := OpenFileUnsearchedBlocks(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(7, "a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(3, "b"); err != nil {
		t.Fatal(err)
	}
	again, err := OpenFileUnsearchedBlocks(path)
	if err != nil {
		t.Fatal(err)
	}
	if kept, _ := again.List(); len(kept) != 2 || kept[0].Height != 3 || kept[1].Height != 7 {
		t.Fatalf("after reopening: %+v", kept)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileUnsearchedBlocks(path); err == nil {
		t.Fatal("an unreadable store was opened as empty")
	}
}
