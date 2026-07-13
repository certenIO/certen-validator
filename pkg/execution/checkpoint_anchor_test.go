package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"testing"
	"time"
)

// fakeSubmitter captures raw write-data submissions for assertions.
type fakeSubmitter struct {
	mu      sync.Mutex
	entries [][]byte
	fail    bool
	block   chan struct{} // if non-nil, each submit blocks until a value is received
}

func (f *fakeSubmitter) SubmitRawWriteData(ctx context.Context, entries [][]byte) (string, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if f.fail {
		return "", fmt.Errorf("submit failed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, entries[0])
	return "acc://tx/" + hex.EncodeToString(entries[0][:4]), nil
}

func (f *fakeSubmitter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

// TestCheckpointAnchorWritesAndChains verifies checkpoints are written with embedded height,
// hex app-hash, and a prev_app_hash chain across consecutive blocks.
func TestCheckpointAnchorWritesAndChains(t *testing.T) {
	sub := &fakeSubmitter{}
	a := NewCheckpointAnchor(sub, "validator-1", 16, log.New(log.Writer(), "", 0))
	defer a.Close()

	ts := time.UnixMilli(1_700_000_000_000)
	a.Enqueue(1, "BLOCKHASH1", []byte{0xaa, 0xbb}, ts)
	a.Enqueue(2, "BLOCKHASH2", []byte{0xcc, 0xdd}, ts)

	waitFor(t, func() bool { return sub.count() == 2 })

	var r1, r2 CheckpointRecord
	if err := json.Unmarshal(sub.entries[0], &r1); err != nil {
		t.Fatalf("unmarshal r1: %v", err)
	}
	if err := json.Unmarshal(sub.entries[1], &r2); err != nil {
		t.Fatalf("unmarshal r2: %v", err)
	}

	if r1.Height != 1 || r1.AppHash != "aabb" || r1.BlockHash != "BLOCKHASH1" {
		t.Fatalf("r1 unexpected: %+v", r1)
	}
	if r1.PrevAppHash != "" {
		t.Fatalf("first checkpoint should have empty prev_app_hash, got %q", r1.PrevAppHash)
	}
	if r2.Height != 2 || r2.AppHash != "ccdd" {
		t.Fatalf("r2 unexpected: %+v", r2)
	}
	// Chain: r2.prev must equal r1.app
	if r2.PrevAppHash != r1.AppHash {
		t.Fatalf("chain broken: r2.prev=%q r1.app=%q", r2.PrevAppHash, r1.AppHash)
	}
	if r1.ValidatorID != "validator-1" || r1.TimestampMs != 1_700_000_000_000 {
		t.Fatalf("metadata unexpected: %+v", r1)
	}
}

// TestCheckpointAnchorNeverBlocks verifies Enqueue drops (does not block) when the writer is
// stalled and the buffer is full — consensus must never be gated by the anchor.
func TestCheckpointAnchorNeverBlocks(t *testing.T) {
	sub := &fakeSubmitter{block: make(chan struct{})} // writer blocks until we release
	a := NewCheckpointAnchor(sub, "validator-1", 2, log.New(log.Writer(), "", 0))
	defer func() {
		// release the (possibly) in-flight write so Close can drain
		close(sub.block)
		a.Close()
	}()

	// The first Enqueue is picked up by the goroutine and blocks in the submitter; the buffer
	// (size 2) then fills, and further Enqueues must be dropped, never block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			a.Enqueue(int64(i), "H", []byte{byte(i)}, time.UnixMilli(0))
		}
		close(done)
	}()

	select {
	case <-done:
		// good: all Enqueues returned without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked — anchor must never block the commit path")
	}

	_, dropped := a.Stats()
	if dropped == 0 {
		t.Fatal("expected some dropped checkpoints under a stalled writer with a full buffer")
	}
}
