package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
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

// TestCheckpointAnchorWritesAndChains verifies each entry carries embedded height + hex app-hash,
// and that entry N+1.Prev == SHA256(entry N bytes) — a walkable tamper-evident hash chain.
func TestCheckpointAnchorWritesAndChains(t *testing.T) {
	sub := &fakeSubmitter{}
	a := NewCheckpointAnchor(sub, "validator-1", "", 16, log.New(log.Writer(), "", 0))
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
	if r1.Prev != "" {
		t.Fatalf("first checkpoint should have empty prev, got %q", r1.Prev)
	}
	if r2.Height != 2 || r2.AppHash != "ccdd" {
		t.Fatalf("r2 unexpected: %+v", r2)
	}
	// Chain: r2.Prev must equal SHA256(entry-1 raw bytes).
	want := sha256.Sum256(sub.entries[0])
	if r2.Prev != hex.EncodeToString(want[:]) {
		t.Fatalf("chain broken: r2.prev=%q want=%x", r2.Prev, want)
	}
	if r1.ValidatorID != "validator-1" || r1.TimestampMs != 1_700_000_000_000 {
		t.Fatalf("metadata unexpected: %+v", r1)
	}
}

// TestCheckpointAnchorSeedsFromStateFile verifies the chain continues unbroken across a restart:
// a new anchor seeded from the persisted head chains its first entry to that head, and advances
// the persisted head to SHA256(the new entry).
func TestCheckpointAnchorSeedsFromStateFile(t *testing.T) {
	sf := filepath.Join(t.TempDir(), "head")
	seed := "deadbeef" + strings.Repeat("00", 28) // 64 hex chars, as if left by a prior run
	if err := os.WriteFile(sf, []byte(seed), 0600); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	sub := &fakeSubmitter{}
	a := NewCheckpointAnchor(sub, "validator-1", sf, 8, log.New(log.Writer(), "", 0))
	defer a.Close()

	a.Enqueue(9, "H9", []byte{0x01}, time.UnixMilli(0))
	waitFor(t, func() bool { return sub.count() == 1 })

	var r CheckpointRecord
	if err := json.Unmarshal(sub.entries[0], &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Prev != seed {
		t.Fatalf("first entry after restart must chain to persisted head %q, got %q", seed, r.Prev)
	}
	// State file must now hold SHA256(this entry) for the next run.
	//
	// persistHead runs AFTER the submit, so waiting on sub.count() proves the
	// entry was sent, not that the head was written. Asserting immediately made
	// this test pass alone and fail in a full-package run, where the extra load
	// widened the gap — a flake that looked like a checkpoint bug and was only
	// ever a missing wait.
	sum := sha256.Sum256(sub.entries[0])
	want := hex.EncodeToString(sum[:])
	waitFor(t, func() bool {
		b, err := os.ReadFile(sf)
		return err == nil && strings.TrimSpace(string(b)) == want
	})
}

// TestCheckpointAnchorNeverBlocks verifies Enqueue drops (does not block) when the writer is
// stalled and the buffer is full — consensus must never be gated by the anchor.
func TestCheckpointAnchorNeverBlocks(t *testing.T) {
	sub := &fakeSubmitter{block: make(chan struct{})}
	a := NewCheckpointAnchor(sub, "validator-1", "", 2, log.New(log.Writer(), "", 0))
	defer func() {
		close(sub.block)
		a.Close()
	}()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			a.Enqueue(int64(i), "H", []byte{byte(i)}, time.UnixMilli(0))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Enqueue blocked — anchor must never block the commit path")
	}

	if _, dropped := a.Stats(); dropped == 0 {
		t.Fatal("expected some dropped checkpoints under a stalled writer with a full buffer")
	}
}
