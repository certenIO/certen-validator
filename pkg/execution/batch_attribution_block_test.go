// Copyright 2026 Certen Protocol

package execution

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// fakeChain has a block time of `step` seconds with `perStamp` consecutive blocks sharing one
// timestamp (as on Arbitrum), served by a node that holds nothing below `pruned`.
type fakeChain struct {
	genesis, step, perStamp, pruned uint64
	lowestRead                      uint64
	reads                           int
}

func (c *fakeChain) time(n uint64) uint64 { return c.genesis + (n/c.perStamp)*c.step }

func (c *fakeChain) timeAt(n uint64) (uint64, error) {
	c.reads++
	if n < c.lowestRead {
		c.lowestRead = n
	}
	if n < c.pruned {
		return 0, fmt.Errorf("pruned history unavailable: requested %d, earliest available %d", n, c.pruned)
	}
	return c.time(n), nil
}

// reference is the answer by definition: the highest block whose time is <= ts.
func (c *fakeChain) reference(head, ts uint64) uint64 {
	best := uint64(0)
	for n := uint64(0); n <= head; n++ {
		if c.time(n) <= ts {
			best = n
		}
	}
	return best
}

// The live failure: base-sepolia's RPC prunes below 45.5M with the head at ~47.3M. A timestamp from a
// minute ago must resolve without reading anything the node pruned - the whole-chain bisection read
// head/2 first, and every lookup failed.
func TestBlockAtOrBefore_RecentTimestampOnAPrunedNode(t *testing.T) {
	const head = 47_308_888
	c := &fakeChain{genesis: 1_700_000_000, step: 2, perStamp: 1, pruned: 45_500_000, lowestRead: head}
	ts := c.time(head) - 60
	got, err := searchBlockAtOrBefore(head, c.time(head), ts, c.timeAt)
	if err != nil {
		t.Fatalf("a recent timestamp on a pruned node: %v", err)
	}
	if want := uint64(head - 30); got != want {
		t.Fatalf("got block %d, want %d", got, want)
	}
	if c.lowestRead < c.pruned {
		t.Fatalf("read block %d, below the pruned floor %d", c.lowestRead, c.pruned)
	}
	t.Logf("resolved in %d reads, lowest block read %d", c.reads, c.lowestRead)
}

// Exact against the definition, across block times, shared timestamps and positions, with nothing
// pruned.
func TestBlockAtOrBefore_MatchesTheDefinition(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, shape := range []struct{ step, perStamp uint64 }{{2, 1}, {12, 1}, {1, 4}, {3, 7}} {
		c := &fakeChain{genesis: 1000, step: shape.step, perStamp: shape.perStamp}
		const head = 5000
		for i := 0; i < 300; i++ {
			ts := c.genesis + uint64(r.Int63n(int64(c.time(head)-c.genesis+20)))
			got, err := searchBlockAtOrBefore(head, c.time(head), ts, c.timeAt)
			if err != nil {
				t.Fatal(err)
			}
			if want := c.reference(head, ts); got != want {
				t.Fatalf("step=%d perStamp=%d ts=%d: got %d, want %d", shape.step, shape.perStamp, ts, got, want)
			}
		}
	}
}

// At or after the head's time, the head is the answer, and nothing else is read.
func TestBlockAtOrBefore_AtTheHead(t *testing.T) {
	c := &fakeChain{genesis: 1000, step: 2, perStamp: 1}
	got, err := searchBlockAtOrBefore(100, c.time(100), c.time(100)+5, c.timeAt)
	if err != nil || got != 100 || c.reads != 0 {
		t.Fatalf("got %d err %v reads %d, want 100, nil, 0", got, err, c.reads)
	}
}

// A timestamp older than the node retains cannot be resolved, and says so rather than guessing.
func TestBlockAtOrBefore_OlderThanRetentionFails(t *testing.T) {
	const head = 10_000
	c := &fakeChain{genesis: 1000, step: 2, perStamp: 1, pruned: 9_000, lowestRead: head}
	_, err := searchBlockAtOrBefore(head, c.time(head), c.time(100), c.timeAt)
	if err == nil {
		t.Fatal("a timestamp from pruned history resolved to a block")
	}
	if !strings.Contains(err.Error(), "pruned history unavailable") {
		t.Fatalf("the refusal should carry the node's reason, got: %v", err)
	}
}
