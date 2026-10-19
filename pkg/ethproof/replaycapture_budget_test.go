// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// callCountingChain counts every HeaderByNumber (numbered and latest) and can make each numbered read slow, ignoring
// its context, as a provider that answers late does.
type callCountingChain struct {
	*fakeChain
	mu       sync.Mutex
	numbered map[uint64]int
	latest   int
	slow     time.Duration
}

func (c *callCountingChain) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	c.mu.Lock()
	if n.Sign() >= 0 {
		c.numbered[n.Uint64()]++
	} else {
		c.latest++
	}
	c.mu.Unlock()
	if n.Sign() >= 0 && c.slow > 0 {
		time.Sleep(c.slow)
	}
	return c.fakeChain.HeaderByNumber(ctx, n)
}

func (c *callCountingChain) counts() (numbered, maxPerHeader, latest int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.numbered {
		numbered += k
		if k > maxPerHeader {
			maxPerHeader = k
		}
	}
	return numbered, maxPerHeader, c.latest
}

func stateless(f *fakeChain) []*fakeProvider {
	var ps []*fakeProvider
	for _, name := range []string{"a", "b", "c"} {
		p := f.add(name, 0, 0)
		p.err = "missing trie node"
		ps = append(ps, p)
	}
	return ps
}

func getProofCalls(ps []*fakeProvider) int {
	n := 0
	for _, p := range ps {
		n += int(atomic.LoadInt32(&p.calls))
	}
	return n
}

// namesEachProvider requires the named state to carry every provider by name, each with its own error.
func namesEachProvider(t *testing.T, ev *ethproof.ReplayGuardEvidence, want ...string) {
	t.Helper()
	if ev == nil || ev.State == nil || ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("want s6_replay_unproven{state_unavailable}, got %+v", ev)
	}
	got := map[string]string{}
	for _, p := range ev.State.Providers {
		got[p.Host] = p.Error
	}
	for _, h := range want {
		if got[h] == "" {
			t.Fatalf("the named state does not name provider %s with its error: %+v", h, ev.State.Providers)
		}
	}
}

// V-R10B D2, the reviewer's probe: head = N+512, three providers without the state. The capture reads each of the 512
// linked headers once and asks the latest header once per pass; a pass asks each provider at most each candidate block
// once. Every count is bounded by the budget's passes, never by headers x candidates x providers.
func TestCapture_ReviewerProbeHeadAtNPlus512IsCallBounded(t *testing.T) {
	const depth = ethproof.MaxReplayHeaderChain
	f := newChain(t, worldOpts{after: depth}, testN+depth)
	ps := stateless(f)
	c := &callCountingChain{fakeChain: f, numbered: map[uint64]int{}}
	budget, poll := 400*time.Millisecond, 5*time.Millisecond
	ev := ethproof.CaptureReplayGuard(context.Background(),
		ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: c, Budget: budget, Poll: poll}, f.w.tx.Hash())
	namesEachProvider(t, ev, "a", "b", "c")
	numbered, maxPer, latest := c.counts()
	passes := int(budget/poll) + 2
	if maxPer > 1 || numbered > depth {
		t.Fatalf("numbered header reads: %d in all, %d of one header; want each of the %d headers read at most once", numbered, maxPer, depth)
	}
	if latest > passes {
		t.Fatalf("latest-header reads: %d, more than one per pass (%d passes at most)", latest, passes)
	}
	if g := getProofCalls(ps); g > latest*len(ps)*4 {
		t.Fatalf("GetProof calls: %d, more than 4 candidates x %d providers x %d passes", g, len(ps), latest)
	}
}

// V-R10B D2: when the head is past N + MaxReplayHeaderChain, the candidate blocks are pinned at the bound and only age:
// one pass that proves nothing decides the capture. It gives up at once with the named state naming each provider and
// the head's distance, instead of asking again until the budget ends.
func TestCapture_GivesUpAtOnceWhenTheHeadIsPastTheHeaderChainBound(t *testing.T) {
	const depth = ethproof.MaxReplayHeaderChain + 88
	f := newChain(t, worldOpts{after: depth}, testN+depth)
	ps := stateless(f)
	c := &callCountingChain{fakeChain: f, numbered: map[uint64]int{}}
	start := time.Now()
	ev := ethproof.CaptureReplayGuard(context.Background(),
		ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: c, Budget: 5 * time.Second, Poll: 5 * time.Millisecond}, f.w.tx.Hash())
	took := time.Since(start)
	namesEachProvider(t, ev, "a", "b", "c")
	if took > 2*time.Second {
		t.Fatalf("the capture took %v; with the head past the header-chain bound it must give up after one pass", took)
	}
	numbered, maxPer, latest := c.counts()
	if latest != 1 || maxPer > 1 || numbered > ethproof.MaxReplayHeaderChain {
		t.Fatalf("latest reads %d (want 1), numbered reads %d (max %d of one header; want each once, at most %d)",
			latest, numbered, maxPer, ethproof.MaxReplayHeaderChain)
	}
	if g := getProofCalls(ps); g != len(ps)*4 {
		t.Fatalf("GetProof calls: %d, want exactly one pass (%d)", g, len(ps)*4)
	}
	if !strings.Contains(ev.State.Detail, "past the") {
		t.Fatalf("the named state must say the head is past the header-chain bound: %s", ev.State.Detail)
	}
}

// V-R10B D2: the deadline is checked inside the linked-header read, so a slow header source cannot hold the capture
// past its budget for the length of the whole chain.
func TestCapture_DeadlineEndsTheLinkedHeaderRead(t *testing.T) {
	const depth = ethproof.MaxReplayHeaderChain
	f := newChain(t, worldOpts{after: depth}, testN+depth)
	stateless(f)
	c := &callCountingChain{fakeChain: f, numbered: map[uint64]int{}, slow: 2 * time.Millisecond}
	start := time.Now()
	ev := ethproof.CaptureReplayGuard(context.Background(),
		ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: c, Budget: 60 * time.Millisecond, Poll: 5 * time.Millisecond}, f.w.tx.Hash())
	took := time.Since(start)
	namesEachProvider(t, ev, "a", "b", "c")
	numbered, _, _ := c.counts()
	if numbered >= depth || took > 500*time.Millisecond {
		t.Fatalf("read %d of %d headers in %v on a 60ms budget: the header read does not check the deadline", numbered, depth, took)
	}
}
