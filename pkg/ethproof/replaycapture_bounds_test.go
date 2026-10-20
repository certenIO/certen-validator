// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// countingChain is a fakeChain that counts every read of a numbered header (the latest-header query aside).
type countingChain struct {
	*fakeChain
	mu    sync.Mutex
	reads map[uint64]int
}

func (c *countingChain) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	if n.Sign() >= 0 {
		c.mu.Lock()
		c.reads[n.Uint64()]++
		c.mu.Unlock()
	}
	return c.fakeChain.HeaderByNumber(ctx, n)
}

// RB10-F6: the capture reads each header of the N+1..h chain once, however many candidate blocks, providers and passes
// it tries; it extends the linked chain it already holds instead of reading it again.
func TestCapture_ReadsEachHeaderOnceAcrossCandidatesProvidersAndPasses(t *testing.T) {
	const depth = 40
	f := newChain(t, worldOpts{after: depth}, testN+depth)
	// Three providers, none of which can serve any of the candidates: every pass tries every candidate of every provider.
	for _, name := range []string{"a", "b", "c"} {
		p := f.add(name, 0, 0)
		p.err = "missing trie node"
	}
	c := &countingChain{fakeChain: f, reads: map[uint64]int{}}
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: c, Budget: 300 * time.Millisecond, Poll: 5 * time.Millisecond}
	ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
	if ev == nil || ev.State == nil || ev.State.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("no provider serves: want s6_replay_unproven{state_unavailable}, got %+v", ev)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for n := uint64(testN + 1); n <= testN+depth; n++ {
		if c.reads[n] > 1 {
			t.Errorf("header %d was read %d times; each header of the chain is read once", n, c.reads[n])
		}
	}
	if c.reads[testN+depth] != 1 {
		t.Errorf("the newest header %d was read %d times, want once", testN+depth, c.reads[testN+depth])
	}
}

// slowProvider answers every state request only after d, unless its context ends first.
type slowProvider struct {
	name  string
	chain *fakeChain
	d     time.Duration
	calls int32
}

func (p *slowProvider) Name() string { return p.name }

func (p *slowProvider) TransactionByHash(_ context.Context, h common.Hash) (*types.Transaction, bool, error) {
	return p.chain.w.tx, false, nil
}

func (p *slowProvider) GetProof(ctx context.Context, _ common.Address, _ []string, _ string) (json.RawMessage, error) {
	atomic.AddInt32(&p.calls, 1)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(p.d):
		return nil, errors.New("upstream timed out")
	}
}

type slowChain struct {
	*fakeChain
	slow []*slowProvider
}

func (s *slowChain) StateProviders() []ethproof.ReplayStateProvider {
	out := make([]ethproof.ReplayStateProvider, len(s.slow))
	for i, p := range s.slow {
		out[i] = p
	}
	return out
}

// RB10-F6: one pass, and every request in it, is bounded by what remains of the budget: providers that hang end the
// capture at the budget in the named state, with each provider's error.
func TestCapture_APassAndEveryRequestAreBoundedByTheBudget(t *testing.T) {
	f := newChain(t, worldOpts{after: 3}, testN+3)
	s := &slowChain{fakeChain: f, slow: []*slowProvider{{name: "hangs-1", chain: f, d: 2 * time.Second}, {name: "hangs-2", chain: f, d: 2 * time.Second}}}
	budget := 300 * time.Millisecond
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: s, Budget: budget, Poll: 5 * time.Millisecond}
	start := time.Now()
	ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
	took := time.Since(start)
	if took > budget+700*time.Millisecond {
		t.Fatalf("the capture took %s, its budget is %s", took, budget)
	}
	if ev == nil || ev.State == nil || ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("want s6_replay_unproven{state_unavailable} at the budget, got %+v", ev)
	}
	if ev.State.BlockNumber != testN || ev.State.BlockHash != f.w.headerN.Hash() {
		t.Fatalf("the state is judged at the settlement block: %+v", ev.State)
	}
	got := map[string]string{}
	for _, pf := range ev.State.Providers {
		got[pf.Host] = pf.Error
	}
	for _, name := range []string{"hangs-1", "hangs-2"} {
		if got[name] == "" {
			t.Errorf("provider %s's error is not named: %v", name, got)
		}
	}
}

// refuseOnce is a fakeProvider that refuses the first request for the settlement block's parent and serves the next.
type refuseOnce struct {
	*fakeProvider
	parentAsks int32
}

func (r *refuseOnce) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	if block == "0x"+big.NewInt(testN-1).Text(16) && atomic.AddInt32(&r.parentAsks, 1) == 1 {
		return nil, errors.New("missing trie node (backend lagging)")
	}
	return r.fakeProvider.GetProof(ctx, account, keys, block)
}

type refuseOnceChain struct {
	*fakeChain
	p *refuseOnce
}

func (c *refuseOnceChain) StateProviders() []ethproof.ReplayStateProvider {
	return []ethproof.ReplayStateProvider{c.p}
}

// RB10-F7: Before is asked again within the budget, as After is: a provider that refuses the parent once and serves it
// the second time gives a proven Before, not s6_before_unavailable.
func TestCapture_BeforeIsAskedAgainWithinTheBudget(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	fp := &fakeProvider{name: "sepolia-rollup.arbitrum.io", chain: f, min: testN - 1, max: testN}
	r := &refuseOnce{fakeProvider: fp}
	src := &refuseOnceChain{fakeChain: f, p: r}
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: src, Budget: 2 * time.Second, Poll: 5 * time.Millisecond}
	ev := ethproof.CaptureReplayGuard(context.Background(), cfg, f.w.tx.Hash())
	if ev == nil || ev.Proof == nil {
		t.Fatalf("no proof: %+v", ev)
	}
	if ev.Proof.Before == nil {
		t.Fatalf("Before was asked %d time(s) and disclosed unavailable: %+v", atomic.LoadInt32(&r.parentAsks), ev.Proof.BeforeUnavailable)
	}
	if ev.Proof.BeforeUnavailable != nil {
		t.Fatalf("a proven Before carries no disclosure: %+v", ev.Proof.BeforeUnavailable)
	}
	chk, err := ev.Verify(f.w.settlement)
	if err != nil || !chk.BeforeVerified {
		t.Fatalf("%v %+v", err, chk)
	}
}

// RB10-F3: CertenAccountV7_2's replay guard is pinned (forge storageLayout at certen-contracts 16c6d47: _consumedLeaf
// slot 4; selectors 0x57f8567d / 0xb7daa901): its settlements are proven with that layout, through both entry points.
func TestReplayGuard_V7_2IsProvenWithItsPinnedLayout(t *testing.T) {
	if base, ok := ethproof.ReplayLayoutBase(ethproof.AccountGenerationV7_2); !ok || base != 4 {
		t.Fatalf("CertenAccountV7_2's base: %d, pinned=%v; want 4, pinned", base, ok)
	}
	sels := ethproof.ReplaySettlementSelectors(ethproof.AccountGenerationV7_2)
	if len(sels) != 2 || sels[0] != [4]byte{0x57, 0xf8, 0x56, 0x7d} || sels[1] != [4]byte{0xb7, 0xda, 0xa9, 0x01} {
		t.Fatalf("CertenAccountV7_2's selectors: %x", sels)
	}
	for _, sel := range [][]byte{replayworld.V72Execute, {0xb7, 0xda, 0xa9, 0x01}} {
		w := newWorld(t, worldOpts{after: 1, selector: sel})
		p := w.clone()
		p.Generation = ethproof.AccountGenerationV7_2
		chk, err := p.Verify(w.settlement)
		if err != nil {
			t.Fatalf("selector %x: a V7_2 settlement with its pinned layout is refused: %v", sel, err)
		}
		if chk.State != ethproof.ReplayProven || !chk.BeforeVerified || len(chk.Established) != 2 ||
			!strings.Contains(chk.Established[0], "CertenAccountV7_2 _consumedLeaf[leaf]") {
			t.Fatalf("selector %x: %+v", sel, chk)
		}
	}
	// The generation must still be the one the calldata calls: a V7_2 proof of a V7_3 call, and a V7_3 proof of a V7_2
	// call, are refused.
	w3 := newWorld(t, worldOpts{after: 0})
	p := w3.clone()
	p.Generation = ethproof.AccountGenerationV7_2
	_, err := p.Verify(w3.settlement)
	refusedAs(t, "a V7_2 proof of a V7_3 call", err, ethproof.ReplayUnproven, ethproof.ReasonAccountGeneration)
	w2 := newWorld(t, worldOpts{after: 0, selector: replayworld.V72Execute})
	_, err = w2.proof.Verify(w2.settlement)
	refusedAs(t, "a V7_3 proof of a V7_2 call", err, ethproof.ReplayUnproven, ethproof.ReasonAccountGeneration)
}

// RB10-F3: the capture proves a CertenAccountV7_2 settlement with V7_2's layout and names that generation.
func TestCapture_V7_2SettlementIsProvenWithItsLayout(t *testing.T) {
	for _, sel := range [][]byte{replayworld.V72Execute, {0xb7, 0xda, 0xa9, 0x01}} {
		f := newChain(t, worldOpts{after: 0, selector: sel}, testN)
		f.add("sepolia.base.org", testN-1, testN)
		ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
		if ev == nil || ev.Proof == nil {
			t.Fatalf("selector %x: no proof: %+v", sel, ev)
		}
		if ev.Proof.Generation != ethproof.AccountGenerationV7_2 || ev.Proof.Slot.Base != 4 {
			t.Fatalf("selector %x: generation %s base %d", sel, ev.Proof.Generation, ev.Proof.Slot.Base)
		}
		chk, err := ev.Verify(f.w.settlement)
		if err != nil || chk.State != ethproof.ReplayProven || !chk.BeforeVerified {
			t.Fatalf("selector %x: %v %+v", sel, err, chk)
		}
	}
}
