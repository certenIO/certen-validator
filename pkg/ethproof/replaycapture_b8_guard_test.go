// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// V-R10B2 note 5a: Resolve runs in the observer's path and Bind's recovery used to verify the settlement again, so a
// deterministic panic in the settlement's verification re-panicked inside the recovery. A panic yields a named state of the
// settlement built from what is already known, and the failing function is called once.
func TestCapturer_APanicInTheSettlementVerificationIsANamedStateBuiltWithoutCallingItAgain(t *testing.T) {
	newCapturer := func(t *testing.T, begin bool) (*ethproof.ReplayGuardCapturer, *ethproof.ReplayGuardStore, *fakeChain, *int32) {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("p", testN, testN)
		store := ethproof.NewReplayGuardStore(16)
		cp := ethproof.NewReplayGuardCapturer(cfgFor(f), store)
		if begin {
			cp.Begin(f.w.tx.Hash())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
				t.Fatal(err)
			}
		}
		var calls int32
		cp.SetSettlementVerifierForTest(func(*ethproof.Settlement) (*types.Header, *ethproof.ReceiptLeaf, error) {
			atomic.AddInt32(&calls, 1)
			panic("the settlement verifier failed")
		})
		return cp, store, f, &calls
	}
	named := func(t *testing.T, what string, f *fakeChain, ev *ethproof.ReplayGuardEvidence, calls *int32) {
		t.Helper()
		st := ev.State
		if st == nil || st.State != ethproof.ReplayUnproven || st.Reason == "" || !strings.Contains(st.Detail, "the settlement verifier failed") {
			t.Fatalf("%s: the panic is not a named state carrying it: %+v", what, ev)
		}
		if got := atomic.LoadInt32(calls); got != 1 {
			t.Fatalf("%s: the failing verification was called %d times, want once", what, got)
		}
		if st.BlockNumber != testN || st.BlockHash != f.w.settlement.BlockHash || st.Contract != *f.w.tx.To() || st.TxHash != f.w.tx.Hash() {
			t.Fatalf("%s: the named state does not say where it was judged: %+v", what, st)
		}
		if _, err := ev.Verify(f.w.settlement); err != nil {
			t.Fatalf("%s: the named state does not verify against the settlement: %v", what, err)
		}
	}
	t.Run("Resolve never panics", func(t *testing.T) {
		cp, _, f, calls := newCapturer(t, true)
		named(t, "Resolve", f, cp.Resolve(f.w.settlement), calls)
	})
	t.Run("Bind stores a named state", func(t *testing.T) {
		cp, store, f, calls := newCapturer(t, true)
		cp.Bind(f.w.settlement)
		named(t, "Bind", f, waitStored(t, store, testChainID, f.w.tx.Hash(), true), calls)
	})
	t.Run("Bind of a settlement first seen at finality stores a named state", func(t *testing.T) {
		cp, store, f, calls := newCapturer(t, false)
		cp.Bind(f.w.settlement)
		ev := waitStored(t, store, testChainID, f.w.tx.Hash(), true)
		if ev.State == nil || ev.State.BlockNumber != testN || atomic.LoadInt32(calls) != 1 {
			t.Fatalf("%+v calls=%d", ev, atomic.LoadInt32(calls))
		}
	})
}

// gatedSource holds every receipt read until released (or its context ends) and counts those in flight per transaction.
type gatedSource struct {
	*fakeChain
	mu          sync.Mutex
	inflight    int
	maxInflight int
	asked       map[common.Hash]int
	release     chan struct{}
}

func (g *gatedSource) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	g.mu.Lock()
	g.asked[h]++
	g.inflight++
	if g.inflight > g.maxInflight {
		g.maxInflight = g.inflight
	}
	g.mu.Unlock()
	defer func() { g.mu.Lock(); g.inflight--; g.mu.Unlock() }()
	select {
	case <-g.release:
	case <-ctx.Done():
	}
	return nil, ethereum.NotFound
}

func (g *gatedSource) stats() (maxInflight int, asked map[common.Hash]int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	asked = map[common.Hash]int{}
	for k, v := range g.asked {
		asked[k] = v
	}
	return g.maxInflight, asked
}

func newGated(t *testing.T) *gatedSource {
	f := newChain(t, worldOpts{after: 0}, testN)
	return &gatedSource{fakeChain: f, asked: map[common.Hash]int{}, release: make(chan struct{})}
}

// V-R10B2 note 5b: at most Concurrent captures of one chain run at once, however many settlements are observed (a restart
// backlog); Begin returns at once all the same, and a capture waiting for a slot is a named state at its budget.
func TestCapturer_CapsConcurrentCapturesAndBeginNeverBlocks(t *testing.T) {
	g := newGated(t)
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 700 * time.Millisecond, Poll: 5 * time.Millisecond, Concurrent: 2}
	store := ethproof.NewReplayGuardStore(64)
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	var txs []common.Hash
	start := time.Now()
	for i := 0; i < 12; i++ {
		h := common.Hash{0xaa, byte(i + 1)}
		txs = append(txs, h)
		cp.Begin(h)
	}
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Fatalf("Begin blocked for %s with every slot taken", took)
	}
	time.Sleep(150 * time.Millisecond)
	if max, _ := g.stats(); max != 2 {
		t.Fatalf("%d captures read the chain at once with Concurrent=2", max)
	}
	close(g.release)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	waited := 0
	for _, h := range txs {
		if _, _, err := store.Wait(ctx, testChainID, h); err != nil {
			t.Fatal(err)
		}
		ev, _, _ := store.Get(testChainID, h)
		if ev == nil || ev.State == nil || ev.State.Reason == "" {
			t.Fatalf("a capture ended without a named state: %+v", ev)
		}
		if strings.Contains(ev.State.Detail, "slot") {
			waited++
		}
	}
	if max, _ := g.stats(); max > 2 {
		t.Fatalf("%d captures read the chain at once with Concurrent=2", max)
	}
	if waited == 0 {
		t.Fatal("no capture was named for waiting for a slot past its budget")
	}
}

// A capture waiting for a slot has begun spending its budget: when the budget ends before a slot frees, the capture is a
// named state of the wait and never reads the chain, and it ends at its own budget, not after the capture holding the slot.
func TestCapturer_ACaptureWaitingForASlotSpendsItsBudget(t *testing.T) {
	g := newGated(t)
	store := ethproof.NewReplayGuardStore(16)
	long := ethproof.NewReplayGuardCapturer(ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 600 * time.Millisecond,
		Poll: 5 * time.Millisecond, Concurrent: 1}, store)
	shortCfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 100 * time.Millisecond, Poll: 5 * time.Millisecond, Concurrent: 1}
	short := ethproof.NewReplayGuardCapturer(shortCfg, store)
	first, second := common.Hash{0x01}, common.Hash{0x02}
	long.Begin(first)
	time.Sleep(30 * time.Millisecond)
	start := time.Now()
	short.Begin(second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := store.Wait(ctx, testChainID, second); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 100*time.Millisecond+200*time.Millisecond {
		t.Fatalf("the waiting capture ended after %s, not at its budget of %s", took, shortCfg.Budget)
	}
	if _, _, ok := store.Get(testChainID, first); ok {
		t.Fatal("the capture holding the slot ended before the waiting one: the test does not hold the slot")
	}
	ev, _, _ := store.Get(testChainID, second)
	if ev == nil || ev.State == nil || ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonStateUnavailable ||
		!strings.Contains(ev.State.Detail, "slot") || !strings.Contains(ev.State.Detail, fmt.Sprint(shortCfg.Budget)) {
		t.Fatalf("the waiting capture is not named for the slot and the budget: %+v", ev)
	}
	if _, asked := g.stats(); asked[second] != 0 {
		t.Fatalf("the capture that never had a slot read the chain %d times", asked[second])
	}
	if _, _, err := store.Wait(ctx, testChainID, first); err != nil {
		t.Fatal(err)
	}
}
