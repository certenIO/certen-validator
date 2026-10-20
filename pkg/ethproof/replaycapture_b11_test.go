// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// parentGated is a chain whose providers answer the state of the settlement block's parent only when the gate opens, and
// ignore their context while they wait (a provider call that does not honour its deadline).
type parentGated struct {
	*fakeChain
	gate chan struct{}
}

func (s parentGated) StateProviders() []ethproof.ReplayStateProvider {
	var out []ethproof.ReplayStateProvider
	for _, p := range s.fakeChain.providers {
		out = append(out, parentGatedProvider{p, s.gate})
	}
	return out
}

type parentGatedProvider struct {
	*fakeProvider
	gate chan struct{}
}

func (p parentGatedProvider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(block, "0x"), 16); ok && n.Uint64() < testN {
		<-p.gate
	}
	return p.fakeProvider.GetProof(ctx, account, keys, block)
}

// V-R10B4 N1: Bind's wait ended and stored the bound named state of the capture that did not finish; the capture that
// finishes later must not replace it with its own unbound evidence (the settlement's layer 6 would then carry no guard).
func TestCapturer_ABoundNamedStateIsNotReplacedByTheCaptureThatFinishesLater(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("windowed.example", testN-1, testN)
	gate := make(chan struct{})
	cfg := cfgFor(f)
	cfg.Source, cfg.Budget = parentGated{f, gate}, 100*time.Millisecond
	store := ethproof.NewReplayGuardStore(16)
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	cp.SetBindWaitForTest(150 * time.Millisecond)
	tx := f.w.tx.Hash()
	cp.Begin(tx)
	cp.Bind(f.w.settlement)
	bound := waitStored(t, store, testChainID, tx, true)
	if bound.State == nil || !strings.Contains(bound.State.Detail, "the capture did not finish") {
		t.Fatalf("Bind did not store the named state of the wait: %+v", bound)
	}
	close(gate) // the parent read that ignored its context answers now: the capture finishes with a proof
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, err := store.Wait(ctx, testChainID, tx); err != nil {
		t.Fatal(err)
	}
	ev, isBound, ok := store.Get(testChainID, tx)
	if !ok || !isBound || ev == nil || ev.State == nil || !strings.Contains(ev.State.Detail, "the capture did not finish") {
		t.Fatalf("the late capture replaced the bound named state (bound=%v): %+v", isBound, ev)
	}
}

// V-R10B4 N2: a waiter is refused only when no budget is left. One that frees with less than a poll of its budget left
// reads the chain and, here, proves.
func TestCapturer_AWaiterWithLessThanOnePollLeftIsNotRefused(t *testing.T) {
	holder, waiter := headOnlyWorld(t, 0), headOnlyWorld(t, 1)
	gate := make(chan struct{})
	holder.providers[0].gate = gate // the holder's After is held while the waiter waits
	store := ethproof.NewReplayGuardStore(16)
	// Budget 1s, the default poll (2s): every waiter had less than one poll left.
	hcfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: holder, Budget: time.Second, Concurrent: 1}
	wcfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: waiter, Budget: time.Second, Concurrent: 1}
	ethproof.NewReplayGuardCapturer(hcfg, store).Begin(holder.w.tx.Hash())
	time.Sleep(20 * time.Millisecond) // the holder has its slot
	ethproof.NewReplayGuardCapturer(wcfg, store).Begin(waiter.w.tx.Hash())
	time.Sleep(60 * time.Millisecond)
	close(gate)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, h := range []common.Hash{holder.w.tx.Hash(), waiter.w.tx.Hash()} {
		if _, _, err := store.Wait(ctx, testChainID, h); err != nil {
			t.Fatal(err)
		}
	}
	if ev, _, _ := store.Get(testChainID, waiter.w.tx.Hash()); ev == nil || ev.Proof == nil {
		t.Fatalf("a waiter with budget left was refused instead of reading the chain: %+v", ev)
	}
}

// jumpClock is a clock whose time a test moves, and whose deadlines never end by themselves.
type jumpClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *jumpClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *jumpClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *jumpClock) Sleep(context.Context, time.Duration) bool { return false }

func (c *jumpClock) WithDeadline(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

// V-R10B4 N2: a waiter that gets its slot after its budget has ended is the slot wait, never a receipt it did not look
// for, and what the state says is true: it does not claim a read was judged too small.
func TestCapturer_AWaiterThatGetsItsSlotAfterItsBudgetEndedIsTheTruthfulSlotWait(t *testing.T) {
	g := newGated(t)
	clk := &jumpClock{now: time.Unix(1_800_000_000, 0)}
	store := ethproof.NewReplayGuardStore(16)
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 300 * time.Millisecond, Poll: 50 * time.Millisecond, Concurrent: 1, Clock: clk}
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	holder, waiter := common.Hash{0x01}, common.Hash{0x02}
	cp.Begin(holder)
	for i := 0; ; i++ {
		if _, asked := g.stats(); asked[holder] > 0 {
			break
		}
		if i > 1000 {
			t.Fatal("the holder never read the chain")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cp.Begin(waiter)
	time.Sleep(20 * time.Millisecond) // the waiter is parked on the slot
	clk.advance(time.Hour)            // its budget ends while it waits
	close(g.release)                  // the holder ends, the slot frees
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, h := range []common.Hash{holder, waiter} {
		if _, _, err := store.Wait(ctx, testChainID, h); err != nil {
			t.Fatal(err)
		}
	}
	ev, _, _ := store.Get(testChainID, waiter)
	if ev == nil || ev.State == nil || ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonStateUnavailable ||
		!strings.Contains(ev.State.Detail, "slot") || !strings.Contains(ev.State.Detail, fmt.Sprint(cfg.Budget)) {
		t.Fatalf("the waiter whose budget ended is not named for the slot wait: %+v", ev)
	}
	if strings.Contains(ev.State.Detail, "too little to read the chain") {
		t.Fatalf("the state claims a judgement no read supports: %s", ev.State.Detail)
	}
	if _, asked := g.stats(); asked[waiter] != 0 {
		t.Fatalf("the waiter with no budget left read the chain %d times", asked[waiter])
	}
}
