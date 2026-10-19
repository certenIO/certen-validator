// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
)

// settlementSelectors are the four settlement calls the capture recognises (V7_3 execute and batch, V7_2 execute and
// batch): worlds built with them carry four distinct settlement transactions.
func settlementSelectors() [][]byte {
	return [][]byte{v73Execute, v73Batch, replayworld.V72Execute, replayworld.V72Batch}
}

// headOnlyWorld is one settlement on a chain whose only provider proves state at the settlement block and nowhere else
// (Adiri's public endpoints, publicnode).
func headOnlyWorld(t *testing.T, i int) *fakeChain {
	t.Helper()
	f := newChain(t, worldOpts{after: 0, selector: settlementSelectors()[i]}, testN)
	f.add("head-only.example", testN, testN)
	return f
}

// V-R10B3 D1: the per-chain capture slot is held for the After phase only. A capture whose providers never serve the
// settlement block's parent keeps asking for it until its budget ends, and it must not hold a slot meanwhile: every
// settlement of a head-only chain gets its After proof and discloses its Before unavailable.
func TestCapturer_ACaptureHoldsItsSlotOnlyForTheAfterPhase(t *testing.T) {
	for _, tc := range []struct {
		name       string
		concurrent int
		worlds     int
		budget     time.Duration
	}{
		{"Concurrent=1, two settlements", 1, 2, time.Second},
		{"Concurrent=2, four settlements", 2, 4, 1500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := ethproof.NewReplayGuardStore(64)
			var chains []*fakeChain
			var capturers []*ethproof.ReplayGuardCapturer
			for i := 0; i < tc.worlds; i++ {
				f := headOnlyWorld(t, i)
				cfg := cfgFor(f)
				cfg.Budget, cfg.Concurrent = tc.budget, tc.concurrent
				chains = append(chains, f)
				capturers = append(capturers, ethproof.NewReplayGuardCapturer(cfg, store))
			}
			for i, cp := range capturers {
				cp.Begin(chains[i].w.tx.Hash())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for i, f := range chains {
				if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
					t.Fatal(err)
				}
				ev, _, _ := store.Get(testChainID, f.w.tx.Hash())
				if ev == nil || ev.Proof == nil {
					t.Fatalf("settlement %d of %d lost S6 to the capture slots: %+v", i, tc.worlds, ev)
				}
				if p := ev.Proof; p.Before != nil || p.BeforeUnavailable == nil || len(p.BeforeUnavailable.Providers) != 1 ||
					!strings.Contains(p.BeforeUnavailable.Providers[0].Error, "maximum proof window") {
					t.Fatalf("settlement %d: the unserved parent is not disclosed: %+v", i, p.BeforeUnavailable)
				}
				chk, err := ev.Verify(f.w.settlement)
				if err != nil || chk.State != ethproof.ReplayProven || chk.BeforeVerified {
					t.Fatalf("settlement %d: %v %+v", i, err, chk)
				}
			}
		})
	}
}

// phaseCounter counts the provider reads that are made for the After phase (state at or after the settlement block) in
// flight at once, and holds them until released.
type phaseCounter struct {
	mu       sync.Mutex
	now, max int
	gate     chan struct{}
}

type phaseProvider struct {
	*fakeProvider
	pc *phaseCounter
}

func (p phaseProvider) GetProof(ctx context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(block, "0x"), 16); ok && n.Uint64() >= testN {
		p.pc.mu.Lock()
		p.pc.now++
		if p.pc.now > p.pc.max {
			p.pc.max = p.pc.now
		}
		p.pc.mu.Unlock()
		defer func() { p.pc.mu.Lock(); p.pc.now--; p.pc.mu.Unlock() }()
		select {
		case <-p.pc.gate:
		case <-ctx.Done():
		}
	}
	return p.fakeProvider.GetProof(ctx, account, keys, block)
}

type phaseSource struct {
	*fakeChain
	pc *phaseCounter
}

func (s phaseSource) StateProviders() []ethproof.ReplayStateProvider {
	var out []ethproof.ReplayStateProvider
	for _, p := range s.fakeChain.providers {
		out = append(out, phaseProvider{p, s.pc})
	}
	return out
}

func (pc *phaseCounter) snapshot() (now, max int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.now, pc.max
}

// V-R10B3 D1: the cap is on the After phase: with Concurrent=2 exactly two captures prove After at once while the others
// wait for a slot, never more; once those two have their After they free their slots (while still asking for Before) and
// the others prove theirs.
func TestCapturer_NoMoreThanConcurrentCapturesAreInTheAfterPhaseAtOnce(t *testing.T) {
	pc := &phaseCounter{gate: make(chan struct{})}
	store := ethproof.NewReplayGuardStore(64)
	var chains []*fakeChain
	start := time.Now()
	for i := 0; i < 4; i++ {
		f := headOnlyWorld(t, i)
		cfg := cfgFor(f)
		cfg.Source, cfg.Budget, cfg.Concurrent = phaseSource{f, pc}, 2*time.Second, 2
		chains = append(chains, f)
		ethproof.NewReplayGuardCapturer(cfg, store).Begin(f.w.tx.Hash())
	}
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Fatalf("Begin blocked for %s with every slot taken", took)
	}
	time.Sleep(200 * time.Millisecond)
	if now, max := pc.snapshot(); now != 2 || max != 2 {
		t.Fatalf("%d captures (at most %d) are proving After with Concurrent=2; the other two must wait for a slot", now, max)
	}
	close(pc.gate)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i, f := range chains {
		if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
			t.Fatal(err)
		}
		if ev, _, _ := store.Get(testChainID, f.w.tx.Hash()); ev == nil || ev.Proof == nil {
			t.Fatalf("settlement %d lost S6: %+v", i, ev)
		}
	}
	if _, max := pc.snapshot(); max > 2 {
		t.Fatalf("%d captures were proving After at once with Concurrent=2", max)
	}
}

// panickingSource panics when it is asked for a receipt.
type panickingSource struct{ *fakeChain }

func (panickingSource) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	panic("the source failed")
}

// V-R10B3 D1 (kept): the slot is released when the capture panics, when it ends on a source error without any After
// proof, and when it ends for its budget: the next settlement of the chain gets its proof.
func TestCapturer_TheSlotIsReleasedOnAPanicAndOnSourceErrors(t *testing.T) {
	prunedWorld := func(t *testing.T) *fakeChain {
		f := newChain(t, worldOpts{after: 0, selector: v73Batch}, testN)
		p := f.add("pruned.example", 0, 0)
		p.err = "missing trie node"
		return f
	}
	noReceipt := func(t *testing.T) *fakeChain {
		f := newChain(t, worldOpts{after: 0, selector: v73Batch}, testN)
		f.noReceipt = true
		f.add("head-only.example", testN, testN)
		return f
	}
	for _, tc := range []struct {
		name  string
		first func(t *testing.T) (ethproof.ReplayCaptureSource, common.Hash)
		want  string
	}{
		{"a panic in the source", func(t *testing.T) (ethproof.ReplayCaptureSource, common.Hash) {
			f := headOnlyWorld(t, 1)
			return panickingSource{f}, f.w.tx.Hash()
		}, "the source failed"},
		{"no provider serves After", func(t *testing.T) (ethproof.ReplayCaptureSource, common.Hash) {
			f := prunedWorld(t)
			return f, f.w.tx.Hash()
		}, ethproof.ReasonStateUnavailable},
		{"no receipt is served", func(t *testing.T) (ethproof.ReplayCaptureSource, common.Hash) {
			f := noReceipt(t)
			return f, f.w.tx.Hash()
		}, ethproof.ReasonReceiptUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := ethproof.NewReplayGuardStore(16)
			src, firstTx := tc.first(t)
			firstCfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: src, Budget: 150 * time.Millisecond, Poll: 5 * time.Millisecond, Concurrent: 1}
			second := headOnlyWorld(t, 0)
			secondCfg := cfgFor(second)
			secondCfg.Budget, secondCfg.Concurrent = time.Second, 1
			ethproof.NewReplayGuardCapturer(firstCfg, store).Begin(firstTx)
			time.Sleep(20 * time.Millisecond) // the first capture has its slot before the second begins
			ethproof.NewReplayGuardCapturer(secondCfg, store).Begin(second.w.tx.Hash())
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, h := range []common.Hash{firstTx, second.w.tx.Hash()} {
				if _, _, err := store.Wait(ctx, testChainID, h); err != nil {
					t.Fatal(err)
				}
			}
			ev, _, _ := store.Get(testChainID, firstTx)
			if ev == nil || ev.State == nil || (ev.State.Reason != tc.want && !strings.Contains(ev.State.Detail, tc.want)) {
				t.Fatalf("the first capture is not the named state %q: %+v", tc.want, ev)
			}
			if ev, _, _ := store.Get(testChainID, second.w.tx.Hash()); ev == nil || ev.Proof == nil {
				t.Fatalf("the slot of the first capture (%s) was not released: %+v", tc.name, ev)
			}
		})
	}
}

var budgetOf = regexp.MustCompile(`budget of (\S+) ended`)

// V-R10B3 D2: a capture that obtains its slot when its budget has (all but) ended is the named state of the slot wait; it
// never reads the chain, and is never receipt_unavailable with a budget it could not have used.
func TestCapturer_ACaptureThatGetsItsSlotWithNoBudgetLeftIsTheNamedStateOfTheSlotWait(t *testing.T) {
	g := newGated(t)
	store := ethproof.NewReplayGuardStore(16)
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 300 * time.Millisecond, Poll: 50 * time.Millisecond, Concurrent: 1}
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	holder, waiter := common.Hash{0x01}, common.Hash{0x02}
	cp.Begin(holder)
	time.Sleep(10 * time.Millisecond) // the waiter's budget ends 10ms after the holder frees the slot: less than one poll
	cp.Begin(waiter)
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
		t.Fatalf("the capture that got its slot with no budget left is not named for the slot wait: %+v", ev)
	}
	if _, asked := g.stats(); asked[waiter] != 0 {
		t.Fatalf("the capture with no budget left read the chain %d times", asked[waiter])
	}
	if hev, _, _ := store.Get(testChainID, holder); hev == nil || hev.State == nil || hev.State.Reason != ethproof.ReasonReceiptUnavailable {
		t.Fatalf("the capture that held the slot and read the chain is receipt_unavailable: %+v", hev)
	}
}

// V-R10B3 D2 (the reviewer's probe): a burst of settlements on a source that serves nothing, with a budget that ends while
// the slots turn over. No capture that never read the chain is receipt_unavailable, none names a budget of 1ns, and every
// receipt_unavailable capture had at least one poll of budget to read with.
func TestCapturer_ABurstNeverNamesAThrottleReceiptUnavailable(t *testing.T) {
	g := newGated(t)
	store := ethproof.NewReplayGuardStore(1024)
	cfg := ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: g, Budget: 400 * time.Millisecond, Poll: 5 * time.Millisecond, Concurrent: 2}
	cp := ethproof.NewReplayGuardCapturer(cfg, store)
	var txs []common.Hash
	for i := 0; i < 300; i++ {
		h := common.BigToHash(big.NewInt(int64(i + 1)))
		txs = append(txs, h)
		cp.Begin(h)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	slotWaits, receiptStates := 0, 0
	for _, h := range txs {
		if _, _, err := store.Wait(ctx, testChainID, h); err != nil {
			t.Fatal(err)
		}
	}
	_, asked := g.stats()
	for _, h := range txs {
		ev, _, _ := store.Get(testChainID, h)
		if ev == nil || ev.State == nil {
			t.Fatalf("a capture ended without a named state: %+v", ev)
		}
		st := ev.State
		switch {
		case st.Reason == ethproof.ReasonReceiptUnavailable:
			receiptStates++
			if asked[h] == 0 {
				t.Fatalf("a capture that never read the chain is receipt_unavailable: %s", st.Detail)
			}
			m := budgetOf.FindStringSubmatch(st.Detail)
			if m == nil {
				t.Fatalf("a receipt_unavailable state names no budget: %s", st.Detail)
			}
			if b, err := time.ParseDuration(m[1]); err != nil || b < cfg.Poll {
				t.Fatalf("receipt_unavailable with a budget of %s, below one poll (%s) it could not use: %s", m[1], cfg.Poll, st.Detail)
			}
		case st.Reason == ethproof.ReasonStateUnavailable && strings.Contains(st.Detail, "slot"):
			slotWaits++
		default:
			t.Fatalf("an unexpected state: %+v", st)
		}
	}
	if slotWaits == 0 || receiptStates == 0 {
		t.Fatalf("the burst did not exercise both paths: %d slot waits, %d receipt states", slotWaits, receiptStates)
	}
}
