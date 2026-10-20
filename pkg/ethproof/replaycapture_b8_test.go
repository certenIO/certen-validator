// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/ethproof"
)

func waitStored(t *testing.T, store *ethproof.ReplayGuardStore, chain int64, tx common.Hash, bound bool) *ethproof.ReplayGuardEvidence {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ev, b, ok := store.Get(chain, tx); ok && (b || !bound) {
			return ev
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("nothing stored (bound=%v) for %s", bound, tx.Hex())
	return nil
}

// V-R10B2 D2 (and D1 at the capture): a capture that could not state the block (no receipt was served, no provider is
// configured) or the contract (no provider served the transaction; a reverted settlement ends before the transaction is
// read) keeps its own reason when it is held to the proven settlement, with the block and contract filled from that
// settlement. It is never re-labelled settlement_block_mismatch or contract_mismatch.
func TestCapturer_ACaptureThatCouldNotStateItsBlockOrContractKeepsItsReason(t *testing.T) {
	noReceipt := func() (ethproof.ReplayCaptureConfig, *fakeChain) {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.noReceipt = true
		f.add("p", testN, testN)
		return cfgFor(f), f
	}
	noTx := func() (ethproof.ReplayCaptureConfig, *fakeChain) {
		f := newChain(t, worldOpts{after: 0}, testN)
		f.add("p", testN, testN).noTx = true
		return cfgFor(f), f
	}
	reverted := func() (ethproof.ReplayCaptureConfig, *fakeChain) {
		f := newChain(t, worldOpts{after: 0, reverted: true}, testN)
		f.add("p", testN, testN)
		return cfgFor(f), f
	}
	noSource := func() (ethproof.ReplayCaptureConfig, *fakeChain) {
		f := newChain(t, worldOpts{after: 0}, testN)
		return ethproof.ReplayCaptureConfig{ChainID: testChainID, Budget: 100 * time.Millisecond, Poll: time.Millisecond}, f
	}
	for _, c := range []struct {
		name, reason, detail string
		build                func() (ethproof.ReplayCaptureConfig, *fakeChain)
		blockStated          bool // the capture stated the block itself
	}{
		{"never saw the receipt (the reviewer's noReceipt probe)", ethproof.ReasonReceiptUnavailable, "no agreed receipt", noReceipt, false},
		{"no provider served the transaction", ethproof.ReasonReceiptUnavailable, "no provider served the settlement transaction", noTx, true},
		{"a reverted settlement", ethproof.ReasonSettlementNotExecuted, "status 0", reverted, true},
		{"no provider configured", ethproof.ReasonStateUnavailable, "no provider that serves state proofs", noSource, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, f := c.build()
			s := f.w.settlement
			tx := f.w.tx.Hash()
			store := ethproof.NewReplayGuardStore(16)
			cp := ethproof.NewReplayGuardCapturer(cfg, store)
			cp.Begin(tx)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, _, err := store.Wait(ctx, testChainID, tx); err != nil {
				t.Fatal(err)
			}
			captured, _, _ := store.Get(testChainID, tx)
			if captured == nil || captured.State == nil || captured.State.Reason != c.reason || !strings.Contains(captured.State.Detail, c.detail) {
				t.Fatalf("the capture is not the named state under test: %+v", captured)
			}
			if !c.blockStated && (captured.State.BlockNumber != 0 || captured.State.BlockHash != (common.Hash{})) {
				t.Fatalf("the capture states a block it could not have known: %+v", captured.State)
			}
			held := func(what string, ev *ethproof.ReplayGuardEvidence) {
				t.Helper()
				st := ev.State
				if st == nil || st.Reason != c.reason || st.State != captured.State.State || st.Detail != captured.State.Detail {
					t.Fatalf("%s: the capture's reason was not kept: %+v (captured %+v)", what, st, captured.State)
				}
				if st.BlockNumber != testN || st.BlockHash != s.BlockHash || st.Contract != *f.w.tx.To() || st.TxHash != tx {
					t.Fatalf("%s: block and contract are not the proven settlement's: %+v", what, st)
				}
				if _, err := ev.Verify(s); err != nil {
					t.Fatalf("%s: does not verify against the settlement: %v", what, err)
				}
			}
			held("Resolve", cp.Resolve(s))
			cp.Bind(s)
			held("Bind", waitStored(t, store, testChainID, tx, true))
		})
	}
}

// V-R10B2 note 5b: a pass asks the newest candidate block of every provider before an older candidate of any, and stops at
// the first verified proof, so a provider that cannot serve is asked once - not once for each of the four candidates -
// before the provider that can.
func TestCapture_AsksTheNewestBlockOfEveryProviderBeforeAnOlderBlockOfAny(t *testing.T) {
	f := newChain(t, worldOpts{after: 6}, testN+6)
	a := f.add("a", 0, 0)
	a.err = "missing trie node"
	b := f.add("b", testN-1, testN+6)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev == nil || ev.Proof == nil || ev.Proof.ProvenAt.Number != testN+6 || ev.Proof.Before == nil {
		t.Fatalf("%+v", ev)
	}
	// After at the newest block, then Before at the parent: one call each.
	if got, want := atomic.LoadInt32(&a.calls), int32(2); got != want {
		t.Fatalf("the provider that cannot serve was asked %d times, want %d (the newest block once, the parent once)", got, want)
	}
	if got := atomic.LoadInt32(&b.calls); got != 2 {
		t.Fatalf("the provider that serves was asked %d times, want 2", got)
	}
}
