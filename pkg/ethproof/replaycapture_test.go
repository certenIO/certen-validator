// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// fakeChain serves a world as the agreeing providers and the individual providers would.
type fakeChain struct {
	w         *world
	latest    uint64
	noReceipt bool
	providers []*fakeProvider
	// parentState is the state served for the settlement block's parent (default the world's before-state).
	parentState *state
}

func (f *fakeChain) header(n uint64) *types.Header {
	switch {
	case n == testN-1:
		return f.w.parent
	case n == testN:
		return f.w.headerN
	case n > testN && int(n-testN) <= len(f.w.chain):
		return f.w.chain[n-testN-1]
	}
	return nil
}

func (f *fakeChain) TransactionReceipt(_ context.Context, h common.Hash) (*types.Receipt, error) {
	if f.noReceipt || h != f.w.tx.Hash() {
		return nil, ethereum.NotFound
	}
	r := *f.w.receipt
	r.TxHash, r.BlockHash, r.BlockNumber = h, f.w.headerN.Hash(), big.NewInt(testN)
	for i, lg := range r.Logs {
		c := *lg
		c.TxHash, c.BlockHash, c.BlockNumber, c.Index = h, r.BlockHash, testN, uint(i)
		r.Logs[i] = &c
	}
	return &r, nil
}

func (f *fakeChain) HeaderByNumber(_ context.Context, n *big.Int) (*types.Header, error) {
	num := f.latest
	if n.Sign() >= 0 {
		num = n.Uint64()
	}
	if num > f.latest {
		return nil, ethereum.NotFound
	}
	if h := f.header(num); h != nil {
		return h, nil
	}
	return nil, ethereum.NotFound
}

func (f *fakeChain) HeaderByHash(_ context.Context, hash common.Hash) (*types.Header, error) {
	for _, h := range append([]*types.Header{f.w.parent, f.w.headerN}, f.w.chain...) {
		if h.Hash() == hash {
			return h, nil
		}
	}
	return nil, ethereum.NotFound
}

func (f *fakeChain) StateProviders() []ethproof.ReplayStateProvider {
	out := make([]ethproof.ReplayStateProvider, len(f.providers))
	for i, p := range f.providers {
		out[i] = p
	}
	return out
}

type fakeProvider struct {
	name  string
	chain *fakeChain
	// Blocks this provider can prove state at; 0/0 serves none.
	min, max uint64
	err      string // the error it answers with outside its window
	// lie serves the state of this tree instead of the chain's.
	lie     *state
	gate    chan struct{} // when set, GetProof blocks until it is closed
	calls   int32
	noTx    bool
	txCalls int32
}

func (p *fakeProvider) Name() string { return p.name }

func (p *fakeProvider) TransactionByHash(_ context.Context, h common.Hash) (*types.Transaction, bool, error) {
	atomic.AddInt32(&p.txCalls, 1)
	if p.noTx || h != p.chain.w.tx.Hash() {
		return nil, false, ethereum.NotFound
	}
	return p.chain.w.tx, false, nil
}

func (p *fakeProvider) GetProof(_ context.Context, account common.Address, keys []string, block string) (json.RawMessage, error) {
	atomic.AddInt32(&p.calls, 1)
	if p.gate != nil {
		<-p.gate
	}
	n, ok := new(big.Int).SetString(strings.TrimPrefix(block, "0x"), 16)
	if !ok {
		return nil, fmt.Errorf("bad block %q", block)
	}
	if n.Uint64() < p.min || n.Uint64() > p.max {
		if p.err != "" {
			return nil, errors.New(p.err)
		}
		return nil, errors.New("distance to target block exceeds maximum proof window")
	}
	st := p.chain.w.after
	if n.Uint64() < testN {
		st = p.chain.w.before
		if p.chain.parentState != nil {
			st = p.chain.parentState
		}
	}
	if p.lie != nil {
		st = p.lie
	}
	slot := common.HexToHash(keys[0])
	sp := st.prove(account, slot)
	type sto struct {
		Key   string          `json:"key"`
		Value string          `json:"value"`
		Proof []hexutil.Bytes `json:"proof"`
	}
	return json.Marshal(map[string]interface{}{
		"accountProof": sp.AccountProof, "storageHash": sp.StorageHash, "codeHash": sp.CodeHash,
		"storageProof": []sto{{Key: slot.Hex(), Value: new(big.Int).SetBytes(sp.Value[:]).Text(16), Proof: sp.StorageProof}},
	})
}

func newChain(t *testing.T, o worldOpts, latest uint64) *fakeChain {
	w := newWorld(t, o)
	return &fakeChain{w: w, latest: latest}
}

func (f *fakeChain) add(name string, min, max uint64) *fakeProvider {
	p := &fakeProvider{name: name, chain: f, min: min, max: max}
	f.providers = append(f.providers, p)
	return p
}

func cfgFor(f *fakeChain) ethproof.ReplayCaptureConfig {
	return ethproof.ReplayCaptureConfig{ChainID: testChainID, Source: f, Budget: 400 * time.Millisecond, Poll: 5 * time.Millisecond}
}

// A head-only provider (Adiri's public endpoints, publicnode): the slot is proven at the settlement block, the parent is
// disclosed unavailable with the provider's own error.
func TestCapture_HeadOnlyProviderProvesAfterAndDisclosesBefore(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("rpc.telcoin.network", testN, testN)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev.Proof == nil {
		t.Fatalf("no proof: %+v", ev.State)
	}
	p := ev.Proof
	if p.Before != nil || p.BeforeUnavailable == nil || len(p.BeforeUnavailable.Providers) != 1 ||
		!strings.Contains(p.BeforeUnavailable.Providers[0].Error, "maximum proof window") || p.BeforeUnavailable.Providers[0].Host != "rpc.telcoin.network" {
		t.Fatalf("the unserved parent must be disclosed with the provider's error: %+v", p.BeforeUnavailable)
	}
	chk, err := ev.Verify(f.w.settlement)
	if err != nil || chk.State != ethproof.ReplayProven || chk.BeforeVerified {
		t.Fatalf("%v %+v", err, chk)
	}
}

// A provider with a window: After at the newest block, Before at the parent, both verified.
func TestCapture_WindowedProviderProvesBeforeAndAfter(t *testing.T) {
	f := newChain(t, worldOpts{after: 2}, testN+2)
	f.add("sepolia.base.org", testN-1, testN+2)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev.Proof == nil {
		t.Fatalf("no proof: %+v", ev.State)
	}
	if ev.Proof.ProvenAt.Number != testN+2 || len(ev.Proof.Headers) != 2 || ev.Proof.Before == nil {
		t.Fatalf("proven at %d with %d headers, before=%v", ev.Proof.ProvenAt.Number, len(ev.Proof.Headers), ev.Proof.Before != nil)
	}
	chk, err := ev.Verify(f.w.settlement)
	if err != nil || !chk.BeforeVerified {
		t.Fatalf("%v %+v", err, chk)
	}
}

// Providers are tried in turn: one without the state, one that lies, one that serves.
func TestCapture_TriesProvidersInTurnAndVerifiesEveryProof(t *testing.T) {
	f := newChain(t, worldOpts{after: 1}, testN+1)
	f.add("pruned", 0, 0)
	liar := f.add("liar", testN-1, testN+1)
	liar.lie = buildState(t, account{addr: testOther}, account{addr: testContract, code: testCode,
		storage: map[common.Hash]*big.Int{f.w.slot: big.NewInt(1), common.BigToHash(big.NewInt(77)): big.NewInt(5)}})
	f.add("honest", testN, testN+1)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev.Proof == nil {
		t.Fatalf("no proof: %+v", ev.State)
	}
	if ev.Proof.ProvenAt.Number != testN+1 {
		t.Fatalf("proven at %d", ev.Proof.ProvenAt.Number)
	}
	if _, err := ev.Verify(f.w.settlement); err != nil {
		t.Fatalf("the liar's bytes must never be kept: %v", err)
	}
	if ev.Proof.Before != nil || ev.Proof.BeforeUnavailable == nil {
		t.Fatalf("the honest provider cannot serve the parent; the liar's parent proof must not be taken: %+v", ev.Proof.Before)
	}
	names := map[string]string{}
	for _, pf := range ev.Proof.BeforeUnavailable.Providers {
		names[pf.Host] = pf.Error
	}
	if !strings.Contains(names["liar"], "does not verify against the agreed state root") || names["pruned"] == "" || names["honest"] == "" {
		t.Fatalf("every provider's failure is named: %v", names)
	}
}

// No provider can serve: the named state carries the block and every provider's own error.
func TestCapture_NoProviderIsAUnprovenStateNamingEachFailure(t *testing.T) {
	f := newChain(t, worldOpts{after: 1}, testN+1)
	a := f.add("publicnode", 0, 0)
	a.err = "distance to target block exceeds maximum proof window"
	b := f.add("sepolia-rollup.arbitrum.io", 0, 0)
	b.err = "historical state 0xabcd is not available"
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	st := ev.State
	if ev.Proof != nil || st == nil || st.State != ethproof.ReplayUnproven || st.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("%+v", ev)
	}
	if st.BlockNumber != testN || st.BlockHash != f.w.headerN.Hash() || st.TxHash != f.w.tx.Hash() || st.ChainID != testChainID || st.Contract != testContract {
		t.Fatalf("the state is judged at a named block: %+v", st)
	}
	got := map[string]string{}
	for _, pf := range st.Providers {
		got[pf.Host] = pf.Error
	}
	if !strings.Contains(got["publicnode"], "maximum proof window") || !strings.Contains(got["sepolia-rollup.arbitrum.io"], "is not available") {
		t.Fatalf("each provider's error is named: %v", got)
	}
	// And it verifies as that state against the proven settlement.
	chk, err := ev.Verify(f.w.settlement)
	if err != nil || chk.State != ethproof.ReplayUnproven || chk.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("%v %+v", err, chk)
	}
}

func TestCapture_NamedStatesWithoutAskingForState(t *testing.T) {
	// An older account generation: named, and no provider is asked for a proof.
	f := newChain(t, worldOpts{after: 0, selector: []byte{0x57, 0xf8, 0x56, 0x7d}}, testN) // CertenAccountV7_2.executeGovernanceProofDirect
	p := f.add("p", testN, testN)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev.State == nil || ev.State.State != ethproof.ReplayUnproven || ev.State.Reason != ethproof.ReasonAccountGeneration || atomic.LoadInt32(&p.calls) != 0 {
		t.Fatalf("%+v calls=%d", ev.State, p.calls)
	}
	if !strings.Contains(ev.State.Detail, ethproof.AccountGenerationV7_2) {
		t.Fatalf("the generation is named: %s", ev.State.Detail)
	}
	// A transaction that is no account settlement of any generation makes no S6 claim.
	fo := newChain(t, worldOpts{after: 0, selector: []byte{0x12, 0x34, 0x56, 0x78}}, testN)
	fo.add("p", testN, testN)
	if ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(fo), fo.w.tx.Hash()); ev != nil {
		t.Fatalf("not a settlement: %+v", ev)
	}
	// A reverted settlement consumed nothing.
	f2 := newChain(t, worldOpts{after: 0, reverted: true}, testN)
	f2.add("p", testN, testN)
	if ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f2), f2.w.tx.Hash()); ev.State == nil || ev.State.Reason != ethproof.ReasonSettlementNotExecuted {
		t.Fatalf("%+v", ev)
	}
	// No LeafConsumed of the account in the receipt.
	attacker := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	f3 := newChain(t, worldOpts{after: 0, eventFrom: &attacker}, testN)
	f3.add("p", testN, testN)
	if ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f3), f3.w.tx.Hash()); ev.State == nil || ev.State.State != ethproof.ReplayEventMissing {
		t.Fatalf("%+v", ev)
	}
	// A receipt the agreeing providers never serve.
	f4 := newChain(t, worldOpts{after: 0}, testN)
	f4.noReceipt = true
	f4.add("p", testN, testN)
	if ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f4), f4.w.tx.Hash()); ev.State == nil || ev.State.Reason != ethproof.ReasonReceiptUnavailable {
		t.Fatalf("%+v", ev)
	}
	// No provider configured at all.
	if ev := ethproof.CaptureReplayGuard(context.Background(), ethproof.ReplayCaptureConfig{ChainID: 1}, common.Hash{1}); ev.State == nil || ev.State.Reason != ethproof.ReasonStateUnavailable {
		t.Fatalf("%+v", ev)
	}
}

// A provider that proves the slot already 1 at the parent contradicts the status-1 receipt.
func TestCapture_BeforeSaysOneIsRefuted(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.parentState = f.w.after
	// The parent header must root the served state for the proof to verify at all.
	parent := *f.w.parent
	parent.Root = f.w.after.root
	f.w.headerN.ParentHash = parent.Hash()
	f.w.parent = &parent
	f.add("p", testN-1, testN)
	ev := ethproof.CaptureReplayGuard(context.Background(), cfgFor(f), f.w.tx.Hash())
	if ev.State == nil || ev.State.State != ethproof.ReplayRefuted || ev.State.Reason != ethproof.ReasonSlotSetAtParent || ev.State.Before == nil {
		t.Fatalf("%+v", ev)
	}
}

// The capture runs beside the observation: Begin returns at once however long the providers take, and a settlement
// first seen at finality is stored as a named state, never omitted.
func TestCapturer_BeginNeverBlocksAndBindHoldsTheEvidenceToTheSettlement(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	p := f.add("slow", testN, testN)
	p.gate = make(chan struct{})
	store := ethproof.NewReplayGuardStore(16)
	c := ethproof.NewReplayGuardCapturer(cfgFor(f), store)

	start := time.Now()
	c.Begin(f.w.tx.Hash())
	c.Begin(f.w.tx.Hash()) // idempotent
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("Begin blocked for %s", time.Since(start))
	}
	if _, _, ok := store.Get(testChainID, f.w.tx.Hash()); ok {
		t.Fatal("nothing is stored before the capture finishes")
	}
	c.Bind(f.w.settlement) // returns at once as well
	close(p.gate)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ev *ethproof.ReplayGuardEvidence
	var bound bool
	for i := 0; i < 500; i++ {
		var ok bool
		if ev, bound, ok = store.Get(testChainID, f.w.tx.Hash()); ok && bound {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("the capture did not finish")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if ev == nil || !bound || ev.Proof == nil {
		t.Fatalf("%+v bound=%v", ev, bound)
	}
	if got := atomic.LoadInt32(&p.calls); got < 1 {
		t.Fatalf("the provider was never asked")
	}

	// A settlement first seen at finality: no capture ran at inclusion.
	g := newChain(t, worldOpts{after: 0}, testN)
	store2 := ethproof.NewReplayGuardStore(16)
	c2 := ethproof.NewReplayGuardCapturer(cfgFor(g), store2)
	c2.Bind(g.w.settlement)
	var late *ethproof.ReplayGuardEvidence
	for i := 0; i < 500 && late == nil; i++ {
		late, _, _ = store2.Get(testChainID, g.w.tx.Hash())
		time.Sleep(5 * time.Millisecond)
	}
	if late == nil || late.State == nil || late.State.Reason != ethproof.ReasonCaptureNotAttempted || late.State.BlockNumber != testN {
		t.Fatalf("%+v", late)
	}
	if _, err := late.Verify(g.w.settlement); err != nil {
		t.Fatal(err)
	}
}

// Evidence captured for one block does not survive being held to a settlement in another (a reorg between inclusion and
// finality): it is replaced by the named state saying so.
func TestCapturer_BindReplacesEvidenceThatDoesNotHoldAtFinality(t *testing.T) {
	f := newChain(t, worldOpts{after: 0}, testN)
	f.add("p", testN, testN)
	store := ethproof.NewReplayGuardStore(16)
	c := ethproof.NewReplayGuardCapturer(cfgFor(f), store)
	c.Begin(f.w.tx.Hash())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := store.Wait(ctx, testChainID, f.w.tx.Hash()); err != nil {
		t.Fatal(err)
	}
	// The block the settlement is finally proven in is another block with the same transaction (another header).
	hdr := *f.w.headerN
	hdr.Time++
	txEnc, _ := f.w.tx.MarshalBinary()
	rcEnc, _ := f.w.receipt.MarshalBinary()
	other, err := (&ethproof.Block{Header: &hdr, Txs: [][]byte{txEnc}, Receipts: [][]byte{rcEnc}}).Prove(f.w.tx.Hash(), 0)
	if err != nil {
		t.Fatal(err)
	}
	c.Bind(other)
	var ev *ethproof.ReplayGuardEvidence
	for i := 0; i < 500; i++ {
		var bound bool
		ev, bound, _ = store.Get(testChainID, f.w.tx.Hash())
		if bound {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if ev == nil || ev.State == nil || ev.State.Reason != ethproof.ReasonBlockMismatch || ev.State.BlockHash != other.BlockHash {
		t.Fatalf("%+v", ev)
	}
}
