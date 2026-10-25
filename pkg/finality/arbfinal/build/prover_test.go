// Copyright 2026 Certen Protocol

package build

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/arbfinal/synthworld"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// ---- a synthetic chain pair served through the provider interfaces ----------------------------------------------------------

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

func trimmed(w common.Hash) []byte {
	i := 0
	for i < 32 && w[i] == 0 {
		i++
	}
	b, _ := rlp.EncodeToBytes(w[i:])
	return b
}

func hdr(parent common.Hash, state, txRoot, rcRoot common.Hash, number, ts uint64, mix []byte) []byte {
	items := []any{parent.Bytes(), bytes.Repeat([]byte{0x1d}, 32), make([]byte, 20), state.Bytes(), txRoot.Bytes(), rcRoot.Bytes(),
		make([]byte, 256), uint64(0), number, uint64(30_000_000), uint64(1), ts, []byte("x"), mix, make([]byte, 8)}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return raw
}

type stateT struct {
	root    common.Hash
	acct    *trie.Trie
	storage map[common.Address]*trie.Trie
}

func buildState(assertion, parent [32]byte, cfg arbfinal.ParentConfig, status uint64) *stateT {
	word := func(a common.Address) common.Hash { var h common.Hash; copy(h[12:], a[:]); return h }
	node := common.BigToHash(new(big.Int).Lsh(new(big.Int).SetUint64(status), 200))
	roll := trie.NewEmpty(nil)
	for s, v := range map[common.Hash]common.Hash{
		synthworld.AdminSlot: word(synthworld.AdminLogic), synthworld.UserSlot: word(synthworld.UserLogic),
		arbfinal.NodeSlot(assertion, 117): node, arbfinal.ConfigSlot(parent, 117, 1): common.Hash(arbfinal.ConfigHash(cfg)),
		common.BigToHash(big.NewInt(123)): {},
	} {
		if v == (common.Hash{}) {
			continue
		}
		if err := roll.Update(crypto.Keccak256(s[:]), trimmed(v)); err != nil {
			panic(err)
		}
	}
	st := &stateT{acct: trie.NewEmpty(nil), storage: map[common.Address]*trie.Trie{synthworld.Rollup: roll, synthworld.AdminLogic: trie.NewEmpty(nil), synthworld.UserLogic: trie.NewEmpty(nil)}}
	for addr, code := range map[common.Address]common.Hash{synthworld.Rollup: crypto.Keccak256Hash([]byte("rollup proxy")), synthworld.AdminLogic: synthworld.AdminCode, synthworld.UserLogic: synthworld.UserCode} {
		enc, _ := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), st.storage[addr].Hash(), code.Bytes()})
		if err := st.acct.Update(crypto.Keccak256(addr[:]), enc); err != nil {
			panic(err)
		}
	}
	st.root = st.acct.Hash()
	return st
}

// addAccount puts an account with the given code hash and storage into the state and recomputes the root.
func (s *stateT) addAccount(addr common.Address, code common.Hash, storage map[common.Hash]common.Hash) {
	sto := trie.NewEmpty(nil)
	for k, v := range storage {
		if err := sto.Update(crypto.Keccak256(k[:]), trimmed(v)); err != nil {
			panic(err)
		}
	}
	if len(storage) > 0 {
		s.storage[addr] = sto
	}
	enc, _ := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), sto.Hash(), code.Bytes()})
	if err := s.acct.Update(crypto.Keccak256(addr[:]), enc); err != nil {
		panic(err)
	}
	s.root = s.acct.Hash()
}

func (s *stateT) proof(addr common.Address, slots []common.Hash) *StateProof {
	var c collector
	if err := s.acct.Prove(crypto.Keccak256(addr[:]), &c); err != nil {
		panic(err)
	}
	out := &StateProof{Account: c.nodes, Storage: map[common.Hash][][]byte{}}
	for _, sl := range slots {
		if s.storage[addr] == nil {
			continue // an absent or storage-less account: eth_getProof answers the account proof and empty storage proofs
		}
		var sc collector
		if err := s.storage[addr].Prove(crypto.Keccak256(sl[:]), &sc); err != nil {
			panic(err)
		}
		out.Storage[sl] = sc.nodes
	}
	return out
}

type fakeL1 struct {
	head     uint64
	headers  map[uint64][]byte
	logs     []Log
	blocks   map[uint64]*L1Block
	states   map[uint64]*stateT
	proofErr map[uint64]error
	// proofErrAddr fails eth_getProof for one address (at any block); proofAddrs records every address asked, in order.
	proofErrAddr map[common.Address]error
	// proofCorrupt serves a proof that does not verify for one address: "account" alters the first node of its account proof, "slot" the
	// first node of each of its storage proofs.
	proofCorrupt map[common.Address]string
	proofAddrs   []common.Address
	logsErr      error
	calls        int
}

func (f *fakeL1) Providers() []string                  { return []string{"https://l1.example"} }
func (f *fakeL1) Head(context.Context) (uint64, error) { return f.head, nil }
func (f *fakeL1) Headers(_ context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; n <= to; n++ {
		h, ok := f.headers[n]
		if !ok {
			return nil, errors.New("no such header")
		}
		out = append(out, h)
	}
	return out, nil
}
func (f *fakeL1) HeaderByHash(_ context.Context, hash [32]byte) ([]byte, error) {
	for _, h := range f.headers {
		if crypto.Keccak256Hash(h) == common.Hash(hash) {
			return h, nil
		}
	}
	return nil, errors.New("unknown hash")
}
func (f *fakeL1) Logs(_ context.Context, _ common.Address, topics [][]common.Hash, from, to uint64) ([]Log, error) {
	if f.logsErr != nil {
		return nil, f.logsErr
	}
	var out []Log
	for _, l := range f.logs {
		if l.Block < from || l.Block > to {
			continue
		}
		ok := true
		for i, alts := range topics {
			if len(alts) == 0 {
				continue
			}
			m := false
			for _, a := range alts {
				if i < len(l.Topics) && l.Topics[i] == a {
					m = true
				}
			}
			ok = ok && m
		}
		if ok {
			out = append(out, l)
		}
	}
	return out, nil
}
func (f *fakeL1) Block(_ context.Context, n uint64) (*L1Block, error) {
	if b, ok := f.blocks[n]; ok {
		return b, nil
	}
	return nil, errors.New("block not served")
}
func (f *fakeL1) Proof(_ context.Context, addr common.Address, slots []common.Hash, block uint64) (*StateProof, error) {
	f.calls++
	f.proofAddrs = append(f.proofAddrs, addr)
	if err := f.proofErr[block]; err != nil {
		return nil, err
	}
	if err := f.proofErrAddr[addr]; err != nil {
		return nil, err
	}
	st, ok := f.states[block]
	if !ok {
		return nil, errors.New("no state at block")
	}
	p := st.proof(addr, slots)
	alter := func(ns [][]byte) [][]byte {
		out := make([][]byte, len(ns))
		for i := range ns {
			out[i] = append([]byte(nil), ns[i]...)
		}
		if len(out) > 0 && len(out[0]) > 0 {
			out[0][len(out[0])-1] ^= 1
		}
		return out
	}
	switch f.proofCorrupt[addr] {
	case "account":
		p.Account = alter(p.Account)
	case "slot":
		for k, v := range p.Storage {
			p.Storage[k] = alter(v)
		}
	}
	return p, nil
}

type fakeL2 struct {
	byNum   map[uint64][]byte
	failNum map[uint64]bool
	failAll bool
}

func (f *fakeL2) Providers() []string { return []string{"https://l2.example"} }
func (f *fakeL2) HeaderByHash(_ context.Context, hash [32]byte) ([]byte, error) {
	if f.failAll {
		return nil, errors.New("l2 down")
	}
	for _, h := range f.byNum {
		if crypto.Keccak256Hash(h) == common.Hash(hash) {
			return h, nil
		}
	}
	return nil, errors.New("unknown l2 hash")
}
func (f *fakeL2) HeaderByNumber(_ context.Context, n uint64) ([]byte, error) {
	if h, ok := f.byNum[n]; ok {
		return h, nil
	}
	return nil, errors.New("unknown l2 block")
}
func (f *fakeL2) Headers(_ context.Context, from, to uint64) ([][]byte, error) {
	var out [][]byte
	for n := from; n <= to; n++ {
		h, ok := f.byNum[n]
		if !ok || f.failNum[n] {
			return nil, errors.New("l2 header missing")
		}
		out = append(out, h)
	}
	return out, nil
}

type fakeLC struct {
	lc  ethl1.LC
	err error
}

func (f *fakeLC) LC(context.Context) (ethl1.LC, error) { return f.lc, f.err }

type world struct {
	pins      *finality.Pins
	l1        *fakeL1
	l2        *fakeL2
	lc        *fakeLC
	leg       finality.BlockRef
	assertion common.Hash
	K, S, F   uint64
	m         uint64
	p         *Prover
}

const (
	wLeg      = 400_000_000
	wAbove    = 5
	wCreated  = 11_999_000
	wK        = 11_999_900
	wTxIndex  = 1
	wHead     = 12_000_090
	wFinalTop = 12_000_040
)

func createdLog(a Assertion, block uint64) Log {
	data := make([]byte, createdDataWords*32)
	put := func(i int, b []byte) { copy(data[32*i+32-len(b):], b) }
	u := func(i int, v uint64) { binary.BigEndian.PutUint64(data[32*i+24:], v) }
	put(2, a.ParentCfg.WasmModuleRoot[:])
	put(3, a.ParentCfg.RequiredStake[:])
	put(4, a.ParentCfg.ChallengeManager[:])
	u(5, a.ParentCfg.ConfirmPeriodBlocks)
	u(6, a.ParentCfg.NextInboxPosition)
	put(13, a.After.BlockHash[:])
	put(14, a.After.SendRoot[:])
	u(15, a.After.InboxPosition)
	u(16, a.After.PositionInMessage)
	u(17, uint64(a.After.MachineStatus))
	put(18, a.After.EndHistoryRoot[:])
	put(19, a.SeqAcc[:])
	return Log{Block: block, BlockHash: crypto.Keccak256Hash([]byte(fmt.Sprint("blk", block))), Topics: []common.Hash{TopicAssertionCreated, a.Hash, a.Parent}, Data: data}
}

// walletOpts shapes the confirmation transaction as a ValidatorWallet call: it is sent to callee with the calldata of
// executeTransaction carrying confirmAssertion for the Rollup, and the state at K and S gains the callee account (nil: the callee has
// no account) and the implementation account named by its slot.
type walletOpts struct {
	callee    common.Address
	proxyCode *common.Hash // the callee account's code hash (nil: no account for the callee)
	implWord  *common.Hash // the implementation slot word (nil: the pinned implementation); with proxyCode set
	noImpl    bool         // do not add the implementation account
}

func newWorld(t *testing.T) *world { return newWorldWith(t, nil) }

// newWorldWith builds the chains the fakes serve: an L2 chain leg..leg+wAbove, an assertion over its top, the confirmation at wK.
func newWorldWith(t *testing.T, wo *walletOpts) *world {
	t.Helper()
	w := &world{K: wK, S: wK + 2, F: wFinalTop}
	var l1ref [8]byte
	mix := func() []byte {
		m := make([]byte, 32)
		binary.BigEndian.PutUint64(m[8:16], wCreated-300)
		_ = l1ref
		return m
	}
	l2 := &fakeL2{byNum: map[uint64][]byte{}}
	prev := common.Hash(crypto.Keccak256Hash([]byte("l2 parent")))
	var top []byte
	for i := uint64(0); i <= wAbove; i++ {
		raw := hdr(prev, crypto.Keccak256Hash([]byte("s")), common.Hash{}, common.Hash{}, wLeg+i, 1_700_000_000+i, mix())
		l2.byNum[wLeg+i] = raw
		prev = crypto.Keccak256Hash(raw)
		top = raw
	}
	w.m = wLeg + wAbove
	w.l2 = l2
	legRaw := l2.byNum[wLeg]
	lh, _ := finality.ReadHeader(legRaw)
	w.leg = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: wLeg, Hash: lh.Hash, HeaderRLP: legRaw}

	a := Assertion{Parent: crypto.Keccak256Hash([]byte("parent")), SeqAcc: crypto.Keccak256Hash([]byte("seq")),
		After:     arbfinal.AfterState{BlockHash: crypto.Keccak256Hash(top), SendRoot: crypto.Keccak256Hash([]byte("send")), InboxPosition: 881475, MachineStatus: 1, EndHistoryRoot: crypto.Keccak256Hash([]byte("ehr"))},
		ParentCfg: arbfinal.ParentConfig{ConfirmPeriodBlocks: 20, NextInboxPosition: 881475}}
	a.Hash = arbfinal.AssertionHash(a.Parent, a.After, a.SeqAcc)
	w.assertion = a.Hash

	// L1: confirmation block K with a transaction list, a receipt list and the Rollup state; S above it.
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	key, _ := crypto.GenerateKey()
	var txs, rcs [][]byte
	for i := 0; i < 3; i++ {
		to, data := common.HexToAddress("0x00000000000000000000000000000000000000aa"), []byte{byte(i)}
		var logs []*types.Log
		if i == wTxIndex {
			to, data = synthworld.Rollup, synthworld.ConfirmCall(synthworld.SelConfirm)
			if wo != nil {
				to, data = wo.callee, synthworld.WalletInput(synthworld.SelWalletTx, [][]byte{synthworld.ConfirmCall(synthworld.SelConfirm)}, []common.Address{synthworld.Rollup})
			}
			logs = []*types.Log{{Address: synthworld.Rollup, Topics: []common.Hash{synthworld.TopicConfirm, a.Hash}, Data: make([]byte, 64)}}
		}
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: uint64(i), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: 500000, To: &to, Value: big.NewInt(0), Data: data}), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		tb, _ := tx.MarshalBinary()
		rb, _ := (&types.Receipt{Type: tx.Type(), Status: 1, CumulativeGasUsed: uint64(100000 * (i + 1)), Logs: logs}).MarshalBinary()
		txs, rcs = append(txs, tb), append(rcs, rb)
	}
	txTrie, rcTrie := trie.NewEmpty(nil), trie.NewEmpty(nil)
	for i := range txs {
		k, _ := rlp.EncodeToBytes(uint64(i))
		_ = txTrie.Update(k, txs[i])
		_ = rcTrie.Update(k, rcs[i])
	}
	st := buildState(a.Hash, a.Parent, a.ParentCfg, 2)
	if wo != nil && wo.proxyCode != nil {
		implWord := synthworld.WalletImplWord()
		if wo.implWord != nil {
			implWord = *wo.implWord
		}
		st.addAccount(wo.callee, *wo.proxyCode, map[common.Hash]common.Hash{synthworld.WalletImplSlot: implWord})
		if !wo.noImpl {
			st.addAccount(common.BytesToAddress(implWord[12:]), synthworld.WalletLogicCodeHash, nil)
		}
	}
	l1 := &fakeL1{head: wHead, headers: map[uint64][]byte{}, blocks: map[uint64]*L1Block{}, states: map[uint64]*stateT{wK: st, wK + 2: st}, proofErr: map[uint64]error{}}
	parent := crypto.Keccak256Hash([]byte("l1 parent"))
	for n := uint64(wK - 5); n <= wHead; n++ {
		state, tr, rr := crypto.Keccak256Hash([]byte(fmt.Sprint("st", n))), types.EmptyRootHash, types.EmptyRootHash
		if n == wK || n == wK+2 {
			state = st.root
		}
		if n == wK {
			tr, rr = txTrie.Hash(), rcTrie.Hash()
		}
		raw := hdr(parent, state, tr, rr, n, 1_790_000_000+n*12, make([]byte, 32))
		l1.headers[n] = raw
		parent = crypto.Keccak256Hash(raw)
	}
	l1.blocks[wK] = &L1Block{Number: wK, Hash: crypto.Keccak256Hash(l1.headers[wK]), HeaderRLP: l1.headers[wK], Txs: txs, Receipts: rcs}
	l1.logs = []Log{
		createdLog(a, wCreated),
		{Block: wK, BlockHash: l1.blocks[wK].Hash, TxHash: crypto.Keccak256Hash(txs[wTxIndex]), TxIndex: wTxIndex, Topics: []common.Hash{synthworld.TopicConfirm, a.Hash}},
	}
	w.l1 = l1
	lc, pinsRaw := synthworld.L1Head(crypto.Keccak256Hash(l1.headers[wFinalTop]))
	w.lc = &fakeLC{lc: lc}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	w.pins = pins
	w.p = &Prover{Pins: pins, L1: l1, L2: l2, LC: w.lc, Store: NewMemStore(), StateAhead: 2, LogChunk: 500}
	return w
}

func canon(err error) string {
	if s, ok := finality.AsNamed(err); ok {
		return string(s.Canonical())
	}
	return "ERR " + err.Error()
}

func (w *world) build(t *testing.T) (*finality.Addendum, *finality.PendingState, error) {
	t.Helper()
	return w.p.BuildLeg(context.Background(), w.leg, 0)
}

func wantPending(t *testing.T, p *finality.PendingState, err error, reason string) {
	t.Helper()
	if err != nil || p == nil {
		t.Fatalf("want pending %s, got pending %v err %v", reason, p, err)
	}
	if p.Reason != reason || p.Chain != finality.ChainArbitrumSepolia || p.NextLevel != finality.LevelFinalized || p.LevelReached != finality.LevelIncluded {
		t.Fatalf("pending = %s, want reason %s", p.State().Canonical(), reason)
	}
}

// ---- tests -----------------------------------------------------------------------------------------------------------------

func TestHappyPathBuildsAndVerifies(t *testing.T) {
	w := newWorld(t)
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("add %v pend %v err %v", add != nil, pend, canon(err))
	}
	if add.Kind != arbfinal.KindName || add.Level != finality.LevelFinalized || add.Chain != finality.ChainArbitrumSepolia {
		t.Fatalf("addendum %+v", add)
	}
	// the stored evidence is the verifier's own: judge it again, independently of the builder
	v, err := arbfinal.New().Verify(w.pins, w.leg, add.Evidence)
	if err != nil {
		t.Fatal(canon(err))
	}
	if v.Fields["assertion"] != [32]byte(w.assertion) || v.Fields["m"] != w.m || v.Fields["k_number"] != uint64(wK) || v.Fields["s_number"] != uint64(wK+2) {
		t.Fatalf("verdict fields %v", v.Fields)
	}
	// two state rows (S, K) and the confirmation row were captured
	if n := w.p.Store.(*MemStore).Len(); n != 3 {
		t.Fatalf("%d capture rows, want 3", n)
	}
}

func TestStoredCaptureServesALaterBuildOutsideTheProofWindow(t *testing.T) {
	w := newWorld(t)
	w.lc.err = errors.New("beacon down")
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingL1State) // captured, but the LC is not served yet
	calls := w.l1.calls
	if calls == 0 {
		t.Fatal("no proof was captured")
	}
	// the window closes: any further eth_getProof fails, the stored rows carry the attestation
	for _, b := range []uint64{wK, wK + 2} {
		w.l1.proofErr[b] = errors.New("distance to target block exceeds maximum proof window")
	}
	w.lc.err = nil
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("pend %v err %v", pend, canon(err))
	}
	if w.l1.calls != calls {
		t.Fatalf("eth_getProof called again (%d -> %d) although the capture was stored", calls, w.l1.calls)
	}
}

func TestPendingAwaitingCoveringAssertion(t *testing.T) {
	w := newWorld(t)
	var info map[string]any
	w.p.OnStatus = func(reason string, i map[string]any) { info = i }
	// a leg above the last assertion's end block
	hRaw := hdr(common.Hash{1}, common.Hash{}, common.Hash{}, common.Hash{}, w.m+10, 1, func() []byte { m := make([]byte, 32); binary.BigEndian.PutUint64(m[8:16], wCreated-300); return m }())
	hf, _ := finality.ReadHeader(hRaw)
	w.leg = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: w.m + 10, Hash: hf.Hash, HeaderRLP: hRaw}
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingCovering)
	if info["latest_assertion_end_block"] != w.m || info["l2_block"] != w.m+10 {
		t.Fatalf("status info %v", info)
	}
}

func TestPendingAwaitingAssertionConfirmation(t *testing.T) {
	w := newWorld(t)
	w.l1.logs = w.l1.logs[:1] // the created event only
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingConfirmation)
}

func TestPendingAwaitingL1FinalityOfConfirmation(t *testing.T) {
	w := newWorld(t)
	// the finalized head is below S: rebuild the LC around a header under K
	lc, pinsRaw := synthworld.L1Head(crypto.Keccak256Hash(w.l1.headers[wK-1]))
	w.lc.lc = lc
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	w.p.Pins = pins
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingL1Finality)
	if got := pend.State().Fields; len(got) != 4 {
		t.Fatalf("awaiting_l1_finality carries unregistered fields: %v", got)
	}
}

func TestProofWindowMissIsANamedStateNotAWeakerLevel(t *testing.T) {
	w := newWorld(t)
	w.l1.proofErr[wK] = errors.New("distance to target block exceeds maximum proof window")
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingProofWindow)
	f := pend.State().Fields
	if f["l1_block"] != uint64(wK) || fmt.Sprint(f["providers"]) != "[https://l1.example]" {
		t.Fatalf("fields %v", f)
	}
	if w.p.Store.(*MemStore).Len() != 0 {
		t.Fatal("a failed capture left rows behind")
	}
}

func TestAssertionHistoryUnavailable(t *testing.T) {
	w := newWorld(t)
	w.l1.logsErr = errors.New("query returned more than 10000 results")
	_, pend, err := w.build(t)
	s, ok := finality.AsNamed(err)
	if pend != nil || !ok || s.Code != arbfinal.CodeHistoryUnavailable {
		t.Fatalf("pend %v err %s", pend, canon(err))
	}
	if s.Fields["l1_from"] == nil || s.Fields["l1_to"] == nil || fmt.Sprint(s.Fields["providers"]) != "[https://l1.example]" {
		t.Fatalf("fields %v", s.Fields)
	}
}

func TestL2UnavailableStates(t *testing.T) {
	w := newWorld(t)
	w.l2.failAll = true
	_, _, err := w.build(t)
	if s, ok := finality.AsNamed(err); !ok || s.Code != arbfinal.CodeL2HeaderUnavail || s.Fields["block"] == nil {
		t.Fatalf("%s", canon(err))
	}
	w = newWorld(t)
	w.l2.failNum = map[uint64]bool{wLeg + 2: true}
	_, _, err = w.build(t)
	if s, ok := finality.AsNamed(err); !ok || s.Code != arbfinal.CodeL2HeadersUnavail || s.Fields["from"] != uint64(wLeg) || s.Fields["to"] != w.m {
		t.Fatalf("%s", canon(err))
	}
}

func TestHeaderChainBoundAndPreBold(t *testing.T) {
	w := newWorld(t)
	mix := make([]byte, 32)
	binary.BigEndian.PutUint64(mix[8:16], wCreated-300)
	far := w.m - 40000
	raw := hdr(common.Hash{1}, common.Hash{}, common.Hash{}, common.Hash{}, far, 1, mix)
	hf, _ := finality.ReadHeader(raw)
	w.leg = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: far, Hash: hf.Hash, HeaderRLP: raw}
	_, _, err := w.build(t)
	if s, ok := finality.AsNamed(err); !ok || s.Code != arbfinal.CodeHeaderChainExceeds || s.Fields["needed"] != uint64(40001) || s.Fields["max"] != uint64(32768) {
		t.Fatalf("%s", canon(err))
	}
	raw = hdr(common.Hash{1}, common.Hash{}, common.Hash{}, common.Hash{}, 105_880_604, 1, mix)
	hf, _ = finality.ReadHeader(raw)
	w.leg = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: 105_880_604, Hash: hf.Hash, HeaderRLP: raw}
	_, _, err = w.build(t)
	if s, ok := finality.AsNamed(err); !ok || s.Code != arbfinal.CodePreBold || s.Fields["n"] != uint64(105_880_604) {
		t.Fatalf("%s", canon(err))
	}
}

func TestOwnerForceConfirmationIsRefusedByTheVerifierNotBuilt(t *testing.T) {
	w := newWorld(t)
	// the confirmation transaction is a force-confirm: the builder returns the verifier's named state, never an addendum
	st := w.l1.blocks[wK]
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	key, _ := crypto.GenerateKey()
	to := synthworld.Rollup
	tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: 7, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: 500000, To: &to, Value: big.NewInt(0), Data: synthworld.ConfirmCall(synthworld.SelForce)}), signer, key)
	tb, _ := tx.MarshalBinary()
	rc := &types.Receipt{Type: tx.Type(), Status: 1, CumulativeGasUsed: 200000, Logs: []*types.Log{
		{Address: synthworld.Rollup, Topics: []common.Hash{synthworld.TopicConfirm, w.assertion}, Data: make([]byte, 64)},
		{Address: synthworld.Rollup, Topics: []common.Hash{synthworld.TopicForce, w.assertion}}}}
	rb, _ := rc.MarshalBinary()
	st.Txs[wTxIndex], st.Receipts[wTxIndex] = tb, rb
	txTrie, rcTrie := ethTrie(st.Txs), ethTrie(st.Receipts)
	hh, _ := finality.ReadHeader(st.HeaderRLP)
	raw := hdr(common.Hash(hh.ParentHash), common.Hash(hh.StateRoot), txTrie, rcTrie, hh.Number, hh.Timestamp, make([]byte, 32))
	// re-link the whole L1 chain above K onto the edited header and re-anchor the LC
	w.l1.headers[wK] = raw
	st.HeaderRLP, st.Hash = raw, crypto.Keccak256Hash(raw)
	parent := crypto.Keccak256Hash(raw)
	for n := uint64(wK + 1); n <= wHead; n++ {
		h, _ := finality.ReadHeader(w.l1.headers[n])
		nr := hdr(parent, common.Hash(h.StateRoot), common.Hash(h.TransactionRoot), common.Hash(h.ReceiptsRoot), n, h.Timestamp, make([]byte, 32))
		w.l1.headers[n] = nr
		parent = crypto.Keccak256Hash(nr)
	}
	lc, pinsRaw := synthworld.L1Head(crypto.Keccak256Hash(w.l1.headers[wFinalTop]))
	w.lc.lc = lc
	w.p.Pins, _ = finality.ParsePinsOverride(pinsRaw)
	w.l1.logs[1].TxHash = crypto.Keccak256Hash(tb)
	add, pend, err := w.build(t)
	s, ok := finality.AsNamed(err)
	if add != nil || pend != nil || !ok || s.Code != arbfinal.CodeConfirmedByOwner || s.Fields["path"] != arbfinal.PathForce {
		t.Fatalf("add %v pend %v err %s", add != nil, pend, canon(err))
	}
}

func ethTrie(vals [][]byte) common.Hash {
	t := trie.NewEmpty(nil)
	for i, v := range vals {
		k, _ := rlp.EncodeToBytes(uint64(i))
		_ = t.Update(k, v)
	}
	return t.Hash()
}

func TestTheFinalityProverContract(t *testing.T) {
	w := newWorld(t)
	var _ finality.Prover = w.p
	if w.p.Chain() != finality.ChainArbitrumSepolia || w.p.Ceiling() != finality.LevelFinalized {
		t.Fatal("chain or ceiling")
	}
	// l1_posted is the sibling prover's level: "not mine" is (nil, nil, nil), never a refusal the upgrader would keep as the leg's status
	if a, pd, err := w.p.Build(context.Background(), nil, 0, finality.LevelL1Posted); a != nil || pd != nil || err != nil {
		t.Fatalf("a level this prover does not serve was answered: %v %v %v", a, pd, err)
	}
	_, _, err := w.p.Build(context.Background(), nil, finality.LevelSetOf(finality.LevelFinalized), finality.LevelFinalized)
	if s, ok := finality.AsNamed(err); !ok || s.Code != finality.CodeLevelAlreadyPresent {
		t.Fatalf("%s", canon(err))
	}
}

func TestDecodeCreatedRecomputesTheAssertionHash(t *testing.T) {
	a := Assertion{Parent: crypto.Keccak256Hash([]byte("p")), SeqAcc: crypto.Keccak256Hash([]byte("s")),
		After:     arbfinal.AfterState{BlockHash: crypto.Keccak256Hash([]byte("b")), InboxPosition: 5, MachineStatus: 1},
		ParentCfg: arbfinal.ParentConfig{ConfirmPeriodBlocks: 20, NextInboxPosition: 9}}
	a.Hash = arbfinal.AssertionHash(a.Parent, a.After, a.SeqAcc)
	l := createdLog(a, 10)
	got, err := DecodeCreated(l)
	if err != nil || got.Hash != a.Hash || got.ParentCfg != a.ParentCfg || got.After != a.After || got.SeqAcc != a.SeqAcc {
		t.Fatalf("%+v %v", got, err)
	}
	for _, w := range []int{13, 15, 19, 5} { // blockHash, inboxPosition, sequencerBatchAcc: the preimage; confirmPeriod is not
		l2 := l
		l2.Data = append([]byte(nil), l.Data...)
		l2.Data[32*w+31] ^= 1
		_, err := DecodeCreated(l2)
		if (w != 5) == (err == nil) {
			t.Fatalf("word %d altered: err %v", w, err)
		}
	}
	short := l
	short.Data = l.Data[:len(l.Data)-1]
	if _, err := DecodeCreated(short); err == nil {
		t.Fatal("short data decoded")
	}
}

func TestMemStoreIsInsertOnly(t *testing.T) {
	s := NewMemStore()
	h := [32]byte{1}
	if err := s.Put(context.Background(), finality.CaptureKey{Chain: 1, L1Block: 2, L1Hash: h, Item: "a"}, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), finality.CaptureKey{Chain: 1, L1Block: 2, L1Hash: h, Item: "a"}, []byte{1}); err != nil {
		t.Fatal("the same bytes may be written again")
	}
	if err := s.Put(context.Background(), finality.CaptureKey{Chain: 1, L1Block: 2, L1Hash: h, Item: "a"}, []byte{2}); err == nil {
		t.Fatal("different bytes under one key must be refused")
	}
	if _, ok, _ := s.Get(context.Background(), finality.CaptureKey{Chain: 1, L1Block: 2, L1Hash: [32]byte{2}, Item: "a"}); ok {
		t.Fatal("a Get names the hash: another hash has no row")
	}
}

// A secret in a provider's answer or URL never reaches an error or a provider label.
func TestProviderTextIsRedacted(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "upstream https://backend.internal.example/v3/%s refused", secret)
	}))
	defer srv.Close()
	ep := srv.URL + "/v3/" + secret
	l1 := &LiveL1{Endpoints: []string{ep}, ProofEndpoints: []string{ep}}
	l2 := &LiveL2{Endpoints: []string{ep}}
	var errs []error
	_, e := l1.Head(context.Background())
	errs = append(errs, e)
	_, e = l1.Logs(context.Background(), common.Address{}, nil, 1, 2)
	errs = append(errs, e)
	_, e = l1.Proof(context.Background(), common.Address{}, nil, 1)
	errs = append(errs, e)
	_, e = l2.HeaderByNumber(context.Background(), 1)
	errs = append(errs, e)
	_, e = (&BeaconLC{Beacon: srv.URL + "/" + secret}).LC(context.Background())
	errs = append(errs, e)
	for i, e := range errs {
		if e == nil || strings.Contains(e.Error(), secret) {
			t.Fatalf("error %d leaks or is nil: %v", i, e)
		}
	}
	for _, p := range append(l1.Providers(), l2.Providers()...) {
		if strings.Contains(p, secret) || strings.Contains(p, "/v3") {
			t.Fatalf("provider label %q leaks the endpoint path", p)
		}
	}
	// a state built from the failing source carries labels only
	w := newWorld(t)
	w.p.L1 = &failingLogsL1{fakeL1: w.l1, real: l1}
	_, _, err := w.build(t)
	if err == nil || strings.Contains(canon(err), secret) {
		t.Fatalf("state leaks: %v", canon(err))
	}
}

type failingLogsL1 struct {
	*fakeL1
	real *LiveL1
}

func (f *failingLogsL1) Providers() []string { return f.real.Providers() }
func (f *failingLogsL1) Logs(ctx context.Context, a common.Address, t [][]common.Hash, from, to uint64) ([]Log, error) {
	return f.real.Logs(ctx, a, t, from, to)
}

func TestHeaderRLPFromJSONChecksTheHash(t *testing.T) {
	raw := hdr(common.Hash{1}, common.Hash{2}, common.Hash{3}, common.Hash{4}, 77, 88, make([]byte, 32))
	h := crypto.Keccak256Hash(raw)
	m := map[string]any{
		"parentHash": common.Hash{1}.Hex(), "sha3Uncles": "0x" + strings.Repeat("1d", 32), "miner": "0x" + strings.Repeat("00", 20), "stateRoot": common.Hash{2}.Hex(),
		"transactionsRoot": common.Hash{3}.Hex(), "receiptsRoot": common.Hash{4}.Hex(), "logsBloom": "0x" + strings.Repeat("00", 256), "difficulty": "0x0",
		"number": "0x4d", "gasLimit": "0x1c9c380", "gasUsed": "0x1", "timestamp": "0x58", "extraData": "0x78", "mixHash": "0x" + strings.Repeat("00", 32), "nonce": "0x0000000000000000",
		"hash": h.Hex(),
	}
	got, gh, err := HeaderRLPFromJSON(m)
	if err != nil || !bytes.Equal(got, raw) || gh != h {
		t.Fatalf("%v %x", err, gh[:4])
	}
	m["gasUsed"] = "0x2"
	if _, _, err := HeaderRLPFromJSON(m); err == nil {
		t.Fatal("a header that does not hash to the stated hash was accepted")
	}
}

// A public provider rate-limits bursts: 429 and gateway errors are retried with backoff, never turned into a state at once.
func TestRateLimitIsRetriedWithBackoff(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"Too Many Requests"}`)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":"0x10"}`)
	}))
	defer srv.Close()
	l1 := &LiveL1{Endpoints: []string{srv.URL}}
	got, err := l1.Head(context.Background())
	if err != nil || got != 16 || n != 3 {
		t.Fatalf("head %d after %d requests: %v", got, n, err)
	}
	// a persistent 429 ends as an error after the retries, with the provider label only
	n = -100
	if _, err := l1.Head(context.Background()); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("persistent rate limit: %v", err)
	}
}

// ---- the wallet route: the builder captures the proofs ProveWallet reads (RB12-E1RAISE) --------------------------------------------

var walletCallee = common.HexToAddress("0x000000000000000000000000000000000000beef")

func provenWallet() *walletOpts {
	return &walletOpts{callee: walletCallee, proxyCode: &synthworld.WalletProxyCodeHash}
}

func routeOf(t *testing.T, w *world, add *finality.Addendum) string {
	t.Helper()
	v, err := arbfinal.New().Verify(w.pins, w.leg, add.Evidence)
	if err != nil {
		t.Fatal(canon(err))
	}
	r, _ := v.Fields["confirmation_route"].(string)
	return r
}

func TestAWalletRouteConfirmationIsBuiltWithItsIdentityProofs(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("add %v pend %v err %v", add != nil, pend, canon(err))
	}
	if got := routeOf(t, w, add); got != "wallet" {
		t.Fatalf("route %q, want wallet", got)
	}
	// state rows at S and K, the confirmation row and the wallet row
	if n := w.p.Store.(*MemStore).Len(); n != 4 {
		t.Fatalf("%d capture rows, want 4", n)
	}
	var asked []common.Address
	for _, a := range w.l1.proofAddrs {
		if a == walletCallee || a == synthworld.WalletImpl {
			asked = append(asked, a)
		}
	}
	if len(asked) != 2 || asked[0] != walletCallee || asked[1] != synthworld.WalletImpl {
		t.Fatalf("wallet proofs asked for %v, want the callee then the implementation, once each", asked)
	}
}

func TestADirectConfirmationCapturesNoWalletProof(t *testing.T) {
	w := newWorld(t)
	if _, _, err := w.build(t); err != nil {
		t.Fatal(canon(err))
	}
	for _, a := range w.l1.proofAddrs {
		if a == walletCallee || a == synthworld.WalletImpl {
			t.Fatalf("a direct confirmation asked for the proof of %s", a)
		}
	}
	if n := w.p.Store.(*MemStore).Len(); n != 3 {
		t.Fatalf("%d capture rows, want 3 (no wallet row)", n)
	}
}

func TestAStoredWalletCaptureServesALaterBuildOutsideTheProofWindow(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	w.lc.err = errors.New("beacon down")
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingL1State)
	calls := w.l1.calls
	for _, b := range []uint64{wK, wK + 2} {
		w.l1.proofErr[b] = errors.New("distance to target block exceeds maximum proof window")
	}
	w.lc.err = nil
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("pend %v err %v", pend, canon(err))
	}
	if w.l1.calls != calls {
		t.Fatalf("eth_getProof called again (%d -> %d) although the wallet capture was stored", calls, w.l1.calls)
	}
	if got := routeOf(t, w, add); got != "wallet" {
		t.Fatalf("route %q", got)
	}
}

func TestAnEarlierConfirmationRowWithoutWalletProofsGetsThemFromTheProvider(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	if _, _, err := w.build(t); err != nil {
		t.Fatal(canon(err))
	}
	// the store of an earlier build: the state rows and the confirmation row, no wallet row (insert-only rows cannot be extended)
	old := NewMemStore()
	ctx := context.Background()
	for _, x := range []uint64{wK, wK + 2} {
		hf, _ := finality.ReadHeader(w.l1.headers[x])
		for _, item := range []string{captureItemState, captureItemConf} {
			if x != wK && item == captureItemConf {
				continue
			}
			key := finality.CaptureKey{Chain: finality.ChainSepolia, L1Block: x, L1Hash: hf.Hash, Item: item + hex.EncodeToString(w.assertion[:])}
			b, ok, err := w.p.Store.Get(ctx, key)
			if err != nil || !ok {
				t.Fatalf("row %s at %d: %v %v", item, x, ok, err)
			}
			if err := old.Put(ctx, key, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	w.p.Store = old
	w.l1.proofAddrs = nil
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("pend %v err %v", pend, canon(err))
	}
	if got := routeOf(t, w, add); got != "wallet" {
		t.Fatalf("route %q", got)
	}
	if n := old.Len(); n != 4 {
		t.Fatalf("%d capture rows, want 4 (the wallet row was added)", n)
	}
	if len(w.l1.proofAddrs) != 2 {
		t.Fatalf("only the callee and the implementation were to be asked, got %v", w.l1.proofAddrs)
	}
}

func TestWalletProofsThatTheProviderCannotServeAreANamedStateAndResume(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	w.l1.proofErrAddr = map[common.Address]error{walletCallee: errors.New("distance to target block exceeds maximum proof window")}
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingProofWindow)
	if pend.Judged["l1_block"] != uint64(wK) {
		t.Fatalf("judged %v", pend.Judged)
	}
	if n := w.p.Store.(*MemStore).Len(); n != 3 {
		t.Fatalf("%d capture rows, want 3 (state S, state K, confirmation; no wallet row)", n)
	}
	// the provider recovers: the same store resumes and builds
	w.l1.proofErrAddr = nil
	add, pend, err := w.build(t)
	if err != nil || pend != nil || add == nil {
		t.Fatalf("pend %v err %v", pend, canon(err))
	}
	if got := routeOf(t, w, add); got != "wallet" {
		t.Fatalf("route %q", got)
	}
}

func TestAnImplementationProofTheProviderCannotServeIsANamedState(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	w.l1.proofErrAddr = map[common.Address]error{synthworld.WalletImpl: errors.New("distance to target block exceeds maximum proof window")}
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingProofWindow)
}

// A callee that is not a wallet needs nothing beyond its own account proof and slot proof: the builder does not chase the implementation
// it names, and the verifier's own verdict (confirmation_path_unproven{indirect}, judged at K) is what the build returns.
func TestACalleeThatIsNotAWalletIsRefusedByTheVerifierAndNoImplementationIsChased(t *testing.T) {
	other := common.BytesToHash(append(make([]byte, 12), common.HexToAddress("0x00000000000000000000000000000000000000dd").Bytes()...))
	for name, wo := range map[string]*walletOpts{
		"no account":             {callee: walletCallee},
		"another contract":       {callee: walletCallee, proxyCode: ptrHash(crypto.Keccak256Hash([]byte("another contract")))},
		"proxy over another one": {callee: walletCallee, proxyCode: &synthworld.WalletProxyCodeHash, implWord: &other},
	} {
		w := newWorldWith(t, wo)
		_, pend, err := w.build(t)
		if pend != nil || err == nil {
			t.Fatalf("%s: pend %v err %v", name, pend, err)
		}
		s, ok := finality.AsNamed(err)
		if !ok || s.Code != arbfinal.CodeConfirmationUnproof || s.Fields["reason"] != arbfinal.ConfirmIndirect || s.Fields["l1_block"] != uint64(wK) {
			t.Fatalf("%s: %s", name, canon(err))
		}
		for _, a := range w.l1.proofAddrs {
			if a == synthworld.WalletImpl || a == common.BytesToAddress(other[12:]) {
				t.Fatalf("%s: the implementation %s was asked for", name, a)
			}
		}
	}
}

func ptrHash(h common.Hash) *common.Hash { return &h }

// The capture row names are stored in proof_finality_capture.item, which the table limits to varchar(160) matching
// ^[a-z0-9_-]+(/[a-z0-9_-]+)*$ (db/migrations/00028): every item name the builder uses fits, with a real 32-byte assertion hash.
func TestEveryCaptureItemNameFitsTheTable(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9_-]+(/[a-z0-9_-]+)*$`)
	h := crypto.Keccak256Hash([]byte("an assertion"))
	for _, prefix := range []string{captureItemState, captureItemConf, captureItemWallet} {
		item := prefix + hex.EncodeToString(h[:])
		if len(item) > 160 || !re.MatchString(item) {
			t.Errorf("%q does not fit proof_finality_capture.item", item)
		}
	}
	if captureItemWallet == captureItemConf || captureItemWallet == captureItemState {
		t.Fatal("the wallet row must not share a name with another row")
	}
}

// ---- a provider answer that is no proof, a store that fails, bytes that are no transaction -------------------------------------------

func TestAWalletAccountProofThatDoesNotVerifyIsNotCapturedAndIsANamedState(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	w.l1.proofCorrupt = map[common.Address]string{walletCallee: "account"}
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingProofWindow)
	if n := w.p.Store.(*MemStore).Len(); n != 3 {
		t.Fatalf("%d capture rows, want 3 (nothing of the bad answer is kept)", n)
	}
	w.l1.proofCorrupt = nil
	if add, pend, err := w.build(t); err != nil || pend != nil || add == nil {
		t.Fatalf("resume: pend %v err %v", pend, canon(err))
	}
}

func TestAnImplementationSlotProofThatDoesNotVerifyIsNotCapturedAndIsANamedState(t *testing.T) {
	w := newWorldWith(t, provenWallet())
	w.l1.proofCorrupt = map[common.Address]string{walletCallee: "slot"}
	_, pend, err := w.build(t)
	wantPending(t, pend, err, PendingProofWindow)
	if n := w.p.Store.(*MemStore).Len(); n != 3 {
		t.Fatalf("%d capture rows, want 3", n)
	}
}

// failingStore refuses to keep one kind of row.
type failingStore struct {
	finality.CaptureStore
	prefix string
}

func (s failingStore) Put(ctx context.Context, k finality.CaptureKey, v []byte) error {
	if strings.HasPrefix(k.Item, s.prefix) {
		return errors.New("disk full for " + k.Item)
	}
	return s.CaptureStore.Put(ctx, k, v)
}

// Bytes that are no transaction have no callee: nothing is asked of the provider and nothing is kept (the verifier refuses the bytes).
func TestBytesThatAreNoTransactionNeedNoWalletProof(t *testing.T) {
	w := newWorld(t)
	arb, err := arbfinal.LoadPins(w.pins)
	if err != nil {
		t.Fatal(err)
	}
	kf, _ := finality.ReadHeader(w.l1.headers[wK])
	a := &Assertion{Hash: w.assertion}
	for _, raw := range [][]byte{nil, {}, {0x02}, {0x02, 0xc0}, bytes.Repeat([]byte{0xff}, 40)} {
		ns, pend, err := w.p.walletProofs(context.Background(), arb, a, wK, kf, raw, 0)
		if ns != nil || pend != nil || err != nil {
			t.Errorf("%x: nodes %d pend %v err %v", raw, len(ns), pend, err)
		}
	}
	if len(w.l1.proofAddrs) != 0 || w.p.Store.(*MemStore).Len() != 0 {
		t.Fatalf("asked %v, kept %d rows", w.l1.proofAddrs, w.p.Store.(*MemStore).Len())
	}
}
