// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// A synthetic chain for the S6 replay-guard tests: real Merkle-Patricia state tries (account and storage), real headers
// linked by parentHash, a real settlement (transaction and receipt proven in the block) - every byte a verifier checks is
// produced by the same encodings the chains use.

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

type account struct {
	addr    common.Address
	code    []byte
	storage map[common.Hash]*big.Int
}

type accountLeaf struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// state is a built state trie: its root, and the means to prove any account and slot against it.
type state struct {
	t     *testing.T
	root  common.Hash
	trie  *trie.Trie
	accts map[common.Address]*builtAccount
}

type builtAccount struct {
	account
	sto  *trie.Trie
	root common.Hash
}

func buildState(t *testing.T, accts ...account) *state {
	t.Helper()
	st := &state{t: t, trie: trie.NewEmpty(nil), accts: map[common.Address]*builtAccount{}}
	for _, a := range accts {
		sto := trie.NewEmpty(nil)
		for slot, v := range a.storage {
			trimmed := common.TrimLeftZeroes(common.BigToHash(v).Bytes())
			enc, _ := rlp.EncodeToBytes(trimmed)
			if err := sto.Update(crypto.Keccak256(slot.Bytes()), enc); err != nil {
				t.Fatal(err)
			}
		}
		b := &builtAccount{account: a, sto: sto, root: sto.Hash()}
		st.accts[a.addr] = b
		enc, err := rlp.EncodeToBytes(&accountLeaf{Nonce: 1, Balance: big.NewInt(7), Root: b.root, CodeHash: crypto.Keccak256(a.code)})
		if err != nil {
			t.Fatal(err)
		}
		if err := st.trie.Update(crypto.Keccak256(a.addr.Bytes()), enc); err != nil {
			t.Fatal(err)
		}
	}
	st.root = st.trie.Hash()
	return st
}

func nodesOf(in [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

// prove is eth_getProof for one slot, as a SlotProof.
func (s *state) prove(addr common.Address, slot common.Hash) ethproof.SlotProof {
	s.t.Helper()
	var acc collector
	if err := s.trie.Prove(crypto.Keccak256(addr.Bytes()), &acc); err != nil {
		s.t.Fatal(err)
	}
	sp := ethproof.SlotProof{AccountProof: nodesOf(acc.nodes)}
	b, ok := s.accts[addr]
	if !ok {
		sp.AccountAbsent = true
		sp.StorageProof = []hexutil.Bytes{}
		return sp
	}
	var sto collector
	if err := b.sto.Prove(crypto.Keccak256(slot.Bytes()), &sto); err != nil {
		s.t.Fatal(err)
	}
	sp.StorageHash, sp.CodeHash = b.root, crypto.Keccak256Hash(b.code)
	sp.StorageProof = nodesOf(sto.nodes)
	if v, ok := b.storage[slot]; ok {
		sp.Value = common.BigToHash(v)
	}
	return sp
}

var (
	testContract = common.HexToAddress("0xb4Ea0cDA7b4755751293cb6d9b8D6027E05077BA")
	testOther    = common.HexToAddress("0x057fC30274d1AB39DC1EF51a84CF995c9b8c50f2")
	testCode     = []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57}
	testAnchor   = common.HexToHash("0xf9d80b95795768f2d29bf69d41cd2c3ac4ce8f5ed0e1d3fa08cc6d4b2d7a5d3b")
	testLeaf     = common.HexToHash("0x11d861d3506473d80b34fbb0ab1ff2c680efafa2132cbe3e0ac4a442f3c5b0bb")
	testOpID     = common.HexToHash("0x8c0f5e4b1a2d3c4e5f60718293a4b5c6d7e8f9011223344556677889900aabbc")
	v73Execute   = []byte{0x60, 0x6f, 0x2c, 0x8d}
	v73Batch     = []byte{0x32, 0x9f, 0xe0, 0x12}
)

const testChainID = 84532
const testN = 5000

// world is one settlement and the chain around it.
type world struct {
	t          *testing.T
	contract   common.Address
	leaf, slot common.Hash
	settlement *ethproof.Settlement
	headerN    *types.Header
	parent     *types.Header
	tx         *types.Transaction
	receipt    *types.Receipt
	chain      []*types.Header // N+1 .. H
	before     *state
	after      *state
	proof      *ethproof.ReplayGuardProof
}

type worldOpts struct {
	after       int // headers after the settlement block
	selector    []byte
	to          *common.Address // the transaction's target (default the contract)
	eventFrom   *common.Address // the LeafConsumed emitter (default the contract)
	reverted    bool            // the receipt is status 0
	noBeforeAcc bool            // the contract is not yet in the parent's state
}

func newWorld(t *testing.T, o worldOpts) *world {
	t.Helper()
	w := &world{t: t, contract: testContract, leaf: testLeaf}
	w.slot = ethproof.ReplaySlotFor(w.leaf, 4)
	one := big.NewInt(1)
	others := map[common.Hash]*big.Int{
		common.BigToHash(big.NewInt(3)):                       big.NewInt(9),
		ethproof.ReplaySlotFor(common.HexToHash("0x3039"), 4): one, // another consumed leaf
	}
	cp := func(m map[common.Hash]*big.Int, extra map[common.Hash]*big.Int) map[common.Hash]*big.Int {
		out := map[common.Hash]*big.Int{}
		for k, v := range m {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	eoa := account{addr: testOther}
	beforeAccts := []account{eoa, {addr: w.contract, code: testCode, storage: cp(others, nil)}}
	if o.noBeforeAcc {
		beforeAccts = []account{eoa}
	}
	w.before = buildState(t, beforeAccts...)
	w.after = buildState(t, eoa, account{addr: w.contract, code: testCode, storage: cp(others, map[common.Hash]*big.Int{w.slot: one})})

	// The settlement: one transaction to the account, one receipt holding the account's LeafConsumed.
	sel := o.selector
	if sel == nil {
		sel = v73Execute
	}
	to := w.contract
	if o.to != nil {
		to = *o.to
	}
	w.tx = types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(testChainID), Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 500000, To: &to, Value: big.NewInt(0), Data: append(append([]byte(nil), sel...), make([]byte, 64)...)})
	emitter := w.contract
	if o.eventFrom != nil {
		emitter = *o.eventFrom
	}
	status := uint64(1)
	if o.reverted {
		status = 0
	}
	w.receipt = &types.Receipt{Type: w.tx.Type(), Status: status, CumulativeGasUsed: 123456, Logs: []*types.Log{
		{Address: common.HexToAddress("0xfab62e84c8e2b9b4f1cb0b4ea8a6f1b8e3d05a11"), Topics: []common.Hash{common.HexToHash("0x01")}, Data: []byte{1}},
		{Address: emitter, Topics: []common.Hash{ethproof.LeafConsumedTopic, testAnchor, w.leaf}, Data: testOpID[:]},
	}}
	w.receipt.Bloom = types.CreateBloom(w.receipt)
	txEnc, err := w.tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	rcEnc, err := w.receipt.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	w.parent = &types.Header{ParentHash: common.HexToHash("0xaa"), Number: big.NewInt(testN - 1), Root: w.before.root, Difficulty: big.NewInt(0),
		GasLimit: 30000000, Time: 1700000000, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, BaseFee: big.NewInt(7)}
	w.headerN = &types.Header{ParentHash: w.parent.Hash(), Number: big.NewInt(testN), Root: w.after.root, Difficulty: big.NewInt(0),
		GasLimit: 30000000, Time: 1700000002, TxHash: ethproof.TrieRoot([][]byte{txEnc}), ReceiptHash: ethproof.TrieRoot([][]byte{rcEnc}), BaseFee: big.NewInt(7)}
	block := &ethproof.Block{Header: w.headerN, Txs: [][]byte{txEnc}, Receipts: [][]byte{rcEnc}}
	w.settlement, err = block.Prove(w.tx.Hash(), 0)
	if err != nil {
		t.Fatal(err)
	}
	prev := w.headerN
	for i := 1; i <= o.after; i++ {
		h := &types.Header{ParentHash: prev.Hash(), Number: big.NewInt(int64(testN + i)), Root: w.after.root, Difficulty: big.NewInt(0),
			GasLimit: 30000000, Time: 1700000002 + uint64(2*i), TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, BaseFee: big.NewInt(7)}
		w.chain = append(w.chain, h)
		prev = h
	}
	w.proof = w.buildProof(prev)
	return w
}

func rawHeader(t *testing.T, h *types.Header) hexutil.Bytes {
	t.Helper()
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (w *world) buildProof(top *types.Header) *ethproof.ReplayGuardProof {
	p := &ethproof.ReplayGuardProof{
		Version: ethproof.ReplayGuardDomain, ChainID: testChainID, Generation: ethproof.AccountGenerationV7_3, Contract: w.contract,
		Slot:            ethproof.ReplaySlot{Key: w.leaf, Base: 4, Derivation: ethproof.ReplayDerivation, Slot: w.slot},
		SettlementBlock: ethproof.BlockRef{Number: testN, Hash: w.headerN.Hash()},
		ProvenAt:        ethproof.BlockRef{Number: top.Number.Uint64(), Hash: top.Hash()},
		Headers:         []hexutil.Bytes{},
		After:           w.after.prove(w.contract, w.slot),
		Before:          &ethproof.ReplayBefore{ParentHeader: rawHeader(w.t, w.parent), Proof: w.before.prove(w.contract, w.slot)},
	}
	for _, h := range w.chain {
		p.Headers = append(p.Headers, rawHeader(w.t, h))
	}
	return p
}

// clone is a deep copy of the proof, through its JSON.
func (w *world) clone() *ethproof.ReplayGuardProof {
	w.t.Helper()
	enc, err := json.Marshal(w.proof)
	if err != nil {
		w.t.Fatal(err)
	}
	var out ethproof.ReplayGuardProof
	if err := json.Unmarshal(enc, &out); err != nil {
		w.t.Fatal(err)
	}
	return &out
}

// refusedAs requires err to be the named refusal.
func refusedAs(t *testing.T, what string, err error, state, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: verified, but must be refused as %s{%s}", what, state, reason)
	}
	var re *ethproof.ReplayError
	if !asReplayError(err, &re) {
		t.Fatalf("%s: refused, but not by a named state: %v", what, err)
	}
	if re.State != state || re.Reason != reason {
		t.Fatalf("%s: refused as %s{%s}, want %s{%s}: %s", what, re.State, re.Reason, state, reason, re.Detail)
	}
}

func asReplayError(err error, target **ethproof.ReplayError) bool { return errors.As(err, target) }
