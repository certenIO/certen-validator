// Copyright 2026 Certen Protocol

// Package replayworld builds a synthetic chain for the S6 replay-guard evidence: real Merkle-Patricia state tries
// (account and storage), real headers linked by parentHash, a real settlement (transaction and receipt proven in the
// block) - every byte a verifier checks is produced by the same encodings the chains use. It is deterministic: the same
// options give the same bytes. The pkg/ethproof tests and the conformance-vector generator (cmd/s6replayvectors) build
// on it.
package replayworld

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// TB is what the builder needs of a test (testing.T satisfies it; the generator passes one that panics).
type TB interface {
	Helper()
	Fatal(args ...interface{})
}

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

// Account is one account of a built state.
type Account struct {
	Addr    common.Address
	Code    []byte
	Storage map[common.Hash]*big.Int
}

type accountLeaf struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// State is a built state trie: its root, and the means to prove any account and slot against it.
type State struct {
	tb    TB
	Root  common.Hash
	trie  *trie.Trie
	accts map[common.Address]*builtAccount
}

type builtAccount struct {
	Account
	sto  *trie.Trie
	root common.Hash
}

// BuildState builds the state trie of the accounts.
func BuildState(tb TB, accts ...Account) *State {
	tb.Helper()
	st := &State{tb: tb, trie: trie.NewEmpty(nil), accts: map[common.Address]*builtAccount{}}
	for _, a := range accts {
		sto := trie.NewEmpty(nil)
		for slot, v := range a.Storage {
			trimmed := common.TrimLeftZeroes(common.BigToHash(v).Bytes())
			enc, _ := rlp.EncodeToBytes(trimmed)
			if err := sto.Update(crypto.Keccak256(slot.Bytes()), enc); err != nil {
				tb.Fatal(err)
			}
		}
		b := &builtAccount{Account: a, sto: sto, root: sto.Hash()}
		st.accts[a.Addr] = b
		enc, err := rlp.EncodeToBytes(&accountLeaf{Nonce: 1, Balance: big.NewInt(7), Root: b.root, CodeHash: crypto.Keccak256(a.Code)})
		if err != nil {
			tb.Fatal(err)
		}
		if err := st.trie.Update(crypto.Keccak256(a.Addr.Bytes()), enc); err != nil {
			tb.Fatal(err)
		}
	}
	st.Root = st.trie.Hash()
	return st
}

// NodesOf is a node list as the wire carries it.
func NodesOf(in [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

// Prove is eth_getProof for one slot, as a SlotProof.
func (s *State) Prove(addr common.Address, slot common.Hash) ethproof.SlotProof {
	s.tb.Helper()
	var acc collector
	if err := s.trie.Prove(crypto.Keccak256(addr.Bytes()), &acc); err != nil {
		s.tb.Fatal(err)
	}
	sp := ethproof.SlotProof{AccountProof: NodesOf(acc.nodes)}
	b, ok := s.accts[addr]
	if !ok {
		sp.AccountAbsent = true
		sp.StorageProof = []hexutil.Bytes{}
		return sp
	}
	var sto collector
	if err := b.sto.Prove(crypto.Keccak256(slot.Bytes()), &sto); err != nil {
		s.tb.Fatal(err)
	}
	sp.StorageHash, sp.CodeHash = b.root, crypto.Keccak256Hash(b.Code)
	sp.StorageProof = NodesOf(sto.nodes)
	if v, ok := b.Storage[slot]; ok {
		sp.Value = common.BigToHash(v)
	}
	return sp
}

// The fixed facts of the synthetic world (the Base Sepolia settlement of R10 M4 lends its addresses and topics).
var (
	Contract   = common.HexToAddress("0xb4Ea0cDA7b4755751293cb6d9b8D6027E05077BA")
	Other      = common.HexToAddress("0x057fC30274d1AB39DC1EF51a84CF995c9b8c50f2")
	Code       = []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x61, 0x00, 0x10, 0x57}
	OtherCode  = []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x00}
	Anchor     = common.HexToHash("0xf9d80b95795768f2d29bf69d41cd2c3ac4ce8f5ed0e1d3fa08cc6d4b2d7a5d3b")
	Leaf       = common.HexToHash("0x11d861d3506473d80b34fbb0ab1ff2c680efafa2132cbe3e0ac4a442f3c5b0bb")
	OtherLeaf  = common.HexToHash("0x3039")
	OpID       = common.HexToHash("0x8c0f5e4b1a2d3c4e5f60718293a4b5c6d7e8f9011223344556677889900aabbc")
	V73Execute = []byte{0x60, 0x6f, 0x2c, 0x8d}
	V73Batch   = []byte{0x32, 0x9f, 0xe0, 0x12}
	V72Execute = []byte{0x57, 0xf8, 0x56, 0x7d}
)

// ChainID and N are the chain and the settlement block number of the world.
const (
	ChainID = 84532
	N       = 5000
)

// World is one settlement and the chain around it.
type World struct {
	TB         TB
	Contract   common.Address
	Leaf, Slot common.Hash
	Settlement *ethproof.Settlement
	HeaderN    *types.Header
	Parent     *types.Header
	Tx         *types.Transaction
	Receipt    *types.Receipt
	Chain      []*types.Header // N+1 .. H
	Before     *State
	After      *State
	Proof      *ethproof.ReplayGuardProof
}

// Opts shape the world.
type Opts struct {
	After       int // headers after the settlement block
	Selector    []byte
	NoCalldata  bool            // the transaction carries no calldata at all
	To          *common.Address // the transaction's target (default the contract)
	EventFrom   *common.Address // the LeafConsumed emitter (default the contract)
	Reverted    bool            // the receipt is status 0
	NoBeforeAcc bool            // the contract is not yet in the parent's state
	// BeforeValue, when set, is the slot's value in the parent's state (default unset: 0).
	BeforeValue *big.Int
	// AfterValue, when set, is the slot's value in the settlement block's state (default 1; 0 leaves it unset).
	AfterValue *big.Int
	// AfterCode / BeforeCode replace the contract's code in that state (an empty non-nil slice: no code).
	AfterCode  []byte
	BeforeCode []byte
}

func copyStorage(m map[common.Hash]*big.Int, extra map[common.Hash]*big.Int) map[common.Hash]*big.Int {
	out := map[common.Hash]*big.Int{}
	for k, v := range m {
		out[k] = v
	}
	for k, v := range extra {
		if v.Sign() == 0 {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

// New builds a world.
func New(tb TB, o Opts) *World {
	tb.Helper()
	w := &World{TB: tb, Contract: Contract, Leaf: Leaf}
	w.Slot = ethproof.ReplaySlotFor(w.Leaf, 4)
	one := big.NewInt(1)
	others := map[common.Hash]*big.Int{
		common.BigToHash(big.NewInt(3)):      big.NewInt(9),
		ethproof.ReplaySlotFor(OtherLeaf, 4): one, // another consumed leaf
	}
	eoa := Account{Addr: Other}
	beforeCode, afterCode := Code, Code
	if o.BeforeCode != nil {
		beforeCode = o.BeforeCode
	}
	if o.AfterCode != nil {
		afterCode = o.AfterCode
	}
	beforeExtra := map[common.Hash]*big.Int{}
	if o.BeforeValue != nil {
		beforeExtra[w.Slot] = o.BeforeValue
	}
	beforeAccts := []Account{eoa, {Addr: w.Contract, Code: beforeCode, Storage: copyStorage(others, beforeExtra)}}
	if o.NoBeforeAcc {
		beforeAccts = []Account{eoa}
	}
	w.Before = BuildState(tb, beforeAccts...)
	afterValue := one
	if o.AfterValue != nil {
		afterValue = o.AfterValue
	}
	w.After = BuildState(tb, eoa, Account{Addr: w.Contract, Code: afterCode, Storage: copyStorage(others, map[common.Hash]*big.Int{w.Slot: afterValue})})

	// The settlement: one transaction to the account, one receipt holding the account's LeafConsumed.
	sel := o.Selector
	if sel == nil {
		sel = V73Execute
	}
	to := w.Contract
	if o.To != nil {
		to = *o.To
	}
	data := append(append([]byte(nil), sel...), make([]byte, 64)...)
	if o.NoCalldata {
		data = nil
	}
	w.Tx = types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(ChainID), Nonce: 3, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2),
		Gas: 500000, To: &to, Value: big.NewInt(0), Data: data})
	emitter := w.Contract
	if o.EventFrom != nil {
		emitter = *o.EventFrom
	}
	status := uint64(1)
	if o.Reverted {
		status = 0
	}
	w.Receipt = &types.Receipt{Type: w.Tx.Type(), Status: status, CumulativeGasUsed: 123456, Logs: []*types.Log{
		{Address: common.HexToAddress("0xfab62e84c8e2b9b4f1cb0b4ea8a6f1b8e3d05a11"), Topics: []common.Hash{common.HexToHash("0x01")}, Data: []byte{1}},
		{Address: emitter, Topics: []common.Hash{ethproof.LeafConsumedTopic, Anchor, w.Leaf}, Data: OpID[:]},
	}}
	w.Receipt.Bloom = types.CreateBloom(w.Receipt)
	txEnc, err := w.Tx.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}
	rcEnc, err := w.Receipt.MarshalBinary()
	if err != nil {
		tb.Fatal(err)
	}

	w.Parent = &types.Header{ParentHash: common.HexToHash("0xaa"), Number: big.NewInt(N - 1), Root: w.Before.Root, Difficulty: big.NewInt(0),
		GasLimit: 30000000, Time: 1700000000, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, BaseFee: big.NewInt(7)}
	w.HeaderN = &types.Header{ParentHash: w.Parent.Hash(), Number: big.NewInt(N), Root: w.After.Root, Difficulty: big.NewInt(0),
		GasLimit: 30000000, Time: 1700000002, TxHash: ethproof.TrieRoot([][]byte{txEnc}), ReceiptHash: ethproof.TrieRoot([][]byte{rcEnc}), BaseFee: big.NewInt(7)}
	block := &ethproof.Block{Header: w.HeaderN, Txs: [][]byte{txEnc}, Receipts: [][]byte{rcEnc}}
	w.Settlement, err = block.Prove(w.Tx.Hash(), 0)
	if err != nil {
		tb.Fatal(err)
	}
	prev := w.HeaderN
	for i := 1; i <= o.After; i++ {
		h := &types.Header{ParentHash: prev.Hash(), Number: big.NewInt(int64(N + i)), Root: w.After.Root, Difficulty: big.NewInt(0),
			GasLimit: 30000000, Time: 1700000002 + uint64(2*i), TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, BaseFee: big.NewInt(7)}
		w.Chain = append(w.Chain, h)
		prev = h
	}
	w.Proof = w.BuildProof(prev)
	return w
}

// RawHeader is a header's RLP.
func RawHeader(tb TB, h *types.Header) hexutil.Bytes {
	tb.Helper()
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// BuildProof is the proof of the world's slot proven at top (the settlement block or the last header of Chain).
func (w *World) BuildProof(top *types.Header) *ethproof.ReplayGuardProof {
	p := &ethproof.ReplayGuardProof{
		Version: ethproof.ReplayGuardDomain, ChainID: ChainID, Generation: ethproof.AccountGenerationV7_3, Contract: w.Contract,
		Slot:            ethproof.ReplaySlot{Key: w.Leaf, Base: 4, Derivation: ethproof.ReplayDerivation, Slot: w.Slot},
		SettlementBlock: ethproof.BlockRef{Number: N, Hash: w.HeaderN.Hash()},
		ProvenAt:        ethproof.BlockRef{Number: top.Number.Uint64(), Hash: top.Hash()},
		Headers:         []hexutil.Bytes{},
		After:           w.After.Prove(w.Contract, w.Slot),
		Before:          &ethproof.ReplayBefore{ParentHeader: RawHeader(w.TB, w.Parent), Proof: w.Before.Prove(w.Contract, w.Slot)},
	}
	for _, h := range w.Chain {
		p.Headers = append(p.Headers, RawHeader(w.TB, h))
	}
	return p
}
