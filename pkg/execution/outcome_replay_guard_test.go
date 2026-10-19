// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB10 (S6): a member's replay-guard evidence rides BESIDE its outcome evidence (layer 6). These tests build a real
// settlement of a v4 member - a CertenAccountV7_3 settlement call, its receipt with the account's LeafConsumed, its block
// whose state root is a real Merkle-Patricia state in which the account's _consumedLeaf[leaf] slot is 1, and the parent
// state in which it is 0 - and hold the evidence to it.

type s6Collector struct{ nodes [][]byte }

func (c *s6Collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *s6Collector) Delete([]byte) error { return nil }

type s6AccountLeaf struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// s6State is one account's state trie: its storage, the account leaf, and proofs of a slot against the state root.
type s6State struct {
	root, storageRoot common.Hash
	code              []byte
	values            map[common.Hash]*big.Int
	state, storage    *trie.Trie
	addr              common.Address
}

func newS6State(t *testing.T, addr common.Address, code []byte, values map[common.Hash]*big.Int) *s6State {
	t.Helper()
	s := &s6State{addr: addr, code: code, values: values, state: trie.NewEmpty(nil), storage: trie.NewEmpty(nil)}
	for slot, v := range values {
		enc, _ := rlp.EncodeToBytes(common.TrimLeftZeroes(common.BigToHash(v).Bytes()))
		if err := s.storage.Update(crypto.Keccak256(slot.Bytes()), enc); err != nil {
			t.Fatal(err)
		}
	}
	s.storageRoot = s.storage.Hash()
	enc, err := rlp.EncodeToBytes(&s6AccountLeaf{Nonce: 1, Balance: big.NewInt(3), Root: s.storageRoot, CodeHash: crypto.Keccak256(code)})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.state.Update(crypto.Keccak256(addr.Bytes()), enc); err != nil {
		t.Fatal(err)
	}
	// another account, so the state trie is not a single leaf
	other, _ := rlp.EncodeToBytes(&s6AccountLeaf{Nonce: 9, Balance: big.NewInt(1), Root: types.EmptyRootHash, CodeHash: crypto.Keccak256(nil)})
	if err := s.state.Update(crypto.Keccak256(common.HexToAddress("0x00000000000000000000000000000000000000bb").Bytes()), other); err != nil {
		t.Fatal(err)
	}
	s.root = s.state.Hash()
	return s
}

func (s *s6State) prove(t *testing.T, slot common.Hash) ethproof.SlotProof {
	t.Helper()
	var acc, sto s6Collector
	if err := s.state.Prove(crypto.Keccak256(s.addr.Bytes()), &acc); err != nil {
		t.Fatal(err)
	}
	if err := s.storage.Prove(crypto.Keccak256(slot.Bytes()), &sto); err != nil {
		t.Fatal(err)
	}
	sp := ethproof.SlotProof{StorageHash: s.storageRoot, CodeHash: crypto.Keccak256Hash(s.code)}
	for _, n := range acc.nodes {
		sp.AccountProof = append(sp.AccountProof, n)
	}
	for _, n := range sto.nodes {
		sp.StorageProof = append(sp.StorageProof, n)
	}
	if v, ok := s.values[slot]; ok {
		sp.Value = common.BigToHash(v)
	}
	return sp
}

// s6Member is a v4 member settled by a CertenAccountV7_3 settlement call, and its S6 evidence.
type s6Member struct {
	*synthMember
	header, parent *types.Header
	tx             *types.Transaction
	proof          *ethproof.ReplayGuardProof
}

var s6Execute = []byte{0x60, 0x6f, 0x2c, 0x8d} // CertenAccountV7_3.executeGovernanceProofDirect

func newS6Member(t *testing.T) *s6Member {
	t.Helper()
	event := outcomeTreeEvent{Contract: common.HexToAddress("0x00000000000000000000000000000000000000aa"), Topic0: common.Hash{0xe1},
		DataHash: crypto.Keccak256Hash([]byte("paid"))}
	emitted := &types.Log{Address: event.Contract, Topics: []common.Hash{event.Topic0}, Data: []byte("paid")}
	committed := CommittedEffectsHash([][]ExpectedEvent{{{Contract: event.Contract, Topic0: event.Topic0, DataHash: event.DataHash}}}, nil)
	m := newSynthMember(t, []outcomeTreeEvent{event}).asV4(t)
	account := common.HexToAddress(m.ev.Account)
	key := common.Hash(m.leaf.BatchLeaf)
	slot := ethproof.ReplaySlotFor(key, 4)
	code := []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x73}
	before := newS6State(t, account, code, map[common.Hash]*big.Int{{0x03}: big.NewInt(7)})
	after := newS6State(t, account, code, map[common.Hash]*big.Int{{0x03}: big.NewInt(8), slot: big.NewInt(1)})

	parent := &types.Header{Number: big.NewInt(99), Time: 990, Difficulty: big.NewInt(0), Root: before.root}
	pk, _ := crypto.ToECDSA(bytes.Repeat([]byte{0x07}, 32))
	tx, err := types.SignNewTx(pk, types.LatestSignerForChainID(big.NewInt(m.chainID)), &types.DynamicFeeTx{ChainID: big.NewInt(m.chainID),
		Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 100_000, To: &account, Data: append(append([]byte(nil), s6Execute...), 0x01)})
	if err != nil {
		t.Fatal(err)
	}
	txBytes, _ := tx.MarshalBinary()
	r := &types.Receipt{Type: types.DynamicFeeTxType, Status: 1, CumulativeGasUsed: 50_000, Logs: []*types.Log{m.consumedLog(m.anchor.bundleID), emitted}}
	r.Bloom = types.CreateBloom(r)
	rBytes, _ := r.MarshalBinary()
	h := &types.Header{ParentHash: parent.Hash(), Number: big.NewInt(100), Time: 1000, Difficulty: big.NewInt(0), Root: after.root,
		TxHash: ethproof.TrieRoot([][]byte{txBytes}), ReceiptHash: ethproof.TrieRoot([][]byte{rBytes})}
	txp, err := ethproof.Prove([][]byte{txBytes}, 0, h.TxHash)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := ethproof.Prove([][]byte{rBytes}, 0, h.ReceiptHash)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := rlp.EncodeToBytes(h)
	incl := &ChainInclusionEvidence{Header: raw, Index: 0, Transaction: txBytes, Receipt: rBytes}
	for _, n := range txp.ProofNodes {
		incl.TransactionProof = append(incl.TransactionProof, n)
	}
	for _, n := range rp.ProofNodes {
		incl.ReceiptProof = append(incl.ReceiptProof, n)
	}
	m.settle(synthBlock{header: h, incl: incl, txHash: tx.Hash(), account: account}, OutcomeExecuted, committed)

	parentRaw, _ := rlp.EncodeToBytes(parent)
	p := &ethproof.ReplayGuardProof{Version: ethproof.ReplayGuardDomain, ChainID: m.chainID, Generation: ethproof.AccountGenerationV7_3,
		Contract: account, Slot: ethproof.ReplaySlot{Key: key, Base: 4, Derivation: ethproof.ReplayDerivation, Slot: slot},
		SettlementBlock: ethproof.BlockRef{Number: 100, Hash: h.Hash()}, ProvenAt: ethproof.BlockRef{Number: 100, Hash: h.Hash()},
		Headers: []hexutil.Bytes{}, After: after.prove(t, slot),
		Before: &ethproof.ReplayBefore{ParentHeader: parentRaw, Proof: before.prove(t, slot)}}
	return &s6Member{synthMember: m, header: h, parent: parent, tx: tx, proof: p}
}

func (m *s6Member) proven() *ethproof.ReplayGuardEvidence {
	cp := *m.proof
	return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: &cp}
}

func (m *s6Member) named() *ethproof.ReplayGuardEvidence {
	return &ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, State: &ethproof.ReplayNamedState{
		State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: m.chainID, TxHash: m.tx.Hash(),
		BlockNumber: 100, BlockHash: m.header.Hash(), Contract: common.HexToAddress(m.ev.Account),
		Providers: []ethproof.ReplayProviderFailure{{Host: "rpc.example", Error: "missing trie node"}}, Detail: "no provider served block 100"}}
}

func (m *s6Member) notVerifying() *ethproof.ReplayGuardEvidence {
	ev := m.proven()
	ev.Proof.After.Value = common.Hash{} // declares the slot unset, which the proof does not prove
	return ev
}

// check verifies the member and returns what it established and what not.
func (m *s6Member) check(t *testing.T) (*OutcomeEvidenceCheck, error) {
	t.Helper()
	if err := m.verify(); err != nil { // fills m.ev.Leaf
		var chk OutcomeEvidenceCheck
		return &chk, err
	}
	root, err := m.leaf.Hash()
	if err != nil {
		t.Fatal(err)
	}
	chk := &OutcomeEvidenceCheck{}
	return chk, m.ev.verify(m.chainID, m.anchor, root, chk)
}

func joined(lines []string) string { return strings.Join(lines, "\n") }

// Deliverable 4: the L6 verification of the replay guard.
func TestTheReplayGuardBesideAnOutcomeIsVerifiedAgainstItsSettlement(t *testing.T) {
	t.Run("carried and verifying: proved", func(t *testing.T) {
		m := newS6Member(t)
		m.ev.ReplayGuard = m.proven()
		chk, err := m.check(t)
		if err != nil {
			t.Fatalf("a verifying replay guard refused: %v", err)
		}
		est, not := joined(chk.Established), joined(chk.NotEstablished)
		for _, want := range []string{"S6: " + common.HexToAddress(m.ev.Account).Hex() + "'s replay-guard slot", "is 1 in the state of block 100",
			"CertenAccountV7_3 _consumedLeaf[leaf]", "is 0 in the state of block 99", "the transition happened in block 100"} {
			if !strings.Contains(est, want) {
				t.Fatalf("established lacks %q:\n%s", want, est)
			}
		}
		if strings.Contains(not, "S6") {
			t.Fatalf("a proven replay guard is also stated as not established:\n%s", not)
		}
	})
	t.Run("carried and not verifying: the member's evidence is refused", func(t *testing.T) {
		m := newS6Member(t)
		m.ev.ReplayGuard = m.notVerifying()
		_, err := m.check(t)
		if !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "the replay-guard evidence") {
			t.Fatalf("want the evidence refused for its replay guard, got %v", err)
		}
	})
	t.Run("carried for another block: refused", func(t *testing.T) {
		m := newS6Member(t)
		ev := m.proven()
		ev.Proof.SettlementBlock.Number = 101
		m.ev.ReplayGuard = ev
		if _, err := m.check(t); !errors.Is(err, ErrOutcomeEvidence) || !strings.Contains(err.Error(), "settlement_block_mismatch") {
			t.Fatalf("want a refusal naming the block mismatch, got %v", err)
		}
	})
	t.Run("absent: stated not established", func(t *testing.T) {
		m := newS6Member(t)
		chk, err := m.check(t)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(joined(chk.NotEstablished), "S6: that the settlement's replay-guard slot was consumed (storage proof): this evidence carries no replay-guard proof") {
			t.Fatalf("an absent replay guard is not stated:\n%s", joined(chk.NotEstablished))
		}
		if strings.Contains(joined(chk.Established), "S6") {
			t.Fatalf("an absent replay guard is stated as established:\n%s", joined(chk.Established))
		}
	})
	t.Run("named state: stated with state{reason} at block", func(t *testing.T) {
		m := newS6Member(t)
		m.ev.ReplayGuard = m.named()
		chk, err := m.check(t)
		if err != nil {
			t.Fatal(err)
		}
		want := "S6: s6_replay_unproven{reason=state_unavailable} at block 100 (" + m.header.Hash().Hex() + "): no provider served block 100"
		if !strings.Contains(joined(chk.NotEstablished), want) {
			t.Fatalf("want %q in:\n%s", want, joined(chk.NotEstablished))
		}
		if strings.Contains(joined(chk.Established), "S6") {
			t.Fatalf("a named state is stated as established:\n%s", joined(chk.Established))
		}
	})
	t.Run("named state of another transaction: refused", func(t *testing.T) {
		m := newS6Member(t)
		ev := m.named()
		ev.State.TxHash = common.Hash{0x01}
		m.ev.ReplayGuard = ev
		if _, err := m.check(t); !errors.Is(err, ErrOutcomeEvidence) {
			t.Fatalf("a named state of another transaction accepted: %v", err)
		}
	})
	t.Run("Before unavailable: disclosed", func(t *testing.T) {
		m := newS6Member(t)
		ev := m.proven()
		ev.Proof.Before = nil
		ev.Proof.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: "state_unavailable",
			Providers: []ethproof.ReplayProviderFailure{{Host: "rpc.example", Error: "missing trie node"}}}
		m.ev.ReplayGuard = ev
		chk, err := m.check(t)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(joined(chk.Established), "is 1 in the state of block 100") {
			t.Fatalf("After is not established:\n%s", joined(chk.Established))
		}
		if !strings.Contains(joined(chk.NotEstablished), "s6_before_unavailable{state_unavailable}") {
			t.Fatalf("the Before disclosure is not stated:\n%s", joined(chk.NotEstablished))
		}
	})
}
