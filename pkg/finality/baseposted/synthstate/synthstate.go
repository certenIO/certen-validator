// Copyright 2026 Certen Protocol

// Package synthstate builds, for tests, a minimal Ethereum state that proves what the Base l1_posted capture authenticates a batch-inbox
// transaction with: the OP SystemConfig proxy (its batcherHash slot and its EIP-1967 implementation slot) and the implementation account
// (its code hash), under a state root a test puts into its synthetic L1 header. Proof answers exactly like eth_getProof (the trie nodes,
// and the slot values the provider reports), so a fake L1Source can serve real, verifiable proofs; a hostile test changes one byte.
//
// It imports nothing of pkg/finality/baseposted (the package's own tests import this one), so the two storage slots are written out here;
// baseposted's own tests pin that they equal the production constants.
package synthstate

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// The storage slots of SystemConfig: batcherHash (slot 103) and the EIP-1967 implementation slot.
var (
	BatcherHashSlot = common.BigToHash(big.NewInt(103))
	ImplSlot        = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
)

// State is a state with the SystemConfig proxy and its implementation.
type State struct {
	Root         [32]byte
	SystemConfig [20]byte
	Impl         [20]byte
	ImplCodeHash [32]byte
	Batcher      [20]byte
	acc          *trie.Trie
	store        *trie.Trie
}

// New builds the state: the proxy at systemConfig holds batcherHash = batcher and the implementation slot = impl; the account at impl has
// the code hash implCodeHash.
func New(systemConfig, impl [20]byte, implCodeHash [32]byte, batcher [20]byte) *State {
	st := trie.NewEmpty(nil)
	bv, _ := rlp.EncodeToBytes(bytes.TrimLeft(common.LeftPadBytes(batcher[:], 32), "\x00"))
	iv, _ := rlp.EncodeToBytes(bytes.TrimLeft(common.LeftPadBytes(impl[:], 32), "\x00"))
	st.Update(crypto.Keccak256(BatcherHashSlot[:]), bv)
	st.Update(crypto.Keccak256(ImplSlot[:]), iv)
	acc := trie.NewEmpty(nil)
	sc, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: st.Hash(), CodeHash: crypto.Keccak256([]byte("proxy"))})
	im, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: types.EmptyRootHash, CodeHash: implCodeHash[:]})
	acc.Update(crypto.Keccak256(systemConfig[:]), sc)
	acc.Update(crypto.Keccak256(impl[:]), im)
	return &State{Root: [32]byte(acc.Hash()), SystemConfig: systemConfig, Impl: impl, ImplCodeHash: implCodeHash, Batcher: batcher, acc: acc, store: st}
}

type sink struct{ nodes [][]byte }

func (p *sink) Put(_ []byte, v []byte) error {
	p.nodes = append(p.nodes, common.CopyBytes(v))
	return nil
}
func (p *sink) Delete([]byte) error { return nil }

func prove(tr *trie.Trie, key []byte) [][]byte {
	var s sink
	if err := tr.Prove(key, &s); err != nil {
		panic(err) // a trie built here always proves its own keys
	}
	return s.nodes
}

// Proof answers eth_getProof for addr and slots: the account proof, then (for the SystemConfig proxy) the storage proof of each slot asked,
// and the reported slot values (the EIP-1967 word carries the implementation address).
func (s *State) Proof(addr [20]byte, slots [][32]byte) (nodes [][]byte, values map[[32]byte][32]byte) {
	values = map[[32]byte][32]byte{}
	nodes = append(nodes, prove(s.acc, crypto.Keccak256(addr[:]))...)
	if addr == s.SystemConfig {
		for _, sl := range slots {
			nodes = append(nodes, prove(s.store, crypto.Keccak256(sl[:]))...)
			switch common.Hash(sl) {
			case ImplSlot:
				var v [32]byte
				copy(v[12:], s.Impl[:])
				values[sl] = v
			case BatcherHashSlot:
				var v [32]byte
				copy(v[12:], s.Batcher[:])
				values[sl] = v
			}
		}
	}
	return nodes, values
}
