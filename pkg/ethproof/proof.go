// Copyright 2026 Certen Protocol

// Package ethproof builds and verifies the Merkle-Patricia inclusion proofs of a settlement on an EVM chain: its
// transaction against the block's transactionsRoot, and its receipt against the block's receiptsRoot (RB-2, RB5-F16).
//
// It is the one implementation. The settlement gate (pkg/execution) and the chain strategy's observer (pkg/chain/strategy)
// both build their proofs here, from agreed reads (Source), and every proof either verifies here before it is used or is
// refused by name. A proof the system emits is verifiable offline with VerifySettlement and nothing else: the block header
// it carries hashes to the block hash, the header's roots are the ones the proofs resolve from, the transaction proof's
// leaf hashes to the transaction hash, and the receipt sits at the same index.
package ethproof

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// InclusionProof proves that LeafValue is the entry at LeafIndex of the Merkle-Patricia trie whose root is ExpectedRoot:
// the trie a block header commits to as its transactionsRoot or receiptsRoot, keyed by rlp(index).
type InclusionProof struct {
	// LeafHash is keccak256(LeafValue). For a transaction it is the transaction's hash.
	LeafHash [32]byte `json:"leaf_hash"`

	// LeafIndex is the entry's position in its block; the trie key is rlp(LeafIndex).
	LeafIndex uint64 `json:"leaf_index"`

	// ProofHashes is keccak256 of each node in ProofNodes, in the same order (root first). Check recomputes it.
	ProofHashes [][32]byte `json:"proof_hashes"`

	// ExpectedRoot is the root the path resolves from: the header's transactionsRoot or receiptsRoot.
	ExpectedRoot [32]byte `json:"expected_root"`

	// Verified is set only by this package, after the proof verified against the block header's root where it was built.
	// A reader never trusts it: Check and VerifySettlement recompute everything.
	Verified bool `json:"verified"`

	// ProofNodes are the RLP-encoded trie nodes on the path from the root to the leaf, root first.
	ProofNodes [][]byte `json:"proof_nodes,omitempty"`

	// LeafValue is the entry's consensus encoding: the EIP-2718 envelope of a transaction or of a receipt.
	LeafValue []byte `json:"leaf_value,omitempty"`
}

// ErrProofInvalid is the class of every verification failure.
var ErrProofInvalid = errors.New("inclusion proof does not verify")

func invalid(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrProofInvalid, fmt.Sprintf(format, args...))
}

// Check verifies the proof against its own ExpectedRoot: every node is keyed by its own keccak256 (a key the proof states
// is never trusted), the path for rlp(LeafIndex) resolves from ExpectedRoot to exactly LeafValue, LeafValue hashes to
// LeafHash, and ProofHashes are the nodes' hashes. It does not say which block ExpectedRoot is: VerifyInclusion and
// VerifySettlement bind that.
func (p *InclusionProof) Check() error {
	if p == nil {
		return invalid("no proof")
	}
	if len(p.ProofNodes) == 0 {
		return invalid("no proof nodes")
	}
	if len(p.LeafValue) == 0 {
		return invalid("no leaf value")
	}
	if len(p.ProofHashes) != len(p.ProofNodes) {
		return invalid("%d node hashes for %d nodes", len(p.ProofHashes), len(p.ProofNodes))
	}
	db := memorydb.New()
	for i, node := range p.ProofNodes {
		if len(node) == 0 {
			return invalid("node %d is empty", i)
		}
		h := crypto.Keccak256(node)
		if !bytes.Equal(h, p.ProofHashes[i][:]) {
			return invalid("node %d hashes to %x, the proof states %x", i, h, p.ProofHashes[i])
		}
		if err := db.Put(h, node); err != nil {
			return invalid("node %d: %v", i, err)
		}
	}
	key, err := rlp.EncodeToBytes(p.LeafIndex)
	if err != nil {
		return invalid("index %d: %v", p.LeafIndex, err)
	}
	value, err := trie.VerifyProof(common.Hash(p.ExpectedRoot), key, db)
	if err != nil {
		return invalid("path for index %d from root %x: %v", p.LeafIndex, p.ExpectedRoot, err)
	}
	if value == nil {
		return invalid("root %x holds no entry at index %d", p.ExpectedRoot, p.LeafIndex)
	}
	if !bytes.Equal(value, p.LeafValue) {
		return invalid("the path for index %d resolves to another value than the proof's leaf", p.LeafIndex)
	}
	if crypto.Keccak256Hash(value) != common.Hash(p.LeafHash) {
		return invalid("the leaf hashes to %s, the proof states %x", crypto.Keccak256Hash(value).Hex(), p.LeafHash)
	}
	return nil
}

// Verify reports whether Check passes.
func (p *InclusionProof) Verify() bool { return p.Check() == nil }

// VerifyInclusion verifies that p proves an entry at index under root - a root the caller holds from the block header -
// and returns the entry's consensus encoding.
func VerifyInclusion(p *InclusionProof, root common.Hash, index uint64) ([]byte, error) {
	if p == nil {
		return nil, invalid("no proof")
	}
	if common.Hash(p.ExpectedRoot) != root {
		return nil, invalid("the proof resolves from root %x, the header's root is %s", p.ExpectedRoot, root.Hex())
	}
	if p.LeafIndex != index {
		return nil, invalid("the proof is for index %d, not %d", p.LeafIndex, index)
	}
	if err := p.Check(); err != nil {
		return nil, err
	}
	return p.LeafValue, nil
}

// commitmentTag domain-separates Commitment from every other hash this system signs.
const commitmentTag = "certen:ethproof:inclusion:v1"

// Commitment is the hash by which a signed observation binds this proof: the domain tag, the root, the index, and the
// leaf value and every node, each length-prefixed. Two proofs commit equally exactly when they are byte-identical, and the
// proof of an entry is a deterministic function of its block's entries, so every validator that proves the same entry
// from the same block computes the same commitment.
func (p *InclusionProof) Commitment() [32]byte {
	h := crypto.NewKeccakState()
	h.Write([]byte(commitmentTag))
	h.Write(p.ExpectedRoot[:])
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], p.LeafIndex)
	h.Write(n[:])
	writeLP := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeLP(p.LeafValue)
	binary.BigEndian.PutUint64(n[:], uint64(len(p.ProofNodes)))
	h.Write(n[:])
	for _, node := range p.ProofNodes {
		writeLP(node)
	}
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// nodeSet collects the nodes trie.Prove emits, in order (root first).
type nodeSet struct{ nodes [][]byte }

func (s *nodeSet) Put(_ []byte, value []byte) error {
	s.nodes = append(s.nodes, common.CopyBytes(value))
	return nil
}

func (s *nodeSet) Delete([]byte) error { return errors.New("a proof is never deleted from") }

// TrieRoot is the root of the trie over the given consensus encodings, keyed by rlp(index): the formula a block header's
// transactionsRoot and receiptsRoot commit to.
func TrieRoot(values [][]byte) common.Hash {
	t := trie.NewEmpty(nil)
	for i, v := range values {
		key, _ := rlp.EncodeToBytes(uint64(i))
		_ = t.Update(key, v)
	}
	return t.Hash()
}

// Prove builds the inclusion proof of values[index] in the trie over values, requires the trie's root to be root (the
// header's), and verifies the proof before returning it.
func Prove(values [][]byte, index uint64, root common.Hash) (*InclusionProof, error) {
	if index >= uint64(len(values)) {
		return nil, fmt.Errorf("index %d is outside the block's %d entries", index, len(values))
	}
	t := trie.NewEmpty(nil)
	for i, v := range values {
		key, _ := rlp.EncodeToBytes(uint64(i))
		if err := t.Update(key, v); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
	}
	if got := t.Hash(); got != root {
		return nil, fmt.Errorf("the block's entries have root %s, the header's is %s", got.Hex(), root.Hex())
	}
	key, _ := rlp.EncodeToBytes(index)
	var set nodeSet
	if err := t.Prove(key, &set); err != nil {
		return nil, fmt.Errorf("prove index %d: %w", index, err)
	}
	hashes := make([][32]byte, len(set.nodes))
	for i, node := range set.nodes {
		hashes[i] = crypto.Keccak256Hash(node)
	}
	leaf := common.CopyBytes(values[index])
	p := &InclusionProof{
		LeafHash:     crypto.Keccak256Hash(leaf),
		LeafIndex:    index,
		ProofHashes:  hashes,
		ExpectedRoot: root,
		ProofNodes:   set.nodes,
		LeafValue:    leaf,
	}
	if _, err := VerifyInclusion(p, root, index); err != nil {
		return nil, fmt.Errorf("the proof built for index %d does not verify: %w", index, err)
	}
	p.Verified = true
	return p, nil
}
