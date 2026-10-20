// Copyright 2026 Certen Protocol

package ethproof

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// This file is the one implementation of the Merkle-Patricia verification of an account and one of its storage slots
// (eth_getProof): account proof -> account.storageRoot -> storage proof -> slot value. The opt-in committed-state proof
// (pkg/execution.StateProof) and the S6 replay-guard proof (ReplayGuardProof) both verify through it.

// ErrStorageProofInvalid is the class of every account or storage proof that does not verify.
var ErrStorageProofInvalid = errors.New("state proof does not verify")

func storageInvalid(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrStorageProofInvalid, fmt.Sprintf(format, args...))
}

// AccountState is an account as a verified account proof states it. Exists is false when the proof is a verified
// exclusion proof: the state holds no such account, so its storage is empty and every slot of it is 0.
type AccountState struct {
	Exists      bool
	Nonce       uint64
	Balance     *big.Int
	StorageRoot common.Hash
	CodeHash    common.Hash
}

// HasCode reports a proven account with contract code.
func (a *AccountState) HasCode() bool {
	return a != nil && a.Exists && a.CodeHash != types.EmptyCodeHash && a.CodeHash != (common.Hash{})
}

// ethAccount is the RLP layout of an Ethereum account leaf: [nonce, balance, storageRoot, codeHash].
type ethAccount struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// proofDB builds an in-memory trie node DB from raw RLP nodes, keyed by keccak256(node), so a key the proof states for a
// node is never trusted.
func proofDB(nodes [][]byte) (*memorydb.Database, error) {
	db := memorydb.New()
	for _, n := range nodes {
		if len(n) == 0 {
			return nil, storageInvalid("empty proof node")
		}
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// VerifyAccount verifies an account proof against stateRoot: the path for keccak256(account) resolves from stateRoot
// either to the account's leaf, or - an exclusion proof - to a verified absence. Every node is keyed by its own hash.
func VerifyAccount(stateRoot common.Hash, account common.Address, proof [][]byte) (*AccountState, error) {
	return VerifyAccountUnder(RuleReplayGuard, stateRoot, account, proof)
}

// Rule names the acceptance rule a state-proof verification applies. Both rules walk the same Merkle-Patricia proof
// (every node keyed by its own hash, the path from the stated root); they differ only in which edge cases they accept.
type Rule uint8

const (
	// RuleReplayGuard is the S6 replay-guard rule (SPEC §4): an exclusion proof is a proven absence, an empty storage
	// root needs no node (or only the empty node 0x80), a code hash is exactly 32 bytes, and a storage leaf is a
	// trimmed value of at most 32 bytes.
	RuleReplayGuard Rule = iota
	// RuleCommittedState is the acceptance rule of the opt-in committed-state proof (pkg/execution.StateProof) exactly as
	// validator main 5565d98 applied it, kept because that answer is consensus-reachable (slotsHoldAt feeds the hashed
	// EffectsHash): an absent account is refused, a storage proof always needs a node and is always walked from the
	// storage root (no empty-root short-circuit), a code hash of any length is accepted, and a storage leaf is read as its
	// last 32 bytes, leading zeros allowed.
	RuleCommittedState
)

// VerifyAccountUnder is VerifyAccount under the named rule.
func VerifyAccountUnder(rule Rule, stateRoot common.Hash, account common.Address, proof [][]byte) (*AccountState, error) {
	if len(proof) == 0 {
		return nil, storageInvalid("no account proof")
	}
	db, err := proofDB(proof)
	if err != nil {
		return nil, err
	}
	enc, err := trie.VerifyProof(stateRoot, crypto.Keccak256(account.Bytes()), db)
	if err != nil {
		return nil, storageInvalid("account %s against state root %s: %v", account.Hex(), stateRoot.Hex(), err)
	}
	if enc == nil {
		return &AccountState{Exists: false, Balance: new(big.Int), StorageRoot: types.EmptyRootHash}, nil
	}
	var acc ethAccount
	if err := rlp.DecodeBytes(enc, &acc); err != nil {
		return nil, storageInvalid("account %s does not decode: %v", account.Hex(), err)
	}
	if rule != RuleCommittedState && len(acc.CodeHash) != common.HashLength {
		return nil, storageInvalid("account %s has a %d-byte code hash", account.Hex(), len(acc.CodeHash))
	}
	if acc.Balance == nil {
		acc.Balance = new(big.Int)
	}
	return &AccountState{Exists: true, Nonce: acc.Nonce, Balance: acc.Balance, StorageRoot: acc.Root, CodeHash: common.BytesToHash(acc.CodeHash)}, nil
}

// VerifySlot verifies a storage proof against an account's storageRoot and returns the slot's 32-byte value. A slot the
// trie does not hold is verified absent and is 0. An empty storage root (an account with no storage, or no account) needs
// no node: every slot of it is 0 and the proof must hold none, or only the empty node.
func VerifySlot(storageRoot common.Hash, slot common.Hash, proof [][]byte) (common.Hash, error) {
	return VerifySlotUnder(RuleReplayGuard, storageRoot, slot, proof)
}

// VerifySlotUnder is VerifySlot under the named rule.
func VerifySlotUnder(rule Rule, storageRoot common.Hash, slot common.Hash, proof [][]byte) (common.Hash, error) {
	if rule != RuleCommittedState && storageRoot == types.EmptyRootHash {
		switch {
		case len(proof) == 0:
			return common.Hash{}, nil
		case len(proof) == 1 && len(proof[0]) == 1 && proof[0][0] == 0x80:
			return common.Hash{}, nil
		}
		return common.Hash{}, storageInvalid("the storage root is the empty root, and the proof holds %d nodes", len(proof))
	}
	if len(proof) == 0 {
		return common.Hash{}, storageInvalid("no storage proof for the non-empty storage root %s", storageRoot.Hex())
	}
	db, err := proofDB(proof)
	if err != nil {
		return common.Hash{}, err
	}
	enc, err := trie.VerifyProof(storageRoot, crypto.Keccak256(slot.Bytes()), db)
	if err != nil {
		return common.Hash{}, storageInvalid("slot %s against storage root %s: %v", slot.Hex(), storageRoot.Hex(), err)
	}
	if enc == nil {
		return common.Hash{}, nil
	}
	// A storage leaf is RLP( the big-endian value with leading zeros trimmed ).
	var trimmed []byte
	if err := rlp.DecodeBytes(enc, &trimmed); err != nil {
		return common.Hash{}, storageInvalid("slot %s: the proven leaf does not decode: %v", slot.Hex(), err)
	}
	// A client never stores a zero (it deletes the slot); a leaf holding an empty value is read as 0, as the opt-in
	// committed-state proof always read it.
	if rule == RuleCommittedState {
		return common.BytesToHash(trimmed), nil
	}
	if len(trimmed) > common.HashLength || (len(trimmed) > 0 && trimmed[0] == 0) {
		return common.Hash{}, storageInvalid("slot %s: the proven leaf is not a trimmed value of at most 32 bytes", slot.Hex())
	}
	return common.BytesToHash(trimmed), nil
}

// StorageResult is what a verified account and storage proof establish at one state root.
type StorageResult struct {
	Account AccountState
	Value   common.Hash
}

// VerifyStorage verifies, against stateRoot, the account (present or absent) and the value of slot in its storage: the
// account proof resolves from stateRoot, and the storage proof resolves from THAT account's storageRoot to the slot.
// It is the single implementation behind pkg/execution.StateProof and ReplayGuardProof.
func VerifyStorage(stateRoot common.Hash, account common.Address, accountProof [][]byte, slot common.Hash, storageProof [][]byte) (*StorageResult, error) {
	return VerifyStorageUnder(RuleReplayGuard, stateRoot, account, accountProof, slot, storageProof)
}

// VerifyStorageUnder is VerifyStorage under the named rule.
func VerifyStorageUnder(rule Rule, stateRoot common.Hash, account common.Address, accountProof [][]byte, slot common.Hash, storageProof [][]byte) (*StorageResult, error) {
	acc, err := VerifyAccountUnder(rule, stateRoot, account, accountProof)
	if err != nil {
		return nil, err
	}
	if !acc.Exists && rule == RuleCommittedState {
		return nil, storageInvalid("account %s is proven absent, and the committed-state rule states values of existing accounts only", account.Hex())
	}
	if !acc.Exists {
		// A verified absence holds no storage: nothing may be claimed in it.
		if len(storageProof) != 0 {
			return nil, storageInvalid("account %s is proven absent and a storage proof of %d nodes is offered", account.Hex(), len(storageProof))
		}
		return &StorageResult{Account: *acc}, nil
	}
	v, err := VerifySlotUnder(rule, acc.StorageRoot, slot, storageProof)
	if err != nil {
		return nil, err
	}
	return &StorageResult{Account: *acc, Value: v}, nil
}
