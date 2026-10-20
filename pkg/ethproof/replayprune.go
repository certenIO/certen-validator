// Copyright 2026 Certen Protocol

package ethproof

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie"
)

// =============================================================================
// The proof the capture keeps (RB10-B14b)
// =============================================================================
//
// VerifyStorage keys every node it is given by its own hash and reads only the ones the path from the root needs, so a
// provider can pad an eth_getProof answer with any number of unused nodes (a 3 MiB one, thousands of small ones, copies,
// nodes of other tries, any order) and the padded proof still verifies. The capture used to copy the answer into the
// evidence as served. It now keeps exactly the nodes the verification walk read, root to leaf, which is what an honest
// provider serves: smaller, deterministic, and verified by the same unchanged verifier to the same account and value.
//
// The walk is not re-implemented: it is go-ethereum's trie.VerifyProof, the function the verifier calls, run over a node
// store that remembers what it was asked for. A node of fewer than 32 bytes is embedded in its parent and is never asked
// for (trie.VerifyProof descends into it inside the parent), so it is not an entry here, as it is not in an honest proof.

// recordingReader is the node store trie.VerifyProof reads: it answers from db and keeps each node it returned, in the
// order it was asked for.
type recordingReader struct {
	db   ethdb.KeyValueReader
	read [][]byte
}

func (r *recordingReader) Has(key []byte) (bool, error) { return r.db.Has(key) }

func (r *recordingReader) Get(key []byte) ([]byte, error) {
	v, err := r.db.Get(key)
	if v != nil {
		r.read = append(r.read, bytes.Clone(v))
	}
	return v, err
}

// ProofWalk verifies proof against root for the trie key exactly as VerifyAccount and VerifySlot do (every node keyed by
// its own hash, the path from root, a verified absence being a nil value) and returns the value with the nodes the walk
// read, root first, each once. proof may hold any other nodes; they are not returned.
func ProofWalk(root common.Hash, key []byte, proof [][]byte) (value []byte, walked [][]byte, err error) {
	db, err := proofDB(proof)
	if err != nil {
		return nil, nil, err
	}
	rec := &recordingReader{db: db}
	value, err = trie.VerifyProof(root, key, rec)
	if err != nil {
		return nil, nil, err
	}
	return value, rec.read, nil
}

// PrunedStorageProof is an account proof and a storage proof reduced to the nodes the verification walk read, with what
// they establish.
type PrunedStorageProof struct {
	AccountProof [][]byte
	StorageProof [][]byte
	Result       *StorageResult
}

// PruneStorageProof verifies the proofs with VerifyStorage (so it refuses, with the verifier's own error, exactly what the
// verifier refuses) and returns the nodes the walk read: the account proof from stateRoot to the account's leaf (or to the
// node that proves it absent), and the storage proof from the account's storage root to the slot's leaf (or to the node
// that proves it absent). The pruned lists verify under the unchanged VerifyStorage to the identical StorageResult; that is
// checked here before they are returned.
//
// Two cases read no node of the storage proof and keep it as the verifier accepted it: an account proven absent (its storage
// proof must be empty) and an account with the empty storage root (the verifier accepts no proof, or the empty node alone:
// at most one byte, never padding).
func PruneStorageProof(stateRoot common.Hash, account common.Address, accountProof [][]byte, slot common.Hash, storageProof [][]byte) (*PrunedStorageProof, error) {
	res, err := VerifyStorage(stateRoot, account, accountProof, slot, storageProof)
	if err != nil {
		return nil, err
	}
	_, acct, err := ProofWalk(stateRoot, crypto.Keccak256(account.Bytes()), accountProof)
	if err != nil {
		return nil, err
	}
	sto := append([][]byte{}, storageProof...)
	if res.Account.Exists && res.Account.StorageRoot != types.EmptyRootHash {
		if _, sto, err = ProofWalk(res.Account.StorageRoot, crypto.Keccak256(slot.Bytes()), storageProof); err != nil {
			return nil, err
		}
	}
	again, err := VerifyStorage(stateRoot, account, acct, slot, sto)
	if err != nil {
		return nil, storageInvalid("the nodes the walk read do not verify: %v", err)
	}
	if !sameStorageResult(res, again) {
		return nil, storageInvalid("the nodes the walk read establish another account or value than the proof as served")
	}
	return &PrunedStorageProof{AccountProof: acct, StorageProof: sto, Result: res}, nil
}

func sameStorageResult(a, b *StorageResult) bool {
	return a.Account.Exists == b.Account.Exists && a.Account.Nonce == b.Account.Nonce && a.Account.Balance.Cmp(b.Account.Balance) == 0 &&
		a.Account.StorageRoot == b.Account.StorageRoot && a.Account.CodeHash == b.Account.CodeHash && a.Value == b.Value
}
