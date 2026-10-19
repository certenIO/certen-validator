// Copyright 2025 Certen Protocol
//
// RB-5: Optional storage-slot state proof.
//
// The strongest "effect" proof: independently prove that a specific storage slot of a
// contract took the committed value, verified against the finalized block stateRoot via
// two chained Merkle-Patricia proofs (account proof → account.storageRoot → storage
// proof → slot value). Generic — no per-contract code. Opt-in per intent; when an intent
// commits expectedState, the validator refuses to attest unless the proven slot value
// equals the committed value.

package execution

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// StateProof is an independently verifiable proof that account `Account`'s storage slot
// `Slot` holds `Value` at a block whose stateRoot is known. It carries the raw account
// and storage MPT proof node sets so it can be re-verified off the original RPC.
type StateProof struct {
	Account common.Address `json:"account"`
	Slot    common.Hash    `json:"slot"`  // storage slot key (unhashed)
	Value   common.Hash    `json:"value"` // committed/observed slot value (32-byte)

	// Raw RLP proof node sets (keyed on verify by keccak256(node)).
	AccountProof [][]byte    `json:"account_proof"`
	StorageHash  common.Hash `json:"storage_hash"` // account.storageRoot; cross-checked against the account proof
	StorageProof [][]byte    `json:"storage_proof"`
}

// ethAccount is the RLP layout of an Ethereum account leaf: [nonce, balance, storageRoot, codeHash].
type ethAccount struct {
	Nonce    uint64
	Balance  *big.Int
	Root     common.Hash
	CodeHash []byte
}

// nodeDB builds an in-memory trie node DB from raw RLP nodes, keyed by keccak256(node),
// so caller-supplied keys are never trusted.
func nodeDB(nodes [][]byte) (*memorydb.Database, error) {
	db := memorydb.New()
	for _, n := range nodes {
		if len(n) == 0 {
			return nil, fmt.Errorf("empty proof node")
		}
		if err := db.Put(crypto.Keccak256(n), n); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// Verify independently verifies the state proof against the given block stateRoot:
//  1. account proof: VerifyProof(stateRoot, keccak256(account)) → account RLP; its
//     storageRoot must equal StorageHash.
//  2. storage proof: VerifyProof(StorageHash, keccak256(slot)) → RLP(value); the decoded
//     32-byte value must equal Value.
//
// Fails closed on any missing/altered node, root mismatch, or value mismatch.
func (p *StateProof) Verify(stateRoot common.Hash) bool {
	if len(p.AccountProof) == 0 || len(p.StorageProof) == 0 {
		return false
	}
	// One implementation (pkg/ethproof, RB10), under the committed-state rule this proof applied at validator main
	// 5565d98 (its answer is consensus-reachable, V-R10B D4): the account proof from the state root, the storage proof
	// from that account's storageRoot. An absent account is no account here: a committed slot of one is not a held value.
	res, err := ethproof.VerifyStorageUnder(ethproof.RuleCommittedState, stateRoot, p.Account, p.AccountProof, p.Slot, p.StorageProof)
	if err != nil || !res.Account.Exists {
		return false
	}
	// The account's storageRoot must be the one the proof states.
	if res.Account.StorageRoot != p.StorageHash {
		return false
	}
	return res.Value == p.Value
}

// verifyAccountProof is true when proof is a valid Merkle-Patricia proof, against stateRoot, that account exists in the
// state: the part of Verify that needs no storage slot. The boot probe uses it, so that an eth_getProof answer that is
// empty, null, of another account or of another state is not taken as a provider serving proofs.
func verifyAccountProof(stateRoot common.Hash, account common.Address, proof [][]byte) bool {
	acc, err := ethproof.VerifyAccountUnder(ethproof.RuleCommittedState, stateRoot, account, proof)
	return err == nil && acc.Exists
}

// EthGetProofResult mirrors the subset of the eth_getProof JSON-RPC response we verify.
// Fetched via the raw rpc.Client (no gethclient dependency).
type EthGetProofResult struct {
	AccountProof []string    `json:"accountProof"`
	StorageHash  common.Hash `json:"storageHash"`
	StorageProof []struct {
		Key   string   `json:"key"`
		Value string   `json:"value"`
		Proof []string `json:"proof"`
	} `json:"storageProof"`
}

// StateProofFromRPC converts an eth_getProof response (for a single slot) into a
// verifiable StateProof. The committed/observed value is taken from the storage entry.
func StateProofFromRPC(res *EthGetProofResult, account common.Address, slot common.Hash) (*StateProof, error) {
	if res == nil {
		return nil, fmt.Errorf("nil account result")
	}
	if len(res.StorageProof) == 0 {
		return nil, fmt.Errorf("no storage proof for slot")
	}
	// Find the storage entry for our slot (getProof echoes the requested keys).
	idx := 0
	for i := range res.StorageProof {
		if common.HexToHash(res.StorageProof[i].Key) == slot {
			idx = i
			break
		}
	}
	st := res.StorageProof[idx]

	accountProof, err := hexNodes(res.AccountProof)
	if err != nil {
		return nil, fmt.Errorf("account proof: %w", err)
	}
	storageProof, err := hexNodes(st.Proof)
	if err != nil {
		return nil, fmt.Errorf("storage proof: %w", err)
	}

	value := new(big.Int)
	if v := strings.TrimPrefix(strings.TrimPrefix(st.Value, "0x"), "0X"); v != "" {
		value.SetString(v, 16)
	}

	return &StateProof{
		Account:      account,
		Slot:         slot,
		Value:        common.BigToHash(value),
		AccountProof: accountProof,
		StorageHash:  res.StorageHash,
		StorageProof: storageProof,
	}, nil
}

// hexNodes decodes a list of 0x-hex proof nodes into raw bytes.
func hexNodes(hexes []string) ([][]byte, error) {
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		b, err := decodeHexBytes(h)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
