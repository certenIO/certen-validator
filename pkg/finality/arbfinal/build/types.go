// Copyright 2026 Certen Protocol

// Package build is the online half of arb-sepolia/finalized/v1 (V2_SPEC_S7 2.8 and 5.7, annex R11-arbitrum-sepolia A3-A5): it
// finds the confirmed BoLD assertion that covers a leg's L2 block, captures the Rollup proofs of the L1 states S and K NEAR THE
// HEAD (public providers serve eth_getProof only there), waits until the L1 finalized head covers both, assembles the
// arbfinal.Evidence and runs arbfinal's verifier before returning. Everything it reads is untrusted and self-verifying; a
// provider miss is a named state and never a weaker level.
//
// The providers are small interfaces so that the whole pipeline is tested offline with fakes; live.go holds the JSON-RPC and
// beacon-API implementations. Every provider error text passes through pkg/ethrpc RedactText before it is stored or returned.
package build

import (
	"context"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Log is one L1 log as the builder needs it.
type Log struct {
	Block     uint64
	BlockHash [32]byte
	TxHash    [32]byte
	TxIndex   uint64
	Topics    []common.Hash
	Data      []byte
}

// L1Block is one L1 block with the consensus encodings of all its transactions and receipts, in order. The builder recomputes
// the tries and compares their roots with the header, so a provider cannot hand over a body the header does not commit to.
type L1Block struct {
	Number    uint64
	Hash      [32]byte
	HeaderRLP []byte
	Txs       [][]byte
	Receipts  [][]byte
}

// StateProof is an eth_getProof answer: the account proof nodes and, per requested slot, its storage proof nodes. The nodes are
// raw RLP trie nodes; whether they prove anything is judged by the verifier, never here.
type StateProof struct {
	Account [][]byte
	Storage map[common.Hash][][]byte
}

// L1 is the Sepolia execution-layer source.
type L1 interface {
	// Providers names the endpoints (scheme and host only, redacted) for the "providers" field of the unavailability states.
	Providers() []string
	// Head is the latest block number.
	Head(ctx context.Context) (uint64, error)
	// Headers returns the raw RLP headers of blocks from..to inclusive in ascending order; every header hashes to the hash the
	// provider states for its block and the parent links hold (the implementation checks them).
	Headers(ctx context.Context, from, to uint64) ([][]byte, error)
	// HeaderByHash returns the raw RLP header with this hash.
	HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error)
	// Logs returns the logs of addr matching topics (position i matches any of topics[i]) over from..to inclusive.
	Logs(ctx context.Context, addr common.Address, topics [][]common.Hash, from, to uint64) ([]Log, error)
	// Block returns the block with its transaction and receipt encodings.
	Block(ctx context.Context, number uint64) (*L1Block, error)
	// Proof returns eth_getProof(addr, slots) at block. A block outside the provider's proof window is an error.
	Proof(ctx context.Context, addr common.Address, slots []common.Hash, block uint64) (*StateProof, error)
}

// L2 is the Arbitrum Sepolia source of block headers.
type L2 interface {
	Providers() []string
	// HeaderByHash returns the raw RLP header with this hash.
	HeaderByHash(ctx context.Context, hash [32]byte) ([]byte, error)
	// HeaderByNumber returns the raw RLP header of this block.
	HeaderByNumber(ctx context.Context, number uint64) ([]byte, error)
	// Headers returns the raw RLP headers of blocks from..to inclusive in ascending order, each hashing to the hash the provider
	// states for its block (the implementation checks it).
	Headers(ctx context.Context, from, to uint64) ([][]byte, error)
}

// LCSource returns the Ethereum L1-finality part (spec 3.2) for the current finalized head: the anchor, the links and the
// finality update, in evidence form. It is the beacon-API client of the live build; tests give a fixed LC.
type LCSource interface {
	LC(ctx context.Context) (ethl1.LC, error)
}

// CaptureStore holds proofs captured near the head until the builder can attest them (spec 2.8): the framework's insert-only
// store (pkg/database.FinalityCaptureStore in production). A reorg yields a second row for the same height with another hash: a
// Get names the hash it wants.
type CaptureStore = finality.CaptureStore

// MemStore is the in-memory CaptureStore of tests and of the one-shot recorder. Rows are insert-only like the real table: a
// second Put of the same key must carry the same bytes.
type MemStore = finality.MemCaptureStore

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return finality.NewMemCaptureStore() }
