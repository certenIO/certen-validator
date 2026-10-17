// Copyright 2026 Certen Protocol

package ethproof

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// NumberedSource is a Source that also serves agreed headers by number, as an ethrpc.AgreeingReader does.
type NumberedSource interface {
	Source
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// BlockCheck is what proving every entry of one block established.
type BlockCheck struct {
	Number  uint64
	Hash    common.Hash
	Entries int
	// Types counts the block's transactions by EIP-2718 type (0 for a legacy transaction).
	Types map[uint8]int
}

// ErrUnread is the class of a block check that could not read the block: too few providers answered, or they disagreed.
// It says nothing about whether the block can be proven; CheckBlock's other errors say it cannot.
var ErrUnread = errors.New("block not read")

// CheckBlock proves every entry of the block at number exactly as a settlement in it would be proven: the agreed header,
// the agreed transaction and receipt encodings whose trie roots must be the header's (ReadBlock), and, for every index,
// the transaction and receipt inclusion proofs built and verified (Block.Prove). A read the providers did not answer or
// agree on is ErrUnread; any other error means a settlement in this block could not be proven.
func CheckBlock(ctx context.Context, src NumberedSource, number uint64) (*BlockCheck, error) {
	header, err := src.HeaderByNumber(ctx, new(big.Int).SetUint64(number))
	if err != nil {
		return nil, fmt.Errorf("%w: header %d: %w", ErrUnread, number, err)
	}
	if header == nil || header.Number == nil || header.Number.Uint64() != number {
		return nil, fmt.Errorf("%w: the agreed header for block %d is not that block", ErrUnread, number)
	}
	b, err := ReadBlock(ctx, src, header.Hash())
	if err != nil {
		if errors.Is(err, ethrpc.ErrTooFewProviders) || errors.Is(err, ethrpc.ErrProvidersDisagree) {
			return nil, fmt.Errorf("%w: block %d: %w", ErrUnread, number, err)
		}
		return nil, fmt.Errorf("block %d: %w", number, err)
	}
	out := &BlockCheck{Number: number, Hash: header.Hash(), Entries: len(b.Txs), Types: map[uint8]int{}}
	for i, enc := range b.Txs {
		out.Types[TxType(enc)]++
		if _, err := b.Prove(crypto.Keccak256Hash(enc), uint64(i)); err != nil {
			return nil, fmt.Errorf("block %d entry %d: %w", number, i, err)
		}
	}
	return out, nil
}

// TxType is the EIP-2718 type of a transaction's consensus encoding: its first byte, or 0 for a legacy RLP list.
func TxType(enc []byte) uint8 {
	if len(enc) == 0 || enc[0] >= 0xc0 {
		return 0
	}
	return enc[0]
}

// CheckBlockFromOne is CheckBlock read from ONE provider: the header by number, the block's transactions and receipts,
// both roots re-derived and every entry proven. It needs no agreement because it decides nothing about the chain - it
// answers only whether this block's bodies, as one provider serves them, can be proven; any refusal it reports is
// confirmed through the agreeing providers (CheckBlock) before anyone acts on it. A read that failed is ErrUnread.
// It exists so a monitor can check every new block at one provider's cost (two reads a block, not one per provider).
func CheckBlockFromOne(ctx context.Context, c *rpc.Client, number uint64) (*BlockCheck, error) {
	var header *types.Header
	if err := c.CallContext(ctx, &header, "eth_getBlockByNumber", hexutil.EncodeUint64(number), false); err != nil {
		return nil, fmt.Errorf("%w: header %d: %w", ErrUnread, number, err)
	}
	if header == nil || header.Number == nil || header.Number.Uint64() != number {
		return nil, fmt.Errorf("%w: the provider served no header for block %d", ErrUnread, number)
	}
	hash := header.Hash()
	txs, err := readTxs(ctx, c, hash)
	if err != nil {
		if errors.Is(err, errUnencodable) {
			return nil, fmt.Errorf("%w: block %d: %w", ErrRefused, number, err)
		}
		return nil, fmt.Errorf("%w: transactions of block %d: %w", ErrUnread, number, err)
	}
	if root := TrieRoot(txs); root != header.TxHash {
		return nil, refused("the transactions of block %d (%s) have root %s, its header's transactionsRoot is %s", number, hash.Hex(),
			root.Hex(), header.TxHash.Hex())
	}
	receipts, err := readReceipts(ctx, c, hash, len(txs))
	if err != nil {
		if errors.Is(err, errUnencodable) {
			return nil, fmt.Errorf("%w: block %d: %w", ErrRefused, number, err)
		}
		return nil, fmt.Errorf("%w: receipts of block %d: %w", ErrUnread, number, err)
	}
	if len(receipts) != len(txs) {
		return nil, fmt.Errorf("%w: block %d: %d transactions, %d receipts served", ErrUnread, number, len(txs), len(receipts))
	}
	if root := TrieRoot(receipts); root != header.ReceiptHash {
		return nil, refused("the receipts of block %d (%s) have root %s, its header's receiptsRoot is %s", number, hash.Hex(),
			root.Hex(), header.ReceiptHash.Hex())
	}
	b := &Block{Header: header, Txs: txs, Receipts: receipts}
	out := &BlockCheck{Number: number, Hash: hash, Entries: len(txs), Types: map[uint8]int{}}
	for i, enc := range txs {
		out.Types[TxType(enc)]++
		if _, err := b.Prove(crypto.Keccak256Hash(enc), uint64(i)); err != nil {
			return nil, fmt.Errorf("block %d entry %d: %w", number, i, err)
		}
	}
	return out, nil
}
