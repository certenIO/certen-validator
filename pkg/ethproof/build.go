// Copyright 2026 Certen Protocol

package ethproof

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Source is where a block's proofs are read from: its header by hash, and its transactions and receipts as every
// answering provider serves them. In production it is an ethrpc.AgreeingReader over the chain's independent providers
// (RB5-F53), so no single provider's answer is ever proven from.
type Source interface {
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	AgreedLists(ctx context.Context, what string, read func(context.Context, *rpc.Client) ([][]byte, error)) ([][]byte, error)
}

// ErrRefused is the class of every refusal to build a proof.
var ErrRefused = errors.New("no inclusion proof")

func refused(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Block is a block's header and the consensus encodings of all its transactions and receipts, already checked against
// the header's roots.
type Block struct {
	Header   *types.Header
	Txs      [][]byte
	Receipts [][]byte
}

// ReadBlock reads the block with this hash from src: the agreed header (which must hash to blockHash), then the agreed
// transaction and receipt encodings, whose trie roots must be the header's transactionsRoot and receiptsRoot. It refuses
// by name anything else.
func ReadBlock(ctx context.Context, src Source, blockHash common.Hash) (*Block, error) {
	if src == nil {
		return nil, refused("no agreed source to read block %s from", blockHash.Hex())
	}
	header, err := src.HeaderByHash(ctx, blockHash)
	if err != nil {
		return nil, fmt.Errorf("%w: header of block %s: %w", ErrRefused, blockHash.Hex(), err)
	}
	if header == nil || header.Hash() != blockHash {
		return nil, refused("the agreed header for block %s is not that block", blockHash.Hex())
	}
	txs, err := src.AgreedLists(ctx, "transactions of block "+blockHash.Hex(), func(ctx context.Context, c *rpc.Client) ([][]byte, error) {
		return readTxs(ctx, c, blockHash)
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if root := TrieRoot(txs); root != header.TxHash {
		return nil, refused("the transactions of block %s have root %s, its header's transactionsRoot is %s; an encoding is wrong for this chain",
			blockHash.Hex(), root.Hex(), header.TxHash.Hex())
	}
	receipts, err := src.AgreedLists(ctx, "receipts of block "+blockHash.Hex(), func(ctx context.Context, c *rpc.Client) ([][]byte, error) {
		return readReceipts(ctx, c, blockHash, len(txs))
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	if len(receipts) != len(txs) {
		return nil, refused("block %s holds %d transactions and %d receipts", blockHash.Hex(), len(txs), len(receipts))
	}
	if root := TrieRoot(receipts); root != header.ReceiptHash {
		return nil, refused("the receipts of block %s have root %s, its header's receiptsRoot is %s; an encoding is wrong for this chain",
			blockHash.Hex(), root.Hex(), header.ReceiptHash.Hex())
	}
	return &Block{Header: header, Txs: txs, Receipts: receipts}, nil
}

// Prove builds the settlement proof of transaction txHash at index in this block, and verifies it as a reader would
// (VerifySettlement) before returning it.
func (b *Block) Prove(txHash common.Hash, index uint64) (*Settlement, error) {
	blockHash := b.Header.Hash()
	if index >= uint64(len(b.Txs)) {
		return nil, refused("block %s has %d transactions; index %d is outside it", blockHash.Hex(), len(b.Txs), index)
	}
	if got := crypto.Keccak256Hash(b.Txs[index]); got != txHash {
		return nil, refused("block %s holds %s at index %d, not %s", blockHash.Hex(), got.Hex(), index, txHash.Hex())
	}
	txProof, err := Prove(b.Txs, index, b.Header.TxHash)
	if err != nil {
		return nil, fmt.Errorf("%w: transaction %s: %w", ErrRefused, txHash.Hex(), err)
	}
	rcProof, err := Prove(b.Receipts, index, b.Header.ReceiptHash)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt of %s: %w", ErrRefused, txHash.Hex(), err)
	}
	headerRLP, err := rlp.EncodeToBytes(b.Header)
	if err != nil {
		return nil, fmt.Errorf("%w: encode the header of %s: %w", ErrRefused, blockHash.Hex(), err)
	}
	s := &Settlement{BlockHash: blockHash, Header: headerRLP, TxHash: txHash, Tx: txProof, Receipt: rcProof}
	if _, _, err := s.Verify(); err != nil {
		return nil, fmt.Errorf("%w: the proof of %s does not verify: %w", ErrRefused, txHash.Hex(), err)
	}
	return s, nil
}

// Build reads the block with this hash from src and proves transaction txHash at index in it.
func Build(ctx context.Context, src Source, blockHash, txHash common.Hash, index uint64) (*Settlement, error) {
	b, err := ReadBlock(ctx, src, blockHash)
	if err != nil {
		return nil, err
	}
	return b.Prove(txHash, index)
}

// BuildWithin is Build, asked again every poll while the providers have not agreed - too few answered, or they disagree,
// as a lagging or briefly forked provider does (ethrpc.ErrTooFewProviders, ethrpc.ErrProvidersDisagree) - until deadline.
// Any other refusal is final at once. The last refusal is returned, named, when the deadline passes.
func BuildWithin(ctx context.Context, src Source, blockHash, txHash common.Hash, index uint64, deadline time.Time, poll time.Duration) (*Settlement, error) {
	if poll <= 0 {
		poll = time.Second
	}
	for {
		s, err := Build(ctx, src, blockHash, txHash, index)
		if err == nil {
			return s, nil
		}
		if !errors.Is(err, ethrpc.ErrTooFewProviders) && !errors.Is(err, ethrpc.ErrProvidersDisagree) {
			return nil, err
		}
		if !time.Now().Add(poll).Before(deadline) {
			return nil, fmt.Errorf("not agreed before the deadline: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w (last: %v)", ctx.Err(), err)
		case <-time.After(poll):
		}
	}
}

// readTxs is one provider's answer for a block's transactions: their consensus encodings, in order, each hashing to the
// hash the provider states for it.
func readTxs(ctx context.Context, c *rpc.Client, blockHash common.Hash) ([][]byte, error) {
	var blk *struct {
		Hash         common.Hash       `json:"hash"`
		Transactions []json.RawMessage `json:"transactions"`
	}
	if err := c.CallContext(ctx, &blk, "eth_getBlockByHash", blockHash, true); err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, fmt.Errorf("block %s: %w", blockHash.Hex(), ethereum.NotFound)
	}
	if blk.Hash != blockHash {
		return nil, fmt.Errorf("asked for block %s, served %s", blockHash.Hex(), blk.Hash.Hex())
	}
	out := make([][]byte, len(blk.Transactions))
	for i, raw := range blk.Transactions {
		enc, stated, err := EncodeTxJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("transaction %d of block %s: %w", i, blockHash.Hex(), err)
		}
		if got := crypto.Keccak256Hash(enc); got != stated {
			return nil, fmt.Errorf("transaction %d of block %s encodes to %s, the provider states %s", i, blockHash.Hex(), got.Hex(), stated.Hex())
		}
		out[i] = enc
	}
	return out, nil
}

// receiptBatch bounds one batched request for receipts.
const receiptBatch = 100

// readReceipts is one provider's answer for a block's receipts: their consensus encodings, in order. It asks for the
// block's receipts in one call; a provider that does not serve eth_getBlockReceipts (sepolia.base.org) is asked for each
// transaction's receipt instead, in batched requests. A provider that cannot answer now is not asked another way: its
// error is returned, and the agreed read asks it again. A provider that serves no receipts for a block of n transactions
// does not hold them (a pruned backend): that is not an answer.
func readReceipts(ctx context.Context, c *rpc.Client, blockHash common.Hash, n int) ([][]byte, error) {
	var raws []json.RawMessage
	var whole json.RawMessage
	err := c.CallContext(ctx, &whole, "eth_getBlockReceipts", blockHash)
	switch {
	case err == nil:
		if len(whole) == 0 || string(whole) == "null" {
			return nil, fmt.Errorf("receipts of block %s: %w", blockHash.Hex(), ethereum.NotFound)
		}
		if err := json.Unmarshal(whole, &raws); err != nil {
			return nil, fmt.Errorf("receipts of block %s: %w", blockHash.Hex(), err)
		}
		if len(raws) == 0 && n > 0 {
			return nil, fmt.Errorf("receipts of block %s (%d transactions): none served: %w", blockHash.Hex(), n, ethereum.NotFound)
		}
	case ethrpc.IsTransient(err) || ctx.Err() != nil:
		return nil, err
	default:
		raws, err = receiptsOneByOne(ctx, c, blockHash)
		if err != nil {
			return nil, err
		}
	}
	out := make([][]byte, len(raws))
	for i, raw := range raws {
		enc, ref, err := EncodeReceiptJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("receipt %d of block %s: %w", i, blockHash.Hex(), err)
		}
		if ref.BlockHash != blockHash || ref.TxIndex != uint64(i) {
			return nil, fmt.Errorf("receipt %d of block %s states block %s index %d", i, blockHash.Hex(), ref.BlockHash.Hex(), ref.TxIndex)
		}
		out[i] = enc
	}
	return out, nil
}

func receiptsOneByOne(ctx context.Context, c *rpc.Client, blockHash common.Hash) ([]json.RawMessage, error) {
	var blk *struct {
		Hash         common.Hash   `json:"hash"`
		Transactions []common.Hash `json:"transactions"`
	}
	if err := c.CallContext(ctx, &blk, "eth_getBlockByHash", blockHash, false); err != nil {
		return nil, err
	}
	if blk == nil {
		return nil, fmt.Errorf("block %s: %w", blockHash.Hex(), ethereum.NotFound)
	}
	if blk.Hash != blockHash {
		return nil, fmt.Errorf("asked for block %s, served %s", blockHash.Hex(), blk.Hash.Hex())
	}
	out := make([]json.RawMessage, len(blk.Transactions))
	for lo := 0; lo < len(blk.Transactions); lo += receiptBatch {
		hi := min(lo+receiptBatch, len(blk.Transactions))
		batch := make([]rpc.BatchElem, hi-lo)
		for i := range batch {
			batch[i] = rpc.BatchElem{Method: "eth_getTransactionReceipt", Args: []interface{}{blk.Transactions[lo+i]}, Result: &out[lo+i]}
		}
		if err := c.BatchCallContext(ctx, batch); err != nil {
			return nil, err
		}
		for i, e := range batch {
			if e.Error != nil {
				return nil, fmt.Errorf("receipt of %s: %w", blk.Transactions[lo+i].Hex(), e.Error)
			}
			if raw := out[lo+i]; len(raw) == 0 || string(raw) == "null" {
				return nil, fmt.Errorf("receipt of %s: %w", blk.Transactions[lo+i].Hex(), ethereum.NotFound)
			}
		}
	}
	return out, nil
}
