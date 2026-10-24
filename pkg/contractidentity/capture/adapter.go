// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethrpc"
)

// AgreedReader is what the validator holds for a chain: an ethrpc.AgreeingReader (the finality reader of the EVM observer). Its headers,
// receipts and lists are what at least ethrpc.MinAgreeingProviders independent providers agree on; its locators are the individual
// providers, asked for state proofs and code (a proof and a code are self-verifying, so one provider that has them is enough).
type AgreedReader interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
	HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error)
	AgreedLists(ctx context.Context, what string, read func(context.Context, *rpc.Client) ([][]byte, error)) ([][]byte, error)
	Locators() []ethrpc.LocatorClient
}

// codeTimeout bounds one eth_getCode call (the answer is up to 256 KiB of hex).
const codeTimeout = 20 * time.Second

type readerSource struct{ r AgreedReader }

// NewReaderSource adapts an agreed reader to the AttestSource a capture reads. It adds what the S6 source lacks: the agreed transaction by
// hash (the receipt's block is read whole, checked against the header's roots, and the transaction is the entry the receipt names) and
// eth_getCode on each provider.
func NewReaderSource(r AgreedReader) (AttestSource, error) {
	if r == nil {
		return nil, errors.New("capture: no agreed reader")
	}
	return readerSource{r}, nil
}

func (s readerSource) TransactionReceipt(ctx context.Context, h common.Hash) (*types.Receipt, error) {
	return s.r.TransactionReceipt(ctx, h)
}

func (s readerSource) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	return s.r.HeaderByNumber(ctx, n)
}

func (s readerSource) HeaderByHash(ctx context.Context, h common.Hash) (*types.Header, error) {
	return s.r.HeaderByHash(ctx, h)
}

func (s readerSource) Block(ctx context.Context, h common.Hash) (*ethproof.Block, error) {
	return ethproof.ReadBlock(ctx, s.r, h)
}

func (s readerSource) TransactionByHash(ctx context.Context, h common.Hash) (*types.Transaction, bool, error) {
	rc, err := s.r.TransactionReceipt(ctx, h)
	if err != nil || rc == nil {
		return nil, false, err
	}
	blk, err := s.Block(ctx, rc.BlockHash)
	if err != nil {
		return nil, false, err
	}
	i := int(rc.TransactionIndex)
	if i < 0 || i >= len(blk.Txs) || crypto.Keccak256Hash(blk.Txs[i]) != h {
		return nil, false, fmt.Errorf("the agreed block %s does not hold %s at index %d", rc.BlockHash.Hex(), h.Hex(), i)
	}
	var tx types.Transaction
	if err := tx.UnmarshalBinary(blk.Txs[i]); err != nil {
		return nil, false, err
	}
	return &tx, true, nil
}

func (s readerSource) Providers() []Provider {
	locs := s.r.Locators()
	out := make([]Provider, len(locs))
	for i, l := range locs {
		out[i] = locatorProvider{l}
	}
	return out
}

type locatorProvider struct{ l ethrpc.LocatorClient }

func (p locatorProvider) Name() string { return p.l.Host }

func (p locatorProvider) GetProof(ctx context.Context, a common.Address, keys []string, block string) (json.RawMessage, error) {
	return p.l.GetProof(ctx, a, keys, block)
}

func (p locatorProvider) GetCode(ctx context.Context, a common.Address, block string) ([]byte, error) {
	if p.l.Client == nil {
		return nil, errors.New("the provider has no client")
	}
	ctx, cancel := context.WithTimeout(ctx, codeTimeout)
	defer cancel()
	var code hexutil.Bytes
	if err := p.l.Client.Client().CallContext(ctx, &code, "eth_getCode", a, block); err != nil {
		return nil, err
	}
	return code, nil
}
