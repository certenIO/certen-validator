// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// Locating an anchor's create transaction (RB3-F33).
//
// A validator whose createBatchAnchor found the anchor already there - another validator created it - did
// not know which transaction did, and recorded nothing: 235 of 289 canonical anchors lacked their create
// transaction. The chain knows it, exactly:
//
//	anchors(bundleId).timestamp  = block.timestamp of the creating block
//	anchors(bundleId).validator  = msg.sender of the creating call
//	BatchAnchorCreated(bundleId indexed, batchRoot indexed, ..., validator indexed, ...) in that block
//
// So the create transaction is the one BatchAnchorCreated log for (bundle, root, validator) in the blocks
// whose timestamp is the anchor's - no search window to guess, and a result the caller still confirms by
// reading the transaction itself (calldata naming bundle and root, signed by that validator).

// AnchorCreateLocation is where the chain says an anchor was created.
type AnchorCreateLocation struct {
	TxHash    string
	Block     uint64
	Validator common.Address
	CreatedAt uint64
}

// anchorCreateChain is the chain access locating a create transaction needs.
type anchorCreateChain interface {
	// AnchorRecord reads anchors(bundle) at the anchor contract.
	AnchorRecord(ctx context.Context, anchor common.Address, bundle [32]byte) (AnchorOnChainState, error)
	// BlockTime is a block's timestamp.
	BlockTime(ctx context.Context, block uint64) (uint64, error)
	// CreateLogs returns the BatchAnchorCreated logs for (bundle, root, validator) in [from, to].
	CreateLogs(ctx context.Context, anchor common.Address, from, to uint64, bundle, root [32]byte, validator common.Address) ([]types.Log, error)
}

// LocateAnchorCreate finds the transaction that created bundle at anchor, created at or before notAfter
// (the block that verified it, or the head). It refuses rather than guesses: an anchor that is not valid,
// names another root, or has no creator; no block with its timestamp; and anything but exactly one log.
func LocateAnchorCreate(ctx context.Context, chain anchorCreateChain, anchor common.Address, bundle, root [32]byte, notAfter uint64) (*AnchorCreateLocation, error) {
	st, err := chain.AnchorRecord(ctx, anchor, bundle)
	if err != nil {
		return nil, fmt.Errorf("reading anchor 0x%x at %s: %w", bundle[:8], anchor.Hex(), err)
	}
	switch {
	case !st.Valid:
		return nil, fmt.Errorf("anchor 0x%x at %s does not exist", bundle[:8], anchor.Hex())
	case st.MerkleRoot != root:
		return nil, fmt.Errorf("anchor 0x%x at %s holds root 0x%x, not 0x%x", bundle[:8], anchor.Hex(), st.MerkleRoot[:8], root[:8])
	case st.CreatedAt == 0 || st.Validator == (common.Address{}):
		return nil, fmt.Errorf("anchor 0x%x at %s records no creation time or creator", bundle[:8], anchor.Hex())
	}
	last, err := chain.BlockTime(ctx, notAfter)
	if err != nil {
		return nil, err
	}
	if last < st.CreatedAt {
		return nil, fmt.Errorf("anchor 0x%x was created at time %d, after block %d (time %d)", bundle[:8], st.CreatedAt, notAfter, last)
	}
	// The first block at or after the creation time, bracketed by galloping back from notAfter: the create
	// is usually seconds before the verify, so the search stays near it and never asks an endpoint for
	// ancient headers it may have pruned (sepolia.base.org serves none below block 46,000,000).
	lo, hi := uint64(0), notAfter
	for step := uint64(1); ; step *= 2 {
		if step > hi {
			lo = 0
			break
		}
		t, err := chain.BlockTime(ctx, hi-step)
		if err != nil {
			return nil, err
		}
		if t < st.CreatedAt {
			lo = hi - step + 1
			break
		}
		hi -= step
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		t, err := chain.BlockTime(ctx, mid)
		if err != nil {
			return nil, err
		}
		if t < st.CreatedAt {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	first := lo
	t, err := chain.BlockTime(ctx, first)
	if err != nil {
		return nil, err
	}
	if t != st.CreatedAt {
		return nil, fmt.Errorf("no block has anchor 0x%x's creation time %d (block %d has %d)", bundle[:8], st.CreatedAt, first, t)
	}
	// Several blocks can share a timestamp (Arbitrum's are sub-second): the creating block is among them.
	final := first
	for final < notAfter {
		next, err := chain.BlockTime(ctx, final+1)
		if err != nil {
			return nil, err
		}
		if next != st.CreatedAt {
			break
		}
		final++
	}
	logs, err := chain.CreateLogs(ctx, anchor, first, final, bundle, root, st.Validator)
	if err != nil {
		return nil, err
	}
	var found []types.Log
	for _, l := range logs {
		if !l.Removed {
			found = append(found, l)
		}
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("blocks %d..%d hold %d BatchAnchorCreated logs for anchor 0x%x by %s, not one",
			first, final, len(found), bundle[:8], st.Validator.Hex())
	}
	return &AnchorCreateLocation{
		TxHash: found[0].TxHash.Hex(), Block: found[0].BlockNumber, Validator: st.Validator, CreatedAt: st.CreatedAt,
	}, nil
}

// clientCreateChain is anchorCreateChain over one endpoint.
type clientCreateChain struct{ c *ethclient.Client }

func (c clientCreateChain) AnchorRecord(ctx context.Context, anchor common.Address, bundle [32]byte) (AnchorOnChainState, error) {
	st, err := ReadAnchorState(ctx, c.c, anchor, bundle, nil)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	return decodeAnchorState(st)
}

func (c clientCreateChain) BlockTime(ctx context.Context, block uint64) (uint64, error) {
	h, err := c.c.HeaderByNumber(ctx, new(big.Int).SetUint64(block))
	if err != nil {
		return 0, fmt.Errorf("reading block %d: %w", block, err)
	}
	if h == nil || h.Number == nil || h.Number.Uint64() != block {
		return 0, fmt.Errorf("the endpoint answered block %d with another header", block)
	}
	return h.Time, nil
}

func (c clientCreateChain) CreateLogs(ctx context.Context, anchor common.Address, from, to uint64, bundle, root [32]byte, validator common.Address) ([]types.Log, error) {
	event, ok := anchorEventsABI.Events["BatchAnchorCreated"]
	if !ok {
		return nil, errors.New("the anchor event ABI declares no BatchAnchorCreated event")
	}
	logs, err := c.c.FilterLogs(ctx, ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{anchor},
		Topics:    [][]common.Hash{{event.ID}, {common.Hash(bundle)}, {common.Hash(root)}, {common.BytesToHash(validator.Bytes())}},
	})
	if err != nil {
		return nil, fmt.Errorf("eth_getLogs %d..%d on %s: %w", from, to, anchor.Hex(), err)
	}
	// The filter is the endpoint's work; what it returns is checked here.
	for _, l := range logs {
		if l.Address != anchor || len(l.Topics) != 4 || l.Topics[0] != event.ID || l.Topics[1] != common.Hash(bundle) ||
			l.Topics[2] != common.Hash(root) || l.Topics[3] != common.BytesToHash(validator.Bytes()) ||
			l.BlockNumber < from || l.BlockNumber > to {
			return nil, fmt.Errorf("eth_getLogs %d..%d on %s returned a log outside the filter (tx %s)", from, to, anchor.Hex(), l.TxHash.Hex())
		}
	}
	return logs, nil
}

// poolCreateChain is anchorCreateChain over a provider pool: each read goes to whichever provider answers.
type poolCreateChain struct{ p *ethrpc.Pool }

func (c poolCreateChain) AnchorRecord(ctx context.Context, anchor common.Address, bundle [32]byte) (st AnchorOnChainState, err error) {
	err = c.p.Do(ctx, func(cl *ethclient.Client) error {
		var e error
		st, e = clientCreateChain{cl}.AnchorRecord(ctx, anchor, bundle)
		return e
	})
	return st, err
}

func (c poolCreateChain) BlockTime(ctx context.Context, block uint64) (t uint64, err error) {
	err = c.p.Do(ctx, func(cl *ethclient.Client) error {
		var e error
		t, e = clientCreateChain{cl}.BlockTime(ctx, block)
		return e
	})
	return t, err
}

func (c poolCreateChain) CreateLogs(ctx context.Context, anchor common.Address, from, to uint64, bundle, root [32]byte, validator common.Address) (logs []types.Log, err error) {
	err = c.p.Do(ctx, func(cl *ethclient.Client) error {
		var e error
		logs, e = clientCreateChain{cl}.CreateLogs(ctx, anchor, from, to, bundle, root, validator)
		return e
	})
	return logs, err
}

// LocateAnchorCreate implements the repair's locating read over this reader's providers.
func (r *EthAnchorTxReader) LocateAnchorCreate(ctx context.Context, chainID int64, anchor string, bundle, root [32]byte, notAfter uint64) (*AnchorCreateLocation, error) {
	if !common.IsHexAddress(anchor) {
		return nil, fmt.Errorf("anchor %q is not an address", anchor)
	}
	p, err := r.pool(chainID)
	if err != nil {
		return nil, err
	}
	return LocateAnchorCreate(ctx, poolCreateChain{p}, common.HexToAddress(strings.TrimSpace(anchor)), bundle, root, notAfter)
}
