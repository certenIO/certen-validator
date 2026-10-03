// Copyright 2026 Certen Protocol

package execution

import (
	"bytes"
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
	"github.com/certen/independant-validator/pkg/execution/contracts"
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

// agreedCreateChain is anchorCreateChain over a chain's agreeing providers (RB5-F53), for the repairs that write what
// they locate:
//   - the anchor's record is an agreed call at a recent block every provider holds identically;
//   - a block's time is the agreed header at its height;
//   - BatchAnchorCreated logs are LOCATED through every provider, and each is taken only once its transaction's agreed
//     receipt carries it, in the agreed canonical block at its height. A provider that hides a log cannot hide it from
//     the others; one that invents a log is refused by the agreed receipt.
type agreedCreateChain struct{ a *ethrpc.AgreeingReader }

func (c agreedCreateChain) AnchorRecord(ctx context.Context, anchor common.Address, bundle [32]byte) (AnchorOnChainState, error) {
	at, err := c.a.RecentAgreedHeader(ctx)
	if err != nil {
		return AnchorOnChainState{}, fmt.Errorf("an agreed block to read anchors(0x%x) at: %w", bundle[:8], err)
	}
	ret, err := c.a.CallContractAtHash(ctx, ethereum.CallMsg{To: &anchor, Data: contracts.AnchorsCallData(bundle)}, at.Hash())
	if err != nil {
		return AnchorOnChainState{}, fmt.Errorf("reading anchors(0x%x) on %s: %w", bundle[:8], anchor.Hex(), err)
	}
	st, err := contracts.DecodeAnchorsReturn(ret)
	if err != nil {
		return AnchorOnChainState{}, err
	}
	return decodeAnchorState(st)
}

func (c agreedCreateChain) BlockTime(ctx context.Context, block uint64) (uint64, error) {
	h, err := c.a.HeaderByNumber(ctx, new(big.Int).SetUint64(block))
	if err != nil {
		return 0, fmt.Errorf("reading block %d: %w", block, err)
	}
	if h == nil || h.Number == nil || h.Number.Uint64() != block {
		return 0, fmt.Errorf("the providers answered block %d with another header", block)
	}
	return h.Time, nil
}

func (c agreedCreateChain) CreateLogs(ctx context.Context, anchor common.Address, from, to uint64, bundle, root [32]byte, validator common.Address) ([]types.Log, error) {
	event, ok := anchorEventsABI.Events["BatchAnchorCreated"]
	if !ok {
		return nil, errors.New("the anchor event ABI declares no BatchAnchorCreated event")
	}
	q := ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{anchor},
		Topics:    [][]common.Hash{{event.ID}, {common.Hash(bundle)}, {common.Hash(root)}, {common.BytesToHash(validator.Bytes())}},
	}
	type logKey struct {
		tx    common.Hash
		index uint
	}
	located := map[logKey]types.Log{}
	var order []logKey
	answered := 0
	var failures []string
	for _, loc := range c.a.Locators() {
		logs, err := loc.FilterLogs(ctx, q)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", loc.Host, err))
			continue
		}
		answered++
		for _, l := range logs {
			if l.Removed {
				continue
			}
			k := logKey{l.TxHash, l.Index}
			if _, seen := located[k]; !seen {
				located[k] = l
				order = append(order, k)
			}
		}
	}
	// Exactly one log is the answer, so every provider's search counts: one that could not search might hold a second.
	if answered < ethrpc.MinAgreeingProviders || len(failures) > 0 {
		return nil, fmt.Errorf("%w: eth_getLogs %d..%d on %s: %d of %d providers searched (%s)", ethrpc.ErrTooFewProviders,
			from, to, anchor.Hex(), answered, answered+len(failures), strings.Join(failures, "; "))
	}
	var established []types.Log
	for _, k := range order {
		l, err := c.establishLog(ctx, located[k], q, from, to)
		if err != nil {
			return nil, err
		}
		established = append(established, l)
	}
	return established, nil
}

// establishLog takes a located log only as its transaction's agreed receipt states it, in the agreed canonical block at
// its height, inside [from, to] and matching the filter.
func (c agreedCreateChain) establishLog(ctx context.Context, l types.Log, q ethereum.FilterQuery, from, to uint64) (types.Log, error) {
	r, err := c.a.TransactionReceipt(ctx, l.TxHash)
	if err != nil {
		return types.Log{}, fmt.Errorf("the receipt of %s, which a provider says logged BatchAnchorCreated: %w", l.TxHash.Hex(), err)
	}
	if r.BlockNumber == nil || r.BlockNumber.Uint64() < from || r.BlockNumber.Uint64() > to {
		return types.Log{}, fmt.Errorf("the agreed receipt of %s is in block %v, outside %d..%d", l.TxHash.Hex(), r.BlockNumber, from, to)
	}
	canonical, err := c.a.HeaderByNumber(ctx, r.BlockNumber)
	if err != nil {
		return types.Log{}, fmt.Errorf("the canonical block at %d: %w", r.BlockNumber.Uint64(), err)
	}
	if canonical.Hash() != r.BlockHash {
		return types.Log{}, fmt.Errorf("the agreed receipt of %s names block %s, not the canonical block %d", l.TxHash.Hex(), r.BlockHash.Hex(), r.BlockNumber.Uint64())
	}
	for _, rl := range r.Logs {
		if rl.Index != l.Index {
			continue
		}
		if rl.Address != q.Addresses[0] || len(rl.Topics) != 4 || rl.Topics[0] != q.Topics[0][0] || rl.Topics[1] != q.Topics[1][0] ||
			rl.Topics[2] != q.Topics[2][0] || rl.Topics[3] != q.Topics[3][0] || !bytes.Equal(rl.Data, l.Data) {
			break
		}
		return *rl, nil
	}
	return types.Log{}, fmt.Errorf("the agreed receipt of %s does not carry the BatchAnchorCreated log a provider located at index %d", l.TxHash.Hex(), l.Index)
}

// LocateAnchorCreate implements the repair's locating read through the chain's agreeing providers.
func (r *EthAnchorTxReader) LocateAnchorCreate(ctx context.Context, chainID int64, anchor string, bundle, root [32]byte, notAfter uint64) (*AnchorCreateLocation, error) {
	if !common.IsHexAddress(anchor) {
		return nil, fmt.Errorf("anchor %q is not an address", anchor)
	}
	a, err := r.reader(ctx, chainID)
	if err != nil {
		return nil, err
	}
	return LocateAnchorCreate(ctx, agreedCreateChain{a}, common.HexToAddress(strings.TrimSpace(anchor)), bundle, root, notAfter)
}
