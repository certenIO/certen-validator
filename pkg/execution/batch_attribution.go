package execution

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Attribution from the chain: who spent a leaf, who attested an anchor
// =============================================================================
//
// Whose outcome a member is - this node's to record, or another sender's - is decided from the
// chain, never from local memory. Local memory can be lost to a restart, a failed write or a
// transaction replaced while nobody was listening; the log of the transaction that spent a leaf, or
// that attested an anchor, cannot. Its SENDER is the answer: this node's key means this node's work,
// whichever of its hashes mined.
//
// Both searches run FORWARD from a floor the event cannot precede - an anchor cannot be attested
// before it was created, and a leaf cannot be spent before its member existed - so they are complete
// however old the anchor, and they stop at the first match, which is normally a few blocks in.

// leafConsumedTopic is keccak256("LeafConsumed(bytes32,bytes32,bytes32)"), CertenAccountV7's record
// of a leaf being spent: anchorId and leaf are indexed.
var leafConsumedTopic = crypto.Keccak256Hash([]byte("LeafConsumed(bytes32,bytes32,bytes32)"))

// attributionLookback bounds a backward search when no floor is known at all - only for a member
// restored from a queue written before members recorded when they were first seen.
const attributionLookback = 300000

// leafSpendMargin is subtracted from a member's first-seen time to find the earliest block its leaf
// could have been spent in: another validator may have enqueued, anchored and settled it before this
// node saw it.
const leafSpendMargin = time.Hour

// anchorFloorMargin: see anchorFloor.
const anchorFloorMargin = 60

// attributionFloors caches the block an anchor was created in (the attester search floor) and the
// block a timestamp maps to, per orchestrator. Both never change.
type attributionFloors struct {
	mu      sync.Mutex
	anchors map[[32]byte]uint64
	times   map[uint64]uint64
}

// cachedBlockAt is blockAtOrBefore, remembered: a member's floor is asked for on every pass.
func (o *BatchOrchestrator) cachedBlockAt(ctx context.Context, ts uint64) (uint64, error) {
	o.floors.mu.Lock()
	if b, ok := o.floors.times[ts]; ok {
		o.floors.mu.Unlock()
		return b, nil
	}
	o.floors.mu.Unlock()
	b, err := o.blockAtOrBefore(ctx, ts)
	if err != nil {
		return 0, err
	}
	o.floors.mu.Lock()
	if o.floors.times == nil {
		o.floors.times = make(map[uint64]uint64)
	}
	o.floors.times[ts] = b
	o.floors.mu.Unlock()
	return b, nil
}

// leafConsumedTx finds the transaction that spent member p's leaf, from the account's own LeafConsumed
// log, and the address that sent it. A leaf is spent at most once, so there is at most one such log,
// under whichever anchor. bundleID is the member's own anchor when it has one, used for the floor.
// found is false when no such log is in view: nothing may be concluded then.
func (o *BatchOrchestrator) leafConsumedTx(ctx context.Context, p *PendingBatchIntent, bundleID [32]byte) (string, common.Address, bool, error) {
	exec, err := p.ExecutionCommitment()
	if err != nil {
		return "", common.Address{}, false, err
	}
	leaf := ComputeBatchLeaf(p.ChainID, BatchLeafInput{ADIURL: p.ADIURL, ExecutionCommitment: exec, OperationID: p.OperationID})
	topics := [][]common.Hash{{leafConsumedTopic}, nil, {common.Hash(leaf)}}

	// The earliest block the leaf could have been spent in is the LOWEST of the floors known for it:
	// the member's first sighting (less a margin - another validator may have seen it first), its
	// anchor's creation when this node created it, and its bundle's anchor creation. Taking the
	// lowest keeps the search complete when one of them is late (a member restored from a queue
	// written before FirstSeen existed carries its restore time).
	floor, have := uint64(0), false
	lower := func(b uint64) {
		if !have || b < floor {
			floor, have = b, true
		}
	}
	if !p.FirstSeen.IsZero() {
		b, ferr := o.cachedBlockAt(ctx, uint64(p.FirstSeen.Add(-leafSpendMargin).Unix()))
		if ferr != nil {
			return "", common.Address{}, false, ferr
		}
		lower(b)
	}
	if p.AnchorBlock > 0 {
		lower(p.AnchorBlock)
	}
	if bundleID != ([32]byte{}) {
		b, ferr := o.anchorFloor(ctx, bundleID)
		if ferr != nil {
			return "", common.Address{}, false, ferr
		}
		lower(b)
	}
	var l *types.Log
	if have {
		l, err = o.scanForward(ctx, p.Account, topics, floor)
		if err == nil && l == nil {
			// Nothing from the floor: a floor that was still too late cannot hide a spend - search
			// back from the head as well before concluding the spend is not in view.
			l, err = o.scanBack(ctx, p.Account, topics)
		}
	} else {
		l, err = o.scanBack(ctx, p.Account, topics)
	}
	if err != nil || l == nil {
		return "", common.Address{}, false, err
	}
	from, err := o.logSender(ctx, l)
	if err != nil {
		return "", common.Address{}, false, err
	}
	return l.TxHash.Hex(), from, true, nil
}

// anchorAttester finds the transaction that attested bundleID on the anchor contract (its
// ProofExecuted event) and the address that sent it. An anchor is attested at most once
// (usedCommitments), so there is at most one such event. floor is the anchor's creation block when
// the caller knows it; zero looks it up. found is false when none is in view.
func (o *BatchOrchestrator) anchorAttester(ctx context.Context, bundleID [32]byte, floor uint64) (string, common.Address, bool, error) {
	if floor == 0 {
		f, err := o.anchorFloor(ctx, bundleID)
		if err != nil {
			return "", common.Address{}, false, err
		}
		floor = f
	}
	l, err := o.scanForward(ctx, o.anchorV7, [][]common.Hash{{proofExecutedTopic}, {common.Hash(bundleID)}}, floor)
	if err != nil || l == nil {
		return "", common.Address{}, false, err
	}
	from, err := o.logSender(ctx, l)
	if err != nil {
		return "", common.Address{}, false, err
	}
	return l.TxHash.Hex(), from, true, nil
}

// anchorFloor is the block bundleID's anchor was created in, found from the creation timestamp the
// anchor stores. Cached: it never changes.
func (o *BatchOrchestrator) anchorFloor(ctx context.Context, bundleID [32]byte) (uint64, error) {
	o.floors.mu.Lock()
	if b, ok := o.floors.anchors[bundleID]; ok {
		o.floors.mu.Unlock()
		return b, nil
	}
	o.floors.mu.Unlock()

	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return 0, err
	}
	bound := bind.NewBoundContract(o.anchorV7, parsed, o.ecm.client, o.ecm.client, o.ecm.client)
	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return 0, readErr(fmt.Errorf("reading anchor 0x%x: %w", bundleID[:8], err))
	}
	const timestampField = 9
	if len(out) <= timestampField {
		return 0, fmt.Errorf("anchors() returned %d fields; the Anchor struct layout changed", len(out))
	}
	ts, ok := out[timestampField].(*big.Int)
	if !ok || ts.Sign() <= 0 {
		return 0, fmt.Errorf("anchor 0x%x has no creation timestamp", bundleID[:8])
	}
	// A minute early: several blocks can share one timestamp (Arbitrum), and "the highest block at
	// or before the creation time" can then be AFTER the creation block - and after an attestation
	// in the same second. Starting early only costs a few blocks of search.
	t := ts.Uint64()
	if t > anchorFloorMargin {
		t -= anchorFloorMargin
	}
	b, err := o.blockAtOrBefore(ctx, t)
	if err != nil {
		return 0, err
	}
	o.floors.mu.Lock()
	if o.floors.anchors == nil {
		o.floors.anchors = make(map[[32]byte]uint64)
	}
	o.floors.anchors[bundleID] = b
	o.floors.mu.Unlock()
	return b, nil
}

// blockAtOrBefore is the highest block whose timestamp is <= ts (0 if none), by binary search.
func (o *BatchOrchestrator) blockAtOrBefore(ctx context.Context, ts uint64) (uint64, error) {
	head, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, readErr(fmt.Errorf("reading the head: %w", err))
	}
	if head.Time <= ts {
		return head.Number.Uint64(), nil
	}
	lo, hi := uint64(0), head.Number.Uint64() // invariant: time(hi) > ts
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		h, err := o.ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(mid))
		if err != nil {
			// One retry: against a load-balanced RPC a single lagging backend should not abort the
			// whole search.
			if h, err = o.ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(mid)); err != nil {
				return 0, readErr(fmt.Errorf("reading block %d: %w", mid, err))
			}
		}
		if h.Time <= ts {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

// scanForward returns the first log matching topics on address from block `from` to the head,
// searching in chunks a public RPC will serve.
func (o *BatchOrchestrator) scanForward(ctx context.Context, address common.Address, topics [][]common.Hash, from uint64) (*types.Log, error) {
	head, err := o.ecm.client.BlockNumber(ctx)
	if err != nil {
		return nil, readErr(fmt.Errorf("reading the head: %w", err))
	}
	for lo := from; lo <= head; lo += proofExecutedChunk {
		hi := lo + proofExecutedChunk - 1
		if hi > head {
			hi = head
		}
		logs, err := o.ecm.client.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(lo),
			ToBlock:   new(big.Int).SetUint64(hi),
			Addresses: []common.Address{address},
			Topics:    topics,
		})
		if err != nil {
			return nil, readErr(fmt.Errorf("logs %d-%d on %s: %w", lo, hi, address.Hex(), err))
		}
		if len(logs) > 0 {
			l := logs[0]
			return &l, nil
		}
	}
	return nil, nil
}

// scanBack returns the most recent log matching topics on address within attributionLookback blocks
// of the head. Used only when no floor is known.
func (o *BatchOrchestrator) scanBack(ctx context.Context, address common.Address, topics [][]common.Hash) (*types.Log, error) {
	head, err := o.ecm.client.BlockNumber(ctx)
	if err != nil {
		return nil, readErr(fmt.Errorf("reading the head: %w", err))
	}
	floor := uint64(0)
	if head > attributionLookback {
		floor = head - attributionLookback
	}
	for hi := head; ; {
		lo := floor
		if hi > proofExecutedChunk && hi-proofExecutedChunk+1 > floor {
			lo = hi - proofExecutedChunk + 1
		}
		logs, err := o.ecm.client.FilterLogs(ctx, ethereum.FilterQuery{
			FromBlock: new(big.Int).SetUint64(lo),
			ToBlock:   new(big.Int).SetUint64(hi),
			Addresses: []common.Address{address},
			Topics:    topics,
		})
		if err != nil {
			return nil, readErr(fmt.Errorf("logs %d-%d on %s: %w", lo, hi, address.Hex(), err))
		}
		if n := len(logs); n > 0 {
			l := logs[n-1]
			return &l, nil
		}
		if lo <= floor {
			return nil, nil
		}
		hi = lo - 1
	}
}

// logSender is the address that sent the transaction which emitted l, read from the node's own record
// of the transaction ("from" in eth_getTransactionByHash). Nothing is decoded or recovered locally, so
// transaction types this binary cannot parse - an L2 deposit, a retryable - are attributed all the same.
func (o *BatchOrchestrator) logSender(ctx context.Context, l *types.Log) (common.Address, error) {
	var raw struct {
		From *common.Address `json:"from"`
	}
	if err := o.ecm.client.Client().CallContext(ctx, &raw, "eth_getTransactionByHash", l.TxHash); err != nil {
		return common.Address{}, readErr(fmt.Errorf("reading transaction %s: %w", l.TxHash.Hex(), err))
	}
	if raw.From == nil {
		return common.Address{}, readErr(fmt.Errorf("transaction %s has no sender in the node's answer", l.TxHash.Hex()))
	}
	return *raw.From, nil
}
