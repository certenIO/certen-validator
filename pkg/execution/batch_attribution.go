package execution

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
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
// before it was created, and a leaf cannot be spent before its member committed on Accumulate - so
// they are complete however old the anchor, and they stop at the first match, which is normally a few
// blocks in. There is no fixed block-count window anywhere: blocks per hour differ about fifty-fold
// between the supported chains.

// leafConsumedTopic is keccak256("LeafConsumed(bytes32,bytes32,bytes32)"), CertenAccountV7's record
// of a leaf being spent: anchorId and leaf are indexed.
var leafConsumedTopic = crypto.Keccak256Hash([]byte("LeafConsumed(bytes32,bytes32,bytes32)"))

// leafSpendMargin is subtracted from a member's first-seen time by the outcome records, to find where to
// search for its leaf's consumption.
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
	leaf, err := p.Leaf()
	if err != nil {
		return "", common.Address{}, false, err
	}
	topics := [][]common.Hash{{leafConsumedTopic}, nil, {common.Hash(leaf)}}

	// The earliest block the leaf could have been spent in is the LOWEST of the floors known for it:
	// the member's commit on Accumulate (less a margin - the clocks of the two networks differ), its
	// anchor's creation when this node created it, and its bundle's anchor creation. A leaf cannot be
	// spent before its member committed, so each is a sound floor; the lowest keeps the search complete
	// when one of them is late. This node's first sighting is NOT a floor: another validator may have
	// settled the member long before this one saw it.
	//
	// The commit time is REQUIRED: an anchor's creation is only a sound floor when it is not above the spend, and the
	// member's own anchor (this node's, or its bundle's) can be created long after another validator spent the leaf
	// under an earlier one. So those two can only LOWER the commit floor; with no commit time there is no floor, and the
	// member is refused by name (deferred, retried), never searched for from a guess.
	if p.CommitTime.IsZero() {
		return "", common.Address{}, false, fmt.Errorf("member %s: no commit time, so no floor for its leaf's spend", p.IntentID)
	}
	ts := uint64(p.CommitTime.Unix())
	if ts > anchorFloorMargin {
		ts -= anchorFloorMargin
	}
	floor, ferr := o.cachedBlockAt(ctx, ts)
	if ferr != nil {
		return "", common.Address{}, false, ferr
	}
	lower := func(b uint64) {
		if b < floor {
			floor = b
		}
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
	l, err := o.scanForward(ctx, p.Account, topics, floor)
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

	st, err := ReadAnchorState(ctx, o.ecm.client, o.anchorV7, bundleID, nil)
	if err != nil {
		return 0, readErr(err)
	}
	ts := st.Timestamp
	if ts == nil || ts.Sign() <= 0 {
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

// blockAtOrBefore is the highest block whose timestamp is <= ts (0 if none).
func (o *BatchOrchestrator) blockAtOrBefore(ctx context.Context, ts uint64) (uint64, error) {
	// "Now" is the chain's head, from its clock (T-11). A time after the head is placed AT the head: no later block
	// exists yet, and every later block will have a later time (block times never decrease).
	head, err := o.chainHead(ctx)
	if err != nil {
		return 0, readErr(fmt.Errorf("reading the head: %w", err))
	}
	timeAt := func(n uint64) (uint64, error) {
		h, err := o.ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(n))
		if err != nil {
			// One retry: against a load-balanced RPC a single lagging backend should not abort the
			// whole search.
			if h, err = o.ecm.client.HeaderByNumber(ctx, new(big.Int).SetUint64(n)); err != nil {
				return 0, readErr(fmt.Errorf("reading block %d: %w", n, err))
			}
		}
		return h.Time, nil
	}
	return searchBlockAtOrBefore(head.Number.Uint64(), head.Time, ts, timeAt)
}

// searchBlockAtOrBefore finds the highest block whose timestamp is <= ts, reading only blocks near
// it: it steps back from the head in doubling strides until it passes ts, then bisects that stride.
//
// Bisecting the whole chain from block 0 would read head/2 first. A node that prunes history does
// not serve that block, so on such an RPC every lookup failed however recent ts was (live on
// base-sepolia: head ~47.3M, earliest retained 45.5M, first probe ~23.65M). The timestamps asked
// about are recent - a member's first sighting, an anchor's creation - so the blocks read here are
// recent too. A ts older than the node retains still fails, because those blocks are gone.
func searchBlockAtOrBefore(head, headTime, ts uint64, timeAt func(uint64) (uint64, error)) (uint64, error) {
	if headTime <= ts {
		return head, nil
	}
	// invariant: time(hi) > ts, and time(lo) <= ts or lo == 0
	hi, lo := head, uint64(0)
	for stride := uint64(1); ; stride *= 2 {
		if stride >= hi {
			lo = 0
			break
		}
		cand := hi - stride
		t, err := timeAt(cand)
		if err != nil {
			return 0, err
		}
		if t <= ts {
			lo = cand
			break
		}
		hi = cand
	}
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		t, err := timeAt(mid)
		if err != nil {
			return 0, err
		}
		if t <= ts {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo, nil
}

// scanForward returns the first log matching topics on address from block `from` to the head,
// searching in chunks (split further wherever the RPC caps the range - filterLogsSplitting).
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
		logs, err := filterLogsSplitting(ctx, o.ecm.client, ethereum.FilterQuery{
			Addresses: []common.Address{address},
			Topics:    topics,
		}, lo, hi)
		if err != nil {
			return nil, readErr(fmt.Errorf("%w on %s", err, address.Hex()))
		}
		if len(logs) > 0 {
			l := logs[0]
			return &l, nil
		}
	}
	return nil, nil
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
