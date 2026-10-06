// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/supportedchains"
)

// =============================================================================
// One clock per chain (RB7 §1.1, decision D7)
// =============================================================================
//
// Every rule that asks "what time is it on this chain" reads it here, and only here:
//
//	T-1  settleMember: no settlement is sent while the head's time is before the leaf's notBefore
//	T-2  settlementExpiry: the settlement's timestamp and expiresAt are the head's time
//	T-3  allPendingPastDeadline: an expired batch is not anchored, judged at the head's time
//	T-4  the settlement windows: the window index is the head's time, a taker acts once the finalized time is past the
//	     previous fence (decideSettlementWindow, OnDemandMemberNeedsThisValidator)
//	T-5  the prior-attempt scan stops at the finalized block
//	T-6  observeNonSettlementAt: a non-settlement is attestable once the finalized time is past deadline + 2 min
//	T-7  verifyNonSettlementClaim: a peer re-reads the finalized block and the claim's block
//	T-8  sequenceReadiness: a predecessor failed once the finalized time is past its deadline + 2 min
//	T-9  deriveMember: status 3 needs the finalized time past deadline + margin, at the first block past it
//	T-10 the outcome record and a consumption are final at or below the finalized block
//	T-11 blockAtOrBefore: a time is placed under the head
//
// The predicates are the rules' own and unchanged; what changed is the SOURCE of the time. It is the chain's agreeing
// reader (ethrpc.AgreeingReader, RB5-F53): a time is a block header at least MinAgreeingProviders independent providers
// return identically, the finalized and latest tags the LOWEST any of them reports - never one provider's word, and never
// this machine's clock. On a pinned chain every read is also refused by name when a provider serves another genesis
// (ethrpc genesis.go, RB7 D8).
//
// A chain whose blocks stop when it is idle (supportedchains.Chain.BlocksOnlyWithTraffic: Telcoin Adiri) also has a
// heartbeat (chain_heartbeat.go): a rule blocked ONLY because no block yet passes its horizon says so (AwaitTime,
// AwaitBlock), and the heartbeat makes such a block exist. The block then decides, through the same predicate, exactly as
// a block of anyone's traffic would. On every other chain AwaitTime and AwaitBlock do nothing.

// chainClockSource is what a clock reads: headers by number or by tag. In production the chain's agreeing reader.
type chainClockSource interface {
	HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error)
}

// ChainClock is one chain's time.
type ChainClock struct {
	chainID int64
	primary string

	mu   sync.Mutex
	src  chainClockSource
	beat *chainHeartbeat
}

// chainClocks is the process's clock per chain: every rule of a chain reads the one clock, and one heartbeat serves them.
var chainClocks = struct {
	sync.Mutex
	m map[int64]*ChainClock
}{m: map[int64]*ChainClock{}}

// chainClockFor is chainID's clock, created on first use over the chain's agreeing providers (primary plus every
// fallback configured for the chain, ethrpc.EndpointsForChainID). Nothing is dialled until the first read.
func chainClockFor(chainID int64, primary string) *ChainClock {
	chainClocks.Lock()
	defer chainClocks.Unlock()
	c := chainClocks.m[chainID]
	if c == nil {
		c = &ChainClock{chainID: chainID, primary: primary}
		chainClocks.m[chainID] = c
	}
	if c.primary == "" {
		c.primary = primary
	}
	return c
}

// registeredChainClock is chainID's clock when one exists.
func registeredChainClock(chainID int64) *ChainClock {
	chainClocks.Lock()
	defer chainClocks.Unlock()
	return chainClocks.m[chainID]
}

// adoptChainClockSource gives chainID's clock an agreeing reader built elsewhere for the same providers, when the clock
// has none yet: the outcome reads and the clock then read through one reader.
func adoptChainClockSource(chainID int64, primary string, src chainClockSource) *ChainClock {
	c := chainClockFor(chainID, primary)
	c.mu.Lock()
	if c.src == nil {
		c.src = src
	}
	c.mu.Unlock()
	return c
}

// newChainClock is a clock over src, outside the registry (an orchestrator's own seam, and tests).
func newChainClock(chainID int64, src chainClockSource) *ChainClock {
	return &ChainClock{chainID: chainID, src: src}
}

// ChainID is the chain the clock reads.
func (c *ChainClock) ChainID() int64 { return c.chainID }

func (c *ChainClock) source(ctx context.Context) (chainClockSource, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.src != nil {
		return c.src, nil
	}
	r, err := ethrpc.NewAgreeingReader(ctx, c.chainID, ethrpc.EndpointsForChainID(c.chainID, c.primary), ethrpc.DefaultReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("the clock of chain %d: %w", c.chainID, err)
	}
	c.src = r
	return r, nil
}

func (c *ChainClock) header(ctx context.Context, number *big.Int, what string) (*types.Header, error) {
	if c == nil {
		return nil, readErr(fmt.Errorf("no chain clock to read the %s from", what))
	}
	src, err := c.source(ctx)
	if err != nil {
		return nil, readErr(err)
	}
	// The source's own error, unchanged: a caller classifies it exactly as it classified a direct read (a disagreement or
	// a shortage of providers is "not yet", anything else as before).
	h, err := src.HeaderByNumber(ctx, number)
	if err != nil {
		return nil, err
	}
	if h == nil || h.Number == nil {
		return nil, readErr(fmt.Errorf("chain %d %s: no header", c.chainID, what))
	}
	return h, nil
}

// Head is the chain's latest block: the lowest latest block the agreeing providers report.
func (c *ChainClock) Head(ctx context.Context) (*types.Header, error) {
	return c.header(ctx, big.NewInt(int64(rpc.LatestBlockNumber)), "head")
}

// Finalized is the chain's finalized block: the lowest finalized block the agreeing providers report.
func (c *ChainClock) Finalized(ctx context.Context) (*types.Header, error) {
	return c.header(ctx, big.NewInt(int64(rpc.FinalizedBlockNumber)), "finalized block")
}

// HeaderAt is the agreed header at height number.
func (c *ChainClock) HeaderAt(ctx context.Context, number uint64) (*types.Header, error) {
	return c.header(ctx, new(big.Int).SetUint64(number), fmt.Sprintf("block %d", number))
}

// AwaitTime says that rule is blocked ONLY because no finalized block of the chain has a time after `after` (unix
// seconds). On a chain with a heartbeat it is a horizon to make a block past; anywhere else it does nothing - the
// chain's own blocks pass every horizon.
func (c *ChainClock) AwaitTime(rule string, after uint64) {
	if b := c.heartbeat(); b != nil {
		b.awaitTime(rule, after)
	}
}

// AwaitBlock says that rule is blocked ONLY because the chain's finalized head has not reached block number.
func (c *ChainClock) AwaitBlock(rule string, number uint64) {
	if b := c.heartbeat(); b != nil {
		b.awaitBlock(rule, number)
	}
}

func (c *ChainClock) heartbeat() *chainHeartbeat {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.beat
}

// setHeartbeat attaches the chain's heartbeat. Only a chain whose blocks stop when idle may have one.
func (c *ChainClock) setHeartbeat(b *chainHeartbeat) error {
	ch, ok := supportedchains.Lookup(c.chainID)
	if b != nil && (!ok || !ch.BlocksOnlyWithTraffic) {
		return fmt.Errorf("chain %d produces blocks without traffic: it has no heartbeat", c.chainID)
	}
	c.mu.Lock()
	c.beat = b
	c.mu.Unlock()
	return nil
}

// awaitChainTime is AwaitTime on chainID's registered clock (nothing when the chain has none).
func awaitChainTime(chainID int64, rule string, after uint64) {
	registeredChainClock(chainID).AwaitTime(rule, after)
}

// awaitChainBlock is AwaitBlock on chainID's registered clock.
func awaitChainBlock(chainID int64, rule string, number uint64) {
	registeredChainClock(chainID).AwaitBlock(rule, number)
}
