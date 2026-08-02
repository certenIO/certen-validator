package execution

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// =============================================================================
// Batch mempool
// =============================================================================
//
// Holds intents that are ALREADY INDIVIDUALLY AUTHORIZED, waiting to be anchored together.
//
// This is the distinction that makes the whole design sound. The mempool never merges
// authorizations: each member arrives with its own operationID (its own Accumulate 4-blob
// intent) and its own executionCommitment, and each becomes its own Merkle leaf. What is
// shared is the ANCHOR and the BLS verification — the attestation, not the authorization.
//
// Because of that, batching here costs nothing in trust: a member's leaf is spendable only
// by the account whose immutable adiURL is hashed into it, for exactly the call committed
// in it. Members cannot affect each other beyond sharing one anchor.
//
// Unlike BatchAccumulator (which groups legs of ONE ADI for a single account call), this
// pool spans MANY ADIs — that is where the 81.2% saving lives, because createAnchor +
// executeComprehensiveProof are paid once for the whole tree.

// PendingBatchIntent is one authorized intent waiting for a tree.
type PendingBatchIntent struct {
	IntentID string
	ADIURL   string
	ChainID  int64

	// Account holding the funds. Must be the CertenAccountV7 for ADIURL.
	Account common.Address

	// OperationID is the Accumulate 4-blob intent hash. Bound into the leaf, so third
	// parties can still verify a single member against the batch root.
	OperationID [32]byte

	// Legs is what this member executes. One leg uses the single-call commitment; more than
	// one uses the multi-leg batch commitment. Both nest inside the same leaf.
	Legs []LegExecution

	// Attestation is the opaque Phase 7-9 snapshot replayed once this member settles.
	Attestation interface{}

	// CommitHeight is the BFT height at which this intent's consensus round committed.
	//
	// This is what makes a batch DETERMINISTIC across validators. EnqueuedAt is local
	// wall-clock and differs on every node, so selecting by it produced divergent trees —
	// observed live 2026-08-01, when validator-2 formed bundleId 0xe4c950df… and validator-3
	// formed 0x5e71d83a… in the same window. Selecting "committed at or before height H"
	// instead gives every validator the same member set, hence the same root, hence the same
	// bundleId — which is precisely what lets a quorum co-sign one batch.
	CommitHeight uint64

	EnqueuedAt time.Time
}

// ExecutionCommitment returns the commitment this member's leaf must carry.
//
// One leg  -> single-call commitment  (identical to the on-demand path)
// N legs   -> multi-leg batch commitment (domain-tagged, disjoint from the single form)
func (p *PendingBatchIntent) ExecutionCommitment() ([32]byte, error) {
	if len(p.Legs) == 0 {
		return [32]byte{}, fmt.Errorf("intent %s has no legs", p.IntentID)
	}
	if len(p.Legs) == 1 {
		leg := p.Legs[0]
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		return computeExecutionCommitment(p.ChainID, leg.Target, v, leg.Data), nil
	}

	calls := make([]BatchCall, 0, len(p.Legs))
	for _, leg := range p.Legs {
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		calls = append(calls, BatchCall{Target: leg.Target, Value: v, Data: leg.Data})
	}
	return computeBatchExecutionCommitment(p.ChainID, calls), nil
}

// IsMultiLeg reports whether this member needs batchExecuteGovernanceProofDirect.
func (p *PendingBatchIntent) IsMultiLeg() bool { return len(p.Legs) > 1 }

// LeafInput converts the member into its tree contribution.
func (p *PendingBatchIntent) LeafInput() (BatchLeafInput, error) {
	exec, err := p.ExecutionCommitment()
	if err != nil {
		return BatchLeafInput{}, err
	}
	return BatchLeafInput{
		ADIURL:              p.ADIURL,
		ExecutionCommitment: exec,
		OperationID:         p.OperationID,
	}, nil
}

// BatchMempoolConfig tunes when a tree is formed.
type BatchMempoolConfig struct {
	// FlushInterval is the cadence at which a non-empty pool is drained.
	FlushInterval time.Duration
	// MaxBatchSize caps members per tree. Bounds worst-case anchor calldata and keeps the
	// Merkle branches short (depth = ceil(log2 N)).
	MaxBatchSize int
	// MinBatchSize is the count that triggers an EARLY flush, before the interval elapses.
	MinBatchSize int
	// MaxAge force-flushes a pool whose oldest member exceeds this, so a quiet chain does
	// not strand an intent behind a long interval.
	MaxAge time.Duration
}

func DefaultBatchMempoolConfig() BatchMempoolConfig {
	return BatchMempoolConfig{
		FlushInterval: 60 * time.Second,
		MaxBatchSize:  64,
		MinBatchSize:  16,
		MaxAge:        5 * time.Minute,
	}
}

func (c BatchMempoolConfig) withDefaults() BatchMempoolConfig {
	d := DefaultBatchMempoolConfig()
	if c.FlushInterval <= 0 {
		c.FlushInterval = d.FlushInterval
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = d.MaxBatchSize
	}
	if c.MinBatchSize <= 0 {
		c.MinBatchSize = d.MinBatchSize
	}
	if c.MaxAge <= 0 {
		c.MaxAge = d.MaxAge
	}
	if c.MinBatchSize > c.MaxBatchSize {
		c.MinBatchSize = c.MaxBatchSize
	}
	return c
}

// BatchMempool pools authorized intents per chain until a tree is worth forming.
//
// Pools are keyed by chain because one anchor lives on one chain: the leaf binds
// block.chainid and the anchor is deployed per-chain, so members from different chains can
// never share a tree.
type BatchMempool struct {
	cfg  BatchMempoolConfig
	mu   sync.Mutex
	pool map[int64][]*PendingBatchIntent
	seen map[string]bool // intentID -> queued, for idempotent Add
}

func NewBatchMempool(cfg BatchMempoolConfig) *BatchMempool {
	return &BatchMempool{
		cfg:  cfg.withDefaults(),
		pool: make(map[int64][]*PendingBatchIntent),
		seen: make(map[string]bool),
	}
}

// Add queues an authorized intent.
//
// Validation happens here rather than at flush time so a malformed member is rejected while
// the caller still has context, instead of poisoning a tree that other intents are waiting on.
func (m *BatchMempool) Add(p *PendingBatchIntent) error {
	if p == nil {
		return fmt.Errorf("nil intent")
	}
	if p.IntentID == "" {
		return fmt.Errorf("intent has no ID")
	}
	if p.ADIURL == "" {
		return fmt.Errorf("intent %s has no ADI URL", p.IntentID)
	}
	if p.Account == (common.Address{}) {
		return fmt.Errorf("intent %s has no account address", p.IntentID)
	}
	if p.OperationID == ([32]byte{}) {
		return fmt.Errorf("intent %s has a zero operationID; the anchor rejects it", p.IntentID)
	}
	if len(p.Legs) == 0 {
		return fmt.Errorf("intent %s has no legs", p.IntentID)
	}
	for i, leg := range p.Legs {
		if leg.ChainID != p.ChainID {
			return fmt.Errorf("intent %s leg %d targets chain %d but the intent is chain %d",
				p.IntentID, i, leg.ChainID, p.ChainID)
		}
	}
	// The commitment must be computable now; a failure here would otherwise surface only
	// when the tree is built, taking the whole batch down with it.
	if _, err := p.ExecutionCommitment(); err != nil {
		return err
	}
	if p.EnqueuedAt.IsZero() {
		p.EnqueuedAt = time.Now()
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.seen[p.IntentID] {
		return fmt.Errorf("intent %s is already queued", p.IntentID)
	}
	m.seen[p.IntentID] = true
	m.pool[p.ChainID] = append(m.pool[p.ChainID], p)
	return nil
}

// DueChains lists chains whose pool should be drained now.
func (m *BatchMempool) DueChains(now time.Time, force bool) []int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	var due []int64
	for chainID, members := range m.pool {
		if len(members) == 0 {
			continue
		}
		if force || len(members) >= m.cfg.MinBatchSize {
			due = append(due, chainID)
			continue
		}
		oldest := members[0].EnqueuedAt
		for _, p := range members {
			if p.EnqueuedAt.Before(oldest) {
				oldest = p.EnqueuedAt
			}
		}
		if now.Sub(oldest) >= m.cfg.MaxAge {
			due = append(due, chainID)
		}
	}
	sort.Slice(due, func(i, j int) bool { return due[i] < due[j] })
	return due
}

// Take removes up to MaxBatchSize members from a chain's pool, oldest first.
//
// Oldest-first matters: without it a busy chain could starve an early intent indefinitely
// while newer ones keep filling each tree.
func (m *BatchMempool) Take(chainID int64) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()

	members := m.pool[chainID]
	if len(members) == 0 {
		return nil
	}
	sort.SliceStable(members, func(i, j int) bool {
		return members[i].EnqueuedAt.Before(members[j].EnqueuedAt)
	})

	n := len(members)
	if n > m.cfg.MaxBatchSize {
		n = m.cfg.MaxBatchSize
	}
	taken := members[:n]
	rest := members[n:]

	if len(rest) == 0 {
		delete(m.pool, chainID)
	} else {
		m.pool[chainID] = append([]*PendingBatchIntent(nil), rest...)
	}
	for _, p := range taken {
		delete(m.seen, p.IntentID)
	}
	return taken
}

// Requeue puts members back after a failed flush, preserving their original enqueue times so
// they keep their place in the oldest-first ordering.
func (m *BatchMempool) Requeue(members []*PendingBatchIntent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range members {
		if p == nil || m.seen[p.IntentID] {
			continue
		}
		m.seen[p.IntentID] = true
		m.pool[p.ChainID] = append(m.pool[p.ChainID], p)
	}
}

// PendingCount returns queued members across all chains.
func (m *BatchMempool) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, v := range m.pool {
		n += len(v)
	}
	return n
}

// PendingCountForChain returns queued members on one chain.
func (m *BatchMempool) PendingCountForChain(chainID int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pool[chainID])
}

// =============================================================================
// Deterministic period selection
// =============================================================================
//
// A batch may only be co-signed by a quorum if every validator derives the SAME batch. These
// two functions are the mechanism: membership is a pure function of (chainID, cutoffHeight)
// over committed state, with no dependence on local clocks or arrival order.

// BatchPeriodCutoff returns the height a batch closes at for the given consensus height.
//
// Heights are bucketed into periods of periodBlocks; the cutoff is the START of the current
// bucket, so an in-flight period is never selected on a boundary race. A validator running a
// few blocks ahead still computes the same cutoff as one lagging, provided both are inside the
// same bucket — and if they are not, their bundleIds differ and neither signs the other's,
// which is the safe outcome rather than a silent mismerge.
func BatchPeriodCutoff(consensusHeight uint64, periodBlocks uint64) uint64 {
	if periodBlocks == 0 {
		periodBlocks = 1
	}
	return (consensusHeight / periodBlocks) * periodBlocks
}

// PeekForPeriod returns the members a batch for periodStart WOULD contain, without removing
// them. Attesters use this: they must be able to recompute a proposer's batch and compare
// bundleIds before signing, but must not lose their copy if the proposer never lands it.
//
// Ordering is by (CommitHeight, IntentID) ascending — deterministic and independent of arrival
// order. Do NOT change this to EnqueuedAt; that is local wall-clock and reintroduces divergence.
func (m *BatchMempool) PeekForPeriod(chainID int64, periodStart, periodBlocks uint64) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selectForPeriodLocked(chainID, periodStart, periodBlocks)
}

// TakeForPeriod is PeekForPeriod plus removal. Only the validator that actually submits the
// batch calls this.
func (m *BatchMempool) TakeForPeriod(chainID int64, periodStart, periodBlocks uint64) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()

	taken := m.selectForPeriodLocked(chainID, periodStart, periodBlocks)
	if len(taken) == 0 {
		return nil
	}
	remove := make(map[string]bool, len(taken))
	for _, p := range taken {
		remove[p.IntentID] = true
		delete(m.seen, p.IntentID)
	}
	var rest []*PendingBatchIntent
	for _, p := range m.pool[chainID] {
		if !remove[p.IntentID] {
			rest = append(rest, p)
		}
	}
	if len(rest) == 0 {
		delete(m.pool, chainID)
	} else {
		m.pool[chainID] = rest
	}
	return taken
}

// selectForPeriodLocked is the shared, deterministic selection. Caller holds m.mu.
//
// # A MEMBER BELONGS TO EXACTLY ONE PERIOD
//
// The window is half-open: periodStart <= CommitHeight < periodStart+periodBlocks. It used to
// be the open-ended "CommitHeight <= cutoff", which was correct ONLY while every validator
// removed taken members in lockstep — and attesters deliberately do not remove (they Peek, so
// a proposer that never lands its batch does not cost them their copy).
//
// With the open-ended rule the first batch worked and every later one failed: the leader had
// removed period P's members, an attester had not, so at period P+1 the leader derived a tree
// over P+1 alone while the attester derived one over P and P+1. Different root, different
// bundleId, refusal — permanently, and looking exactly like an ordinary disagreement.
//
// Bucketing makes selection idempotent and independent of what any node removed. It also means
// a period can be reproduced long after it closed, which is what lets a later leader pick up a
// bucket an earlier one failed to flush.
func (m *BatchMempool) selectForPeriodLocked(
	chainID int64,
	periodStart, periodBlocks uint64,
) []*PendingBatchIntent {
	src := m.pool[chainID]
	if len(src) == 0 {
		return nil
	}
	if periodBlocks == 0 {
		return nil
	}
	periodEnd := periodStart + periodBlocks // exclusive

	eligible := make([]*PendingBatchIntent, 0, len(src))
	for _, p := range src {
		if p == nil {
			continue
		}
		// A member with no commit height cannot be placed in a period deterministically —
		// including it would make this validator's tree differ from one that had not yet seen
		// it. Skip rather than guess; it becomes eligible once its height is known.
		if p.CommitHeight == 0 {
			continue
		}
		if p.CommitHeight >= periodStart && p.CommitHeight < periodEnd {
			eligible = append(eligible, p)
		}
	}
	if len(eligible) == 0 {
		return nil
	}

	sort.SliceStable(eligible, func(i, j int) bool {
		if eligible[i].CommitHeight != eligible[j].CommitHeight {
			return eligible[i].CommitHeight < eligible[j].CommitHeight
		}
		return eligible[i].IntentID < eligible[j].IntentID
	})

	// The cap must be applied identically everywhere, and after sorting, or two validators
	// holding the same members could truncate to different subsets.
	if len(eligible) > m.cfg.MaxBatchSize {
		eligible = eligible[:m.cfg.MaxBatchSize]
	}
	return eligible
}

// PendingPeriods returns the period starts, ascending, that hold members for this chain and are
// strictly older than beforeStart.
//
// The flush loop iterates these rather than only the most recently closed period. A period
// whose elected leader was down, or whose flush failed before the anchor, would otherwise sit
// in every node's pool forever: nobody would ever select it again, because selection is now
// bucket-scoped. Leadership rotates per period, so the next leader picks up the straggler.
func (m *BatchMempool) PendingPeriods(chainID int64, periodBlocks, beforeStart uint64) []uint64 {
	if periodBlocks == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := map[uint64]bool{}
	for _, p := range m.pool[chainID] {
		if p == nil || p.CommitHeight == 0 {
			continue
		}
		start := (p.CommitHeight / periodBlocks) * periodBlocks
		// Strictly older: the current period may still be accepting members, and forming a
		// batch over a period that has not closed is what made trees diverge in the first place.
		if start < beforeStart {
			seen[start] = true
		}
	}
	out := make([]uint64, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PruneOlderThan removes members whose period closed more than the retention horizon ago, and
// reports how many went.
//
// This is a MEMORY backstop, not a correctness mechanism — bucket-scoped selection already makes
// stale members harmless to the tree. It exists because attesters never remove what they peek
// at: on a validator that is not the leader, every member it has ever seen would otherwise
// accumulate for the life of the process.
//
// It deliberately does NOT route the pruned members to the per-intent fallback. On a non-leader
// those members were settled by whichever node did lead their period, and re-executing them
// individually would double-spend the intent. Only FlushChain, which the leader alone runs,
// produces members that genuinely need a fallback.
func (m *BatchMempool) PruneOlderThan(horizonStart uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	pruned := 0
	for chainID, pool := range m.pool {
		var rest []*PendingBatchIntent
		for _, p := range pool {
			if p != nil && p.CommitHeight != 0 && p.CommitHeight < horizonStart {
				delete(m.seen, p.IntentID)
				pruned++
				continue
			}
			rest = append(rest, p)
		}
		if len(rest) == 0 {
			delete(m.pool, chainID)
		} else {
			m.pool[chainID] = rest
		}
	}
	return pruned
}

// DropMembers removes specific members, used when a batch settled elsewhere (the leader landed
// it) or when members fall back to the per-intent path. Fallback is the approved policy on
// quorum failure: requeueing risks a permanently stuck batch, whereas falling back costs more
// gas but always settles.
func (m *BatchMempool) DropMembers(members []*PendingBatchIntent) {
	if len(members) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	remove := make(map[string]bool, len(members))
	for _, p := range members {
		if p != nil {
			remove[p.IntentID] = true
			delete(m.seen, p.IntentID)
		}
	}
	for chainID, pool := range m.pool {
		var rest []*PendingBatchIntent
		for _, p := range pool {
			if p != nil && !remove[p.IntentID] {
				rest = append(rest, p)
			}
		}
		if len(rest) == 0 {
			delete(m.pool, chainID)
		} else {
			m.pool[chainID] = rest
		}
	}
}
