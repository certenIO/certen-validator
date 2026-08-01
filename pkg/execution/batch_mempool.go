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
