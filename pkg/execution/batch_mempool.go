package execution

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/ethereum/go-ethereum/common"
)

// Admission outcomes a caller must be able to tell apart. They are consensus's (it owns the
// BatchEnqueuer interface this package implements), aliased so both packages match with errors.Is.
var (
	// ErrMemberAlreadyQueued is the SAME intent arriving again for a chain it is already queued on
	// - a workflow re-run. It is not a refusal, and the intent must not be executed a second time.
	ErrMemberAlreadyQueued = consensus.ErrMemberAlreadyQueued
	// ErrMemberAlreadyDecided: the member has a recorded outcome (BatchStack.MemberOutcomes).
	ErrMemberAlreadyDecided = consensus.ErrMemberAlreadyDecided

	// ErrOperationAlreadyQueued is a DIFFERENT intent carrying an operation (the same four
	// Accumulate blobs) that is already queued on the chain: a replay, refused for good.
	ErrOperationAlreadyQueued = consensus.ErrOperationAlreadyQueued

	// ErrBatchUnavailable is CERTEN being unable to settle the member right now - no anchor
	// configured for the chain, or no commit height resolved yet. It is never the intent's defect,
	// so the intent is retried, not refused.
	ErrBatchUnavailable = consensus.ErrBatchUnavailable

	// ErrNoGovernanceCommitment: a member without a governance decision to commit to (RB4-F66).
	ErrNoGovernanceCommitment = consensus.ErrNoGovernanceCommitment
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

	// GovernanceCommitment commits to who decided the intent (RB4-F66): the batch operation id aggregates it.
	// Required on admission. Zero only on a member restored from a mempool written before it existed, which is
	// then LegacyNoGovernance: formed with the v1 operation id its anchor may already carry.
	GovernanceCommitment [32]byte
	LegacyNoGovernance   bool

	// AccumTxHash is the Accumulate transaction that carried this intent. Evidence only — never hashed
	// into the leaf. Empty is honest for a member restored from a pre-2026-09-18 mempool blob.
	AccumTxHash string

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

	// CommitPartition is the Accumulate partition whose minor block CommitHeight counts, and
	// CommitTime that block's consensus time. CommitTime is the member's COMMON clock: every
	// validator reads the same value for it, and it survives a restart. The on-demand failover
	// rotation and the gas-deferral deadline are measured from it (see Origin). Zero until known.
	CommitPartition string
	CommitTime      time.Time

	// EnqueuedAt is when this process queued the member. Local, and reset by a restart: only the
	// memory-backstop prune uses it, where a restart extending retention is the safe direction.
	EnqueuedAt time.Time

	// FirstSeen is when this validator first queued the member. Unlike EnqueuedAt it is persisted and
	// never reset by a restart: it is the floor for searching the chain for the member's spent leaf.
	FirstSeen time.Time

	// What THIS validator did toward settling an on-demand member, persisted with it so a restart
	// does not forget it. Every validator holds every member and the settlement failover hands it
	// to each in turn, so a validator that finds the member's anchor already attested must be able
	// to tell its own work from another's: only the validator that sent a settlement attests its
	// outcome, and only the validator that attested the anchor settles under it.
	//
	// AnchorTx and VerifyTx are the anchor and quorum-verify transactions this validator paid for,
	// when it did, so their cost is reported with the member's outcome however many passes later.
	AnchorProved bool
	AnchorTx     string
	VerifyTx     string
	// AnchorBlock is the block the member's anchor was created in - by this validator, or by another and
	// located on chain (RB3-F33): the floor for searching the account's LeafConsumed log and the anchor's
	// attestation.
	AnchorBlock uint64
	// AttestedSeen: this validator has seen the member's anchor attested. Such a member may still be
	// this validator's to settle in a later settlement window, so the memory-backstop prune keeps it.
	AttestedSeen bool
	// SettlementTx is the settlement transaction this validator sent, recorded before its receipt
	// is awaited: the most recent broadcast.
	SettlementTx string
	// SettlementTxs is every hash this validator's settlement was broadcast under. A settlement that
	// does not mine is replaced at the same nonce with a higher fee (txSender), so any ONE of these
	// may be the one that mines; SettlementNonce is that shared nonce.
	SettlementTxs      []string
	SettlementNonce    uint64
	SettlementNonceSet bool

	// Outcome is the member's terminal outcome as THIS validator knows it, once it has one. A member
	// with an outcome stays in its period until the retention horizon: a period's member set is
	// fixed, and every validator must keep deriving the same trees over it - removing members as
	// they settle made the leader's view of a period drift from its peers' (RB3-F54). Settlement
	// acts only on members without an outcome.
	Outcome MemberOutcome

	// After is the member the intent's declared order places immediately before this one on another
	// chain; nil for a member that waits on none. SequencePosition is this member's place in that
	// order (0 for the first, or for an intent that declares none). See batch_sequence.go.
	After            *MemberPredecessor
	SequencePosition int
}

// MemberOutcome is a batch member's terminal outcome on this validator.
type MemberOutcome string

const (
	// MemberSettled: this validator's settlement executed the member.
	MemberSettled MemberOutcome = "settled"
	// MemberSettledElsewhere: the member's leaf was consumed by a transaction this validator did not send.
	MemberSettledElsewhere MemberOutcome = "settled_elsewhere"
	// MemberFailed: this validator's settlement was mined and reverted, or could not be formed.
	MemberFailed MemberOutcome = "failed"
	// MemberDropped: the member cannot settle through the batch path, with a recorded cause.
	MemberDropped MemberOutcome = "dropped"
	// MemberReleased: past its deadline and unsettled under another validator's attested anchor - that
	// validator's outcome to record.
	MemberReleased MemberOutcome = "released"
)

// Deadline is the latest time the member may execute, and whether it has one: the earliest of its
// legs' signed deadlines and CERTEN's own settlement horizon (its commit time + settlementHorizon).
// Both parts are the same on every validator - signed data and Accumulate consensus time - so
// validators agree on it. A member with neither has no deadline.
func (p *PendingBatchIntent) Deadline() (time.Time, bool) {
	var d time.Time
	for _, l := range p.Legs {
		if l.Deadline <= 0 {
			continue
		}
		if t := time.Unix(l.Deadline, 0).UTC(); d.IsZero() || t.Before(d) {
			d = t
		}
	}
	if !p.CommitTime.IsZero() {
		if h := p.CommitTime.Add(p.settlementHorizon()).UTC(); d.IsZero() || h.Before(d) {
			d = h
		}
	}
	return d, !d.IsZero()
}

// pending reports whether the member still has no terminal outcome here.
func (p *PendingBatchIntent) pending() bool { return p != nil && p.Outcome == "" }

// settlementHashes is every hash this validator's settlement for p was broadcast under.
func (p *PendingBatchIntent) settlementHashes() []string {
	out := append([]string(nil), p.SettlementTxs...)
	if p.SettlementTx != "" {
		seen := false
		for _, h := range out {
			if h == p.SettlementTx {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, p.SettlementTx)
		}
	}
	return out
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
		ADIURL:               p.ADIURL,
		ExecutionCommitment:  exec,
		OperationID:          p.OperationID,
		GovernanceCommitment: p.GovernanceCommitment,
		LegacyNoGovernance:   p.LegacyNoGovernance,
		IntentID:             p.IntentID,
		Provenance:           p.provenance(),
	}, nil
}

// provenance describes the member for the canonical row. It reads the FIRST leg: a member with several
// legs settles them together under one leaf, and the row records one line, so the first is the one shown.
// Nothing here is hashed.
func (p *PendingBatchIntent) provenance() MemberProvenance {
	prov := MemberProvenance{
		AccumTxHash: p.AccumTxHash,
		FromChain:   "accumulate",
		UserID:      p.ADIURL,
		FromAddress: p.Account.Hex(),
	}
	if len(p.Legs) > 0 {
		leg := p.Legs[0]
		prov.ToChain = leg.Chain
		if prov.ToChain == "" {
			prov.ToChain = chainName(leg.ChainID)
		}
		prov.ToAddress = leg.Target.Hex()
		if leg.Value != nil {
			prov.Amount = leg.Value.String()
		} else {
			prov.Amount = "0"
		}
		// The batch path settles native value; a contract-call leg moves none, and says so as "0".
		prov.TokenSymbol = "ETH"
	}
	return prov
}

// BatchMempoolConfig tunes tree formation.
//
// There is no early-flush trigger: a tree is formed when its period closes (consensus height), so
// every validator forms it over the same members. Count- and age-based triggers belonged to the
// removed EnqueuedAt path.
type BatchMempoolConfig struct {
	// FlushInterval is the cadence at which closed periods are flushed.
	FlushInterval time.Duration
	// MaxBatchSize caps members per tree; a period with more is cut into several trees
	// (chunkMembers). Bounds worst-case anchor calldata and keeps the Merkle branches short
	// (depth = ceil(log2 N)).
	MaxBatchSize int
}

func DefaultBatchMempoolConfig() BatchMempoolConfig {
	return BatchMempoolConfig{
		FlushInterval: 60 * time.Second,
		MaxBatchSize:  64,
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
	// seen keys on intentID+chainID, NOT intentID alone.
	//
	// A cross-chain intent contributes ONE MEMBER PER CHAIN — same intent id, different chain,
	// different account, different leaf. Keying on the id alone accepted the first chain's member
	// and refused every other with "already queued", so a Sepolia+Base intent settled on one chain
	// and silently lost the other. Idempotency still holds: re-adding the same intent for the same
	// chain is still refused.
	seen map[string]bool // intentID|chainID -> queued, for idempotent Add

	// onDemand holds intent-keyed members, which settle one per anchor and never form a period.
	//
	// DELIBERATELY A SEPARATE STRUCTURE, not a lane tag on `pool`. Keeping them physically apart
	// is what guarantees selectForPeriodLocked and PruneOlderThan cannot see an on-demand member,
	// so the period path needs no lane-scoping anywhere and keeps its current behaviour exactly.
	// A shared pool with a filter would put a lane check on every one of those call sites, and
	// the ones that were missed would fail silently — a batch formed over the wrong members.
	//
	// Keyed by operationID because that is the intent's identity and the lookup key an attester
	// is given. See batch_mempool_ondemand.go.
	onDemand map[int64]map[[32]byte]*PendingBatchIntent
	// heldPastTTL: see HeldPastTTL.
	heldPastTTL int

	// store persists the queue so a restart resumes with its members instead of stranding
	// intents the round has already reported as batch_queued. Nil disables persistence and
	// leaves only the discovery watermark rewind as the recovery path.
	store *BatchMempoolStore
	// unsaved is the last snapshot write's failure, nil once the disk holds the queue. While it is set
	// nothing new is sent (Durable), so no settlement happens that a restart could forget.
	unsaved error
}

// BatchLane identifies which settlement mechanism owns a member.
//
// It is NOT a field on PendingBatchIntent. The structure holding a member is the single
// authority on its lane, so there is no second copy that can disagree with it.
type BatchLane string

const (
	// LaneOnCadence members are pooled into height-bucketed periods and share one anchor.
	LaneOnCadence BatchLane = "on_cadence"
	// LaneOnDemand members are intent-keyed: one member, one anchor, no period.
	LaneOnDemand BatchLane = "on_demand"
)

// SetStore attaches durable storage and restores anything previously queued.
//
// Called once during wiring, BEFORE the enqueuer is published, so a restored member cannot race
// a freshly discovered one.
func (m *BatchMempool) SetStore(store *BatchMempoolStore, logf func(string, ...interface{})) error {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	m.mu.Lock()
	m.store = store
	m.mu.Unlock()

	if store == nil {
		return nil
	}
	n, err := store.Load(m)
	if err != nil {
		return fmt.Errorf("restore the queued batch members: %w", err)
	}
	if n > 0 {
		logf("[BATCH-STORE] restored %d queued batch member(s) from the previous run; they keep "+
			"their original CommitHeight, so they land in exactly the period they would have", n)
	}
	return nil
}

// persist writes the queue and returns the write's failure. Caller must NOT hold m.mu — Save takes it.
//
// A failed write used to be logged as harmless - "re-derivation remains available" - but re-deriving
// from Accumulate cannot recover a member's anchor, settlement transactions or nonce. The failure is now
// kept (unsaved) and nothing is sent until a write succeeds (RB3 sweep).
func (m *BatchMempool) persist() error {
	m.mu.Lock()
	st := m.store
	m.mu.Unlock()
	if st == nil {
		return nil
	}
	err := st.Save(m)
	m.mu.Lock()
	m.unsaved = err
	m.mu.Unlock()
	if err != nil {
		st.logf("❌ [BATCH-STORE] snapshot write failed (%v); nothing is sent until the queue is on disk", err)
	}
	return err
}

// Durable is nil when the disk holds the queue. After a failed write it tries the write again and
// reports the result: the senders call it before sending anything.
func (m *BatchMempool) Durable() error {
	m.mu.Lock()
	unsaved := m.unsaved
	m.mu.Unlock()
	if unsaved == nil {
		return nil
	}
	if err := m.persist(); err != nil {
		return fmt.Errorf("the batch queue is not on disk: %w", err)
	}
	return nil
}

func NewBatchMempool(cfg BatchMempoolConfig) *BatchMempool {
	return &BatchMempool{
		cfg:      cfg.withDefaults(),
		pool:     make(map[int64][]*PendingBatchIntent),
		seen:     make(map[string]bool),
		onDemand: make(map[int64]map[[32]byte]*PendingBatchIntent),
	}
}

// Add queues an authorized intent.
//
// Validation happens here rather than at flush time so a malformed member is rejected while
// the caller still has context, instead of poisoning a tree that other intents are waiting on.
// Add queues a member and snapshots the queue.
//
// The snapshot is taken AFTER the lock is released, never from inside it: persist() acquires
// m.mu to read the pool, and a deferred call would run before the unlock and deadlock.
func (m *BatchMempool) Add(p *PendingBatchIntent) error {
	if err := m.add(p); err != nil {
		return err
	}
	if err := m.persist(); err != nil {
		// Not queued: a member the disk does not hold would be lost by a restart after it was reported
		// queued. Taken back, and refused as this validator's outage - retried, never held against the
		// intent.
		m.dropMembers([]*PendingBatchIntent{p})
		return fmt.Errorf("%w: intent %s on chain %d could not be persisted: %v", consensus.ErrBatchUnavailable, p.IntentID, p.ChainID, err)
	}
	return nil
}

// validateMember is the admission check both lanes share.
//
// Extracted from add() unchanged so the on-demand index cannot drift into accepting members the
// period pool would reject — a member that is malformed is malformed regardless of which
// mechanism settles it, and every one of these checks exists because letting it through would
// surface later as a failed tree or an anchor no account can spend.
//
// It also stamps EnqueuedAt, which is the only mutation here.
func validateMember(p *PendingBatchIntent) error {
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
	if p.FirstSeen.IsZero() {
		p.FirstSeen = p.EnqueuedAt
	}
	return nil
}

// Origin is the time a member's age is measured from, and whether it is the consensus time that
// every validator shares. It is CommitTime when known. Until then it is FirstSeen: this
// validator's own first sighting, which is persisted, so a restart still never restarts the
// clock, but which differs between validators - callers that coordinate validators (the failover
// rotation) resolve CommitTime first and fall back only when it cannot be read.
func (p *PendingBatchIntent) Origin() (t time.Time, consensus bool) {
	switch {
	case !p.CommitTime.IsZero():
		return p.CommitTime, true
	case !p.FirstSeen.IsZero():
		return p.FirstSeen, false
	default:
		return p.EnqueuedAt, false
	}
}

func (m *BatchMempool) add(p *PendingBatchIntent) error {
	if err := validateMember(p); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := memberKey(p.IntentID, p.ChainID)
	if m.seen[key] {
		return fmt.Errorf("%w: intent %s on chain %d", ErrMemberAlreadyQueued, p.IntentID, p.ChainID)
	}
	// Queued in the on-demand lane already (the lane flag changed between two runs of the same
	// intent): it is queued, and a second member would settle it twice.
	if held := m.onDemand[p.ChainID][p.OperationID]; held != nil && held.IntentID == p.IntentID {
		return fmt.Errorf("%w: intent %s on chain %d (on-demand lane)", ErrMemberAlreadyQueued, p.IntentID, p.ChainID)
	}
	if holder := m.operationHolderLocked(p.ChainID, p.OperationID, p.IntentID); holder != "" {
		return fmt.Errorf("%w: intent %s carries operation %x, already queued on chain %d by intent %s",
			ErrOperationAlreadyQueued, p.IntentID, p.OperationID[:8], p.ChainID, holder)
	}
	m.seen[key] = true
	m.pool[p.ChainID] = append(m.pool[p.ChainID], p)
	return nil
}

// PendingCount returns queued members without a terminal outcome, across all chains.
func (m *BatchMempool) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, v := range m.pool {
		for _, p := range v {
			if p.pending() {
				n++
			}
		}
	}
	return n
}

// PendingCountForChain returns queued members without a terminal outcome on one chain.
func (m *BatchMempool) PendingCountForChain(chainID int64) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, p := range m.pool[chainID] {
		if p.pending() {
			n++
		}
	}
	return n
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

// PeriodMembers returns every member of the period - with or without an outcome - in the
// deterministic order (CommitHeight, IntentID). It removes nothing.
//
// The whole period, not a capped prefix and not only the members still pending: a period's trees are
// cut from this list (periodChunks), and every validator must cut the same trees from it long after
// some of its members settled. A leader that removed members as it went derived trees over a
// subset its peers did not hold (RB3-F54).
//
// Ordering is by (CommitHeight, IntentID) ascending - deterministic and independent of arrival
// order. Do NOT change this to EnqueuedAt; that is local wall-clock and reintroduces divergence.
func (m *BatchMempool) PeriodMembers(chainID int64, periodStart, periodBlocks uint64) []*PendingBatchIntent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selectForPeriodLocked(chainID, periodStart, periodBlocks)
}

// MaxBatchSize is the member cap per tree; a period with more members is cut into several trees.
func (m *BatchMempool) MaxBatchSize() int { return m.cfg.MaxBatchSize }

// MarkOutcome records a terminal outcome on the pooled copies of members, and persists it.
func (m *BatchMempool) MarkOutcome(members []*PendingBatchIntent, outcome MemberOutcome) {
	if len(members) == 0 {
		return
	}
	m.mu.Lock()
	byKey := make(map[string]bool, len(members))
	for _, p := range members {
		if p != nil {
			byKey[memberKey(p.IntentID, p.ChainID)] = true
			p.Outcome = outcome
		}
	}
	for _, pool := range m.pool {
		for _, p := range pool {
			if p != nil && byKey[memberKey(p.IntentID, p.ChainID)] {
				p.Outcome = outcome
			}
		}
	}
	m.mu.Unlock()
	m.persist()
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
	return eligible
}

// chunkMembers cuts an ordered member list into trees of at most max members. Applied to the same
// ordered list, it cuts the same trees on every validator.
func chunkMembers(members []*PendingBatchIntent, max int) [][]*PendingBatchIntent {
	if max <= 0 {
		max = len(members)
	}
	var chunks [][]*PendingBatchIntent
	for len(members) > 0 {
		n := max
		if n > len(members) {
			n = len(members)
		}
		chunks = append(chunks, members[:n:n])
		members = members[n:]
	}
	return chunks
}

// anyPending reports whether any member still lacks a terminal outcome.
func anyPending(members []*PendingBatchIntent) bool {
	for _, p := range members {
		if p.pending() {
			return true
		}
	}
	return false
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
		// A period whose members all have outcomes has nothing left to do; it stays in the pool,
		// fixed, until the retention horizon.
		if p == nil || p.CommitHeight == 0 || !p.pending() {
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
// It deliberately does NOT record the pruned members as failed. On a non-leader those members
// were settled by whichever node did lead their period. Only FlushChain, which the leader alone
// runs, produces members that genuinely failed (Dropped, recorded with their cause).
func (m *BatchMempool) PruneOlderThan(horizonStart uint64) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	pruned := 0
	for chainID, pool := range m.pool {
		var rest []*PendingBatchIntent
		for _, p := range pool {
			if p != nil && p.CommitHeight != 0 && p.CommitHeight < horizonStart {
				delete(m.seen, memberKey(p.IntentID, p.ChainID))
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

// DropMembers removes specific members outright. Used only to take back a member this validator
// queued moments ago for an intent whose other members could not be queued (the all-or-nothing
// enqueue): it never reached a period. A member that leaves the batch path after it was queued is
// marked (MarkOutcome), not removed, so its period's trees stay what every validator derives.
func (m *BatchMempool) DropMembers(members []*PendingBatchIntent) {
	if len(members) == 0 {
		return
	}
	m.dropMembers(members)
	m.persist()
}

func (m *BatchMempool) dropMembers(members []*PendingBatchIntent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Keyed by member (intent AND chain), exactly like the dedupe index. Keyed by intent alone, a
	// multi-chain intent dropped on one chain lost its member on every other chain too - removed
	// from the pool while still marked queued, so it could never be queued again and never settled
	// (RB3-F38).
	remove := make(map[string]bool, len(members))
	for _, p := range members {
		if p != nil {
			key := memberKey(p.IntentID, p.ChainID)
			remove[key] = true
			delete(m.seen, key)
		}
	}
	for chainID, pool := range m.pool {
		var rest []*PendingBatchIntent
		for _, p := range pool {
			if p != nil && !remove[memberKey(p.IntentID, p.ChainID)] {
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

// memberKey identifies a batch member: one intent may have a member on each chain it touches.
func memberKey(intentID string, chainID int64) string {
	return intentID + "|" + strconv.FormatInt(chainID, 10)
}

// FindMember returns this validator's own copy of the member holding operationID on chainID, in
// either lane - whatever its outcome - and whether it is held.
func (m *BatchMempool) FindMember(chainID int64, operationID [32]byte) (*PendingBatchIntent, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.onDemand[chainID][operationID]; p != nil {
		c := *p
		return &c, true
	}
	for _, p := range m.pool[chainID] {
		if p != nil && p.OperationID == operationID {
			c := *p
			return &c, true
		}
	}
	return nil, false
}

// OperationHolder reports which OTHER intent already has the operation queued on the chain, in
// either lane, or "" when none does. The same intent re-running is not a holder of its own
// operation.
func (m *BatchMempool) OperationHolder(chainID int64, operationID [32]byte, intentID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.operationHolderLocked(chainID, operationID, intentID)
}

// operationHolderLocked is OperationHolder for a caller that holds m.mu.
func (m *BatchMempool) operationHolderLocked(chainID int64, operationID [32]byte, intentID string) string {
	for _, p := range m.pool[chainID] {
		if p != nil && p.OperationID == operationID && p.IntentID != intentID {
			return p.IntentID
		}
	}
	if p := m.onDemand[chainID][operationID]; p != nil && p.IntentID != intentID {
		return p.IntentID
	}
	return ""
}

// OnDemandCount is the number of members queued in the on-demand lane, across chains.
func (m *BatchMempool) OnDemandCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, byOp := range m.onDemand {
		n += len(byOp)
	}
	return n
}
