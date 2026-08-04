package execution

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// =============================================================================
// On-demand submitter — event-driven, retry-until-ready
// =============================================================================
//
// # WHY THERE IS NO SETTLE GRACE HERE
//
// The period path waits four minutes before forming a batch because a peer holding a DIFFERENT
// SUBSET of a period derives a different bundleId. A one-member batch has no subset: a peer
// either holds the intent (and derives the identical bundleId, because the derivation is a pure
// function of the intent) or it does not, and says so with CodeMemberNotHeld.
//
// So instead of guessing how long convergence takes, this measures it: attempt, and if the only
// shortfall is peers that have not caught up, wait a short backoff and attempt again. Measured
// live 2026-08-04 — all seven validators enqueued the same intent within 5 seconds and answered
// a quorum request in 0.53s. The 60s solo grace was waiting for something that had finished 55
// seconds earlier.
//
// # WHY IT IS EVENT-DRIVEN
//
// The period flush loop wakes on a 15s sub-tick, which is fine when the batch is already waiting
// minutes. Here that tick would be a large fraction of the total, so an enqueue signals the
// worker directly. The ticker remains as a backstop for members whose signal was lost to a
// restart.

// OnDemandDefaults. Each is sized from the 2026-08-04 measurement, not intuition.
const (
	// OnDemandQuorumDeadline bounds the whole readiness retry for one member. Generous relative
	// to the ~5s convergence actually observed: the sample was a healthy set, and a node under
	// load or catching up will be slower. On expiry the member routes to fallback and is
	// attested as FAILED, so this must not be tight.
	OnDemandQuorumDeadline = 3 * time.Minute

	// OnDemandRetryBackoff is the pause between readiness attempts. Short, because the thing
	// being waited on resolves in seconds, and each attempt is a cheap fan-out of HTTP requests
	// — no gas, no chain write.
	OnDemandRetryBackoff = 3 * time.Second

	// OnDemandSweepInterval is the backstop scan for members whose enqueue signal was lost
	// (restart, full channel). Correctness never depends on it; latency does not either, except
	// in that recovery case.
	OnDemandSweepInterval = 60 * time.Second

	// OnDemandFailoverAfter is how long a member may sit unsettled before THIS node will take
	// over leadership for it.
	//
	// PROVISIONAL — see docs/ON_DEMAND_LANE_BUILD_PLAN.md §10. It must exceed one
	// quorum-plus-anchor cycle by a healthy multiple; measured live 2026-08-04, flush→settled
	// was 47s, so 4 minutes is roughly 5x. Too short steals leadership mid-flight and burns gas
	// on duplicate anchors; too long leaves an urgent intent waiting on a dead node. Duplicate
	// anchors ARE absorbed (createBatchAnchor treats an existing anchor as success and an
	// already-attested one short-circuits), so erring long is the safer direction.
	OnDemandFailoverAfter = 4 * time.Minute
)

// OnDemandLeaderRoster supplies the ordered validator roster used for leader election.
type OnDemandLeaderRoster func() []string

// OnDemandSubmitterConfig is what the submitter needs from the node around it.
type OnDemandSubmitterConfig struct {
	Stack       *BatchStack
	Prover      *BatchQuorumAttestor
	ValidatorID string
	Roster      OnDemandLeaderRoster

	// Attest closes a settled (or failed) member's proof cycle — the same Phase 7-9 replay the
	// period path performs.
	Attest BatchAttestFn
	// Fallback routes a member that could not settle. Attests it as FAILED; it does NOT
	// re-execute, because the per-intent submitter cannot land against CertenAnchorV8_1.
	Fallback BatchFallbackFn

	QuorumDeadline time.Duration
	RetryBackoff   time.Duration
	SweepInterval  time.Duration
	FailoverAfter  time.Duration
	TTL            time.Duration

	Logf func(string, ...interface{})
}

func (c *OnDemandSubmitterConfig) withDefaults() {
	if c.QuorumDeadline <= 0 {
		c.QuorumDeadline = OnDemandQuorumDeadline
	}
	if c.RetryBackoff <= 0 {
		c.RetryBackoff = OnDemandRetryBackoff
	}
	if c.SweepInterval <= 0 {
		c.SweepInterval = OnDemandSweepInterval
	}
	if c.FailoverAfter <= 0 {
		c.FailoverAfter = OnDemandFailoverAfter
	}
	if c.TTL <= 0 {
		c.TTL = DefaultOnDemandTTL
	}
	if c.Logf == nil {
		c.Logf = func(string, ...interface{}) {}
	}
}

// OnDemandSubmitter settles intent-keyed members.
type OnDemandSubmitter struct {
	cfg    OnDemandSubmitterConfig
	wake   chan struct{}
	inWork map[string]bool // chainID|opID currently being worked, so a signal cannot double-start
}

// NewOnDemandSubmitter builds the submitter.
func NewOnDemandSubmitter(cfg OnDemandSubmitterConfig) (*OnDemandSubmitter, error) {
	if cfg.Stack == nil || cfg.Stack.Mempool == nil {
		return nil, fmt.Errorf("on-demand submitter requires a batch stack")
	}
	if cfg.Prover == nil {
		return nil, fmt.Errorf("on-demand submitter requires a quorum prover")
	}
	cfg.withDefaults()
	return &OnDemandSubmitter{
		cfg:    cfg,
		wake:   make(chan struct{}, 1),
		inWork: make(map[string]bool),
	}, nil
}

// Wake signals that a member was enqueued. Non-blocking: a full channel already means a pass is
// pending, and one pass processes everything queued.
func (s *OnDemandSubmitter) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run drives the submitter until ctx is cancelled.
func (s *OnDemandSubmitter) Run(ctx context.Context) {
	logf := s.cfg.Logf
	ticker := time.NewTicker(s.cfg.SweepInterval)
	defer ticker.Stop()

	logf("[OD] submitter started: deadline=%s backoff=%s sweep=%s failover=%s",
		s.cfg.QuorumDeadline, s.cfg.RetryBackoff, s.cfg.SweepInterval, s.cfg.FailoverAfter)

	for {
		select {
		case <-ctx.Done():
			logf("[OD] submitter stopping (%d member(s) still queued)",
				s.cfg.Stack.Mempool.PendingOnDemandCount())
			return
		case <-s.wake:
			s.pass(ctx)
		case <-ticker.C:
			s.pass(ctx)
			if n := s.cfg.Stack.Mempool.PruneOnDemandOlderThan(s.cfg.TTL, time.Now()); n > 0 {
				logf("[OD] pruned %d member(s) past the %s TTL", n, s.cfg.TTL)
			}
		}
	}
}

// pass walks every queued member on every configured chain.
func (s *OnDemandSubmitter) pass(ctx context.Context) {
	for _, chainID := range s.cfg.Stack.Resolver.Chains() {
		for _, member := range s.cfg.Stack.Mempool.PendingOnDemand(chainID) {
			if ctx.Err() != nil {
				return
			}
			s.consider(ctx, member)
		}
	}
}

// memberWorkKey identifies a member for the in-flight guard. Chain-scoped, because a
// cross-chain intent is one member per chain and each settles independently.
func memberWorkKey(chainID int64, opID [32]byte) string {
	return fmt.Sprintf("%d|%x", chainID, opID)
}

// consider decides whether this node should settle the member now, and does so if it should.
func (s *OnDemandSubmitter) consider(ctx context.Context, member *PendingBatchIntent) {
	logf := s.cfg.Logf
	key := memberWorkKey(member.ChainID, member.OperationID)
	if s.inWork[key] {
		return
	}

	elapsed := time.Since(member.EnqueuedAt)
	if !s.isLeaderFor(member, elapsed) {
		return
	}

	s.inWork[key] = true
	defer delete(s.inWork, key)

	orch, err := s.cfg.Stack.OrchestratorFor(member.ChainID)
	if err != nil {
		logf("[OD] chain %d has no orchestrator: %v", member.ChainID, err)
		return
	}

	outcome, err := s.settleWithReadinessRetry(ctx, orch, member)
	if err != nil {
		// Terminal for this member: deadline expired, a real disagreement, or a settle failure.
		logf("[OD] intent=%s could not settle: %v", member.IntentID, err)
		s.dispose(ctx, member, outcome, false, err)
		return
	}
	if outcome != nil && outcome.Deferred {
		// Gas ceiling. The leaf is untouched; leave the member queued and try again next pass.
		return
	}
	s.dispose(ctx, member, outcome, true, nil)
}

// settleWithReadinessRetry performs attempts until the quorum forms, the deadline expires, or a
// non-recoverable error occurs.
//
// THE KEY DISTINCTION: *QuorumNotReadyError means peers are merely behind — retry, and do not
// count it as a failure. Anything else, including a single peer that actively disagrees, is
// terminal: for a one-member batch a mismatch is about the intent's own data and waiting cannot
// resolve it.
func (s *OnDemandSubmitter) settleWithReadinessRetry(
	ctx context.Context,
	orch *BatchOrchestrator,
	member *PendingBatchIntent,
) (*OnDemandOutcome, error) {
	logf := s.cfg.Logf
	deadline := time.Now().Add(s.cfg.QuorumDeadline)
	attempts := 0

	prove := func(ctx context.Context, tree *BatchTree) error {
		return s.cfg.Prover.ProveBatchRootOnDemand(ctx, tree, member)
	}

	for {
		attempts++
		outcome, err := orch.SettleOnDemandMember(ctx, member, prove)
		if err == nil {
			if attempts > 1 {
				logf("[OD] intent=%s settled on attempt %d after %s of readiness waiting",
					member.IntentID, attempts, time.Since(deadline.Add(-s.cfg.QuorumDeadline)).Truncate(time.Second))
			}
			return outcome, nil
		}

		var notReady *QuorumNotReadyError
		if !errors.As(err, &notReady) {
			return outcome, err
		}
		if time.Now().After(deadline) {
			return outcome, fmt.Errorf("quorum still not ready after %s (%d attempt(s); last: %w)",
				s.cfg.QuorumDeadline, attempts, err)
		}
		logf("[OD] intent=%s attempt %d: %d agreed, %d not held yet — retrying in %s",
			member.IntentID, attempts, notReady.Agreed, notReady.NotHeld, s.cfg.RetryBackoff)

		select {
		case <-ctx.Done():
			return outcome, ctx.Err()
		case <-time.After(s.cfg.RetryBackoff):
		}
	}
}

// dispose records the member's outcome and removes it from the index.
//
// Order matters: attest FIRST, remove second. A crash between them leaves the member queued and
// the idempotent path (anchor already attested → leaf consumed) resolves it correctly on the
// next pass. Removing first would lose it silently — the failure this whole policy exists to
// prevent.
func (s *OnDemandSubmitter) dispose(
	ctx context.Context,
	member *PendingBatchIntent,
	outcome *OnDemandOutcome,
	ok bool,
	cause error,
) {
	settled := ok && outcome != nil && outcome.Settled
	txHash := ""
	if outcome != nil {
		txHash = outcome.TxHash
	}

	if settled {
		if s.cfg.Attest != nil {
			s.cfg.Attest(ctx, member.Attestation, txHash, member.ChainID, true)
		}
		s.cfg.Stack.Mempool.RemoveOnDemand(member.ChainID, member.OperationID)
		return
	}

	// Not settled. Attest the FAILURE — loudly and with the transaction hash if the member
	// reverted on chain, because a reverted transaction is the evidence of the failure and
	// Phase 7 needs it to write the outcome back to Accumulate.
	s.cfg.Logf("[OD] ❌ intent=%s attested as FAILED (tx=%q): %v — it is NOT re-executed; the "+
		"per-intent submitter cannot land against CertenAnchorV8_1. Re-run it deliberately.",
		member.IntentID, txHash, cause)
	if s.cfg.Attest != nil {
		s.cfg.Attest(ctx, member.Attestation, txHash, member.ChainID, false)
	} else if s.cfg.Fallback != nil {
		s.cfg.Fallback(ctx, member)
	}
	s.cfg.Stack.Mempool.RemoveOnDemand(member.ChainID, member.OperationID)
}

// =============================================================================
// Leadership
// =============================================================================

// isLeaderFor reports whether this validator should settle the member now.
//
// Leadership is a pure hash of (chainID, operationID) over the roster, so exactly one node acts
// and gas is spread across the set. A cross-chain intent naturally elects a different leader per
// chain, because the chain is in the key.
//
// Failover is WALL CLOCK, not a count of periods — there are no periods here, and the period
// path's constant (3 periods) would mean 21 seconds at a 5-block width, far shorter than one
// quorum-plus-anchor cycle. After FailoverAfter the next node in the roster takes over, and
// again each interval after that, so a dead leader cannot strand an urgent intent.
func (s *OnDemandSubmitter) isLeaderFor(member *PendingBatchIntent, elapsed time.Duration) bool {
	roster := s.cfg.Roster()
	if len(roster) == 0 {
		// No roster configured: single-node devnet. Always lead, matching the period path's
		// nil-IsLeaderFn behaviour.
		return true
	}
	idx := onDemandLeaderIndex(member.ChainID, member.OperationID, len(roster))

	handoffs := 0
	if s.cfg.FailoverAfter > 0 && elapsed > 0 {
		handoffs = int(elapsed / s.cfg.FailoverAfter)
	}
	idx = (idx + handoffs) % len(roster)
	return roster[idx] == s.cfg.ValidatorID
}

// onDemandLeaderIndex is the deterministic election. Every validator must compute the same
// answer from the same roster, so it depends on nothing local.
func onDemandLeaderIndex(chainID int64, opID [32]byte, rosterLen int) int {
	if rosterLen <= 0 {
		return 0
	}
	key := fmt.Sprintf("certen:ondemand:v1|%d|%x", chainID, opID)
	sum := sha256.Sum256([]byte(key))
	// Fold four bytes rather than one: with a single byte and a 7-way modulus the selection is
	// measurably biased toward the low indices (256 = 7*36 + 4).
	base := uint64(binary.BigEndian.Uint32(sum[:4]))
	return int(base % uint64(rosterLen))
}
