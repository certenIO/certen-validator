package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/consensus"
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

	// onDemandCommitTimeRetry spaces the attempts to read a member's Accumulate block time when a
	// read fails, so an unreachable API costs one query per member per interval, not one per pass.
	onDemandCommitTimeRetry = 30 * time.Second
	// onDemandCommitTimeRead bounds one such read.
	onDemandCommitTimeRead = 10 * time.Second
)

// CommitTimeResolver reads the consensus time of an Accumulate partition's minor block.
type CommitTimeResolver func(ctx context.Context, partition string, height uint64) (time.Time, error)

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
	// OnDropped records a member that could not settle as FAILED, with its cause, when no Attest is
	// wired. Nothing is ever re-executed: there is no other path to settle it.
	OnDropped BatchDropFn

	QuorumDeadline time.Duration
	RetryBackoff   time.Duration
	SweepInterval  time.Duration
	FailoverAfter  time.Duration
	TTL            time.Duration

	// CommitTime reads a member's Accumulate block time when the member arrived without it
	// (discovery could not read it, or the member was queued before it was carried). Optional:
	// without it such a member's failover runs from this validator's persisted first sighting.
	CommitTime CommitTimeResolver

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
	// commitTimeTried is when a member's block time was last asked for and could not be read.
	commitTimeTried map[string]time.Time
	// proveRoot replaces cfg.Prover.ProveBatchRootOnDemand in tests that have no peers. Nil in production.
	proveRoot func(ctx context.Context, tree *BatchTree, member *PendingBatchIntent) error
}

// NewOnDemandSubmitter builds the submitter.
func NewOnDemandSubmitter(cfg OnDemandSubmitterConfig) (*OnDemandSubmitter, error) {
	if cfg.Stack == nil || cfg.Stack.Mempool == nil {
		return nil, fmt.Errorf("on-demand submitter requires a batch stack")
	}
	if cfg.Prover == nil {
		return nil, fmt.Errorf("on-demand submitter requires a quorum prover")
	}
	if cfg.Stack.SequenceChain == nil {
		return nil, fmt.Errorf("on-demand submitter requires the stack's sequence chain reader - " +
			"without it a sequential intent's later members could never be settled in order")
	}
	cfg.withDefaults()
	return &OnDemandSubmitter{
		cfg:    cfg,
		wake:   make(chan struct{}, 1),
		inWork: make(map[string]bool),

		commitTimeTried: make(map[string]time.Time),
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
			leads := func(m *PendingBatchIntent) bool { return s.isLeaderFor(m, s.failoverElapsed(ctx, m)) }
			if n := s.cfg.Stack.settleOnDemandAtTTL(s.cfg.TTL, time.Now(), leads, s.cfg.OnDropped, s.cfg.Logf); n > 0 {
				logf("[OD] pruned %d member(s) past the %s TTL", n, s.cfg.TTL)
			}
			for key, at := range s.commitTimeTried {
				if time.Since(at) > s.cfg.TTL {
					delete(s.commitTimeTried, key)
				}
			}
			if held := s.cfg.Stack.Mempool.HeldPastTTL(); held > 0 {
				logf("⚠️ [OD] %d member(s) past the %s TTL are held because this validator acted on them "+
					"(a settlement in flight, or an anchor it attested); they leave only through their outcome",
					held, s.cfg.TTL)
			}
		}
	}
}

// pass walks every queued member on every configured chain.
func (s *OnDemandSubmitter) pass(ctx context.Context) {
	// Nothing is sent while the queue is not on disk: a restart would forget the settlement.
	if err := s.cfg.Stack.Mempool.Durable(); err != nil {
		s.cfg.Logf("❌ [OD] not submitting: %v", err)
		return
	}
	for _, chainID := range s.cfg.Stack.Resolver.Chains() {
		for _, member := range s.cfg.Stack.Mempool.PendingOnDemand(chainID) {
			if ctx.Err() != nil {
				return
			}
			if busy := s.consider(ctx, member); busy {
				// This chain's key has a transaction still in flight (or its sender is unavailable):
				// every other member on it would wait on the same thing. Move on to the next chain.
				break
			}
		}
	}
}

// memberWorkKey identifies a member for the in-flight guard. Chain-scoped, because a
// cross-chain intent is one member per chain and each settles independently.
func memberWorkKey(chainID int64, opID [32]byte) string {
	return fmt.Sprintf("%d|%x", chainID, opID)
}

// consider decides whether this node should settle the member now, and does so if it should. It
// reports whether this chain's key was found busy, so the pass can skip the rest of the chain.
func (s *OnDemandSubmitter) consider(ctx context.Context, member *PendingBatchIntent) (keyBusy bool) {
	logf := s.cfg.Logf
	key := memberWorkKey(member.ChainID, member.OperationID)
	if s.inWork[key] {
		return
	}

	// Once the anchor is attested the leader rotation no longer decides: the member's settlement
	// windows do, and one of them may be this validator's - which is how a dead attester's member is
	// taken over. The check also pre-scans ahead of this validator's window, leader or not.
	leader := s.isLeaderFor(member, s.failoverElapsed(ctx, member))
	if orch, err := s.cfg.Stack.OrchestratorFor(member.ChainID); err == nil {
		needed, nerr := orch.OnDemandMemberNeedsThisValidator(ctx, member)
		if !leader && (nerr != nil || !needed) {
			return
		}
	} else if !leader {
		return
	}

	s.inWork[key] = true
	defer delete(s.inWork, key)

	orch, err := s.cfg.Stack.OrchestratorFor(member.ChainID)
	if err != nil {
		logf("[OD] chain %d has no orchestrator: %v", member.ChainID, err)
		return
	}

	// A successor in a sequential intent is settled only once its predecessor has an outcome on its
	// chain (batch_sequence.go). A member already acted on is past that point.
	// The predecessor's leaf binds the key page the intent's certificate certifies (RB5-F29): the certificate is read
	// first. Uncertified, a successor waits - past its deadline the settle path refuses it by name.
	sequenced := member.After != nil && !member.AnchorProved && !member.AttestedSeen
	if sequenced {
		if cerr := s.cfg.Stack.Mempool.RequireCertified(member); cerr != nil {
			// It stops waiting - and goes on to be refused by name - only once its chain is past its deadline, by the
			// chain's clock (RB7 D7).
			past, _, perr := orch.pastDeadlineOnChain(ctx, member)
			if perr != nil || !past {
				logf("[OD] intent=%s on chain %d waits: %v", member.IntentID, member.ChainID, cerr)
				return false
			}
			sequenced = false
		}
	}
	if sequenced {
		state, cause, serr := sequenceReadiness(ctx, s.cfg.Stack.SequenceChain, member)
		switch {
		case serr != nil:
			logf("[OD] intent=%s on chain %d: its predecessor on chain %d could not be read (%v); it waits",
				member.IntentID, member.ChainID, member.After.ChainID, serr)
			return false
		case state == sequenceWaiting:
			return false
		case state == sequenceStopped:
			logf("[OD] intent=%s on chain %d is not executed: %s", member.IntentID, member.ChainID, cause)
			s.dispose(ctx, member, nil, false, errors.New(cause))
			return false
		}
		logf("[OD] intent=%s on chain %d: its predecessor on chain %d has its outcome; settling",
			member.IntentID, member.ChainID, member.After.ChainID)
	}

	outcome, err := s.settleWithReadinessRetry(ctx, orch, member)
	if err != nil && IsChainReadError(err) {
		// A read that failed decides nothing about the member. It stays queued for a read that works.
		logf("[OD] intent=%s deferred: a chain read failed (%v)", member.IntentID, err)
		return false
	}
	if err != nil {
		// Terminal for this member: deadline expired, a real disagreement, or a settle failure.
		logf("[OD] intent=%s could not settle: %v", member.IntentID, err)
		s.dispose(ctx, member, outcome, false, err)
		return
	}
	if outcome != nil && outcome.Deferred {
		// Nothing terminal is known: a price refusal, or a transaction whose result is not in yet.
		// The member stays queued and is tried again next pass.
		return outcome.KeyBusy
	}
	s.dispose(ctx, member, outcome, true, nil)
	return false
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
		if s.proveRoot != nil {
			return s.proveRoot(ctx, tree, member)
		}
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
			// The wall clock bounds how long THIS pass waits for the peers, and nothing more: peers that are behind
			// decide nothing about the member (RB7 D7). It is deferred, and the next pass tries again; its outcome is
			// decided on its chain - past its deadline it is refused, or never settled, by the chain's clock.
			logf("[OD] intent=%s quorum still not ready after %s (%d attempt(s); last: %v) — deferred to the next pass",
				member.IntentID, s.cfg.QuorumDeadline, attempts, err)
			return &OnDemandOutcome{Deferred: true}, nil
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

	// Another validator's outcome: it attested the anchor, or its settlement spent the leaf. It
	// records the outcome. Attesting here as well - with no transaction of this node's to show -
	// is what sent every failover validator's empty-handed attestation into Phase 7.
	if ok && outcome != nil && outcome.Released {
		s.cfg.Logf("[OD] intent=%s released: its outcome is another validator's to record",
			member.IntentID)
		s.cfg.Stack.Mempool.RemoveOnDemand(member.ChainID, member.OperationID)
		return
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
	// Phase 7 proves it (VerifyRevertedCall) to write the outcome back to Accumulate.
	s.cfg.Logf("[OD] ❌ intent=%s attested as FAILED (tx=%q): %v — it is not re-executed; there is "+
		"no other path to settle it. The ADI resubmits it deliberately.",
		member.IntentID, txHash, cause)
	// With a transaction, the failure is proved from it (Attest). Without one there is nothing on chain
	// to prove, and the cause is the record: it goes to the drop handler, which records the member
	// failed WITH that cause - Attest would record only "no settlement transaction reached the chain".
	switch {
	case txHash != "" && s.cfg.Attest != nil:
		s.cfg.Attest(ctx, member.Attestation, txHash, member.ChainID, false)
	case s.cfg.OnDropped != nil:
		var refused *IntentRefusedError
		if errors.As(cause, &refused) {
			// The named cause travels with the member's failure record: the intent is refused, not a failed settlement.
			member.Refusal = refused.Error()
		}
		s.cfg.OnDropped(ctx, member, fmt.Sprintf("%v", cause))
	case s.cfg.Attest != nil:
		s.cfg.Attest(ctx, member.Attestation, txHash, member.ChainID, false)
	default:
		s.cfg.Logf("[OD] ⚠️ intent=%s failed with no attest or drop handler wired; it is recorded nowhere", member.IntentID)
	}
	// Refused by name before any chain transaction: kept, never attempted again here, so this validator can verify the
	// member's non-settlement from its own copy (RB6-F11). Anything else leaves the queue.
	var refused *IntentRefusedError
	if txHash == "" && errors.As(cause, &refused) {
		s.cfg.Stack.Mempool.RefuseOnDemand(member.ChainID, member.OperationID, time.Now().UTC())
		return
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

// failoverElapsed is how far the member is into the failover rotation: the time since its
// Accumulate block. That time is consensus data, so every validator places the member at the same
// point in the rotation, and it survives a restart - measured from a local clock, as it used to be,
// every restart put this validator back at the start of the rotation and a dead leader's members
// waited for a node that no longer counted as late.
//
// A member without its block time has it read first. If it cannot be read the rotation runs from
// this validator's persisted first sighting: still immune to a restart, but no longer aligned with
// the other validators, so that is logged.
func (s *OnDemandSubmitter) failoverElapsed(ctx context.Context, member *PendingBatchIntent) time.Duration {
	s.resolveCommitTime(ctx, member)
	origin, _ := member.Origin()
	if origin.IsZero() {
		return 0
	}
	return time.Since(origin)
}

// resolveCommitTime reads and records the member's commit time if it is missing: the consensus time of its commit block,
// with ResolveCommitTime - never the Directory block that anchored it (CommitPartition/CommitHeight), whose time is later
// and would give this validator another notBefore than its peers (RB5-F57).
func (s *OnDemandSubmitter) resolveCommitTime(ctx context.Context, member *PendingBatchIntent) {
	if !member.CommitTime.IsZero() || s.cfg.CommitTime == nil {
		return
	}
	key := memberWorkKey(member.ChainID, member.OperationID)
	if at, ok := s.commitTimeTried[key]; ok && time.Since(at) < onDemandCommitTimeRetry {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, onDemandCommitTimeRead)
	t, err := ResolveCommitTime(rctx, s.cfg.CommitTime, member.ExecPartition, member.ExecBlock)
	cancel()
	if err != nil {
		s.commitTimeTried[key] = time.Now()
		s.cfg.Logf("⚠️ [OD] intent=%s: reading the time of its commit block %d on %s: %v - failover runs from this "+
			"validator's first sighting until it can be read", member.IntentID, member.ExecBlock, member.ExecPartition, err)
		return
	}
	delete(s.commitTimeTried, key)
	if !s.cfg.Stack.Mempool.NoteOnDemandProgress(member.ChainID, member.OperationID, func(p *PendingBatchIntent) {
		if p.CommitTime.IsZero() {
			p.CommitTime = t
		}
	}) {
		// No longer queued (its outcome landed meanwhile): the time still serves this decision.
		member.CommitTime = t
	}
}

// onDemandLeaderIndex is the deterministic election, defined once in consensus so the round that queues a member
// names the same leader this submitter acts on (RB5-F38).
func onDemandLeaderIndex(chainID int64, opID [32]byte, rosterLen int) int {
	return consensus.OnDemandLeaderIndex(chainID, opID, rosterLen)
}
