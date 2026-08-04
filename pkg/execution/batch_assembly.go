package execution

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
)

// =============================================================================
// Batch stack assembly
// =============================================================================
//
// Constructs the pieces the batch path needs and wires them together. Everything below is
// inert until BatchMempool.Add has a caller — deliberately. A mempool that fills but never
// flushes is strictly WORSE than the current per-intent path, because intents would
// accumulate and silently never settle, whereas today they take the single-call path and do
// settle. So this file builds the machinery; it does not switch anything on.
//
// The remaining wiring, in order:
//   1. (this file) construct resolver -> submitter -> prover -> orchestrator
//   2. call BatchMempool.Add from the on_cadence branch in bft_integration.go
//   3. drive BatchOrchestrator.FlushChain off the scheduler tick, replaying RunProofCycle
//      per settled member

// EVMChainResolverImpl resolves a chain id to its contract manager and V8 anchor address.
//
// Managers are cached: NewEthereumContractManager dials RPC and builds bindings, and the
// orchestrator asks for the same chain repeatedly (once per verification step, once per
// member). Re-dialling each time would multiply RPC connections by the batch size.
type EVMChainResolverImpl struct {
	anchorCfg *config.AnchorConfig

	// anchorOverrides maps chainID -> CertenAnchorV8 address. The batch path needs the V8
	// anchor, which is NOT the AnchorV4Address the per-intent path uses — V8 is a separate
	// deployment carrying createBatchAnchor and the CRYPTO-007 binding.
	anchorOverrides map[int64]common.Address

	mu       sync.Mutex
	managers map[int64]*EthereumContractManager
}

// NewEVMChainResolver builds a resolver.
//
// anchorV8ByChain must be populated for every chain the batch path will run on. It is kept
// explicit rather than read from AnchorConfig because pointing the batch path at the wrong
// anchor is the failure this whole session kept surfacing — an anchor whose validator set or
// authorized commitments differ produces attestations nothing can verify.
func NewEVMChainResolver(
	anchorCfg *config.AnchorConfig,
	anchorV8ByChain map[int64]common.Address,
) (*EVMChainResolverImpl, error) {
	if anchorCfg == nil {
		return nil, fmt.Errorf("anchor config required")
	}
	if len(anchorV8ByChain) == 0 {
		return nil, fmt.Errorf("no CertenAnchorV8 addresses supplied; the batch path cannot run")
	}
	for chainID, addr := range anchorV8ByChain {
		if addr == (common.Address{}) {
			return nil, fmt.Errorf("chain %d has a zero V8 anchor address", chainID)
		}
	}
	return &EVMChainResolverImpl{
		anchorCfg:       anchorCfg,
		anchorOverrides: anchorV8ByChain,
		managers:        make(map[int64]*EthereumContractManager),
	}, nil
}

// NewEVMChainResolverFromEnv reads the V8 anchor addresses from environment.
//
// Looks for CERTEN_ANCHOR_V8_<chainID>, e.g. CERTEN_ANCHOR_V8_11155111. Chains without an
// entry are simply absent from the batch path rather than silently falling back to a
// different anchor.
func NewEVMChainResolverFromEnv(anchorCfg *config.AnchorConfig, chainIDs []int64) (*EVMChainResolverImpl, error) {
	out := make(map[int64]common.Address)
	for _, id := range chainIDs {
		key := fmt.Sprintf("CERTEN_ANCHOR_V8_%d", id)
		v := strings.TrimSpace(os.Getenv(key))
		if v == "" {
			continue
		}
		if !common.IsHexAddress(v) {
			return nil, fmt.Errorf("%s is not a valid address: %q", key, v)
		}
		out[id] = common.HexToAddress(v)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf(
			"no CERTEN_ANCHOR_V8_<chainId> variables set for chains %v; the batch path cannot run",
			chainIDs)
	}
	return NewEVMChainResolver(anchorCfg, out)
}

// ManagerForChain satisfies EVMChainResolver.
func (r *EVMChainResolverImpl) ManagerForChain(chainID int64) (*EthereumContractManager, common.Address, error) {
	anchorAddr, ok := r.anchorOverrides[chainID]
	if !ok {
		return nil, common.Address{}, fmt.Errorf(
			"chain %d has no CertenAnchorV8 configured; refusing to fall back to another anchor",
			chainID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if m, cached := r.managers[chainID]; cached {
		return m, anchorAddr, nil
	}

	chainCfg := r.anchorCfg.GetEVMChainConfig(chainID)
	if chainCfg == nil || chainCfg.RPCURL == "" {
		return nil, common.Address{}, fmt.Errorf("no RPC configuration for chainId=%d", chainID)
	}

	// The manager's anchor binding points at the V8 address: the batch path reads
	// isBatchAnchor / batchLeafCount / verifyProof from it and submits its attestation there.
	cc := &CertenContractConfig{
		EthereumRPC:          chainCfg.RPCURL,
		ChainID:              chainCfg.ChainID,
		PrivateKey:           os.Getenv("ETH_PRIVATE_KEY"),
		CreationContract:     anchorAddr.Hex(),
		VerificationContract: anchorAddr.Hex(),
		AccountContract:      chainCfg.AccountFactory,
		GasLimit:             uint64(chainCfg.GasLimitAnchor),
		MaxGasPriceGwei:      chainCfg.MaxGasPriceGwei,
	}

	m, err := NewEthereumContractManager(cc)
	if err != nil {
		return nil, common.Address{}, fmt.Errorf("contract manager for chainId=%d: %w", chainID, err)
	}
	r.managers[chainID] = m
	return m, anchorAddr, nil
}

// Chains lists the chain ids the batch path is configured for.
func (r *EVMChainResolverImpl) Chains() []int64 {
	out := make([]int64, 0, len(r.anchorOverrides))
	for id := range r.anchorOverrides {
		out = append(out, id)
	}
	return out
}

// =============================================================================
// Assembled stack
// =============================================================================

// BatchStack is the fully-wired batch path for a set of chains.
type BatchStack struct {
	Resolver      *EVMChainResolverImpl
	Submitter     *BatchProofSubmitterImpl
	Mempool       *BatchMempool
	Orchestrators map[int64]*BatchOrchestrator

	// closedAt records when this node FIRST saw each period close, for the settle grace.
	closedMu sync.Mutex
	closedAt map[periodKey]time.Time

	// PeriodBlocks is THIS validator's configured period width. The attester compares an
	// incoming request's width against it and refuses a mismatch, rather than adopting the
	// proposer's value — see HandleBatchAttestationRequest. Zero means the default.
	PeriodBlocks uint64

	// onDemandWaker signals the on-demand submitter after an intent-keyed enqueue, so
	// settlement starts on the event rather than on the next sweep. Nil until the submitter is
	// wired, and nil forever when the on-demand lane is disabled — EnqueueOnDemand is simply
	// never called in that case.
	onDemandWaker atomic.Pointer[func()]
}

// NewBatchStack assembles resolver -> submitter -> orchestrator for every configured chain.
//
// prover is supplied by the caller because producing a quorum attestation needs the
// validator BLS keys, which live in pkg/consensus. Passing it in as an interface keeps this
// package free of a consensus dependency (consensus already depends on execution).
//
// A nil prover is REJECTED rather than tolerated: without it the orchestrator would create
// batch anchors that no account can ever accept, having already paid for them.
func NewBatchStack(
	resolver *EVMChainResolverImpl,
	prover QuorumProver,
	mempoolCfg BatchMempoolConfig,
	logf func(string, ...interface{}),
) (*BatchStack, error) {
	if resolver == nil {
		return nil, fmt.Errorf("chain resolver required")
	}
	if prover == nil {
		return nil, fmt.Errorf(
			"quorum prover required: without it the batch path would create anchors that no " +
				"account will accept, after paying for them")
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}

	submitter := NewBatchProofSubmitter(resolver, logf)
	mempool := NewBatchMempool(mempoolCfg)

	orchestrators := make(map[int64]*BatchOrchestrator)
	for _, chainID := range resolver.Chains() {
		ecm, anchorAddr, err := resolver.ManagerForChain(chainID)
		if err != nil {
			return nil, fmt.Errorf("assembling chain %d: %w", chainID, err)
		}
		orchestrators[chainID] = NewBatchOrchestrator(ecm, anchorAddr, prover, mempool, logf)
		logf("[BATCH-STACK] chain %d wired to CertenAnchorV8 %s", chainID, anchorAddr.Hex())
	}

	return &BatchStack{
		Resolver:      resolver,
		Submitter:     submitter,
		Mempool:       mempool,
		Orchestrators: orchestrators,
	}, nil
}

// OrchestratorFor returns the orchestrator for a chain.
func (s *BatchStack) OrchestratorFor(chainID int64) (*BatchOrchestrator, error) {
	o, ok := s.Orchestrators[chainID]
	if !ok {
		return nil, fmt.Errorf("no batch orchestrator for chain %d", chainID)
	}
	return o, nil
}

// =============================================================================
// Flush driver
// =============================================================================

// BatchAttestFn closes the proof cycle for one settled member. Supplied by pkg/consensus
// (bound to BFTValidator.RunProofCycle) so this package stays free of a consensus import.
//
// attestation is the opaque snapshot carried on PendingBatchIntent; res describes what
// actually settled on chain.
type BatchAttestFn func(ctx context.Context, attestation interface{}, txHash string, chainID int64, success bool)

// FlushDueChains drains every chain whose pool is due and attests each settled member.
//
// Attestation is per-member even though one anchor and one batch tx covered them all: each
// intent keeps its own operationID and its own Accumulate write-back, so collapsing them
// would destroy per-intent status tracking.
//
// A member that failed is attested as UNSUCCESSFUL rather than skipped. Silently dropping it
// would leave the intent pending forever with nothing recording why.
func (s *BatchStack) FlushDueChains(
	ctx context.Context,
	now time.Time,
	force bool,
	cutoffHeight uint64,
	attest BatchAttestFn,
	fallback BatchFallbackFn,
	logf func(string, ...interface{}),
) {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	// Without a real consensus height there is no period, and TakeForPeriod would select
	// nothing. Say so once per pass rather than spinning silently.
	if cutoffHeight == 0 {
		if s.Mempool.PendingCount() > 0 {
			logf("[BATCH-FLUSH] %d member(s) queued but the consensus height is 0 — no period "+
				"can be formed; check the height source wiring", s.Mempool.PendingCount())
		}
		return
	}

	for _, chainID := range s.Mempool.DueChains(now, force) {
		s.flushChainPeriods(ctx, chainID, cutoffHeight, DefaultBatchPeriodBlocks, nil, 0, now, attest, fallback, logf)
	}
}

// flushChainPeriods flushes every CLOSED period this chain still holds members for.
//
// Iterating periods rather than flushing only the newest closed one is what stops a straggler
// stranding. Selection is bucket-scoped, so a period whose elected leader was down is never
// selected again by the newest-period-only rule — it would sit in every node's pool forever.
// Leadership rotates per period, so the next leader picks it up here.
//
// isLeader is consulted per period, not per chain: leadership is a function of (chain, period).
func (s *BatchStack) flushChainPeriods(
	ctx context.Context,
	chainID int64,
	currentPeriodStart uint64,
	periodBlocks uint64,
	isLeader func(chainID int64, periodStart, elapsedPeriods uint64) bool,
	grace time.Duration,
	now time.Time,
	attest BatchAttestFn,
	fallback BatchFallbackFn,
	logf func(string, ...interface{}),
) {
	// Strictly older than the current period: a period still accepting members must not be
	// formed, or two validators at different heights inside it derive different trees.
	periods := s.Mempool.PendingPeriods(chainID, periodBlocks, currentPeriodStart)
	if len(periods) == 0 {
		return
	}
	logf("[BATCH-FLUSH] chain %d: %d closed period(s) pending %v (current period %d)",
		chainID, len(periods), periods, currentPeriodStart)
	for _, start := range periods {
		// How many periods have closed since this one. Drives leader rotation below.
		var elapsed uint64
		if periodBlocks > 0 && currentPeriodStart > start {
			elapsed = (currentPeriodStart - start) / periodBlocks
		}

		// Say which gate declines a pending period.
		//
		// Neither the leader check nor the settle grace logged when it said no, so a chain with
		// queued members and closed periods produced TOTAL SILENCE — no flush, no error, nothing
		// to grep. Chain 84532 sat like that for 35 minutes on 2026-08-04 with five members
		// waiting. A declined period is normal; an undiagnosable one is not.
		if isLeader != nil && !isLeader(chainID, start, elapsed) {
			logf("[BATCH-FLUSH] chain %d period %d: not this node's period to lead (elapsed=%d)",
				chainID, start, elapsed)
			continue
		}
		// SETTLE GRACE — see settleGraceElapsed. A period that closed seconds ago is very
		// likely incomplete on peers that are still generating proofs for its members.
		// A SOLO period needs far less grace than a shared one.
		//
		// The grace exists because a leader that forms a batch the instant its period closes can
		// out-run peers still proving that period's OTHER members — on 2026-08-02 a 2-member
		// batch found two peers holding one member and three holding neither, and quorum failed
		// 2-of-7 with every node healthy. That risk is about CO-MEMBERS: a peer holding some but
		// not all of them derives a different bundleId.
		//
		// With exactly one member there are no co-members. A peer either has it or does not, and
		// measurement says they all do, quickly: an on_demand intent enqueued on all seven within
		// FOUR SECONDS (14:51:16-14:51:20 on 2026-08-04), ~17s after discovery, while the period
		// itself takes ~143s to close at Accumulate's ~1.43s/block. The full grace is waiting for
		// a condition that was satisfied over two minutes earlier.
		//
		// on_demand is by definition a single intent, so this is exactly that path — without
		// having to thread proofClass through the enqueue interface and the persisted schema.
		// soloSettleGrace still leaves ~15x margin over the observed spread, because that sample
		// was a healthy idle set and a loaded or catching-up node will be slower.
		effectiveGrace := grace
		if n := len(s.Mempool.PeekForPeriod(chainID, start, periodBlocks)); n == 1 && grace > soloSettleGrace {
			effectiveGrace = soloSettleGrace
			logf("[BATCH-FLUSH] chain %d period %d: solo member — grace %s instead of %s",
				chainID, start, effectiveGrace, grace)
		}

		if !s.settleGraceElapsed(chainID, start, effectiveGrace, now, logf) {
			logf("[BATCH-FLUSH] chain %d period %d: leading, but holding for settle grace %s",
				chainID, start, effectiveGrace)
			continue
		}
		logf("[BATCH-FLUSH] chain %d period %d: leading and past grace — flushing", chainID, start)
		s.flushOneChain(ctx, chainID, start, periodBlocks, attest, fallback, logf)
	}
}

// settleGraceElapsed reports whether a closed period has been closed long enough for peers to
// have finished processing its members.
//
// # WHY A DELAY IS NEEDED AT ALL
//
// Membership is a pure function of committed BFT height, so every validator eventually derives
// the same tree. "Eventually" is the problem: a validator only LEARNS about a member when it
// finishes its own processing of that round, and that takes minutes — L1-L3 proof, then G0, G1
// and G2 governance proofs at roughly thirty seconds each. Those pipelines run at different
// speeds on different nodes.
//
// Observed live 2026-08-02: the leader formed a 2-member batch for period [210,215) moments
// after the period closed. Two peers had only ONE of the members and derived a different
// bundleId; three had neither and had nothing to rebuild from. One peer agreed. Quorum failed
// at 2-of-7 even though every node was healthy, honest, and would have agreed a minute later.
//
// # WHY A WALL CLOCK IS SAFE HERE, WHEN IT IS NOT SAFE FOR MEMBERSHIP
//
// The clock decides only WHEN the leader forms the batch, never WHICH members are in it — that
// stays keyed on committed height. Two validators with skewed clocks still derive identical
// trees for a given period; one merely offers to lead it sooner. So this costs latency and
// cannot cause the divergence the whole design exists to prevent.
//
// The grace starts when THIS node first observes the period closed, not when the period's
// heights were committed, so a node that was restarted or was catching up does not immediately
// consider a long-closed period ready.
func (s *BatchStack) settleGraceElapsed(
	chainID int64,
	periodStart uint64,
	grace time.Duration,
	now time.Time,
	logf func(string, ...interface{}),
) bool {
	if grace <= 0 {
		return true
	}
	key := periodKey{chainID: chainID, periodStart: periodStart}

	s.closedMu.Lock()
	first, seen := s.closedAt[key]
	if !seen {
		if s.closedAt == nil {
			s.closedAt = make(map[periodKey]time.Time)
		}
		s.closedAt[key] = now
		first = now
	}
	// Bound the map. Entries are only ever consulted for periods still holding members, so
	// anything older than the one being asked about is dead weight.
	if len(s.closedAt) > 512 {
		for k, t := range s.closedAt {
			if now.Sub(t) > 24*time.Hour {
				delete(s.closedAt, k)
			}
		}
	}
	s.closedMu.Unlock()

	if now.Sub(first) >= grace {
		return true
	}
	if !seen {
		logf("[BATCH-FLUSH] chain %d period %d closed; holding %s for peers to finish "+
			"processing its members before forming the batch", chainID, periodStart, grace)
	}
	return false
}

// flushOneChain is the shared body: form the period's tree, settle it, then dispose of every
// member exactly once — settled and failed to the attester, dropped to the fallback.
func (s *BatchStack) flushOneChain(
	ctx context.Context,
	chainID int64,
	cutoffHeight uint64,
	periodBlocks uint64,
	attest BatchAttestFn,
	fallback BatchFallbackFn,
	logf func(string, ...interface{}),
) {
	orch, err := s.OrchestratorFor(chainID)
	if err != nil {
		logf("[BATCH-FLUSH] chain %d has no orchestrator: %v", chainID, err)
		return
	}

	res, err := orch.FlushChain(ctx, chainID, cutoffHeight, periodBlocks)
	if err != nil {
		// FlushChain requeues on any pre-anchor failure, so nothing is lost there. Past the
		// anchor it DROPS instead, and those members are handed to the fallback below.
		logf("[BATCH-FLUSH] chain %d flush failed: %v", chainID, err)
	}
	if res == nil {
		return
	}

	// Dropped members have left the batch path for good. Routing them to the per-intent path
	// is the approved failure policy; skipping this would strand them silently, which is
	// precisely the outcome the policy exists to avoid.
	if len(res.Dropped) > 0 {
		if fallback == nil {
			logf("[BATCH-FLUSH] ⚠️ chain %d dropped %d member(s) but NO FALLBACK is wired — "+
				"they will never settle", chainID, len(res.Dropped))
		} else {
			logf("[BATCH-FLUSH] chain %d routing %d dropped member(s) to the per-intent path",
				chainID, len(res.Dropped))
			for _, m := range res.Dropped {
				fallback(ctx, m)
			}
		}
	}

	// Released because a previous leader had already anchored this period.
	//
	// A member whose leaf IS consumed genuinely settled under that leader, which also attested
	// it — re-attesting would duplicate the Accumulate write-back, and routing it to the fallback
	// would re-execute an intent that has already moved funds. Those are skipped.
	//
	// A member whose leaf is still SPENDABLE never executed. The old code returned here for both
	// cases on the assumption that the previous leader had attested every member, so these were
	// released with no settlement, no failure and no record — the silent drop this failure policy
	// exists to prevent. Observed live 2026-08-03 on period 6300300: anchor present, two members
	// released, no funds moved, nothing written back. They are attested as unsettled so the ADI
	// learns the outcome; their leaves remain spendable, so a later flush can still settle them.
	if len(res.AlreadySettled) > 0 {
		var settled, unsettled int
		for _, m := range res.AlreadySettled {
			if res.AlreadySettledOutcome[m.IntentID] {
				settled++
				continue
			}
			unsettled++
			if attest != nil {
				attest(ctx, m.Attestation, "", chainID, false)
			}
		}
		logf("[BATCH-FLUSH] chain %d period %d: %d member(s) released under a previous leader's "+
			"anchor — %d had consumed leaves (already attested), %d never executed and were "+
			"attested as unsettled", chainID, cutoffHeight, len(res.AlreadySettled), settled, unsettled)
		if attest == nil && unsettled > 0 {
			logf("[BATCH-FLUSH] NO ATTESTATION FN — %d released member(s) never executed and "+
				"their proof cycles will NOT close", unsettled)
		}
		return
	}

	if res.MemberCount == 0 {
		return
	}
	logf("[BATCH-FLUSH] chain %d: %d settled, %d failed, %d dropped, anchor gas %d amortised over %d members",
		chainID, len(res.Settled), len(res.Failed), len(res.Dropped), res.GasAnchor, res.MemberCount)

	if attest == nil {
		logf("[BATCH-FLUSH] NO ATTESTATION FN — %d members settled on chain but their "+
			"proof cycles will NOT close", len(res.Settled))
		return
	}

	for _, m := range res.Settled {
		attest(ctx, m.Attestation, res.TxHashes[m.IntentID], chainID, true)
	}
	for _, m := range res.Failed {
		// Pass the reverted member's transaction hash when it has one. It is empty only when the
		// member never reached the chain at all (branch error, or a send that never entered the
		// mempool); in that case RunProofCycle routes to recordFailedProofCycle, which still
		// attests and writes back so the outcome is never silent.
		attest(ctx, m.Attestation, res.TxHashes[m.IntentID], chainID, false)
	}
}

// BatchFallbackFn routes a member that has left the batch path to the per-intent on_demand
// path. Supplied by pkg/consensus, which owns that path.
//
// It is not optional in production: FlushChain drops members after the anchor is mined rather
// than requeueing them (a requeue re-derives the same bundleId and reverts), so without this
// they never settle.
type BatchFallbackFn func(ctx context.Context, member *PendingBatchIntent)

// BatchFlushConfig is what RunFlushLoop needs from the node around it.
type BatchFlushConfig struct {
	// Interval is the flush cadence.
	Interval time.Duration

	// PeriodBlocks buckets consensus heights into batch periods. Every validator MUST use the
	// same value: it feeds BatchPeriodCutoff, which feeds accumulateBlockHeight, which feeds
	// the bundleId. A node configured differently derives a different bundleId from identical
	// membership and can neither propose nor attest successfully.
	PeriodBlocks uint64

	// ConsensusHeightFn reports the current BFT height. A stub returning 0 makes every cutoff
	// 0, so no period ever selects members and the batch path is silently inert — which is
	// exactly what shipped before this was wired.
	ConsensusHeightFn func() uint64

	// IsLeaderFn reports whether THIS validator is the elected submitter for the period.
	// Non-leaders never form a batch; they only answer attestation requests. Without it every
	// validator would race to anchor the same period, and six of the seven would burn gas
	// reverting with AnchorAlreadyExists.
	//
	// Nil means "always leader" — correct only for a single-node devnet.
	// elapsedPeriods is how many periods have closed since this one did. It exists so leadership
	// can ROTATE when the elected node is down: without it a period whose leader is offline can
	// never be flushed by anyone. Every node derives it from currentPeriodStart, which they
	// already compute identically, so the rotation stays deterministic.
	IsLeaderFn func(chainID int64, cutoffHeight, elapsedPeriods uint64) bool

	// Attest closes each settled member's proof cycle.
	Attest BatchAttestFn

	// Fallback routes dropped members to the per-intent path.
	Fallback BatchFallbackFn

	// SettleGrace delays forming a closed period so peers can finish processing its members.
	// Zero means DefaultBatchSettleGrace.
	SettleGrace time.Duration

	// RetentionPeriods is how many periods a member may sit before being pruned as garbage.
	// Zero means DefaultBatchRetentionPeriods.
	RetentionPeriods uint64
}

// periodKey identifies one chain's period for grace tracking.
type periodKey struct {
	chainID     int64
	periodStart uint64
}

// DefaultBatchSettleGrace is how long a period must have been closed before the leader forms
// it. It must comfortably exceed the slowest member pipeline: L1-L3 plus G0/G1/G2 measured at
// roughly three minutes per intent on Sepolia/Kermit, and a peer that has not finished cannot
// reproduce the batch.
const DefaultBatchSettleGrace = 4 * time.Minute

// soloSettleGrace applies to a period holding exactly one member — the on_demand shape.
//
// Sized from measurement, not intuition: all seven validators enqueued the same intent within a
// 4-second window, so 60s is roughly fifteen times the observed spread. It is deliberately not
// smaller; the sample came from an idle set, and a node under load or catching up will lag.
const soloSettleGrace = time.Minute

// DefaultBatchRetentionPeriods is the memory backstop horizon. Generous on purpose: a member
// pruned while its period was still waiting for a working leader would never settle, and
// leadership rotates, so the set has many chances to pick a straggler up.
const DefaultBatchRetentionPeriods uint64 = 50

// RunFlushLoop drives FlushDueChains on the cadence until ctx is cancelled.
//
// On shutdown it performs one final forced flush so queued intents are not abandoned
// mid-window — the same drain-on-exit contract BatchAccumulator honours.
func (s *BatchStack) RunFlushLoop(
	ctx context.Context,
	cfg BatchFlushConfig,
	logf func(string, ...interface{}),
) {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	periodBlocks := cfg.PeriodBlocks
	if periodBlocks == 0 {
		periodBlocks = DefaultBatchPeriodBlocks
	}
	heightFn := cfg.ConsensusHeightFn
	if heightFn == nil {
		heightFn = func() uint64 { return 0 }
	}
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// A faster sub-tick so MaxAge is honoured with reasonable granularity even when the
	// cadence interval is long.
	sub := interval / 4
	if sub < time.Second {
		sub = time.Second
	}
	subTicker := time.NewTicker(sub)
	defer subTicker.Stop()

	logf("[BATCH-FLUSH] loop started: interval=%s periodBlocks=%d chains=%v",
		interval, periodBlocks, s.Resolver.Chains())
	if cfg.IsLeaderFn == nil {
		logf("[BATCH-FLUSH] ⚠️ no leader election wired — this node will attempt to anchor EVERY " +
			"period. Correct for a single-node devnet only.")
	}

	// RetentionPeriods bounds how long a member may sit unflushed before it is pruned as
	// garbage. Attesters never remove what they peek at, so without this every intent a node
	// has ever seen accumulates for the life of the process.
	retention := cfg.RetentionPeriods
	if retention == 0 {
		retention = DefaultBatchRetentionPeriods
	}
	grace := cfg.SettleGrace
	if grace == 0 {
		grace = DefaultBatchSettleGrace
	}

	// flush runs one pass: every closed period, leader-gated per period.
	flush := func(passCtx context.Context, now time.Time, force bool) {
		height := heightFn()
		cutoff := BatchPeriodCutoff(height, periodBlocks)
		if cutoff == 0 {
			if s.Mempool.PendingCount() > 0 {
				logf("[BATCH-FLUSH] %d member(s) queued but the consensus height is %d — no period "+
					"has closed yet", s.Mempool.PendingCount(), height)
			}
			return
		}
		for _, chainID := range s.Resolver.Chains() {
			s.flushChainPeriods(passCtx, chainID, cutoff, periodBlocks,
				cfg.IsLeaderFn, grace, now, cfg.Attest, cfg.Fallback, logf)
		}

		// Memory backstop. Correctness does not depend on it — selection is bucket-scoped, so
		// stale members cannot pollute a later period's tree.
		if horizonPeriods := retention * periodBlocks; cutoff > horizonPeriods {
			if n := s.Mempool.PruneOlderThan(cutoff - horizonPeriods); n > 0 {
				logf("[BATCH-FLUSH] pruned %d member(s) older than %d periods. On a node that led "+
					"their period this means a batch never settled; on any other node it is the "+
					"expected copy of a batch some other leader settled.", n, retention)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			logf("[BATCH-FLUSH] shutting down — draining %d queued members", s.Mempool.PendingCount())
			flush(context.Background(), time.Now(), true)
			return
		case now := <-ticker.C:
			flush(ctx, now, true)
		case now := <-subTicker.C:
			flush(ctx, now, false)
		}
	}
}

// DefaultBatchPeriodBlocks is the period width used when none is configured, in ACCUMULATE
// block heights.
//
// It must match across validators. Accumulate advances continuously and independently of
// Certen's own traffic, which is what lets a period close at all — the CometBFT chain only
// advances when Certen commits something, so a lone intent could never close its own period
// there.
//
// A hundred blocks is wide enough that intents submitted within a minute of each other land
// together (that is the whole point of batching) and narrow enough that a period closes
// promptly.
const DefaultBatchPeriodBlocks uint64 = 100

// =============================================================================
// BatchEnqueuer adapter
// =============================================================================

// enqueueLeg mirrors consensus.BatchLeg structurally. Declared here so the conversion is
// explicit and this package needs no consensus import (consensus already imports execution).
type enqueueLeg struct {
	LegID   string
	ChainID int64
	Target  [20]byte
	Value   *big.Int
	Data    []byte
}

// EnqueueForBatch satisfies consensus.BatchEnqueuer.
//
// legs arrives as interface{} because the concrete slice type lives in pkg/consensus.
// It is converted reflectively via a structural mirror; anything that does not match is
// REJECTED so the caller falls back rather than silently queueing a malformed member.
func (s *BatchStack) EnqueueForBatch(
	intentID string,
	adiURL string,
	chainID int64,
	account [20]byte,
	operationID [32]byte,
	legs interface{},
	attestation interface{},
	commitHeight uint64,
) error {
	if _, err := s.OrchestratorFor(chainID); err != nil {
		// No orchestrator means no anchor for this chain — the member could never settle.
		return fmt.Errorf("chain %d is not configured for batching: %w", chainID, err)
	}

	converted, err := convertLegs(legs, chainID, common.BytesToAddress(account[:]))
	if err != nil {
		return err
	}
	if len(converted) == 0 {
		return fmt.Errorf("intent %s produced no batch legs", intentID)
	}

	// A member with no commit height can never be placed in a period deterministically, so
	// PeekForPeriod skips it and it would sit in the pool forever. Refuse it here, where the
	// caller can still fall back to the per-intent path, rather than silently stranding it.
	if commitHeight == 0 {
		return fmt.Errorf("intent %s has no BFT commit height and could never be batched "+
			"deterministically", intentID)
	}

	return s.Mempool.Add(&PendingBatchIntent{
		IntentID:     intentID,
		ADIURL:       adiURL,
		ChainID:      chainID,
		Account:      common.BytesToAddress(account[:]),
		OperationID:  operationID,
		Legs:         converted,
		Attestation:  attestation,
		CommitHeight: commitHeight,
	})
}

// EnqueueOnDemand queues an intent-keyed member: one intent, one anchor, no period.
//
// Identical admission rules to EnqueueForBatch — the two differ ONLY in which structure the
// member lands in, and therefore which mechanism settles it. Routing is the caller's decision,
// made from the intent's proofClass; this function does not inspect it.
//
// Signals the submitter so settlement starts immediately rather than on the next sweep. The
// signal is best-effort: a member whose signal is lost is picked up by the backstop ticker.
func (s *BatchStack) EnqueueOnDemand(
	intentID string,
	adiURL string,
	chainID int64,
	account [20]byte,
	operationID [32]byte,
	legs interface{},
	attestation interface{},
	commitHeight uint64,
) error {
	if _, err := s.OrchestratorFor(chainID); err != nil {
		return fmt.Errorf("chain %d is not configured for batching: %w", chainID, err)
	}

	converted, err := convertLegs(legs, chainID, common.BytesToAddress(account[:]))
	if err != nil {
		return err
	}
	if len(converted) == 0 {
		return fmt.Errorf("intent %s produced no batch legs", intentID)
	}
	// The commit height is bound into the bundleId. Without it every validator with a different
	// local view derives a different id, exactly as on the period path.
	if commitHeight == 0 {
		return fmt.Errorf("intent %s has no BFT commit height; its bundleId is not derivable",
			intentID)
	}

	if err := s.Mempool.AddOnDemand(&PendingBatchIntent{
		IntentID:     intentID,
		ADIURL:       adiURL,
		ChainID:      chainID,
		Account:      common.BytesToAddress(account[:]),
		OperationID:  operationID,
		Legs:         converted,
		Attestation:  attestation,
		CommitHeight: commitHeight,
	}); err != nil {
		return err
	}
	if w := s.onDemandWaker.Load(); w != nil {
		(*w)()
	}
	return nil
}

// SetOnDemandWaker installs the callback that signals the on-demand submitter after an enqueue.
//
// Stored as a pointer-to-func in an atomic so the submitter can be wired AFTER the stack is
// published for attestation, without a lock on the enqueue hot path.
func (s *BatchStack) SetOnDemandWaker(wake func()) {
	if wake == nil {
		return
	}
	s.onDemandWaker.Store(&wake)
}

// convertLegs turns the caller's leg slice into LegExecution via reflection over a
// structural mirror. Field names and types must match enqueueLeg exactly.
func convertLegs(legs interface{}, chainID int64, account common.Address) ([]LegExecution, error) {
	if legs == nil {
		return nil, fmt.Errorf("nil legs")
	}
	rv := reflect.ValueOf(legs)
	if rv.Kind() != reflect.Slice {
		return nil, fmt.Errorf("legs is %s, expected a slice", rv.Kind())
	}

	out := make([]LegExecution, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		e := rv.Index(i)
		if e.Kind() != reflect.Struct {
			return nil, fmt.Errorf("leg %d is %s, expected a struct", i, e.Kind())
		}

		get := func(name string) (reflect.Value, error) {
			f := e.FieldByName(name)
			if !f.IsValid() {
				return f, fmt.Errorf("leg %d has no field %s", i, name)
			}
			return f, nil
		}

		legIDF, err := get("LegID")
		if err != nil {
			return nil, err
		}
		targetF, err := get("Target")
		if err != nil {
			return nil, err
		}
		valueF, err := get("Value")
		if err != nil {
			return nil, err
		}
		dataF, err := get("Data")
		if err != nil {
			return nil, err
		}
		chainF, err := get("ChainID")
		if err != nil {
			return nil, err
		}

		if chainF.Int() != chainID {
			return nil, fmt.Errorf("leg %d targets chain %d but the member is chain %d",
				i, chainF.Int(), chainID)
		}

		var target common.Address
		tb := targetF
		if tb.Kind() != reflect.Array || tb.Len() != 20 {
			return nil, fmt.Errorf("leg %d Target is not [20]byte", i)
		}
		for j := 0; j < 20; j++ {
			target[j] = byte(tb.Index(j).Uint())
		}

		val, _ := valueF.Interface().(*big.Int)
		if val == nil {
			val = new(big.Int)
		}
		data, _ := dataF.Interface().([]byte)

		out = append(out, LegExecution{
			LegID:   legIDF.String(),
			ChainID: chainID,
			Target:  target,
			Value:   val,
			Data:    data,
			// Every leg of a member executes from that member's own account — consensus
			// already rejected an intent whose legs span two source accounts.
			SourceAddress: account,
		})
	}
	return out, nil
}
