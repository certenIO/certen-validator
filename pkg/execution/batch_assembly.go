package execution

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
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
		s.flushOneChain(ctx, chainID, cutoffHeight, attest, fallback, logf)
	}
}

// flushChainIfDue flushes one chain, but only if its pool says it is due.
//
// RunFlushLoop uses this rather than FlushDueChains so leadership can be evaluated per chain
// BEFORE the pool is consulted — a non-leader must not form a batch even for a due chain.
func (s *BatchStack) flushChainIfDue(
	ctx context.Context,
	chainID int64,
	now time.Time,
	force bool,
	cutoffHeight uint64,
	attest BatchAttestFn,
	fallback BatchFallbackFn,
	logf func(string, ...interface{}),
) {
	for _, due := range s.Mempool.DueChains(now, force) {
		if due == chainID {
			s.flushOneChain(ctx, chainID, cutoffHeight, attest, fallback, logf)
			return
		}
	}
}

// flushOneChain is the shared body: form the period's tree, settle it, then dispose of every
// member exactly once — settled and failed to the attester, dropped to the fallback.
func (s *BatchStack) flushOneChain(
	ctx context.Context,
	chainID int64,
	cutoffHeight uint64,
	attest BatchAttestFn,
	fallback BatchFallbackFn,
	logf func(string, ...interface{}),
) {
	orch, err := s.OrchestratorFor(chainID)
	if err != nil {
		logf("[BATCH-FLUSH] chain %d has no orchestrator: %v", chainID, err)
		return
	}

	res, err := orch.FlushChain(ctx, chainID, cutoffHeight)
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
		attest(ctx, m.Attestation, "", chainID, false)
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
	IsLeaderFn func(chainID int64, cutoffHeight uint64) bool

	// Attest closes each settled member's proof cycle.
	Attest BatchAttestFn

	// Fallback routes dropped members to the per-intent path.
	Fallback BatchFallbackFn
}

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

	// flush runs one pass, gated on leadership for the current period.
	flush := func(passCtx context.Context, now time.Time, force bool) {
		cutoff := BatchPeriodCutoff(heightFn(), periodBlocks)
		if cutoff == 0 {
			s.FlushDueChains(passCtx, now, force, 0, cfg.Attest, cfg.Fallback, logf)
			return
		}
		for _, chainID := range s.Resolver.Chains() {
			if cfg.IsLeaderFn != nil && !cfg.IsLeaderFn(chainID, cutoff) {
				continue
			}
			s.flushChainIfDue(passCtx, chainID, now, force, cutoff, cfg.Attest, cfg.Fallback, logf)
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

// DefaultBatchPeriodBlocks is the period width used when none is configured.
//
// It must match across validators. Ten BFT blocks is short enough that a member does not wait
// long for its period to close, and long enough that peers have committed the same rounds
// before the leader forms the tree.
const DefaultBatchPeriodBlocks uint64 = 10

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
