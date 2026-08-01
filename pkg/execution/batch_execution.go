package execution

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// Authority levels — must mirror CertenAccountV6.AuthorityLevel
// =============================================================================

const (
	AuthorityNone     uint8 = 0
	AuthorityOperator uint8 = 1
	AuthorityManager  uint8 = 2
	AuthorityAdmin    uint8 = 3
	AuthorityRoot     uint8 = 4
)

var (
	oneTenthEther = new(big.Int).Div(big.NewInt(1e18), big.NewInt(10)) // 0.1 ETH
	oneEther      = big.NewInt(1e18)
	tenEther      = new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))
)

// requiredLevelForValue mirrors CertenAccountV6._requiredLevelFor's value ladder.
//
// The contract rejects any leg whose demanded level exceeds proof.requiredLevel, and it
// applies that check to EVERY element of a batch. If the validator submits a batch under a
// level lower than its most demanding leg, the whole batch reverts after the anchor has
// already been created and paid for. So the level must be computed from the legs, not fixed.
//
// Note this covers only the value-derived ladder. CertenAccountV6 also honours explicit
// per-selector requirements registered via setOperationRequirement; those default to unset
// for ordinary transfers and contract calls, and the four self-administration selectors it
// pre-registers are not reachable as ordinary legs.
func requiredLevelForValue(value *big.Int) uint8 {
	if value == nil {
		return AuthorityOperator
	}
	switch {
	case value.Cmp(tenEther) >= 0:
		return AuthorityRoot
	case value.Cmp(oneEther) >= 0:
		return AuthorityAdmin
	case value.Cmp(oneTenthEther) >= 0:
		return AuthorityManager
	default:
		return AuthorityOperator
	}
}

// requiredLevelForLegs returns the highest level demanded by any leg in the batch.
func requiredLevelForLegs(legs []LegExecution) uint8 {
	level := AuthorityOperator
	for _, leg := range legs {
		if l := requiredLevelForValue(leg.Value); l > level {
			level = l
		}
	}
	return level
}

// =============================================================================
// Batch grouping
// =============================================================================

// BatchKey identifies the unit that can share one anchor and one account call.
//
// A batch executes as a single call on a single CertenAccountV6, and that account is
// per-ADI. The anchor binds exactly one adiURLHash (CertenAnchorV6_1.Anchor.adiURLHash), so
// legs belonging to different ADIs can never share an anchor or a batch — they are separate
// batches even when flushed in the same cadence tick.
type BatchKey struct {
	ADIURL        string
	ChainID       int64
	SourceAccount common.Address
}

func (k BatchKey) String() string {
	return fmt.Sprintf("%s|%d|%s", k.ADIURL, k.ChainID, k.SourceAccount.Hex())
}

// BatchGroup is an ordered set of legs sharing one anchor and one account call.
type BatchGroup struct {
	Key  BatchKey
	Legs []LegExecution
}

// GroupLegsForBatch partitions legs into batchable groups.
//
// Legs are grouped by (ADI, chain, source account) and the original relative order within
// each group is preserved — CertenAccountV6 commits to an ORDERED sequence and rejects a
// reordered batch, so grouping must be order-stable.
//
// Legs with a zero source account cannot be batched (there is no account to call) and are
// returned separately for the caller to handle via the legacy anchor path.
func GroupLegsForBatch(adiURL string, legs []LegExecution) (groups []BatchGroup, unbatchable []LegExecution) {
	index := make(map[string]int)

	for _, leg := range legs {
		if leg.SourceAddress == (common.Address{}) {
			unbatchable = append(unbatchable, leg)
			continue
		}
		key := BatchKey{ADIURL: adiURL, ChainID: leg.ChainID, SourceAccount: leg.SourceAddress}
		ks := key.String()
		if i, ok := index[ks]; ok {
			groups[i].Legs = append(groups[i].Legs, leg)
			continue
		}
		index[ks] = len(groups)
		groups = append(groups, BatchGroup{Key: key, Legs: []LegExecution{leg}})
	}

	return groups, unbatchable
}

// ToBatchCalls converts a group's legs into the commitment input.
func (g BatchGroup) ToBatchCalls() []BatchCall {
	calls := make([]BatchCall, 0, len(g.Legs))
	for _, leg := range g.Legs {
		v := leg.Value
		if v == nil {
			v = big.NewInt(0)
		}
		calls = append(calls, BatchCall{Target: leg.Target, Value: v, Data: leg.Data})
	}
	return calls
}

// ToCallArrays converts a group's legs into the three parallel arrays the contract takes.
func (g BatchGroup) ToCallArrays() (targets []common.Address, values []*big.Int, datas [][]byte) {
	for _, leg := range g.Legs {
		v := leg.Value
		if v == nil {
			v = big.NewInt(0)
		}
		targets = append(targets, leg.Target)
		values = append(values, v)
		datas = append(datas, leg.Data)
	}
	return targets, values, datas
}

// ExecutionCommitment returns the anchor-side commitment this group must be anchored under.
//
// A one-leg group uses the SINGLE-call commitment and the single-call execution path, so an
// intent that happens to have one leg behaves exactly as it does today. Only genuine
// multi-leg groups take the batch shape. This keeps the on-demand path bit-identical to the
// pre-batch behaviour rather than silently re-shaping every intent.
func (g BatchGroup) ExecutionCommitment() [32]byte {
	if len(g.Legs) == 1 {
		leg := g.Legs[0]
		v := leg.Value
		if v == nil {
			v = big.NewInt(0)
		}
		return computeExecutionCommitment(g.Key.ChainID, leg.Target, v, leg.Data)
	}
	return computeBatchExecutionCommitment(g.Key.ChainID, g.ToBatchCalls())
}

// IsBatch reports whether this group must use batchExecuteGovernanceProofDirect.
func (g BatchGroup) IsBatch() bool { return len(g.Legs) > 1 }

// TotalValue sums the native value the account must hold to satisfy the whole batch.
// Checked before submission — an underfunded batch reverts atomically and wastes the anchor.
func (g BatchGroup) TotalValue() *big.Int {
	total := big.NewInt(0)
	for _, leg := range g.Legs {
		if leg.Value != nil {
			total = new(big.Int).Add(total, leg.Value)
		}
	}
	return total
}

// =============================================================================
// Batch execution against a deployed CertenAccountV6
// =============================================================================

// ExecuteBatchViaUserAccount submits an anchored ordered batch to the user's account via
// CertenAccountV6.batchExecuteGovernanceProofDirect.
//
// All-or-nothing: CertenAccountV6._executeOperation bubbles any leg's revert, so either every
// leg executed or none did and the anchor was NOT consumed (the state write is rolled back
// with the rest of the transaction). A failed batch is therefore safe to retry against the
// same anchor once the cause is resolved.
//
// Preflight checks below exist because a revert still costs gas and, worse, leaves the
// operator unsure whether the anchor was spent. Each check turns a guaranteed on-chain
// failure into a cheap local error.
func (ecm *EthereumContractManager) ExecuteBatchViaUserAccount(
	ctx context.Context,
	group BatchGroup,
	bundleID [32]byte,
	certenProof *proof.CertenProof,
	adiURL string,
) (string, error) {
	if len(group.Legs) == 0 {
		return "", fmt.Errorf("batch execution called with no legs")
	}

	userAccountAddress := group.Key.SourceAccount
	targets, values, datas := group.ToCallArrays()
	requiredLevel := requiredLevelForLegs(group.Legs)

	fmt.Printf("📦 [BATCH-ACCOUNT] Executing anchored batch via user's Abstract Account...\n")
	fmt.Printf("   User Account: %s\n", userAccountAddress.Hex())
	fmt.Printf("   Chain ID: %d\n", group.Key.ChainID)
	fmt.Printf("   ADI URL: %s\n", adiURL)
	fmt.Printf("   Legs: %d\n", len(group.Legs))
	fmt.Printf("   Total value: %s wei\n", group.TotalValue().String())
	fmt.Printf("   Required authority level: %d\n", requiredLevel)
	for i, leg := range group.Legs {
		fmt.Printf("     [%d] %s -> %s value=%s data=%dB\n",
			i, leg.LegID, leg.Target.Hex(), values[i].String(), len(leg.Data))
	}

	account, err := contracts.NewCertenAccountV6(userAccountAddress, ecm.client)
	if err != nil {
		return "", fmt.Errorf("failed to bind user account (V6) contract: %w", err)
	}

	// Preflight 1: the account must actually be a keyless V6 account. If this call reverts
	// or returns false we are pointed at a V4/V5 account (or something else entirely), and
	// batchExecuteGovernanceProofDirect does not exist there — the tx would burn gas on a
	// fallback-function revert with no useful error.
	keyless, err := account.IsKeylessOwner(&bind.CallOpts{Context: ctx})
	if err != nil {
		return "", fmt.Errorf("account %s does not expose isKeylessOwner — not a CertenAccountV6: %w",
			userAccountAddress.Hex(), err)
	}
	if !keyless {
		return "", fmt.Errorf("account %s reports a non-keyless owner; refusing to submit batch",
			userAccountAddress.Hex())
	}

	// Preflight 2: the anchor must not already be consumed. CertenAccountV6 allows each
	// anchor exactly one execution (Finding B), so a retry after a SUCCESSFUL batch would
	// revert with "invalid governance proof" — a confusing error for what is really
	// "already done".
	consumed, err := account.IsAnchorConsumed(&bind.CallOpts{Context: ctx}, bundleID)
	if err != nil {
		return "", fmt.Errorf("failed to read anchor-consumed state: %w", err)
	}
	if consumed {
		return "", fmt.Errorf("anchor 0x%x already consumed by account %s — batch already executed",
			bundleID[:8], userAccountAddress.Hex())
	}

	// Preflight 3: the account must hold enough native value for every leg. The batch is
	// atomic, so one underfunded leg reverts all of them.
	balance, err := ecm.client.BalanceAt(ctx, userAccountAddress, nil)
	if err != nil {
		return "", fmt.Errorf("failed to read account balance: %w", err)
	}
	if total := group.TotalValue(); balance.Cmp(total) < 0 {
		return "", fmt.Errorf("account %s holds %s wei but batch requires %s wei",
			userAccountAddress.Hex(), balance.String(), total.String())
	}

	// Preflight 4: the Go-computed batch commitment must equal the contract's own. This is
	// the cross-language encoding check performed against the ACTUAL deployed bytecode
	// rather than a test fixture — it catches an ABI-encoding drift before it costs an
	// anchor. Pinned in tests by TestBatchExecutionCommitment_MatchesSolidity.
	onChainCommitment, err := account.ComputeBatchCommitment(&bind.CallOpts{Context: ctx}, targets, values, datas)
	if err != nil {
		return "", fmt.Errorf("failed to read on-chain batch commitment: %w", err)
	}
	localCommitment := computeBatchExecutionCommitment(group.Key.ChainID, group.ToBatchCalls())
	if onChainCommitment != localCommitment {
		return "", fmt.Errorf(
			"batch commitment mismatch — Go computed 0x%x but contract computed 0x%x; "+
				"encoding drift between validator and CertenAccountV6",
			localCommitment, onChainCommitment)
	}
	fmt.Printf("   ✅ Batch commitment agrees with on-chain: 0x%x\n", localCommitment[:8])

	// Fetch the anchor's commitments for the merkle proof, polling for confirmation.
	opCommitment, ccCommitment, govRoot, err := ecm.waitForAnchorCommitments(ctx, bundleID)
	if err != nil {
		return "", err
	}

	// The merkle leaf must be tagged with the BATCH commitment, matching what createAnchor
	// stored — otherwise verifyProof fails against the anchor's root.
	accountProof := ecm.buildAccountProofWithExec(
		bundleID, certenProof, adiURL,
		opCommitment, ccCommitment, govRoot,
		&localCommitment, requiredLevel,
	)

	// Gas scales with the number of legs. The 500k baseline matches the single-call path;
	// each additional leg costs roughly a call plus its own authority check.
	ecm.auth.GasLimit = 400000 + uint64(len(group.Legs))*250000
	fmt.Printf("   Gas Limit: %d\n", ecm.auth.GasLimit)

	tx, err := account.BatchExecuteGovernanceProofDirect(ecm.auth, targets, values, datas, accountProof)
	if err != nil {
		return "", fmt.Errorf("batchExecuteGovernanceProofDirect failed: %w", err)
	}

	txHash := tx.Hash().Hex()
	fmt.Printf("✅ [BATCH-ACCOUNT] Batch submitted: %s\n", txHash)

	receipt, err := bind.WaitMined(ctx, ecm.client, tx)
	if err != nil {
		return "", fmt.Errorf("failed to get batch receipt (tx %s): %w", txHash, err)
	}
	fmt.Printf("   Block: %d  Gas Used: %d  Status: %d\n",
		receipt.BlockNumber.Uint64(), receipt.GasUsed, receipt.Status)
	if receipt.Status == 0 {
		// All-or-nothing: nothing executed and the anchor was not consumed.
		return "", fmt.Errorf("batch reverted on-chain (tx %s) — no leg executed, anchor 0x%x still spendable",
			txHash, bundleID[:8])
	}

	return txHash, nil
}

// waitForAnchorCommitments polls the anchor until createAnchor has been mined, returning the
// three commitments needed to rebuild the merkle proof.
func (ecm *EthereumContractManager) waitForAnchorCommitments(
	ctx context.Context,
	bundleID [32]byte,
) (opCommitment, ccCommitment, govRoot [32]byte, err error) {
	var zeroHash [32]byte
	for attempts := 0; attempts < 30; attempts++ {
		select {
		case <-ctx.Done():
			return zeroHash, zeroHash, zeroHash, ctx.Err()
		default:
		}

		anchorData, callErr := ecm.anchor.CertenAnchorV4Caller.GetAnchor(nil, bundleID)
		if callErr != nil {
			return zeroHash, zeroHash, zeroHash, fmt.Errorf("failed to fetch anchor for commitments: %w", callErr)
		}
		opCommitment = anchorData.OperationCommitment
		ccCommitment = anchorData.CrossChainCommitment
		govRoot = anchorData.GovernanceRoot
		if opCommitment != zeroHash || ccCommitment != zeroHash || govRoot != zeroHash {
			return opCommitment, ccCommitment, govRoot, nil
		}
		if attempts == 0 {
			fmt.Printf("   ⏳ Anchor not yet confirmed on-chain, waiting for mining...\n")
		}
		time.Sleep(2 * time.Second)
	}
	return zeroHash, zeroHash, zeroHash,
		fmt.Errorf("anchor commitments still zero after polling — createAnchor may not have been mined")
}

// =============================================================================
// On-cadence batcher
// =============================================================================

// PendingLeg is a leg awaiting its cadence flush, with everything needed to execute it later.
type PendingLeg struct {
	Leg         LegExecution
	ADIURL      string
	IntentID    string
	CertenProof *proof.CertenProof
	EnqueuedAt  time.Time
}

// BatchFlush is one cadence-tick unit of work: an ordered group ready to be anchored and
// executed as a single batch.
type BatchFlush struct {
	Group          BatchGroup
	IntentID       string // first contributing intent; the group may span several
	IntentIDs      []string
	CertenProof    *proof.CertenProof
	OldestEnqueued time.Time
	Reason         string // "cadence", "max_size", or "max_age"
}

// BatchAccumulatorConfig tunes the cadence batcher.
type BatchAccumulatorConfig struct {
	// Interval between cadence flushes. Every pending group is flushed on each tick.
	Interval time.Duration
	// MaxBatchSize forces an early flush of a group once it reaches this many legs. Bounds
	// worst-case gas per transaction so a batch cannot grow past the block gas limit.
	MaxBatchSize int
	// MaxAge forces an early flush of any group whose oldest leg exceeds this age, so a
	// low-traffic ADI is not held hostage to a long interval.
	MaxAge time.Duration
}

// DefaultBatchAccumulatorConfig returns production-safe defaults.
func DefaultBatchAccumulatorConfig() BatchAccumulatorConfig {
	return BatchAccumulatorConfig{
		Interval:     30 * time.Second,
		MaxBatchSize: 20,
		MaxAge:       2 * time.Minute,
	}
}

func (c BatchAccumulatorConfig) withDefaults() BatchAccumulatorConfig {
	d := DefaultBatchAccumulatorConfig()
	if c.Interval <= 0 {
		c.Interval = d.Interval
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = d.MaxBatchSize
	}
	if c.MaxAge <= 0 {
		c.MaxAge = d.MaxAge
	}
	return c
}

// BatchAccumulator collects legs per (ADI, chain, account) and emits them as batches on a
// cadence.
//
// Grouping is per-ADI by necessity, not by choice: one batch is one call on one
// CertenAccountV6, and each account belongs to exactly one ADI. Legs from different ADIs
// arriving in the same tick are emitted as separate BatchFlush values, each of which will get
// its own anchor.
//
// The accumulator is safe for concurrent Add from multiple intent-processing goroutines.
type BatchAccumulator struct {
	cfg     BatchAccumulatorConfig
	pending map[string][]PendingLeg
	order   []string // insertion order of keys, so flushes are deterministic
	keys    map[string]BatchKey
	mu      chan struct{} // 1-buffered channel used as a mutex (keeps zero value usable via New)
	onFlush func(BatchFlush)
	stop    chan struct{}
	stopped bool
}

// NewBatchAccumulator creates a cadence batcher. onFlush is invoked for each emitted group;
// it must not block for long, since flushes are serialized.
func NewBatchAccumulator(cfg BatchAccumulatorConfig, onFlush func(BatchFlush)) *BatchAccumulator {
	b := &BatchAccumulator{
		cfg:     cfg.withDefaults(),
		pending: make(map[string][]PendingLeg),
		keys:    make(map[string]BatchKey),
		mu:      make(chan struct{}, 1),
		onFlush: onFlush,
		stop:    make(chan struct{}),
	}
	b.mu <- struct{}{} // unlocked
	return b
}

func (b *BatchAccumulator) lock()   { <-b.mu }
func (b *BatchAccumulator) unlock() { b.mu <- struct{}{} }

// Add enqueues a leg. If the leg's group reaches MaxBatchSize it is flushed immediately
// rather than waiting for the next tick.
//
// A leg with no source account cannot be batched (there is no account to call); Add rejects
// it so the caller routes it through the legacy anchor path instead of silently dropping it.
func (b *BatchAccumulator) Add(p PendingLeg) error {
	if p.Leg.SourceAddress == (common.Address{}) {
		return fmt.Errorf("leg %s has no source account and cannot be batched", p.Leg.LegID)
	}
	if strings.TrimSpace(p.ADIURL) == "" {
		return fmt.Errorf("leg %s has no ADI URL and cannot be batched", p.Leg.LegID)
	}
	if p.EnqueuedAt.IsZero() {
		p.EnqueuedAt = time.Now()
	}

	key := BatchKey{ADIURL: p.ADIURL, ChainID: p.Leg.ChainID, SourceAccount: p.Leg.SourceAddress}
	ks := key.String()

	b.lock()
	if _, seen := b.keys[ks]; !seen {
		b.keys[ks] = key
		b.order = append(b.order, ks)
	}
	b.pending[ks] = append(b.pending[ks], p)
	full := len(b.pending[ks]) >= b.cfg.MaxBatchSize
	var ready *BatchFlush
	if full {
		ready = b.takeLocked(ks, "max_size")
	}
	b.unlock()

	if ready != nil && b.onFlush != nil {
		b.onFlush(*ready)
	}
	return nil
}

// takeLocked removes a group and converts it to a BatchFlush. Caller must hold the lock.
func (b *BatchAccumulator) takeLocked(ks, reason string) *BatchFlush {
	legs := b.pending[ks]
	if len(legs) == 0 {
		return nil
	}
	key := b.keys[ks]

	delete(b.pending, ks)
	delete(b.keys, ks)
	for i, k := range b.order {
		if k == ks {
			b.order = append(b.order[:i], b.order[i+1:]...)
			break
		}
	}

	group := BatchGroup{Key: key}
	oldest := legs[0].EnqueuedAt
	var ids []string
	seenIDs := make(map[string]bool)
	for _, p := range legs {
		group.Legs = append(group.Legs, p.Leg)
		if p.EnqueuedAt.Before(oldest) {
			oldest = p.EnqueuedAt
		}
		if !seenIDs[p.IntentID] {
			seenIDs[p.IntentID] = true
			ids = append(ids, p.IntentID)
		}
	}

	return &BatchFlush{
		Group:          group,
		IntentID:       legs[0].IntentID,
		IntentIDs:      ids,
		CertenProof:    legs[0].CertenProof,
		OldestEnqueued: oldest,
		Reason:         reason,
	}
}

// FlushDue emits every group that is due: all groups when force is true (the cadence tick),
// otherwise only groups whose oldest leg exceeds MaxAge.
//
// Returns the flushes emitted, in deterministic insertion order.
func (b *BatchAccumulator) FlushDue(now time.Time, force bool) []BatchFlush {
	b.lock()
	keys := append([]string(nil), b.order...)
	var out []BatchFlush
	for _, ks := range keys {
		legs := b.pending[ks]
		if len(legs) == 0 {
			continue
		}
		reason := "cadence"
		if !force {
			oldest := legs[0].EnqueuedAt
			for _, p := range legs {
				if p.EnqueuedAt.Before(oldest) {
					oldest = p.EnqueuedAt
				}
			}
			if now.Sub(oldest) < b.cfg.MaxAge {
				continue
			}
			reason = "max_age"
		}
		if f := b.takeLocked(ks, reason); f != nil {
			out = append(out, *f)
		}
	}
	b.unlock()

	if b.onFlush != nil {
		for _, f := range out {
			b.onFlush(f)
		}
	}
	return out
}

// PendingCount returns the number of legs currently queued across all groups.
func (b *BatchAccumulator) PendingCount() int {
	b.lock()
	n := 0
	for _, legs := range b.pending {
		n += len(legs)
	}
	b.unlock()
	return n
}

// PendingGroups returns the queued group keys, sorted, for observability.
func (b *BatchAccumulator) PendingGroups() []string {
	b.lock()
	out := append([]string(nil), b.order...)
	b.unlock()
	sort.Strings(out)
	return out
}

// Run drives the cadence until ctx is cancelled or Stop is called. On shutdown it performs a
// final forced flush so no leg is silently abandoned in the queue.
func (b *BatchAccumulator) Run(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.Interval)
	defer ticker.Stop()

	// A faster sub-tick so MaxAge is honoured with reasonable granularity even when
	// Interval is long.
	ageTick := b.cfg.Interval / 4
	if ageTick < time.Second {
		ageTick = time.Second
	}
	ageTicker := time.NewTicker(ageTick)
	defer ageTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.FlushDue(time.Now(), true) // drain, do not abandon queued legs
			return
		case <-b.stop:
			b.FlushDue(time.Now(), true)
			return
		case now := <-ticker.C:
			b.FlushDue(now, true)
		case now := <-ageTicker.C:
			b.FlushDue(now, false)
		}
	}
}

// Stop ends the Run loop after a final drain. Safe to call more than once.
func (b *BatchAccumulator) Stop() {
	b.lock()
	already := b.stopped
	b.stopped = true
	b.unlock()
	if !already {
		close(b.stop)
	}
}

// =============================================================================
// Intent -> batch group resolution
// =============================================================================

// batchGroupForThisChain returns the batchable group of legs this manager's chain is
// responsible for, and whether that group is a genuine multi-leg batch.
//
// ok is false when there is nothing to batch — no legs, a single leg, or legs without a
// source account. In every one of those cases the caller falls back to the pre-existing
// single-call behaviour, so the on-demand path is untouched by this function's presence.
//
// Only legs whose ChainID matches this manager's configured chain are considered: an intent
// may span several chains, and each chain gets its own anchor from its own manager.
func (ecm *EthereumContractManager) batchGroupForThisChain(
	certenIntent *intent.CertenIntent,
	certenProof *proof.CertenProof,
) (BatchGroup, bool) {
	legs := ecm.extractLegsForExecCommitment(certenIntent, certenProof)
	if len(legs) < 2 {
		return BatchGroup{}, false
	}

	adiURL := ""
	if certenProof != nil {
		adiURL = certenProof.AccountURL
	}
	if adiURL == "" && certenIntent != nil {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI)
	}

	// Keep only the legs this manager is responsible for.
	var mine []LegExecution
	for _, leg := range legs {
		if leg.ChainID == ecm.config.ChainID {
			mine = append(mine, leg)
		}
	}
	if len(mine) < 2 {
		return BatchGroup{}, false
	}

	groups, unbatchable := GroupLegsForBatch(adiURL, mine)
	if len(unbatchable) > 0 {
		// Mixed batchable/unbatchable legs on one chain cannot be covered by a single
		// anchor. Fall back to the single-call path rather than anchoring a batch that
		// silently omits legs.
		fmt.Printf("⚠️ [BATCH-GROUP] %d leg(s) on chain %d have no source account; "+
			"not batching this chain\n", len(unbatchable), ecm.config.ChainID)
		return BatchGroup{}, false
	}
	if len(groups) != 1 {
		// More than one source account on one chain would need more than one anchor.
		// A single-ADI intent should never produce this; refuse rather than guess.
		fmt.Printf("⚠️ [BATCH-GROUP] %d distinct source accounts on chain %d; "+
			"one anchor cannot cover them, not batching\n", len(groups), ecm.config.ChainID)
		return BatchGroup{}, false
	}
	if !groups[0].IsBatch() {
		return BatchGroup{}, false
	}

	return groups[0], true
}
