package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// =============================================================================
// Batch orchestrator: mempool -> tree -> anchor -> N branch-carrying calls
// =============================================================================
//
// Ordering is not cosmetic. The anchor must exist and be quorum-verified BEFORE any account
// call, because CertenAccountV7 refuses an anchor whose proofExecuted flag is false. And the
// tree must be fully self-verified BEFORE the anchor is paid for, because a bad branch only
// surfaces at TX3 — by which point createBatchAnchor and executeComprehensiveProof have both
// been paid and every other member is stuck behind the failure.
//
// So the orchestrator verifies at four separate points, each catching a different class of
// error while it is still free to fix:
//
//   1. Locally, before any transaction: every branch verifies against its own root.
//   2. Against DEPLOYED bytecode, before the anchor: each account's own computeLeaf agrees
//      with the Go leaf. This is the cross-language contract checked against production code
//      rather than a test fixture.
//   3. After createBatchAnchor: read back isBatchAnchor / batchLeafCount, and have the real
//      anchor verifyProof EVERY member leaf against what it actually stored.
//   4. Before each account call: the leaf is not already consumed.

// QuorumProver supplies the BLS/ZK proof over a batch root. Implemented by the consensus
// layer, which owns the validator keys; kept as an interface so the orchestrator has no
// dependency on consensus (which already imports this package).
type QuorumProver interface {
	// ProveBatchRoot obtains quorum attestation for a batch anchor and submits
	// executeComprehensiveProof. It must not return until the anchor's proofExecuted flag
	// is set, or return an error.
	//
	// It takes the TREE, not loose fields: peers are asked to attest by (chainID,
	// cutoffHeight) and reply with the bundleId they independently derived, so the prover
	// needs the same object the branches came from or the comparison means nothing.
	// cutoffHeight is the period boundary that defined membership — peers reconstruct from
	// it, and it is also the accumulateBlockHeight bound into the bundleId.
	ProveBatchRoot(ctx context.Context, tree *BatchTree, cutoffHeight, periodBlocks uint64) error
}

// BatchFlushResult reports what happened to one tree.
type BatchFlushResult struct {
	ChainID      int64
	BundleID     [32]byte
	Root         [32]byte
	MemberCount  int
	AnchorTxHash string

	Settled []*PendingBatchIntent
	Failed  []*PendingBatchIntent
	// Dropped members left the batch path entirely and MUST be routed to the per-intent
	// on_demand path by the caller. They are not requeued and will never reappear in a batch,
	// so a caller that ignores this field strands them.
	Dropped []*PendingBatchIntent
	// AlreadySettled members were found under an anchor a previous leader had already attested.
	// They are removed from the pool and must NOT be attested or fallen back to — the leader
	// that landed the batch already did both. Reported so the condition is visible rather than
	// looking like members silently vanishing.
	AlreadySettled []*PendingBatchIntent

	// Retryable members hit a TRANSIENT refusal — today only a gas ceiling breach. Their leaf
	// was never consumed, so the member is requeued rather than attested as failed. Reported so
	// the caller can see a period was deferred rather than assuming everything settled.
	Retryable []*PendingBatchIntent

	// AlreadySettledOutcome reports, per intent id, whether that released member's leaf was
	// actually consumed on chain. Absent means the outcome could not be resolved and the member
	// must be treated as unsettled.
	AlreadySettledOutcome map[string]bool
	TxHashes              map[string]string // intentID -> account tx hash

	GasAnchor uint64
}

// BatchOrchestrator forms and settles batches for one chain's contract manager.
// maxQuorumAttempts bounds retries of one period's attestation. Five gives a transient peer
// outage several flush cycles to clear while still surfacing a permanent disagreement.
const maxQuorumAttempts = 5

type BatchOrchestrator struct {
	attemptsMu sync.Mutex
	attempts   map[uint64]int

	ecm      *EthereumContractManager
	anchorV7 common.Address
	prover   QuorumProver
	mempool  *BatchMempool
	logf     func(string, ...interface{})

	// onLegProgress persists how many of a member's legs executed.
	//
	// Settlement is where a leg's outcome becomes a fact: one transaction per chain settles
	// every leg the member has on it — measured 2026-08-07, a 5-leg intent produced exactly one
	// transaction of 281,407 gas. LegCompletionHandler.OnLegCompleted was written to record
	// this and has no caller in any execution path, so intent_lifecycle.legs_completed stayed 0
	// even on intents whose status was 'complete'.
	//
	// A callback rather than a repository handle, so the orchestrator keeps no database
	// dependency and the wiring stays visible in main.go alongside the other lifecycle hooks.
	onLegProgress func(ctx context.Context, intentID string, legsCompleted, legsFailed int)
}

// SetLegProgressHook wires persistence of per-member leg outcomes. Optional: unset, settlement
// proceeds exactly as before and only the durable leg counters go unwritten.
func (o *BatchOrchestrator) SetLegProgressHook(
	fn func(ctx context.Context, intentID string, legsCompleted, legsFailed int),
) {
	o.onLegProgress = fn
}

// recordLegProgress reports each member's leg outcome after a settled batch.
//
// Settled members have executed every leg they carry on this chain; failed members have not.
// Counting len(p.Legs) rather than 1 is the point: a member is an INTENT, and an intent may
// carry many legs that all rode in the same transaction.
func (o *BatchOrchestrator) recordLegProgress(ctx context.Context, settled, failed []*PendingBatchIntent) {
	if o.onLegProgress == nil {
		return
	}
	for _, p := range settled {
		if p == nil {
			continue
		}
		o.onLegProgress(ctx, p.IntentID, len(p.Legs), 0)
	}
	for _, p := range failed {
		if p == nil {
			continue
		}
		o.onLegProgress(ctx, p.IntentID, 0, len(p.Legs))
	}
}

// NewBatchOrchestrator wires an orchestrator to a chain.
func NewBatchOrchestrator(
	ecm *EthereumContractManager,
	anchorV7 common.Address,
	prover QuorumProver,
	mempool *BatchMempool,
	logf func(string, ...interface{}),
) *BatchOrchestrator {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &BatchOrchestrator{
		ecm: ecm, anchorV7: anchorV7, prover: prover, mempool: mempool, logf: logf,
		attempts: make(map[uint64]int),
	}
}

// FlushChain forms ONE tree from the chain's pool and settles it end to end.
//
// # MEMBERSHIP IS DETERMINISTIC, NOT TIMER-DRIVEN
//
// cutoffHeight selects members via TakeForPeriod: every intent whose BFT round committed at or
// below the cutoff, ordered by (CommitHeight, IntentID). This is the property the whole quorum
// design rests on — an honest peer holding the same committed intents derives a byte-identical
// tree, root and bundleId, so its independent reconstruction is a meaningful check rather than
// a coin flip.
//
// It replaces mempool.Take(chainID), which took whatever had arrived locally by the time a
// 1-minute wall-clock timer fired. That is why validator-2 flushed bundleId 0xe4c950df… while
// validator-3 flushed 0x5e71d83a… in the same window on Sepolia: nothing made them agree.
//
// # FAILURE HANDLING
//
// Before the anchor is created, members are requeued untouched — nothing has been spent.
// After the anchor exists they are never requeued: re-forming the identical tree derives the
// same bundleId and reverts with AnchorAlreadyExists, which hides the real fault. A quorum
// failure past that point DROPS the members so the caller can route them to the per-intent
// on_demand path (approved policy: fall back, never requeue).
func (o *BatchOrchestrator) FlushChain(
	ctx context.Context,
	chainID int64,
	cutoffHeight uint64,
	periodBlocks uint64,
) (*BatchFlushResult, error) {
	// Defensive: a misconstructed orchestrator must ERROR, never panic. This runs inside the
	// flush loop, and a panic there would take the whole validator down rather than skipping
	// one chain.
	if o == nil || o.mempool == nil || o.ecm == nil {
		return nil, fmt.Errorf("batch orchestrator for chain %d is not properly constructed "+
			"(use NewBatchOrchestrator)", chainID)
	}
	// Height 0 is not a period. Forming a batch at it would bind accumulateBlockHeight=0 into
	// the bundleId on every validator that happened to have a different local view, and
	// TakeForPeriod would select nothing anyway.
	if cutoffHeight == 0 {
		return nil, fmt.Errorf("chain %d: cutoff height 0 is not a valid period; the consensus "+
			"height source is not wired", chainID)
	}

	members := o.mempool.TakeForPeriod(chainID, cutoffHeight, periodBlocks)
	if len(members) == 0 {
		return nil, nil
	}

	res := &BatchFlushResult{
		ChainID:     chainID,
		MemberCount: len(members),
		TxHashes:    make(map[string]string, len(members)),
	}

	// ---- Build the tree -----------------------------------------------------
	// Screen out members whose account cannot participate, BEFORE the tree is formed.
	//
	// A member whose account is not a CertenAccountV7 fails verification, and that check used to
	// abort the ENTIRE flush — one bad member blocked every other ADI's intent in the same period
	// indefinitely. Observed live 2026-08-04 on chain 84532: account 0x12565E20 (11765 bytes, an
	// older account version) stalled the Base batch and nothing settled for over 20 minutes.
	//
	// Dropping is deterministic across validators because the predicate is on-chain state every
	// node reads identically, so all seven form the same tree from the same survivors. Dropped
	// members are returned as such and routed to the per-intent path rather than silently lost.
	screened := make([]*PendingBatchIntent, 0, len(members))
	for _, p := range members {
		if err := o.memberAccountUsable(ctx, p); err != nil {
			o.logf("[BATCH] chain=%d dropping member %s from this period: %v", chainID, p.IntentID, err)
			res.Dropped = append(res.Dropped, p)
			continue
		}
		screened = append(screened, p)
	}
	if len(screened) == 0 {
		o.mempool.DropMembers(members)
		return res, fmt.Errorf("every member of period %d has an unusable account; %d dropped",
			cutoffHeight, len(members))
	}
	if len(screened) != len(members) {
		o.mempool.DropMembers(res.Dropped)
		members = screened
	}

	inputs := make([]BatchLeafInput, 0, len(members))
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			o.mempool.Requeue(members)
			return nil, fmt.Errorf("building leaf for %s: %w", p.IntentID, err)
		}
		inputs = append(inputs, in)
	}

	tree, err := BuildBatchTree(chainID, inputs, cutoffHeight)
	if err != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("building batch tree: %w", err)
	}
	res.BundleID = tree.BundleID
	res.Root = tree.Root

	o.logf("[BATCH] chain=%d forming tree: %d members, root=0x%x, bundleId=0x%x",
		chainID, tree.Size(), tree.Root[:8], tree.BundleID[:8])

	// ---- ALREADY SETTLED ELSEWHERE? ----------------------------------------
	// Leadership rotates per period and the flush loop picks up stragglers, so two different
	// nodes can legitimately reach the same period. bundleId is deterministic, so an anchor
	// that already exists AND is attested means the batch settled under a previous leader.
	//
	// This MUST short-circuit. Continuing would re-submit executeComprehensiveProof, which
	// reverts on usedCommitments replay protection; the quorum step would then report failure
	// and route every member to the per-intent fallback — RE-EXECUTING intents that already
	// moved funds. A double-spend produced by a retry is far worse than a skipped flush.
	if settled, serr := o.anchorAlreadyAttested(ctx, tree.BundleID); serr != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("checking whether anchor 0x%x already settled: %w", tree.BundleID[:8], serr)
	} else if settled {
		o.logf("[BATCH] chain=%d period %d already settled under anchor 0x%x by a previous leader "+
			"— releasing %d member(s) without re-executing",
			chainID, cutoffHeight, tree.BundleID[:8], len(members))
		// Determine each released member's ACTUAL outcome instead of assuming one.
		//
		// "Already settled" is inferred from the anchor being attested — NOT from the members
		// having executed. Those diverge: a previous leader can anchor and attest, then lose
		// leadership or die before settling its members. Observed live 2026-08-03, period
		// 6300300 — the anchor existed, two members were released, and no funds moved.
		//
		// Releasing them unattested is the silent drop this whole failure policy exists to
		// prevent, and neither blanket answer is safe: assuming success records a settlement
		// that never happened, assuming failure libels one that did. The consumed leaf is the
		// on-chain ground truth, so ask the account.
		res.AlreadySettled = members
		res.AlreadySettledOutcome = make(map[string]bool, len(members))
		for _, m := range members {
			ok, cerr := o.memberLeafConsumed(ctx, m)
			if cerr != nil {
				// Unresolved: leave it out of the map. The caller attests it as unsettled, which
				// is the conservative direction — the leaf is still spendable, so a retry can
				// still settle it, whereas a false "settled" would strand it forever.
				o.logf("[BATCH] member %s: cannot resolve released outcome: %v", m.IntentID, cerr)
				continue
			}
			res.AlreadySettledOutcome[m.IntentID] = ok
		}
		return res, nil
	}

	// ---- VERIFY 2: every account's own leaf agrees with ours ----------------
	// Checked against DEPLOYED bytecode, not a fixture. A drift here would mint an anchor
	// whose leaves no account can reproduce — unspendable, and paid for.
	if err := o.verifyLeavesAgainstAccounts(ctx, members, tree); err != nil {
		o.mempool.Requeue(members)
		return nil, err
	}

	// ---- Pin the nonce for the whole flush ----------------------------------
	//
	// The anchor, the attestation and every member call are sent from one key in one sequence.
	// Re-reading the pending nonce between them is what let a failover provider hand back an
	// already-consumed value and fail both members with "nonce too low". Read once, advance
	// locally; see beginNonceSequence.
	if err := o.ecm.beginNonceSequence(ctx); err != nil {
		o.mempool.Requeue(members)
		return nil, err
	}
	defer o.ecm.endNonceSequence()

	// ---- Create the anchor --------------------------------------------------
	anchorTx, gasUsed, err := o.createBatchAnchor(ctx, tree)
	if err != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("createBatchAnchor: %w", err)
	}
	res.AnchorTxHash = anchorTx
	res.GasAnchor = gasUsed
	o.logf("[BATCH] chain=%d anchor created tx=%s gas=%d", chainID, anchorTx, gasUsed)

	// ---- VERIFY 3: the deployed anchor accepts every member leaf ------------
	if err := o.verifyLeavesAgainstAnchor(ctx, tree); err != nil {
		// The anchor exists but is unusable. Do NOT requeue: re-forming the identical tree
		// would derive the same bundleId and revert with "Anchor already exists", hiding
		// the real fault. Drop to the per-intent path and surface the cause.
		o.mempool.DropMembers(members)
		res.Dropped = members
		return res, fmt.Errorf("anchor created but membership verification failed (%d member(s) "+
			"dropped to the per-intent path): %w", len(members), err)
	}

	// ---- Quorum attestation over the root -----------------------------------
	if o.prover == nil {
		return res, fmt.Errorf("no quorum prover configured; anchor 0x%x is created but not verified "+
			"and no account will accept it", tree.BundleID[:8])
	}
	if err := o.prover.ProveBatchRoot(ctx, tree, cutoffHeight, periodBlocks); err != nil {
		// REQUEUE, do not drop.
		//
		// The original policy was "fall back, never requeue", on the reasoning that re-forming
		// the identical tree reverts with AnchorAlreadyExists. That reasoning no longer holds:
		// createBatchAnchor treats an existing anchor for this exact bundleId as SUCCESS
		// ("already-exists"), and FlushChain short-circuits entirely when that anchor is also
		// already attested. So a retry re-attests an anchor that is already paid for, which is
		// exactly what a transient quorum failure needs — a peer that was mid-pipeline or
		// briefly unreachable will answer on the next attempt.
		//
		// Dropping was also routing members to a path that CANNOT land: the per-intent
		// submitter declares voting power from hardcoded defaults (300/200) which
		// _verifyBLSProof rejects against an on-chain total of 700. Sending members there
		// stranded them while reporting a fallback had occurred.
		//
		// Attempts are bounded so a genuinely unreachable quorum surfaces as a loud failure
		// rather than an endless retry.
		o.attemptsMu.Lock()
		o.attempts[cutoffHeight]++
		n := o.attempts[cutoffHeight]
		o.attemptsMu.Unlock()

		if n < maxQuorumAttempts {
			o.mempool.Requeue(members)
			return res, fmt.Errorf("quorum attestation over batch root failed (attempt %d/%d; "+
				"%d member(s) requeued for retry): %w", n, maxQuorumAttempts, len(members), err)
		}

		o.attemptsMu.Lock()
		delete(o.attempts, cutoffHeight)
		o.attemptsMu.Unlock()
		o.mempool.DropMembers(members)
		res.Dropped = members
		return res, fmt.Errorf("quorum attestation over batch root failed %d times; %d member(s) "+
			"dropped and will be attested as FAILED — they cannot be re-derived into a batch and "+
			"the per-intent path is not usable: %w", n, len(members), err)
	}
	o.attemptsMu.Lock()
	delete(o.attempts, cutoffHeight)
	o.attemptsMu.Unlock()
	o.logf("[BATCH] chain=%d quorum verified root 0x%x", chainID, tree.Root[:8])

	// ---- Settle each member -------------------------------------------------
	for i, p := range members {
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			res.Failed = append(res.Failed, p)
			o.logf("[BATCH] member %s: branch error: %v", p.IntentID, berr)
			continue
		}

		txHash, serr := o.settleMember(ctx, p, tree, branch)
		if serr != nil {
			// A gas-ceiling refusal is "too expensive right now", NOT "this can never work".
			//
			// Every settle error used to become a permanent FAILED, so a transient fee spike
			// killed a perfectly valid intent and wrote that failure back to Accumulate. The
			// leaf is untouched by a refusal — nothing was submitted — so the member can simply
			// be requeued and settled in a later period once prices subside.
			//
			// errors.As, not errors.Is: ErrGasCeilingExceeded is a struct pointer carrying the
			// observed and permitted prices, and it arrives wrapped from evaluateGasPrice.
			var gasCeil *ErrGasCeilingExceeded
			if errors.As(serr, &gasCeil) {
				if o.memberPastDeadline(p) {
					o.logf("[BATCH] member %s: gas ceiling %v but the intent has expired — "+
						"failing rather than retrying forever", p.IntentID, serr)
					res.Failed = append(res.Failed, p)
					continue
				}
				o.logf("[BATCH] member %s deferred: %v (leaf untouched; will retry in a later period)",
					p.IntentID, serr)
				res.Retryable = append(res.Retryable, p)
				continue
			}
			res.Failed = append(res.Failed, p)
			// Keep the hash of a member that REVERTED. settleMember returns one whenever the
			// transaction was mined, and a reverted transaction is on chain and independently
			// verifiable — it is the evidence of the failure, not the absence of evidence.
			// Discarding it left Phase 7 with nothing to observe, so the failure never reached
			// acc://certen-protocol.acme/execution-results and the ADI could not tell a reverted
			// intent from one that was never processed.
			if txHash != "" {
				res.TxHashes[p.IntentID] = txHash
			}
			o.logf("[BATCH] member %s FAILED: %v (tx=%s)", p.IntentID, serr, txHash)
			continue
		}
		res.Settled = append(res.Settled, p)
		res.TxHashes[p.IntentID] = txHash
	}

	// Put deferred members back so a later period retries them. Requeue, never Drop: dropping
	// routes to the per-intent path, which would re-derive and re-execute an intent that simply
	// could not afford gas this minute.
	if len(res.Retryable) > 0 {
		o.mempool.Requeue(res.Retryable)
		o.logf("[BATCH] chain=%d %d member(s) deferred on gas and requeued", chainID, len(res.Retryable))
	}

	o.logf("[BATCH] chain=%d complete: %d settled, %d failed (anchor amortised across %d)",
		chainID, len(res.Settled), len(res.Failed), tree.Size())

	// Attribute cost: the anchor once, divided across the members that shared it, plus each
	// member's own settlement transaction.
	//
	// Includes FAILED members deliberately. A member that reverted still consumed its share of
	// the anchor and burned gas on its own transaction; excluding it would under-report real
	// spend and make failures look free. Members with no transaction at all are skipped inside
	// reportBatchCosts, since there is nothing on chain to measure.
	costMembers := make([]costMember, 0, len(res.Settled)+len(res.Failed))
	for _, p := range append(append([]*PendingBatchIntent{}, res.Settled...), res.Failed...) {
		costMembers = append(costMembers, costMemberFor(p, res.TxHashes[p.IntentID]))
	}
	// This is the PERIOD path, so its members are on_cadence by definition — including a period
	// that happens to flush a single member. It waited the full period and shared an anchor
	// sized for a batch, which is what the customer was quoted for.
	o.reportBatchCosts(ctx, chainID, res.AnchorTxHash, o.lastVerifyTx(), costMembers,
		string(LaneOnCadence))

	// Record which legs actually executed. Same membership as cost attribution, and for the same
	// reason: settlement is the moment a leg's outcome is known.
	o.recordLegProgress(ctx, res.Settled, res.Failed)

	return res, nil
}

// verifyLeavesAgainstAccounts asks each deployed account to compute its own leaf and compares.
func (o *BatchOrchestrator) verifyLeavesAgainstAccounts(
	ctx context.Context,
	members []*PendingBatchIntent,
	tree *BatchTree,
) error {
	for i, p := range members {
		acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
		if err != nil {
			return fmt.Errorf("binding account for %s: %w", p.IntentID, err)
		}

		// The account must be the keyless V7 for this ADI, or its leaf identity half is
		// something other than what we hashed.
		keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
		if err != nil {
			return fmt.Errorf("account %s is not a CertenAccountV7 (%s): %w",
				p.Account.Hex(), p.IntentID, err)
		}
		if !keyless {
			return fmt.Errorf("account %s reports a non-keyless owner; refusing to anchor %s",
				p.Account.Hex(), p.IntentID)
		}

		onChainADIHash, err := acct.ADIURLHash(&bind.CallOpts{Context: ctx})
		if err != nil {
			return fmt.Errorf("reading adiURLHash for %s: %w", p.IntentID, err)
		}
		if onChainADIHash != tree.Inputs[i].ADIURLHash() {
			return fmt.Errorf(
				"account %s is bound to a different ADI than intent %s claims "+
					"(on-chain 0x%x, intent %s)",
				p.Account.Hex(), p.IntentID, onChainADIHash[:8], p.ADIURL)
		}

		exec := tree.Inputs[i].ExecutionCommitment
		onChainLeaf, err := acct.ComputeLeaf(&bind.CallOpts{Context: ctx}, exec, p.OperationID)
		if err != nil {
			return fmt.Errorf("computeLeaf on %s: %w", p.Account.Hex(), err)
		}
		if onChainLeaf != tree.Leaves[i] {
			return fmt.Errorf(
				"leaf mismatch for %s: Go computed 0x%x, deployed account computed 0x%x — "+
					"cross-language drift between the validator and CertenAccountV7",
				p.IntentID, tree.Leaves[i], onChainLeaf)
		}
	}
	return nil
}

// anchorAlreadyAttested reports whether this bundleId already exists on chain with its quorum
// attestation landed — i.e. the batch settled under a previous leader.
//
// Reads the `anchors` struct getter directly rather than anchorExists + a second call, because
// only the combination matters: an anchor that exists but is NOT attested is a stranded
// createBatchAnchor from a failed flush, and that one SHOULD be retried.
func (o *BatchOrchestrator) anchorAlreadyAttested(ctx context.Context, bundleID [32]byte) (bool, error) {
	parsed, err := abiFromJSON(anchorsABIJSON)
	if err != nil {
		return false, err
	}
	bound := bind.NewBoundContract(o.anchorV7, parsed, o.ecm.client, o.ecm.client, o.ecm.client)
	var out []interface{}
	if err := bound.Call(&bind.CallOpts{Context: ctx}, &out, "anchors", bundleID); err != nil {
		return false, err
	}
	const proofExecutedIndex = 12
	if len(out) <= proofExecutedIndex {
		return false, fmt.Errorf("anchors() returned %d fields, need at least %d",
			len(out), proofExecutedIndex+1)
	}
	executed, ok := out[proofExecutedIndex].(bool)
	if !ok {
		return false, fmt.Errorf("proofExecuted has unexpected type %T", out[proofExecutedIndex])
	}
	return executed, nil
}

// verifyLeavesAgainstAnchor confirms the deployed anchor stored what we think it did and
// accepts every member's branch.
func (o *BatchOrchestrator) verifyLeavesAgainstAnchor(ctx context.Context, tree *BatchTree) error {
	anchor, err := contracts.NewCertenAnchorV7Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return fmt.Errorf("binding anchor: %w", err)
	}
	opts := &bind.CallOpts{Context: ctx}

	// READ-AFTER-WRITE.
	//
	// bind.WaitMined returns as soon as the tx appears in a block, but the very next eth_call
	// can be served by a node that has not applied it yet — public RPC endpoints are load
	// balanced across peers with independent lag. Observed live 2026-08-02: an anchor mined,
	// and 121ms later batchLeafCount read back as 0, so the batch was declared unusable and
	// every member was dropped to the per-intent path even though the anchor was perfectly
	// good.
	//
	// A stale read is indistinguishable from a genuinely broken anchor on a single sample, so
	// this retries briefly before concluding anything. It gives up quickly: a real mismatch
	// must still surface rather than being retried forever.
	var (
		isBatch bool
		count   *big.Int
	)
	for attempt := 1; attempt <= 6; attempt++ {
		isBatch, err = anchor.IsBatchAnchor(opts, tree.BundleID)
		if err == nil && isBatch {
			count, err = anchor.BatchLeafCount(opts, tree.BundleID)
			if err == nil && count != nil && count.Int64() == int64(tree.Size()) {
				break
			}
		}
		if attempt == 6 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
		}
	}
	if err != nil {
		return fmt.Errorf("reading batch anchor state: %w", err)
	}
	if !isBatch {
		return fmt.Errorf("anchor 0x%x is not flagged as a batch anchor", tree.BundleID[:8])
	}
	if count == nil || count.Int64() != int64(tree.Size()) {
		return fmt.Errorf("anchor records %v leaves but the tree has %d "+
			"(re-read %d times, so this is not RPC lag)", count, tree.Size(), 6)
	}

	for i := range tree.Leaves {
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			return berr
		}
		ok, verr := anchor.VerifyProof(opts, tree.BundleID, branch, tree.Leaves[i])
		if verr != nil {
			return fmt.Errorf("verifyProof for member %d: %w", i, verr)
		}
		if !ok {
			return fmt.Errorf("deployed anchor rejects member %d's branch", i)
		}
	}
	return nil
}

// createBatchAnchor submits the anchor and waits for it to mine.
func (o *BatchOrchestrator) createBatchAnchor(
	ctx context.Context,
	tree *BatchTree,
) (string, uint64, error) {
	anchor, err := contracts.NewCertenAnchorV7Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return "", 0, err
	}

	// Idempotence: a retry after a timeout must not revert with "Anchor already exists"
	// and lose the batch. bundleId is deterministic, so an existing anchor for this exact
	// tree is a SUCCESS, not a conflict.
	if exists, eerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID); eerr == nil && exists {
		o.logf("[BATCH] anchor 0x%x already exists — treating as created", tree.BundleID[:8])
		return "already-exists", 0, nil
	}

	o.ecm.auth.GasLimit = 500000
	o.ecm.nextNonce()
	tx, err := anchor.CreateBatchAnchor(
		o.ecm.auth,
		tree.BundleID,
		tree.Root,
		big.NewInt(int64(tree.Size())),
		tree.BatchOperationID,
		new(big.Int).SetUint64(tree.BlockHeight),
	)
	if err != nil {
		return "", 0, err
	}

	receipt, err := bind.WaitMined(ctx, o.ecm.client, tx)
	if err != nil {
		return tx.Hash().Hex(), 0, fmt.Errorf("waiting for anchor: %w", err)
	}
	if receipt.Status == 0 {
		return tx.Hash().Hex(), receipt.GasUsed, fmt.Errorf("createBatchAnchor reverted")
	}
	return tx.Hash().Hex(), receipt.GasUsed, nil
}

// settleMember submits one member's account call carrying its Merkle branch.
func (o *BatchOrchestrator) settleMember(
	ctx context.Context,
	p *PendingBatchIntent,
	tree *BatchTree,
	branch [][32]byte,
) (string, error) {
	acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
	if err != nil {
		return "", err
	}

	exec, err := p.ExecutionCommitment()
	if err != nil {
		return "", err
	}
	leaf := ComputeBatchLeaf(p.ChainID, BatchLeafInput{
		ADIURL: p.ADIURL, ExecutionCommitment: exec, OperationID: p.OperationID,
	})

	// VERIFY 4: a consumed leaf means this member already settled. Reporting that plainly
	// beats paying gas to hit "leaf already consumed" on-chain.
	consumed, err := acct.IsLeafConsumed(&bind.CallOpts{Context: ctx}, leaf)
	if err != nil {
		return "", fmt.Errorf("reading isLeafConsumed: %w", err)
	}
	if consumed {
		return "", fmt.Errorf("leaf 0x%x already consumed — member %s has already settled",
			leaf[:8], p.IntentID)
	}

	proof := contracts.AccountProofV7{
		AdiURL:      p.ADIURL, // advisory; the contract uses its own immutable adiURL
		AnchorId:    tree.BundleID,
		MerkleProof: branch,
		OperationID: p.OperationID,
		Timestamp:   big.NewInt(time.Now().Unix() - 60), // clock-skew allowance
		ExpiresAt:   big.NewInt(time.Now().Add(time.Hour).Unix()),
		Nonce:       big.NewInt(0),
		// Must cover the most demanding leg or the contract rejects the whole call.
		RequiredLevel: requiredLevelForLegs(p.Legs),
	}

	var tx *types.Transaction
	if p.IsMultiLeg() {
		targets, values, datas := legArrays(p.Legs)
		o.ecm.auth.GasLimit = 400000 + uint64(len(p.Legs))*250000
		o.ecm.nextNonce()
		tx, err = acct.BatchExecuteGovernanceProofDirect(o.ecm.auth, targets, values, datas, proof)
	} else {
		leg := p.Legs[0]
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		o.ecm.auth.GasLimit = 500000
		o.ecm.nextNonce()
		tx, err = acct.ExecuteGovernanceProofDirect(o.ecm.auth, leg.Target, v, leg.Data, proof)
	}
	if err != nil {
		// The transaction never reached the mempool, so its nonce was not consumed. Give it back:
		// leaving the gap would strand every LATER member behind a nonce the chain never sees.
		o.ecm.rewindNonce()
		return "", err
	}

	txHash := tx.Hash().Hex()
	receipt, err := bind.WaitMined(ctx, o.ecm.client, tx)
	if err != nil {
		return txHash, fmt.Errorf("waiting for member tx: %w", err)
	}
	if receipt.Status == 0 {
		// Only THIS member failed. Its leaf was rolled back with the rest of the tx, so it
		// stays spendable — the other members are unaffected, which is the point of giving
		// each its own leaf rather than sharing one anchor-wide consumption flag.
		return txHash, fmt.Errorf("member execution reverted on-chain (leaf still spendable)")
	}
	return txHash, nil
}

// legArrays splits legs into the three parallel arrays the contract takes.
func legArrays(legs []LegExecution) ([]common.Address, []*big.Int, [][]byte) {
	targets := make([]common.Address, 0, len(legs))
	values := make([]*big.Int, 0, len(legs))
	datas := make([][]byte, 0, len(legs))
	for _, leg := range legs {
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		targets = append(targets, leg.Target)
		values = append(values, v)
		datas = append(datas, leg.Data)
	}
	return targets, values, datas
}

// memberLeafConsumed reports whether this member's leaf has been spent on chain.
//
// The account itself is the authority: a consumed leaf means the member settled, a spendable one
// means it did not. Used to resolve members released because a previous leader had already
// anchored their period, where the anchor's existence says nothing about whether they executed.
func (o *BatchOrchestrator) memberLeafConsumed(ctx context.Context, p *PendingBatchIntent) (bool, error) {
	if p == nil {
		return false, fmt.Errorf("nil member")
	}
	acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
	if err != nil {
		return false, fmt.Errorf("binding account %s: %w", p.Account.Hex(), err)
	}
	exec, err := p.ExecutionCommitment()
	if err != nil {
		return false, err
	}
	leaf := ComputeBatchLeaf(p.ChainID, BatchLeafInput{
		ADIURL: p.ADIURL, ExecutionCommitment: exec, OperationID: p.OperationID,
	})
	return acct.IsLeafConsumed(&bind.CallOpts{Context: ctx}, leaf)
}

// memberAccountUsable reports whether this member's account can take part in a batch.
//
// Screens the two properties that make a member unanchorable regardless of the tree: the account
// must be a CertenAccountV7, and it must be bound to the ADI the intent claims. Both are read
// from chain, so every validator reaches the same verdict and drops the same members.
func (o *BatchOrchestrator) memberAccountUsable(ctx context.Context, p *PendingBatchIntent) error {
	acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
	if err != nil {
		return fmt.Errorf("binding account %s: %w", p.Account.Hex(), err)
	}
	keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("account %s is not a CertenAccountV7: %w", p.Account.Hex(), err)
	}
	if !keyless {
		return fmt.Errorf("account %s reports a non-keyless owner", p.Account.Hex())
	}
	onChainADIHash, err := acct.ADIURLHash(&bind.CallOpts{Context: ctx})
	if err != nil {
		return fmt.Errorf("reading adiURLHash on %s: %w", p.Account.Hex(), err)
	}
	if onChainADIHash != (BatchLeafInput{ADIURL: p.ADIURL}).ADIURLHash() {
		return fmt.Errorf("account %s is bound to a different ADI than %q", p.Account.Hex(), p.ADIURL)
	}
	return nil
}

// memberPastDeadline reports whether a member has been deferred for longer than we will keep
// retrying it on gas.
//
// Bounds the retry: without a bound, a member on a chain that stays expensive is requeued forever
// and never resolves either way — the silent limbo the whole failure policy exists to prevent.
// Measured from EnqueuedAt, which the mempool stamps once and preserves across requeue and across
// a restore from disk, so the window does not restart every time the member is deferred.
func (o *BatchOrchestrator) memberPastDeadline(p *PendingBatchIntent) bool {
	if p == nil || p.EnqueuedAt.IsZero() {
		return false
	}
	return time.Since(p.EnqueuedAt) > maxGasDeferral
}

// maxGasDeferral is how long a member may be deferred on gas before it is failed outright.
//
// Long enough to ride out an ordinary fee spike, short enough that an ADI learns the outcome the
// same hour it submitted.
const maxGasDeferral = time.Hour
