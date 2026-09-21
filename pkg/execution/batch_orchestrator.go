package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
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

	// Retryable members hit a TRANSIENT condition - a gas ceiling, a settlement still in flight, a
	// send that never reached the chain, a spent leaf whose spender is not in view yet. Nothing
	// about the member is known to have failed, so it is requeued rather than attested as failed.
	Retryable []*PendingBatchIntent

	// SpentElsewhere members' leaves were spent by a transaction this node did not send: another
	// validator (or a relayer) executed them, and records them. Removed without attesting.
	SpentElsewhere []*PendingBatchIntent

	// stopSending: a settlement in this flush is still in flight, holding its nonce, so no further
	// member is sent this flush.
	stopSending bool

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

	// odChain replaces the orchestrator's own chain operations for on-demand settlement. Nil in
	// production, where the orchestrator IS the chain; set by tests to drive the decisions.
	odChain onDemandChain

	// floors caches where attribution searches start; see batch_attribution.go.
	floors attributionFloors

	// roster is the chain-confirmed settlement roster; see settlementRoster.
	rosterMu sync.Mutex
	roster   []common.Address
	// peersFn names the peers asked for settlement evidence. Nil means ATTESTATION_PEERS.
	peersFn func() []string
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

	// ---- Pin the nonce for the whole flush ----------------------------------
	//
	// The anchor, the attestation and every member call are sent from one key in one sequence.
	// Re-reading the pending nonce between them is what let a failover provider hand back an
	// already-consumed value and fail both members with "nonce too low". Read once, advance
	// locally; see beginNonceSequence.
	//
	// Pinned BEFORE the chain is read for this batch's state: beginNonceSequence first drives any
	// transaction this key still has in flight to a result. Reading "is the anchor attested?" before
	// that could see an attestation this node already sent as not yet landed, and send it again.
	if err := o.ecm.beginNonceSequenceWaiting(ctx); err != nil {
		o.mempool.Requeue(members)
		return nil, err
	}
	defer o.ecm.endNonceSequence()

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
		// Whose attestation is it? The chain says: the sender of its ProofExecuted transaction. If it
		// is THIS node's - a verify of its own that had no result when an earlier flush gave up on it,
		// and has since landed - this node is the period's settler and settles the members under it.
		// Attesting them unsettled would write back as failed a batch this node anchored and attested
		// itself and never got to settle.
		attesterTx, attester, found, aerr := o.anchorAttester(ctx, tree.BundleID, 0)
		if aerr != nil || !found {
			o.mempool.Requeue(members)
			return nil, fmt.Errorf("anchor 0x%x is attested but its attester is not in view (found=%t): %v",
				tree.BundleID[:8], found, aerr)
		}
		if attester == o.ecm.auth.From {
			o.logf("[BATCH] chain=%d period %d: anchor 0x%x was attested by this node; settling its %d member(s) under it",
				chainID, cutoffHeight, tree.BundleID[:8], len(members))
			o.attemptsMu.Lock()
			delete(o.attempts, cutoffHeight)
			o.attemptsMu.Unlock()
			// The verify is the attester's transaction, read from the chain - this flush sent none.
			// The anchor was created by an earlier flush whose cost was not reported; its hash is not
			// known here, so that leg is left unreported rather than guessed.
			return o.settleFlushMembers(ctx, chainID, members, tree, res, attesterTx), nil
		}
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
		//
		// Another validator attested this anchor, so the settlement is that validator's. A member
		// whose leaf is spent is settled (by it). A member whose leaf is NOT yet spent is not a
		// failure: the attesting validator may be between its attestation and its settlement -
		// the normal case when two leaders raced this period and this node's attestation lost.
		// Attesting it unsettled here wrote FAILED for members that went on to settle. It is
		// requeued, and a later flush sees its leaf spent. (Settling in the attester's place when
		// the attester has died is the dead-leader takeover, deliberately not done here.)
		res.AlreadySettledOutcome = make(map[string]bool, len(members))
		var awaiting []*PendingBatchIntent
		for _, m := range members {
			ok, cerr := o.memberLeafConsumed(ctx, m)
			if cerr != nil || !ok {
				if cerr != nil {
					o.logf("[BATCH] member %s: leaf state unreadable (%v); requeued", m.IntentID, cerr)
				}
				awaiting = append(awaiting, m)
				continue
			}
			res.AlreadySettled = append(res.AlreadySettled, m)
			res.AlreadySettledOutcome[m.IntentID] = true
		}
		// A member still unsettled PAST ITS DEADLINE under another validator's attestation is that
		// validator's outcome - most often its settlement reverted and it recorded the failure. It
		// leaves this node's pool without being attested here (the attester owns the record),
		// loudly, instead of being re-examined on every flush for ever.
		var expired []*PendingBatchIntent
		kept := awaiting[:0:0]
		for _, m := range awaiting {
			if o.memberPastDeadline(m) {
				expired = append(expired, m)
			} else {
				kept = append(kept, m)
			}
		}
		awaiting = kept
		if len(expired) > 0 {
			o.mempool.DropMembers(expired)
			for _, m := range expired {
				o.logf("⚠️ [BATCH] member %s: past its deadline, unsettled under anchor 0x%x attested by %s; "+
					"removed from this node's pool - its outcome is that validator's record", m.IntentID, tree.BundleID[:8], attester.Hex())
			}
		}
		if len(awaiting) > 0 {
			o.mempool.Requeue(awaiting)
			o.logf("[BATCH] chain=%d period %d: %d member(s) under anchor 0x%x attested by %s are not settled yet; "+
				"requeued until that validator settles them", chainID, cutoffHeight, len(awaiting), tree.BundleID[:8], attester.Hex())
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

	// ---- Create the anchor --------------------------------------------------
	anchorTx, gasUsed, anchorBlock, err := o.createBatchAnchor(ctx, tree)
	if err != nil {
		o.mempool.Requeue(members)
		return nil, fmt.Errorf("createBatchAnchor: %w", err)
	}
	res.AnchorTxHash = anchorTx
	res.GasAnchor = gasUsed
	// Same as the on-demand lane: the tree carries the transaction that published its root, so the
	// quorum evidence records where the root actually is.
	// Only a real transaction hash. createBatchAnchor returns "already-exists" when another
	// validator created the anchor first; this node then does not know the creating transaction, and
	// empty is how that is said. See IsTransactionHash.
	if IsTransactionHash(anchorTx) {
		tree.AnchorCreateTx, tree.AnchorCreateBlock = anchorTx, anchorBlock
	}
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
		// An attestation that was broadcast and has no observed result yet - or was refused on price
		// before broadcast - is not a quorum failure and does not count toward dropping the batch:
		// it may land, and the retry finds the anchor attested.
		if isTransientSendError(err) || isAnchorConfirmUnread(err) || errors.Is(err, ErrAttestedByAnother) {
			// No result yet, or the anchor was attested by another validator's transaction: the next
			// flush reads the anchor attested and decides from its attester who settles.
			o.mempool.Requeue(members)
			return res, fmt.Errorf("quorum attestation over batch root has no result of this node's yet (%d member(s) "+
				"requeued; not counted as a failed attempt): %w", len(members), err)
		}
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

	return o.settleFlushMembers(ctx, chainID, members, tree, res, o.lastVerifyTx(tree.BundleID)), nil
}

// settleFlushMembers settles each member of a flushed period under its attested anchor, then requeues
// the deferred ones, reports cost and records leg progress. Shared by a fresh flush and by a flush
// that finds its own attestation of this period's anchor already on chain.
func (o *BatchOrchestrator) settleFlushMembers(
	ctx context.Context,
	chainID int64,
	members []*PendingBatchIntent,
	tree *BatchTree,
	res *BatchFlushResult,
	verifyTx string,
) *BatchFlushResult {
	// ---- Settle each member -------------------------------------------------
	for i, p := range members {
		// A settlement still in flight holds its nonce: every later member would queue behind it and
		// wait out the same bound. Stop, and leave the rest for the next flush, which first drives
		// the in-flight transaction to a result.
		if res.stopSending {
			res.Retryable = append(res.Retryable, p)
			continue
		}
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			res.Failed = append(res.Failed, p)
			o.logf("[BATCH] member %s: branch error: %v", p.IntentID, berr)
			continue
		}

		txHash, serr := o.settleMember(ctx, p, tree, branch, time.Time{})
		var unknown *SettlementOutcomeUnknownError
		if serr != nil && errors.As(serr, &unknown) {
			// Sent, outcome not observed within the wait. NOT a failure: it may still land. The
			// member is retried; the next flush drives this transaction to a result first, and if it
			// executed the member's leaf reads spent and is attributed to it (below).
			o.logf("[BATCH] member %s: settlement %s has no result yet; retried after it resolves",
				p.IntentID, unknown.TxHash)
			res.Retryable = append(res.Retryable, p)
			res.stopSending = true
			continue
		}
		if serr != nil && errors.Is(serr, errLeafAlreadyConsumed) {
			// Already spent when this node went to settle it. The chain's own record says who spent
			// it: this node's key (a settlement of its own that landed meanwhile) is this member's
			// success; anyone else's is theirs to record.
			spender, from, found, lerr := o.leafConsumedTx(ctx, p, [32]byte{})
			switch {
			case lerr != nil || !found:
				o.logf("[BATCH] member %s: leaf spent, spending transaction not in view (%v); retried", p.IntentID, lerr)
				res.Retryable = append(res.Retryable, p)
			case from == o.ecm.auth.From:
				o.logf("[BATCH] member %s: leaf spent by this node's own settlement %s", p.IntentID, spender)
				res.Settled = append(res.Settled, p)
				res.TxHashes[p.IntentID] = spender
			default:
				o.logf("[BATCH] member %s: leaf spent by %s from %s, not this node; its sender records it",
					p.IntentID, spender, from.Hex())
				res.SpentElsewhere = append(res.SpentElsewhere, p)
			}
			continue
		}
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
			// Nothing of this settlement executed: refused before broadcast, never reached a
			// mempool, or its nonce went to another transaction. Not a failure of the member.
			if !errors.As(serr, &unknown) && isTransientSendError(serr) {
				o.logf("[BATCH] member %s deferred: the settlement did not reach the chain (%v); will retry",
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
	o.reportBatchCosts(ctx, chainID, res.AnchorTxHash, verifyTx, costMembers,
		string(LaneOnCadence))

	// Record which legs actually executed. Same membership as cost attribution, and for the same
	// reason: settlement is the moment a leg's outcome is known.
	o.recordLegProgress(ctx, res.Settled, res.Failed)

	return res
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
) (txHash string, gasUsed uint64, block uint64, err error) {
	anchor, err := contracts.NewCertenAnchorV7Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return "", 0, 0, err
	}

	// Idempotence: a retry after a timeout must not revert with "Anchor already exists"
	// and lose the batch. bundleId is deterministic, so an existing anchor for this exact
	// tree is a SUCCESS, not a conflict.
	exists, eerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID)
	if eerr != nil {
		// Unknown is not "absent": sending on an unreadable answer created a second anchor attempt
		// that reverts, and the revert was then read as the member failing.
		return "", 0, 0, readErr(fmt.Errorf("reading anchorExists for 0x%x: %w", tree.BundleID[:8], eerr))
	}
	if exists {
		o.logf("[BATCH] anchor 0x%x already exists — treating as created", tree.BundleID[:8])
		return "already-exists", 0, 0, nil
	}

	// Priced when sent, replaced at the same nonce while it does not mine, and bounded: see
	// txSender. A bound that runs out returns *ChainWaitError - "not yet known", never a failure;
	// the anchor is idempotent by bundleId, so the retry finds it once it lands.
	receipt, txHash, err := o.ecm.sendBatchTx(ctx, "anchor", "", 500000,
		func(opts *bind.TransactOpts) (*types.Transaction, error) {
			return anchor.CreateBatchAnchor(
				opts,
				tree.BundleID,
				tree.Root,
				big.NewInt(int64(tree.Size())),
				tree.BatchOperationID,
				new(big.Int).SetUint64(tree.BlockHeight),
			)
		}, nil)
	if err != nil {
		return "", 0, 0, err
	}
	if receipt.Status == 0 {
		// The usual cause is another validator's anchor for this exact bundleId landing first -
		// the anchor this node wanted now exists. Anything else is a real failure.
		if now, rerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID); rerr == nil && now {
			o.logf("[BATCH] createBatchAnchor %s reverted because anchor 0x%x already exists — treating as created",
				txHash, tree.BundleID[:8])
			return "already-exists", receipt.GasUsed, 0, nil
		}
		return txHash, receipt.GasUsed, 0, fmt.Errorf("createBatchAnchor reverted")
	}
	return txHash, receipt.GasUsed, receipt.BlockNumber.Uint64(), nil
}

// settleMember submits one member's account call carrying its Merkle branch.
//
// fence is the latest time the settlement may execute: its expiresAt. The on-demand lane always
// passes its settlement window's fence (see batch_settlement_window.go); zero leaves the hour the
// period lane has always used. The proof's timestamp is the chain head's time, not this machine's
// clock: the account requires block.timestamp >= timestamp, and a local clock running ahead made
// that a revert the intent did not cause.
func (o *BatchOrchestrator) settleMember(
	ctx context.Context,
	p *PendingBatchIntent,
	tree *BatchTree,
	branch [][32]byte,
	fence time.Time,
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
		return "", readErr(fmt.Errorf("reading isLeafConsumed: %w", err))
	}
	if consumed {
		return "", fmt.Errorf("leaf 0x%x already consumed — member %s has already settled: %w",
			leaf[:8], p.IntentID, errLeafAlreadyConsumed)
	}

	head, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return "", readErr(fmt.Errorf("reading chain head for the settlement's timestamp: %w", err))
	}
	notBefore := int64(head.Time)
	expiresAt := notBefore + int64(time.Hour/time.Second)
	if !fence.IsZero() {
		expiresAt = fence.Unix()
		if expiresAt <= notBefore {
			return "", fmt.Errorf("settlement window closed at %s (chain time %d): %w",
				fence.UTC().Format(time.RFC3339), notBefore, errSettlementWindowClosed)
		}
	}
	proof := contracts.AccountProofV7{
		AdiURL:      p.ADIURL, // advisory; the contract uses its own immutable adiURL
		AnchorId:    tree.BundleID,
		MerkleProof: branch,
		OperationID: p.OperationID,
		Timestamp:   big.NewInt(notBefore),
		ExpiresAt:   big.NewInt(expiresAt),
		Nonce:       big.NewInt(0),
		// Must cover the most demanding leg or the contract rejects the whole call.
		RequiredLevel: requiredLevelForLegs(p.Legs),
	}

	gas := uint64(500000)
	if p.IsMultiLeg() {
		gas = 400000 + uint64(len(p.Legs))*250000
	}
	build := func(opts *bind.TransactOpts) (*types.Transaction, error) {
		if p.IsMultiLeg() {
			targets, values, datas := legArrays(p.Legs)
			return acct.BatchExecuteGovernanceProofDirect(opts, targets, values, datas, proof)
		}
		leg := p.Legs[0]
		v := leg.Value
		if v == nil {
			v = bigZero()
		}
		return acct.ExecuteGovernanceProofDirect(opts, leg.Target, v, leg.Data, proof)
	}
	// Every hash this settlement is broadcast under - the first and each fee-bumped replacement at
	// the same nonce - is recorded BEFORE its receipt is awaited. A crash, a shutdown or a lost
	// receipt from here on must not lose the fact that this node sent a settlement for this
	// member, nor which hashes might be the one that mines.
	var lastHash string
	onBroadcast := func(nonce uint64, hash string) {
		lastHash = hash
		o.noteOnDemandProgress(p, func(m *PendingBatchIntent) {
			m.SettlementTx = hash
			m.SettlementTxs = append(m.SettlementTxs, hash)
			m.SettlementNonce, m.SettlementNonceSet = nonce, true
		})
	}
	receipt, txHash, err := o.ecm.sendBatchTx(ctx, "settle", settlementOwner(p), gas, build, onBroadcast)
	if err != nil {
		var cwe *ChainWaitError
		switch {
		case errors.As(err, &cwe):
			// NOT a revert. The transaction was sent and its outcome was not observed; it may yet
			// execute. Saying "reverted" here recorded failures for settlements that went on to land.
			return lastHash, &SettlementOutcomeUnknownError{TxHash: lastHash, Err: err}
		case errors.Is(err, ErrNonceConsumedElsewhere):
			// None of this settlement's hashes executed: another transaction took the nonce. The
			// hashes stay on the member's record (history attributes a spend correctly later);
			// nothing is in flight at that nonce, so a later pass may settle afresh.
			return "", err
		default:
			// Refused before broadcast (a ceiling, a read) or never reached a mempool: nothing is
			// in flight, and the nonce has been given back - it may now carry another transaction.
			// The member keeps its hashes as history but no longer claims that nonce.
			// The hash recorded for this attempt never reached a mempool, so it is removed: it is not
			// history, it is nothing. Earlier hashes (other attempts) stay.
			var nb *NotBroadcastError
			if errors.As(err, &nb) {
				o.forgetUnbroadcastSettlement(p, lastHash)
			}
			return "", err
		}
	}
	if receipt.Status == 0 {
		// Only THIS member failed. Its leaf was rolled back with the rest of the tx, so it
		// stays spendable — the other members are unaffected, which is the point of giving
		// each its own leaf rather than sharing one anchor-wide consumption flag.
		return txHash, errSettlementReverted
	}
	return txHash, nil
}

// forgetUnbroadcastSettlement removes the record of a settlement attempt that never reached a mempool
// (its first broadcast was refused before or at sending): that hash is not history, it is nothing,
// and its nonce may now carry another transaction. Earlier attempts' hashes stay.
func (o *BatchOrchestrator) forgetUnbroadcastSettlement(p *PendingBatchIntent, hash string) {
	o.noteOnDemandProgress(p, func(m *PendingBatchIntent) {
		m.SettlementNonceSet = false
		kept := m.SettlementTxs[:0:0]
		for _, h := range m.SettlementTxs {
			if h != hash {
				kept = append(kept, h)
			}
		}
		m.SettlementTxs = kept
		m.SettlementTx = ""
		if n := len(kept); n > 0 {
			m.SettlementTx = kept[n-1]
		}
	})
}

// errLeafAlreadyConsumed: the member's leaf was already spent when this node went to settle it, so it
// sent nothing. Another settlement - another validator's, or a relayer's - executed the member.
var errLeafAlreadyConsumed = errors.New("leaf already consumed")

// settlementInFlight reports whether this node's key still has a transaction outstanding at nonce -
// broadcast, not yet mined, still being driven by the sender.
func (o *BatchOrchestrator) settlementInFlight(nonce uint64) bool {
	sender, err := o.ecm.batchSender()
	if err != nil || sender == nil {
		// Unknown is treated as in flight: concluding "not in flight" would settle a second time.
		return true
	}
	return sender.outbox.has(nonce)
}

// settlementHashesAt is every hash this node's key broadcast at nonce for member p's settlement, from
// the sender's durable history - including replacements made while no caller was listening (Resume).
func (o *BatchOrchestrator) settlementHashesAt(p *PendingBatchIntent, nonce uint64) []string {
	sender, err := o.ecm.batchSender()
	if err != nil || sender == nil {
		return nil
	}
	return sender.outbox.hashesAt(nonce, settlementOwner(p))
}

// settlementOwner names a member's settlement in the sender's outbox.
func settlementOwner(p *PendingBatchIntent) string {
	return "settle:" + memberWorkKey(p.ChainID, p.OperationID)
}

// ownAddress is the address this node settles from.
func (o *BatchOrchestrator) ownAddress() common.Address { return o.ecm.auth.From }

// settlementWaitTimeout bounds how long a sent settlement is waited on before its outcome is
// reported unknown. Far longer than a block on any chain the batch path settles on.
const settlementWaitTimeout = 10 * time.Minute

// errSettlementWindowClosed: the settlement's window ended before it could be sent. Nothing was sent.
var errSettlementWindowClosed = errors.New("settlement window closed")

// errSettlementReverted is a settlement that was mined and reverted: a terminal, observed outcome.
var errSettlementReverted = errors.New("member execution reverted on-chain (leaf still spendable)")

// SettlementOutcomeUnknownError is a settlement that was SENT but whose outcome was not observed -
// the wait timed out or its context ended. The transaction may still execute or revert.
type SettlementOutcomeUnknownError struct {
	TxHash string
	Err    error
}

func (e *SettlementOutcomeUnknownError) Error() string {
	return fmt.Sprintf("settlement %s sent but its outcome was not observed: %v", e.TxHash, e.Err)
}
func (e *SettlementOutcomeUnknownError) Unwrap() error { return e.Err }

// noteOnDemandProgress records this validator's own progress on an on-demand member, persisting it
// with the queue. A member that is not queued on demand (a period member) is updated in memory only.
func (o *BatchOrchestrator) noteOnDemandProgress(p *PendingBatchIntent, update func(*PendingBatchIntent)) {
	if p == nil {
		return
	}
	if o.mempool == nil || !o.mempool.NoteOnDemandProgress(p.ChainID, p.OperationID, update) {
		update(p)
	}
}

// settlementStatus reports whether a transaction is mined, and if so whether it reverted. found is
// false when the node does not know the transaction at all - dropped, or never broadcast.
func (o *BatchOrchestrator) settlementStatus(ctx context.Context, txHash string) (found, mined, reverted bool, err error) {
	if !IsTransactionHash(txHash) {
		return false, false, false, fmt.Errorf("%q is not a transaction hash", txHash)
	}
	h := common.HexToHash(txHash)
	_, pending, err := o.ecm.client.TransactionByHash(ctx, h)
	if err != nil {
		if errors.Is(err, ethereum.NotFound) {
			return false, false, false, nil
		}
		return false, false, false, err
	}
	if pending {
		return true, false, false, nil
	}
	receipt, err := o.ecm.client.TransactionReceipt(ctx, h)
	if err != nil {
		return true, false, false, err
	}
	return true, true, receipt.Status == 0, nil
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
//
// A read that fails is not a verdict: it is returned as a chain read error, and the member waits for
// a read that succeeds. Only an answer the chain gave - no code, a call the account rejects, a wrong
// owner or ADI - disqualifies the member.
func (o *BatchOrchestrator) memberAccountUsable(ctx context.Context, p *PendingBatchIntent) error {
	code, err := o.ecm.client.CodeAt(ctx, p.Account, nil)
	if err != nil {
		return readErr(fmt.Errorf("reading code at %s: %w", p.Account.Hex(), err))
	}
	if len(code) == 0 {
		return fmt.Errorf("account %s has no code", p.Account.Hex())
	}
	acct, err := contracts.NewCertenAccountV7(p.Account, o.ecm.client)
	if err != nil {
		return fmt.Errorf("binding account %s: %w", p.Account.Hex(), err)
	}
	keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
	if err != nil {
		if !isCallVerdict(err) {
			return readErr(fmt.Errorf("reading isKeylessOwner on %s: %w", p.Account.Hex(), err))
		}
		return fmt.Errorf("account %s is not a CertenAccountV7: %w", p.Account.Hex(), err)
	}
	if !keyless {
		return fmt.Errorf("account %s reports a non-keyless owner", p.Account.Hex())
	}
	onChainADIHash, err := acct.ADIURLHash(&bind.CallOpts{Context: ctx})
	if err != nil {
		if !isCallVerdict(err) {
			return readErr(fmt.Errorf("reading adiURLHash on %s: %w", p.Account.Hex(), err))
		}
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
// Measured from the member's Origin - its Accumulate block time, or its persisted first sighting
// - never from EnqueuedAt, which a restart resets: measured from that, a validator restarting
// within the hour would defer the member for ever.
func (o *BatchOrchestrator) memberPastDeadline(p *PendingBatchIntent) bool {
	if p == nil {
		return false
	}
	origin, _ := p.Origin()
	if origin.IsZero() {
		return false
	}
	return time.Since(origin) > maxGasDeferral
}

// maxGasDeferral is how long a member may be deferred on gas before it is failed outright.
//
// Long enough to ride out an ordinary fee spike, short enough that an ADI learns the outcome the
// same hour it submitted.
const maxGasDeferral = time.Hour
