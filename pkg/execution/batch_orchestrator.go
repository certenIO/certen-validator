package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/certen/independant-validator/pkg/ethrpc"
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

// drop records members as having left the batch path for good, with the cause.
func (r *BatchFlushResult) drop(cause string, members ...*PendingBatchIntent) {
	if r.dropCause == nil {
		r.dropCause = make(map[string]string, len(members))
	}
	for _, p := range members {
		if p == nil {
			continue
		}
		r.Dropped = append(r.Dropped, p)
		r.dropCause[memberKey(p.IntentID, p.ChainID)] = cause
	}
}

// DropCauseOf reports why a dropped member was dropped.
func (r *BatchFlushResult) DropCauseOf(p *PendingBatchIntent) string {
	if r == nil || p == nil {
		return ""
	}
	return r.dropCause[memberKey(p.IntentID, p.ChainID)]
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
	// Dropped members left the batch path for good: their account cannot participate, the anchor
	// mined but rejects their leaves, or quorum over the root was never reached. There is no other
	// path to settle them, so the caller MUST record each as FAILED with its cause (DropCauseOf);
	// a caller that ignores this field leaves them settled nowhere and recorded nowhere. Always add
	// to it through drop, which records the cause.
	Dropped []*PendingBatchIntent
	// dropCause is why each dropped member was dropped, keyed by member (intent and chain).
	dropCause map[string]string
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
	// incarnation is the Accumulate incarnation every tree this orchestrator forms commits (BatchStack.Incarnation).
	incarnation [32]byte

	attemptsMu sync.Mutex
	// attempts counts failed quorum attempts per tree (bundleId): a period may be cut into several.
	attempts map[[32]byte]int

	// usable caches definitive account-screen verdicts (nil = usable) by member and account. The
	// properties screened are fixed once an account exists, so a verdict never changes; a read that
	// failed is not a verdict and is never cached.
	usableMu sync.Mutex
	usable   map[string]error
	// screen replaces memberAccountUsable for tests that have no chain. Nil in production.
	screen func(context.Context, *PendingBatchIntent) error

	ecm      *EthereumContractManager
	anchorV7 common.Address
	prover   QuorumProver
	mempool  *BatchMempool
	logf     func(string, ...interface{})

	// odChain replaces the orchestrator's own chain operations for on-demand settlement. Nil in
	// production, where the orchestrator IS the chain; set by tests to drive the decisions.
	odChain onDemandChain

	// floors caches where attribution searches start; see batch_attribution.go.
	floors attributionFloors

	// roster is the chain-confirmed settlement roster; see settlementRoster.
	rosterMu sync.Mutex
	roster   []common.Address
	// scanned is, per anchor, the last finalized block already searched for earlier windows' attempts.
	scanMu  sync.Mutex
	scanned map[[32]byte]uint64

	// agreed is the chain's agreeing reader (RB5-F53), built on first use over every provider configured for the chain:
	// what the orchestrator records about a transaction it did not send - another validator's anchor creation - is read
	// through it, never from its own single client.
	agreedMu sync.Mutex
	agreed   *ethrpc.AgreeingReader
}

// agreedReader is the chain's agreeing reader: the orchestrator's own endpoint and every fallback configured for the
// chain (ethrpc.EndpointsForChainID). Fewer than ethrpc.MinAgreeingProviders independent providers is refused by name.
func (o *BatchOrchestrator) agreedReader(ctx context.Context, chainID int64) (*ethrpc.AgreeingReader, error) {
	o.agreedMu.Lock()
	defer o.agreedMu.Unlock()
	if o.agreed != nil {
		return o.agreed, nil
	}
	primary := ""
	if o.ecm != nil && o.ecm.config != nil {
		primary = o.ecm.config.EthereumRPC
	}
	r, err := ethrpc.NewAgreeingReader(ctx, chainID, ethrpc.EndpointsForChainID(chainID, primary), ethrpc.DefaultReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("the agreeing providers of chain %d: %w", chainID, err)
	}
	o.agreed = r
	return r, nil
}

// NewBatchOrchestrator wires an orchestrator to a chain.
func NewBatchOrchestrator(
	ecm *EthereumContractManager,
	anchorV7 common.Address,
	prover QuorumProver,
	mempool *BatchMempool,
	incarnation [32]byte,
	logf func(string, ...interface{}),
) *BatchOrchestrator {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	return &BatchOrchestrator{
		ecm: ecm, anchorV7: anchorV7, prover: prover, mempool: mempool, incarnation: incarnation, logf: logf,
		attempts: make(map[[32]byte]int),
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
// Before the anchor is created, members are requeued untouched — nothing has been spent. After
// it exists, a transient quorum failure is retried (createBatchAnchor treats the existing anchor
// as success) up to maxQuorumAttempts; past that, or when the anchor rejects the leaves, the
// members are DROPPED with their cause and the caller records each as FAILED. There is no other
// path to settle them.
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
	// PeriodMembers would select nothing anyway.
	if cutoffHeight == 0 {
		return nil, fmt.Errorf("chain %d: cutoff height 0 is not a valid period; the consensus "+
			"height source is not wired", chainID)
	}

	// The period's WHOLE member set - settled and pending alike - cut into trees by the one
	// eligibility rule every validator applies (periodChunks). A peer asked to co-sign cuts the same
	// trees from its own copy; the leader never works from a subset it alone holds (RB3-F54).
	// A period with a member still awaiting its quorum certificate is not formed: that member would be left out of the
	// period's trees and could be in no batch once its certificate arrived (RB5-F44). It is formed once the
	// certificate exists; a member never certified before its deadline is refused by name (settleNeverCertified).
	if waiting := o.mempool.AwaitingCertificate(chainID, cutoffHeight, periodBlocks); len(waiting) > 0 {
		ids := make([]string, 0, len(waiting))
		for _, p := range waiting {
			ids = append(ids, p.IntentID)
		}
		return nil, fmt.Errorf("%w: period %d on chain %d is not formed while %d member(s) await their quorum certificate: %s",
			ErrIntentNotYetCertified, cutoffHeight, chainID, len(waiting), strings.Join(ids, ", "))
	}
	periodMembers := o.mempool.PeriodMembers(chainID, cutoffHeight, periodBlocks)
	if !anyPending(periodMembers) {
		return nil, nil
	}
	chunks, excluded, err := o.periodChunks(ctx, periodMembers, o.mempool.MaxBatchSize())
	if err != nil {
		// A read that failed is not the on-chain state every validator reads. Nothing is decided;
		// the period is flushed again once the read succeeds.
		return nil, fmt.Errorf("period %d on chain %d: %w", cutoffHeight, chainID, err)
	}

	res := &BatchFlushResult{
		ChainID:  chainID,
		TxHashes: make(map[string]string, len(periodMembers)),
	}
	// Every exit records the outcomes this flush reached on the pooled members.
	defer o.markOutcomes(res)

	// A member whose account cannot take part is excluded by every validator alike, so it is in no
	// tree anywhere. It is dropped here - recorded as failed with its cause - once.
	for _, x := range excluded {
		if x.member.pending() {
			o.logf("[BATCH] chain=%d dropping member %s from period %d: %v", chainID, x.member.IntentID, cutoffHeight, x.cause)
			res.drop(fmt.Sprintf("its account cannot take part in a batch on chain %d: %v", chainID, x.cause), x.member)
		}
	}

	// One tree per flush: the first with a member still to resolve. The next flush takes the next.
	var members []*PendingBatchIntent
	for _, c := range chunks {
		if anyPending(c) {
			members = c
			break
		}
	}
	if members == nil {
		return res, nil
	}
	res.MemberCount = len(members)
	pendingMembers := pendingOf(members)

	inputs := make([]BatchLeafInput, 0, len(members))
	for _, p := range members {
		in, err := p.LeafInput()
		if err != nil {
			return res, fmt.Errorf("building leaf for %s: %w", p.IntentID, err)
		}
		inputs = append(inputs, in)
	}

	tree, err := BuildBatchTree(chainID, inputs, cutoffHeight, o.incarnation)
	if err != nil {
		return res, fmt.Errorf("building batch tree: %w", err)
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
		return res, err
	}
	defer o.ecm.endNonceSequence()

	// ---- ALREADY SETTLED ELSEWHERE? ----------------------------------------
	// Leadership rotates per period and the flush loop picks up stragglers, so two different
	// nodes can legitimately reach the same period. bundleId is deterministic, so an anchor
	// that already exists AND is attested means the batch settled under a previous leader.
	//
	// This MUST short-circuit. Continuing would re-submit executeComprehensiveProof, which
	// reverts on usedCommitments replay protection; the quorum step would then report failure
	// and record every member as FAILED although it already moved funds. A false failure
	// produced by a retry contradicts the chain; a skipped flush does not.
	if settled, serr := o.anchorAlreadyAttested(ctx, tree.BundleID); serr != nil {
		return res, fmt.Errorf("checking whether anchor 0x%x already settled: %w", tree.BundleID[:8], serr)
	} else if settled {
		// Whose attestation is it? The chain says: the sender of its ProofExecuted transaction. If it
		// is THIS node's - a verify of its own that had no result when an earlier flush gave up on it,
		// and has since landed - this node is the period's settler and settles the members under it.
		// Attesting them unsettled would write back as failed a batch this node anchored and attested
		// itself and never got to settle.
		attesterTx, attester, found, aerr := o.anchorAttester(ctx, tree.BundleID, 0)
		if aerr != nil || !found {
			return res, fmt.Errorf("anchor 0x%x is attested but its attester is not in view (found=%t): %v",
				tree.BundleID[:8], found, aerr)
		}
		if attester == o.ecm.auth.From {
			o.logf("[BATCH] chain=%d period %d: anchor 0x%x was attested by this node; settling its %d member(s) under it",
				chainID, cutoffHeight, tree.BundleID[:8], len(members))
			o.attemptsMu.Lock()
			delete(o.attempts, tree.BundleID)
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
		res.AlreadySettledOutcome = make(map[string]bool, len(pendingMembers))
		var awaiting []*PendingBatchIntent
		for _, m := range pendingMembers {
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
			o.mempool.MarkOutcome(expired, MemberReleased)
			for _, m := range expired {
				o.logf("⚠️ [BATCH] member %s: past its deadline, unsettled under anchor 0x%x attested by %s; "+
					"removed from this node's pool - its outcome is that validator's record", m.IntentID, tree.BundleID[:8], attester.Hex())
			}
		}
		if len(awaiting) > 0 {
			o.logf("[BATCH] chain=%d period %d: %d member(s) under anchor 0x%x attested by %s are not settled yet; "+
				"requeued until that validator settles them", chainID, cutoffHeight, len(awaiting), tree.BundleID[:8], attester.Hex())
		}
		return res, nil
	}

	// ---- VERIFY 2: every account's own leaf agrees with ours ----------------
	// Checked against DEPLOYED bytecode, not a fixture. A drift here would mint an anchor
	// whose leaves no account can reproduce — unspendable, and paid for.
	if err := o.verifyLeavesAgainstAccounts(ctx, members, tree); err != nil {
		return res, err
	}

	// ---- NOTHING LEFT THAT CAN SETTLE? ---------------------------------------
	// A tree whose every pending member is past its deadline at the chain's time can settle nothing: each settlement
	// would be refused as errMemberPastDeadline after the anchor and its attestation were paid for (RB5-F45: period
	// 10244900 on 2026-10-02 spent 340,916 + 561,855 gas to drop its one member). They are refused by name here,
	// before anything is sent. A tree with any member still within its deadline is anchored as before.
	if expired, err := o.allPendingPastDeadline(ctx, pendingMembers); err != nil {
		return res, err
	} else if expired {
		for _, p := range pendingMembers {
			deadline, _ := p.Deadline()
			o.logf("[BATCH] member %s: past its deadline %s before its batch was anchored — refused, nothing sent",
				p.IntentID, deadline.Format(time.RFC3339))
			res.drop(fmt.Sprintf("its deadline %s passed before its batch could be anchored on chain %d",
				deadline.Format(time.RFC3339), chainID), p)
		}
		return res, nil
	}

	// ---- Create the anchor --------------------------------------------------
	created, err := o.createBatchAnchor(ctx, tree)
	if err != nil {
		return res, fmt.Errorf("createBatchAnchor: %w", err)
	}
	res.AnchorTxHash = created.TxHash
	res.GasAnchor = created.GasUsed
	// Same as the on-demand lane: the tree carries the transaction that published its root and who sent
	// it, so the quorum evidence records where the root actually is.
	created.onTree(tree)
	o.logf("[BATCH] chain=%d anchor created tx=%s by %s gas=%d", chainID, created.TxHash, created.Sender, created.GasUsed)

	// ---- VERIFY 3: the deployed anchor accepts every member leaf ------------
	if err := o.verifyLeavesAgainstAnchor(ctx, tree); err != nil {
		// The anchor exists but rejects these leaves. Do NOT requeue: re-forming the identical tree
		// derives the same bundleId, finds the same anchor, and fails this same check again - the
		// rejection is a property of the tree, not a transient. Drop the members, recorded as
		// FAILED with this cause by the caller.
		res.drop(fmt.Sprintf("its batch anchor 0x%x on chain %d was created but rejects the member leaves: %v",
			tree.BundleID[:8], chainID, err), pendingMembers...)
		return res, fmt.Errorf("anchor created but membership verification failed (%d member(s) "+
			"dropped and recorded as FAILED): %w", len(members), err)
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
		o.attempts[tree.BundleID]++
		n := o.attempts[tree.BundleID]
		o.attemptsMu.Unlock()

		if n < maxQuorumAttempts {
			return res, fmt.Errorf("quorum attestation over batch root failed (attempt %d/%d; "+
				"%d member(s) requeued for retry): %w", n, maxQuorumAttempts, len(members), err)
		}

		o.attemptsMu.Lock()
		delete(o.attempts, tree.BundleID)
		o.attemptsMu.Unlock()
		res.drop(fmt.Sprintf("quorum over its batch root 0x%x on chain %d was not reached after %d attempts: %v",
			tree.BundleID[:8], chainID, n, err), pendingMembers...)
		return res, fmt.Errorf("quorum attestation over batch root failed %d times; %d member(s) "+
			"dropped and recorded as FAILED: %w", n, len(members), err)
	}
	o.attemptsMu.Lock()
	delete(o.attempts, tree.BundleID)
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
		// Its position in the tree is fixed; only a member without an outcome is acted on.
		if !p.pending() {
			continue
		}
		// A settlement still in flight holds its nonce: every later member would queue behind it and
		// wait out the same bound. Stop, and leave the rest for the next flush, which first drives
		// the in-flight transaction to a result.
		if res.stopSending {
			res.Retryable = append(res.Retryable, p)
			continue
		}
		branch, berr := tree.BranchFor(i)
		if berr != nil {
			// Nothing reached the chain: the failure is recorded with its cause, and attested as the
			// member's non-settlement (RB3-F49).
			res.drop(fmt.Sprintf("its settlement on chain %d could not be formed: %v", p.ChainID, berr), p)
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
		if serr != nil && errors.Is(serr, errMemberPastDeadline) {
			o.logf("[BATCH] member %s: %v — not sent", p.IntentID, serr)
			res.drop(fmt.Sprintf("its deadline passed before it could settle on chain %d: %v", p.ChainID, serr), p)
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
					res.drop(fmt.Sprintf("the gas price on chain %d stayed above the ceiling until its settlement horizon: %v", p.ChainID, serr), p)
					continue
				}
				o.logf("[BATCH] member %s deferred: %v (leaf untouched; will retry in a later period)",
					p.IntentID, serr)
				res.Retryable = append(res.Retryable, p)
				continue
			}
			// Nothing of this settlement executed: refused before broadcast, never reached a
			// mempool, or its nonce went to another transaction. Not a failure of the member.
			if !errors.As(serr, &unknown) && (isTransientSendError(serr) || IsChainReadError(serr)) {
				o.logf("[BATCH] member %s deferred: the settlement did not reach the chain (%v); will retry",
					p.IntentID, serr)
				res.Retryable = append(res.Retryable, p)
				continue
			}
			if txHash == "" {
				// Nothing reached the chain: no transaction to prove the failure from, so its cause is
				// the record, and the member's non-settlement is attested (RB3-F49).
				res.drop(fmt.Sprintf("its settlement on chain %d failed before reaching the chain: %v", p.ChainID, serr), p)
				o.logf("[BATCH] member %s FAILED before reaching the chain: %v", p.IntentID, serr)
				continue
			}
			res.Failed = append(res.Failed, p)
			// Keep the hash of a member that REVERTED. settleMember returns one whenever the
			// transaction was mined, and a reverted transaction is on chain and independently
			// verifiable — it is the evidence of the failure, not the absence of evidence.
			// Discarding it left Phase 7 with nothing to observe, so the failure never reached
			// acc://certen-protocol.acme/execution-results and the ADI could not tell a reverted
			// intent from one that was never processed.
			res.TxHashes[p.IntentID] = txHash
			o.logf("[BATCH] member %s FAILED: %v (tx=%s)", p.IntentID, serr, txHash)
			continue
		}
		res.Settled = append(res.Settled, p)
		res.TxHashes[p.IntentID] = txHash
	}

	// Deferred members keep no outcome, so the next flush of this period retries them. Never an
	// outcome: an intent that simply could not afford gas this minute has not failed.
	if len(res.Retryable) > 0 {
		o.logf("[BATCH] chain=%d %d member(s) deferred; retried by the next flush", chainID, len(res.Retryable))
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

	return res
}

// verifyLeavesAgainstAccounts asks each deployed account to compute its own leaf and compares.
func (o *BatchOrchestrator) verifyLeavesAgainstAccounts(
	ctx context.Context,
	members []*PendingBatchIntent,
	tree *BatchTree,
) error {
	for i, p := range members {
		// The account generation the chain is on (RB5-F57): its leaf is the one the tree holds.
		acct, version, err := bindMemberAccount(p.ChainID, p.Account, o.ecm.client)
		if err != nil {
			return fmt.Errorf("binding account for %s: %w", p.IntentID, err)
		}

		// The account must be the keyless account of the chain's generation for this ADI, or its leaf identity half
		// is something other than what we hashed.
		keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
		if err != nil {
			return fmt.Errorf("account %s is not a %s (%s): %w",
				p.Account.Hex(), version.AccountContract(), p.IntentID, err)
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

		if tree.Inputs[i].OperationID != p.OperationID {
			return fmt.Errorf("tree member %d is operation 0x%x, the member %s 0x%x", i, tree.Inputs[i].OperationID[:8],
				p.IntentID, p.OperationID[:8])
		}
		onChainLeaf, err := acct.MemberLeaf(&bind.CallOpts{Context: ctx}, tree.Inputs[i])
		if err != nil {
			return fmt.Errorf("computeLeaf on %s: %w", p.Account.Hex(), err)
		}
		if onChainLeaf != tree.Leaves[i] {
			return fmt.Errorf(
				"leaf mismatch for %s: Go computed 0x%x, deployed account computed 0x%x — "+
					"cross-language drift between the validator and %s",
				p.IntentID, tree.Leaves[i], onChainLeaf, version.AccountContract())
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
	st, err := ReadAnchorState(ctx, o.ecm.client, o.anchorV7, bundleID, nil)
	if err != nil {
		return false, err
	}
	return st.ProofExecuted, nil
}

// verifyLeavesAgainstAnchor confirms the deployed anchor stored what we think it did and
// accepts every member's branch.
func (o *BatchOrchestrator) verifyLeavesAgainstAnchor(ctx context.Context, tree *BatchTree) error {
	anchor, err := contracts.NewCertenAnchorV8_2Batch(o.anchorV7, o.ecm.client)
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
	// every member was dropped from it even though the anchor was perfectly good.
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

	// The anchor committed exactly the Accumulate validator set and incarnation this tree carries: the fields the
	// quorum's message covers and a verifier reads back (RB5).
	stored, serr := anchor.Anchors(opts, tree.BundleID)
	if serr != nil {
		return fmt.Errorf("reading anchor 0x%x: %w", tree.BundleID[:8], serr)
	}
	if stored.AccumulateValidatorSetRoot != tree.AccumulateSetRoot || stored.AccumulateIncarnation != tree.Incarnation {
		return fmt.Errorf("anchor 0x%x committed Accumulate set %x under incarnation %x; the tree carries %x under %x",
			tree.BundleID[:8], stored.AccumulateValidatorSetRoot[:8], stored.AccumulateIncarnation[:8],
			tree.AccumulateSetRoot[:8], tree.Incarnation[:8])
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
func (o *BatchOrchestrator) createBatchAnchor(ctx context.Context, tree *BatchTree) (anchorCreation, error) {
	anchor, err := contracts.NewCertenAnchorV8_2Batch(o.anchorV7, o.ecm.client)
	if err != nil {
		return anchorCreation{}, err
	}

	// Idempotence: a retry after a timeout must not revert with "Anchor already exists"
	// and lose the batch. bundleId is deterministic, so an existing anchor for this exact
	// tree is a SUCCESS, not a conflict - and the transaction that created it is located, not left
	// unknown (RB3-F33).
	exists, eerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID)
	if eerr != nil {
		// Unknown is not "absent": sending on an unreadable answer created a second anchor attempt
		// that reverts, and the revert was then read as the member failing.
		return anchorCreation{}, readErr(fmt.Errorf("reading anchorExists for 0x%x: %w", tree.BundleID[:8], eerr))
	}
	if exists {
		created, err := o.existingAnchorCreation(ctx, tree, 0)
		if err != nil {
			return anchorCreation{}, err
		}
		o.logf("[BATCH] anchor 0x%x already exists — created by %s in %s", tree.BundleID[:8], created.Sender, created.TxHash)
		return created, nil
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
				tree.AccumulateSetRoot,
				tree.Incarnation,
			)
		}, nil)
	if err != nil {
		return anchorCreation{}, err
	}
	if receipt.Status == 0 {
		// The usual cause is another validator's anchor for this exact bundleId landing first -
		// the anchor this node wanted now exists. Anything else is a real failure.
		if now, rerr := anchor.AnchorExists(&bind.CallOpts{Context: ctx}, tree.BundleID); rerr == nil && now {
			created, err := o.existingAnchorCreation(ctx, tree, receipt.GasUsed)
			if err != nil {
				return anchorCreation{}, err
			}
			o.logf("[BATCH] createBatchAnchor %s reverted because anchor 0x%x already exists — created by %s in %s",
				txHash, tree.BundleID[:8], created.Sender, created.TxHash)
			return created, nil
		}
		return anchorCreation{TxHash: txHash, GasUsed: receipt.GasUsed}, fmt.Errorf("createBatchAnchor reverted")
	}
	// This node's own transaction: its signer is the key it was sent with.
	return anchorCreation{
		TxHash: txHash, GasUsed: receipt.GasUsed, Block: receipt.BlockNumber.Uint64(),
		Sender: strings.ToLower(o.ecm.SenderAddress().Hex()), Paid: txHash,
	}, nil
}

// anchorCreation is the transaction that created a batch anchor: this node's own, or - when another
// validator's landed first - the one located on chain. GasUsed is what this node spent (zero, or its own
// reverted attempt); Paid is TxHash when this node sent it, and empty when another validator did, whose
// spend it is (see PendingBatchIntent.AnchorTx).
type anchorCreation struct {
	TxHash  string
	GasUsed uint64
	Block   uint64
	Sender  string
	Paid    string
}

// onTree records the creation on the tree, for the quorum evidence and layer 5.
func (c anchorCreation) onTree(tree *BatchTree) {
	tree.AnchorCreateTx, tree.AnchorCreateBlock, tree.AnchorCreateSender = c.TxHash, c.Block, c.Sender
}

// existingAnchorCreation locates the transaction that created an anchor another validator created (see
// LocateAnchorCreate) and reads it back: accepted only as the successful createBatchAnchor call of this
// bundle and root at this anchor, signed by the creator the anchor records. Every fact it records - the anchor's
// record, the block, the receipt, the head - is read through the chain's agreeing providers (agreedReader); one
// provider's word is never written to the tree. Anything it cannot read is a read error - the anchor exists, and
// the pass that retries will find it.
func (o *BatchOrchestrator) existingAnchorCreation(ctx context.Context, tree *BatchTree, gasUsed uint64) (anchorCreation, error) {
	agreed, err := o.agreedReader(ctx, tree.ChainID)
	if err != nil {
		return anchorCreation{}, readErr(fmt.Errorf("locating anchor 0x%x's creation: %w", tree.BundleID[:8], err))
	}
	head, err := agreed.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if err != nil {
		return anchorCreation{}, readErr(fmt.Errorf("reading the head to locate anchor 0x%x's creation: %w", tree.BundleID[:8], err))
	}
	loc, err := LocateAnchorCreate(ctx, agreedCreateChain{agreed}, o.anchorV7, tree.BundleID, tree.Root, head.Number.Uint64())
	if err != nil {
		return anchorCreation{}, readErr(fmt.Errorf("locating the transaction that created anchor 0x%x: %w", tree.BundleID[:8], err))
	}
	reading, err := ReadAnchorTxAgreed(ctx, agreed, tree.ChainID, loc.TxHash)
	if err != nil {
		return anchorCreation{}, readErr(fmt.Errorf("reading anchor 0x%x's create transaction %s: %w", tree.BundleID[:8], loc.TxHash, err))
	}
	bundle, root, derr := createBatchAnchorArgs(tree.ChainID, reading.Input)
	switch {
	case !reading.Found || !reading.Succeeded || reading.BlockNumber != loc.Block:
		return anchorCreation{}, readErr(fmt.Errorf("anchor 0x%x's located create transaction %s reads as found=%v succeeded=%v in block %d, not block %d",
			tree.BundleID[:8], loc.TxHash, reading.Found, reading.Succeeded, reading.BlockNumber, loc.Block))
	case derr != nil || bundle != tree.BundleID || root != tree.Root:
		return anchorCreation{}, fmt.Errorf("anchor 0x%x's located create transaction %s is not its createBatchAnchor call: %v", tree.BundleID[:8], loc.TxHash, derr)
	case !strings.EqualFold(reading.To, o.anchorV7.Hex()) || !strings.EqualFold(reading.From, loc.Validator.Hex()):
		return anchorCreation{}, fmt.Errorf("anchor 0x%x's located create transaction %s called %s from %s; the anchor is %s and records creator %s",
			tree.BundleID[:8], loc.TxHash, reading.To, reading.From, o.anchorV7.Hex(), loc.Validator.Hex())
	}
	return anchorCreation{TxHash: loc.TxHash, GasUsed: gasUsed, Block: loc.Block, Sender: reading.From}, nil
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
	// The account generation the chain is on (RB5-F57); a v4 account's proof also carries the leaf's window.
	acct, _, err := bindMemberAccount(p.ChainID, p.Account, o.ecm.client)
	if err != nil {
		return "", err
	}
	in, err := p.LeafInput()
	if err != nil {
		return "", err
	}
	leaf, err := ComputeAccountLeaf(p.ChainID, in)
	if err != nil {
		return "", err
	}
	book, page := in.AuthorityBook, in.AuthorityPage

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
	// A v4 leaf's window opens at the member's commit time: before it the account refuses the leaf (LeafNotYetValid).
	// That is not the member's outcome - only too early - so nothing is sent and nothing is decided.
	if in.NotBefore != 0 && head.Time < in.NotBefore {
		return "", readErr(fmt.Errorf("member %s: chain time %d is before its leaf's notBefore %d", p.IntentID, head.Time,
			in.NotBefore))
	}
	expiresAt, err := settlementExpiry(p, notBefore, fence)
	if err != nil {
		return "", err
	}
	proof := settlementProofFields(p, tree, branch, book, page, notBefore, expiresAt)

	gas := uint64(500000)
	if p.IsMultiLeg() {
		gas = 400000 + uint64(len(p.Legs))*250000
	}
	build := func(opts *bind.TransactOpts) (*types.Transaction, error) {
		// Single leg: executeGovernanceProofDirect; several: batchExecuteGovernanceProofDirect. On a v4 chain the proof
		// carries the window the leaf binds (RB5-F57).
		return acct.Settle(opts, p.Legs, proof, in)
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

// settlementProofFields is the proof a settlement carries, in the fields both account generations share; a v4 account's
// proof adds the window of the member's leaf (memberAccount.Settle, RB5-F57). timestamp and expiresAt are this
// settlement's own bound, which on a v4 account only narrows the window the leaf binds.
func settlementProofFields(p *PendingBatchIntent, tree *BatchTree, branch [][32]byte, book [32]byte, page uint64,
	timestamp, expiresAt int64) contracts.AccountProofV7_2 {
	return contracts.AccountProofV7_2{
		AdiURL:      p.ADIURL, // advisory; the contract uses its own immutable adiURL
		AnchorId:    tree.BundleID,
		MerkleProof: branch,
		OperationID: p.OperationID,
		Timestamp:   big.NewInt(timestamp),
		ExpiresAt:   big.NewInt(expiresAt),
		Nonce:       big.NewInt(0),
		// The certified key book and page, bound into the leaf: the account derives every leg's level from them
		// (RB3-F39, RB5-F30) - no level is declared.
		AuthorityBook: book,
		AuthorityPage: page,
	}
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
// An unavailable sender is an error, not an empty history (RB3-F118).
func (o *BatchOrchestrator) settlementHashesAt(p *PendingBatchIntent, nonce uint64) ([]string, error) {
	sender, err := o.ecm.batchSender()
	if err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, fmt.Errorf("the transaction sender is not available")
	}
	return sender.outbox.hashesAt(nonce, settlementOwner(p)), nil
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

// allPendingPastDeadline reports whether every one of members is past its deadline at the chain's head time - the same
// clock and rule settlementExpiry applies to each settlement. False when any member has no deadline or is still within
// it, or when members is empty.
func (o *BatchOrchestrator) allPendingPastDeadline(ctx context.Context, members []*PendingBatchIntent) (bool, error) {
	if len(members) == 0 {
		return false, nil
	}
	for _, p := range members {
		if _, ok := p.Deadline(); !ok {
			return false, nil
		}
	}
	head, err := o.ecm.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("reading the chain head to judge the members' deadlines: %w", err)
	}
	return allPastDeadlineAt(members, int64(head.Time)), nil
}

// allPastDeadlineAt is allPendingPastDeadline's rule at chain time now: past means now >= deadline, as settlementExpiry
// refuses it.
func allPastDeadlineAt(members []*PendingBatchIntent, now int64) bool {
	if len(members) == 0 {
		return false
	}
	for _, p := range members {
		d, ok := p.Deadline()
		if !ok || now < d.Unix() {
			return false
		}
	}
	return true
}

// errMemberPastDeadline: the chain's time is past the member's deadline, so its settlement is not sent.
// Terminal: the member can never execute within its deadline (RB3-F53).
var errMemberPastDeadline = errors.New("member past its deadline")

// settlementExpiry is the expiresAt a member's settlement carries, from the chain time it is sent at.
//
// CertenAccountV7 refuses a settlement mined after its proof's expiresAt (block.timestamp <=
// proof.expiresAt), so this is where a member's deadline is ENFORCED ON CHAIN for every settlement
// this validator sends: expiresAt is the earliest of the settlement horizon (an hour), the window's
// fence, and the member's own deadline (PendingBatchIntent.Deadline). A settlement that does not mine
// before the deadline reverts instead of executing late. The deadline was parsed from the signed
// intent and enforced nowhere before (RB3-F53).
//
// A window that already closed is errSettlementWindowClosed (not the member's outcome); a deadline
// that already passed is errMemberPastDeadline (its outcome).
func settlementExpiry(p *PendingBatchIntent, notBefore int64, fence time.Time) (int64, error) {
	expiresAt := notBefore + int64(time.Hour/time.Second)
	if !fence.IsZero() {
		expiresAt = fence.Unix()
		if expiresAt <= notBefore {
			return 0, fmt.Errorf("settlement window closed at %s (chain time %d): %w",
				fence.UTC().Format(time.RFC3339), notBefore, errSettlementWindowClosed)
		}
	}
	if deadline, ok := p.Deadline(); ok {
		if notBefore >= deadline.Unix() {
			return 0, fmt.Errorf("member %s: chain time %s is past its deadline %s: %w", p.IntentID,
				time.Unix(notBefore, 0).UTC().Format(time.RFC3339), deadline.Format(time.RFC3339), errMemberPastDeadline)
		}
		if deadline.Unix() < expiresAt {
			expiresAt = deadline.Unix()
		}
	}
	return expiresAt, nil
}

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
	acct, _, err := bindMemberAccount(p.ChainID, p.Account, o.ecm.client)
	if err != nil {
		return false, fmt.Errorf("binding account %s: %w", p.Account.Hex(), err)
	}
	leaf, err := p.Leaf()
	if err != nil {
		return false, err
	}
	return acct.IsLeafConsumed(&bind.CallOpts{Context: ctx}, leaf)
}

// excludedMember is a period member the eligibility rule leaves out of every tree, with why.
type excludedMember struct {
	member *PendingBatchIntent
	cause  error
}

// periodChunks is THE eligibility rule for a period, applied identically by the leader forming its
// trees and by every peer asked to co-sign one (HandleBatchAttestationRequest). It screens every
// member - settled or pending - with memberAccountUsable, keeps the eligible ones in the period's
// fixed order and cuts them into trees of at most maxBatch (the mempool's MaxBatchSize).
//
// The leader used to screen and a peer did not: one member with an unusable account made every peer
// derive a different bundleId, no quorum formed, and after the bounded retries the whole period was
// dropped as failed (RB3-F54). A read that fails decides nothing: it is returned, and the caller
// neither forms nor co-signs a tree until it succeeds.
func (o *BatchOrchestrator) periodChunks(ctx context.Context, members []*PendingBatchIntent, maxBatch int) ([][]*PendingBatchIntent, []excludedMember, error) {
	eligible := make([]*PendingBatchIntent, 0, len(members))
	var legacy []*PendingBatchIntent
	var excluded []excludedMember
	for _, p := range members {
		if p.GovernanceCommitment == ([32]byte{}) && !p.LegacyNoGovernance {
			// Not reachable through admission, which requires the commitment; refused by name if it ever is.
			excluded = append(excluded, excludedMember{member: p, cause: fmt.Errorf("%w: intent %s on chain %d",
				ErrNoGovernanceCommitment, p.IntentID, p.ChainID)})
			continue
		}
		if p.AccumulateSetRoot == ([32]byte{}) {
			// Not reachable through admission or restore, which both require it; refused by name if it ever is.
			excluded = append(excluded, excludedMember{member: p, cause: fmt.Errorf("%w: intent %s on chain %d",
				ErrNoAccumulateSetRoot, p.IntentID, p.ChainID)})
			continue
		}
		verdict, err := o.accountVerdict(ctx, p)
		if err != nil {
			return nil, nil, err
		}
		if verdict != nil {
			excluded = append(excluded, excludedMember{member: p, cause: verdict})
			continue
		}
		if p.LegacyNoGovernance {
			legacy = append(legacy, p)
			continue
		}
		eligible = append(eligible, p)
	}
	// Members admitted before governance commitments are batched apart, with the v1 operation id their anchors
	// carry; every validator restored the same members the same way, so every validator cuts the same chunks.
	// One V8.2 anchor commits one Accumulate validator set, so members are cut into trees per set root, in the order
	// each root first appears in the period (RB5 design D2). Every validator derives each member's root from its own
	// proof of the same execution - measured identical across the fleet on every production operation - so every
	// validator cuts the same chunks. On Kermit, whose set has never changed, there is one group.
	chunks := chunkMembers(legacy, maxBatch)
	for _, group := range groupByAccumulateSet(eligible) {
		chunks = append(chunks, chunkMembers(group, maxBatch)...)
	}
	return chunks, excluded, nil
}

// groupByAccumulateSet splits members by AccumulateSetRoot, keeping their order within a group and ordering the
// groups by first appearance.
func groupByAccumulateSet(members []*PendingBatchIntent) [][]*PendingBatchIntent {
	// The key is the Accumulate set root AND the operation id class the members are formed with: v1 (admitted
	// before governance commitments), v2, or v3 (a quorum-certified intent, RB5 D3). batchOperationIDOf refuses a
	// tree that mixes classes, so every validator must cut them apart the same way.
	type key struct {
		root  [32]byte
		class string
	}
	classOf := func(p *PendingBatchIntent) string {
		switch {
		case p.IntentMessage != ([32]byte{}):
			return BatchOperationIDV3
		case p.LegacyNoGovernance:
			return BatchOperationIDV1
		default:
			return BatchOperationIDV2
		}
	}
	var order []key
	groups := map[key][]*PendingBatchIntent{}
	for _, p := range members {
		k := key{p.AccumulateSetRoot, classOf(p)}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}
		groups[k] = append(groups[k], p)
	}
	out := make([][]*PendingBatchIntent, 0, len(order))
	for _, r := range order {
		out = append(out, groups[r])
	}
	return out
}

// accountVerdict is memberAccountUsable, cached. It returns (nil, nil) for a usable account,
// (verdict, nil) for one the chain disqualifies, and (nil, err) when the chain could not be read.
func (o *BatchOrchestrator) accountVerdict(ctx context.Context, p *PendingBatchIntent) (error, error) {
	key := memberKey(p.IntentID, p.ChainID) + "|" + p.Account.Hex()
	o.usableMu.Lock()
	verdict, known := o.usable[key]
	o.usableMu.Unlock()
	if known {
		return verdict, nil
	}
	screen := o.memberAccountUsable
	if o.screen != nil {
		screen = o.screen
	}
	err := screen(ctx, p)
	if err != nil && IsChainReadError(err) {
		return nil, err
	}
	o.usableMu.Lock()
	// Bounded: a verdict is only a saved read, recomputed identically if dropped, and members leave
	// the pool at the retention horizon while this map would otherwise keep them for ever.
	if o.usable == nil || len(o.usable) >= maxCachedAccountVerdicts {
		o.usable = make(map[string]error)
	}
	o.usable[key] = err
	o.usableMu.Unlock()
	return err, nil
}

// maxCachedAccountVerdicts bounds accountVerdict's cache.
const maxCachedAccountVerdicts = 10000

// pendingOf returns the members still without an outcome, in order.
func pendingOf(members []*PendingBatchIntent) []*PendingBatchIntent {
	out := make([]*PendingBatchIntent, 0, len(members))
	for _, p := range members {
		if p.pending() {
			out = append(out, p)
		}
	}
	return out
}

// markOutcomes records on the pooled members the terminal outcomes a flush reached.
func (o *BatchOrchestrator) markOutcomes(res *BatchFlushResult) {
	if res == nil {
		return
	}
	o.mempool.MarkOutcome(res.Settled, MemberSettled)
	o.mempool.MarkOutcome(res.Failed, MemberFailed)
	o.mempool.MarkOutcome(res.Dropped, MemberDropped)
	o.mempool.MarkOutcome(res.SpentElsewhere, MemberSettledElsewhere)
	o.mempool.MarkOutcome(res.AlreadySettled, MemberSettledElsewhere)
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
	// Before any read: a member that would point its account away from CERTEN is refused on its
	// calldata alone, the same way on every validator.
	if err := checkMemberAnchorPin(orchestratorAnchorPolicy{o}, p); err != nil {
		return err
	}
	// Its leaf binds the key book and page CERTEN's quorum certified (RB5-F29/F30) - decided from the chain's record
	// alone, the same on every validator.
	book, page, err := p.Authority()
	if err != nil {
		return err
	}
	if o.ecm == nil || o.ecm.client == nil {
		return readErr(fmt.Errorf("no chain client for chain %d", p.ChainID))
	}
	code, err := o.ecm.client.CodeAt(ctx, p.Account, nil)
	if err != nil {
		return readErr(fmt.Errorf("reading code at %s: %w", p.Account.Hex(), err))
	}
	if len(code) == 0 {
		return fmt.Errorf("account %s has no code", p.Account.Hex())
	}
	// The account generation the chain is on (RB5-F57). Exactly one: an account of any other generation is refused by
	// name below, never settled through another generation's leaf.
	acct, version, err := bindMemberAccount(p.ChainID, p.Account, o.ecm.client)
	if err != nil {
		return fmt.Errorf("binding account %s: %w", p.Account.Hex(), err)
	}
	wantDomain, err := version.LeafDomain()
	if err != nil {
		return err
	}
	// A tree holds leaves of the chain's generation only. An account of another generation - a CertenAccountV7 (v1
	// leaf, a self-declared authority level - RB3-F39), or a CertenAccountV7_2 (v3, no window) on a v4 chain - is
	// superseded, not migrated in place: it is refused by name. LEAF_DOMAIN is a constant of the code.
	domain, err := acct.LeafDomain(&bind.CallOpts{Context: ctx})
	if err != nil {
		if !isCallVerdict(err) {
			return readErr(fmt.Errorf("reading LEAF_DOMAIN on %s: %w", p.Account.Hex(), err))
		}
		return fmt.Errorf("account %s is not a CertenAccount: %w", p.Account.Hex(), err)
	}
	if domain != wantDomain {
		return fmt.Errorf("account %s verifies %q leaves, not %q: it is not a %s, the account generation chain %d is on "+
			"(%s)", p.Account.Hex(), domain, wantDomain, version.AccountContract(), p.ChainID, version)
	}
	keyless, err := acct.IsKeylessOwner(&bind.CallOpts{Context: ctx})
	if err != nil {
		if !isCallVerdict(err) {
			return readErr(fmt.Errorf("reading isKeylessOwner on %s: %w", p.Account.Hex(), err))
		}
		return fmt.Errorf("account %s is not a %s: %w", p.Account.Hex(), version.AccountContract(), err)
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
	// The account says what the certified (key book, page) may do (RB5-F30): its governing book's pages carry the
	// default levels, another book's pages carry none until its governance grants them. A pair it gives no authority
	// can execute nothing, so the member is refused by name before any anchor is paid for.
	level, err := acct.AuthorityLevelOfPage(&bind.CallOpts{Context: ctx}, book, page)
	if err != nil {
		if !isCallVerdict(err) {
			return readErr(fmt.Errorf("reading authorityLevelOfPage on %s: %w", p.Account.Hex(), err))
		}
		return fmt.Errorf("reading authorityLevelOfPage on %s: %w", p.Account.Hex(), err)
	}
	if level == 0 {
		return fmt.Errorf("account %s gives key page %s (of book %s) no authority: it is not a page of the account's "+
			"governing book and the account's governance granted it none", p.Account.Hex(), p.CertifiedKeyPage, p.CertifiedKeyBook)
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
	return time.Since(origin) > p.settlementHorizon()
}

// maxGasDeferral is how long a member may be deferred on gas before it is failed outright.
//
// Long enough to ride out an ordinary fee spike, short enough that an ADI learns the outcome the
// same hour it submitted.
const maxGasDeferral = time.Hour
