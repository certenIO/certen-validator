package execution

import (
	"context"
	"errors"
	"fmt"
)

// =============================================================================
// On-demand settlement — one member, one anchor
// =============================================================================
//
// This does NOT reimplement FlushChain. It calls the same verification primitives in the same
// order — memberAccountUsable, anchorAlreadyAttested, verifyLeavesAgainstAccounts,
// createBatchAnchor, verifyLeavesAgainstAnchor, settleMember — so the security-critical checks
// have exactly one implementation and cannot drift between the lanes.
//
// What it drops is FlushChain's MEMBER LIFECYCLE, which is the genuinely complicated part and
// is entirely about sets: requeue-some-drop-others, per-period attempt counters, partial
// outcomes across a tree. With one member there is one outcome, so the caller simply learns
// which it was.
//
// The member is NOT removed from the on-demand index here. The caller removes it once it knows
// the outcome, so a crash between settling and recording leaves the member queued — where the
// member's own record of what this validator did (AnchorProved, SettlementTx) resolves it from
// the chain on the next pass.
//
// # WHO RECORDS AN OUTCOME
//
// Every validator holds every on-demand member, and the settlement failover hands it to each in
// turn, so every validator eventually reaches every member. Exactly one of them may attest its
// outcome: the one that sent the settlement transaction. Any other validator that reaches the
// member after its anchor was attested only reads the chain and releases its own copy. It must not
// attest - it has no transaction, so its "success" or "failure" reached Phase 7 empty-handed and
// was recorded as a failure (live, intent 5a2ebba0, 2026-09-20) - and it must not settle again,
// which could execute an intent whose failure is already on record.

// OnDemandOutcome is what happened to a single intent-keyed member.
type OnDemandOutcome struct {
	// Settled is true only if THIS validator's settlement transaction succeeded on chain.
	Settled bool
	// Reverted is true when THIS validator's settlement transaction was mined and REVERTED with the
	// member's leaf still unspent. TxHash is then that transaction: the evidence of the failure,
	// which Phase 7 proves and writes back and cost attribution reports to the gateway.
	Reverted bool
	// TxHash is this validator's settlement transaction, on success and on a revert.
	TxHash string
	// BundleID and Root identify the anchor this member settled (or tried to) under.
	BundleID [32]byte
	Root     [32]byte
	// GasAnchor is what createBatchAnchor cost. Unamortised, by design: on-demand pays a whole
	// anchor for one intent, which is the trade being made for latency.
	GasAnchor uint64
	// Deferred is true when nothing terminal is known yet and the member must stay queued: a gas
	// ceiling refusal (nothing was submitted, the leaf is untouched), or this validator's own
	// settlement whose outcome cannot be read yet.
	Deferred bool
	// AlreadySettled is true when the anchor was already attested when this attempt began.
	AlreadySettled bool
	// Released is true when the outcome belongs to ANOTHER validator: it attested the anchor, or
	// its settlement consumed the leaf first. That validator records the outcome; this one drops
	// its copy of the member without attesting anything and without executing it.
	Released bool
}

// onDemandChain is every chain operation on-demand settlement performs.
//
// *BatchOrchestrator implements it against the real chain. It exists as a seam so the settlement
// DECISIONS — which outcome a given chain state leads to — can be tested without a chain, which
// matters most for the branches that only occur when something else went wrong.
type onDemandChain interface {
	memberAccountUsable(ctx context.Context, p *PendingBatchIntent) error
	anchorAlreadyAttested(ctx context.Context, bundleID [32]byte) (bool, error)
	memberLeafConsumed(ctx context.Context, p *PendingBatchIntent) (bool, error)
	verifyLeavesAgainstAccounts(ctx context.Context, members []*PendingBatchIntent, tree *BatchTree) error
	beginSettlementSequence(ctx context.Context) error
	endSettlementSequence()
	createBatchAnchor(ctx context.Context, tree *BatchTree) (txHash string, gasUsed uint64, block uint64, err error)
	verifyLeavesAgainstAnchor(ctx context.Context, tree *BatchTree) error
	settleMember(ctx context.Context, p *PendingBatchIntent, tree *BatchTree, branch [][32]byte) (string, error)
	settlementStatus(ctx context.Context, txHash string) (found, mined, reverted bool, err error)
	memberPastDeadline(p *PendingBatchIntent) bool
	lastVerifyTx() string
	reportOnDemandCosts(ctx context.Context, member *PendingBatchIntent, settleTx string)
	recordLegProgress(ctx context.Context, settled, failed []*PendingBatchIntent)
}

func (o *BatchOrchestrator) chainOps() onDemandChain {
	if o.odChain != nil {
		return o.odChain
	}
	return o
}

func (o *BatchOrchestrator) beginSettlementSequence(ctx context.Context) error {
	return o.ecm.beginNonceSequence(ctx)
}

func (o *BatchOrchestrator) endSettlementSequence() { o.ecm.endNonceSequence() }

// reportOnDemandCosts attributes one on-demand member's spend at its outcome, success or revert.
//
// The anchor and verify legs are the ones THIS validator paid for (recorded on the member when it
// did); an anchor another validator created is that validator's spend. The settlement is reported
// whether it succeeded or reverted: the cost event carries the receipt status, and a reverted
// vault_execute is the gateway's signal that the payment failed on chain. Without it the gateway
// never learned of the failure and left the intent at "anchoring".
func (o *BatchOrchestrator) reportOnDemandCosts(ctx context.Context, member *PendingBatchIntent, settleTx string) {
	anchorTx := member.AnchorTx
	if !IsTransactionHash(anchorTx) {
		anchorTx = ""
	}
	verifyTx := member.VerifyTx
	if !IsTransactionHash(verifyTx) {
		verifyTx = ""
	}
	// on_demand by construction: this path is intent-keyed and never carries a second member,
	// so the whole anchor is this intent's own cost. That is the dearer product and must be
	// priced as such, not blended with batched observations.
	o.reportBatchCosts(ctx, member.ChainID, anchorTx, verifyTx,
		[]costMember{costMemberFor(member, settleTx)}, string(LaneOnDemand))
}

// SettleOnDemandMember anchors and settles exactly one member.
//
// prove is injected rather than called directly so the caller controls the readiness-retry
// policy: this function performs ONE attempt and reports what happened, and the submitter above
// decides whether a shortfall is worth waiting on.
func (o *BatchOrchestrator) SettleOnDemandMember(
	ctx context.Context,
	member *PendingBatchIntent,
	prove func(context.Context, *BatchTree) error,
) (*OnDemandOutcome, error) {
	if o == nil || (o.odChain == nil && (o.mempool == nil || o.ecm == nil)) {
		return nil, fmt.Errorf("batch orchestrator is not properly constructed (use NewBatchOrchestrator)")
	}
	if member == nil {
		return nil, fmt.Errorf("nil member")
	}
	if member.CommitHeight == 0 {
		// The height is bound into the bundleId. Zero would make every validator that had a
		// different local view derive a different id, exactly as on the period path.
		return nil, fmt.Errorf("intent %s has no commit height; its bundleId is not derivable",
			member.IntentID)
	}
	chain := o.chainOps()
	chainID := member.ChainID
	out := &OnDemandOutcome{}

	// ---- Screen the account BEFORE forming anything -------------------------
	// Same predicate the period path uses, and deterministic across validators because it reads
	// on-chain state every node sees identically.
	if err := chain.memberAccountUsable(ctx, member); err != nil {
		return nil, fmt.Errorf("member %s account unusable: %w", member.IntentID, err)
	}

	// ---- Form the one-leaf tree at the member's OWN height -------------------
	in, err := member.LeafInput()
	if err != nil {
		return nil, fmt.Errorf("building leaf for %s: %w", member.IntentID, err)
	}
	tree, err := BuildBatchTree(chainID, []BatchLeafInput{in}, member.CommitHeight)
	if err != nil {
		return nil, fmt.Errorf("building one-member batch tree: %w", err)
	}
	out.BundleID = tree.BundleID
	out.Root = tree.Root

	o.logf("[OD] chain=%d intent=%s forming one-member batch: root=0x%x bundleId=0x%x height=%d",
		chainID, member.IntentID, tree.Root[:8], tree.BundleID[:8], member.CommitHeight)

	// ---- ALREADY ATTESTED? ---------------------------------------------------
	// The bundleId is deterministic, so an existing AND attested anchor means a validator already
	// did the anchoring. Whose work it was decides everything that follows; see
	// resolveUnderAttestedAnchor.
	attested, aerr := chain.anchorAlreadyAttested(ctx, tree.BundleID)
	if aerr != nil {
		return nil, fmt.Errorf("checking whether anchor 0x%x already settled: %w", tree.BundleID[:8], aerr)
	}
	if attested {
		out.AlreadySettled = true
		if done := o.resolveUnderAttestedAnchor(ctx, chain, member, tree, out); done {
			return out, nil
		}
		// This validator attested the anchor itself and never sent a settlement: it stopped (a
		// restart) between the two. It is the settler; settle under its own anchor.
		o.logf("[OD] chain=%d intent=%s anchor 0x%x was attested by this validator, which never "+
			"settled it — settling now", chainID, member.IntentID, tree.BundleID[:8])
		if err := chain.beginSettlementSequence(ctx); err != nil {
			return nil, err
		}
		defer chain.endSettlementSequence()
		return o.settleAndClassify(ctx, chain, member, tree, out)
	}

	// ---- VERIFY: the deployed account computes the same leaf we did ---------
	if err := chain.verifyLeavesAgainstAccounts(ctx, []*PendingBatchIntent{member}, tree); err != nil {
		return nil, err
	}

	// ---- Pin the nonce for the whole sequence -------------------------------
	if err := chain.beginSettlementSequence(ctx); err != nil {
		return nil, err
	}
	defer chain.endSettlementSequence()

	// ---- Create the anchor --------------------------------------------------
	anchorTx, gasUsed, anchorBlock, err := chain.createBatchAnchor(ctx, tree)
	if err != nil {
		return nil, fmt.Errorf("createBatchAnchor: %w", err)
	}
	out.GasAnchor = gasUsed
	// The transaction that published this root. Carried on the tree so the quorum evidence — and through
	// it layer 5 — can say which transaction contains the root, instead of borrowing the settlement's.
	// Only a real transaction hash. createBatchAnchor returns "already-exists" when another
	// validator created the anchor first; this node then does not know the creating transaction, and
	// empty is how that is said. See IsTransactionHash.
	if IsTransactionHash(anchorTx) {
		tree.AnchorCreateTx, tree.AnchorCreateBlock = anchorTx, anchorBlock
	}
	o.logf("[OD] chain=%d intent=%s anchor created tx=%s gas=%d",
		chainID, member.IntentID, anchorTx, gasUsed)

	// ---- VERIFY: the deployed anchor accepts the leaf -----------------------
	if err := chain.verifyLeavesAgainstAnchor(ctx, tree); err != nil {
		return nil, fmt.Errorf("anchor created but membership verification failed: %w", err)
	}

	// ---- Quorum attestation over the root -----------------------------------
	if prove == nil {
		return nil, fmt.Errorf("no quorum prover configured; anchor 0x%x is created but not "+
			"verified and no account will accept it", tree.BundleID[:8])
	}
	if err := prove(ctx, tree); err != nil {
		// Surface as-is, including *QuorumNotReadyError, so the caller can decide whether to
		// wait. The anchor is already paid for and createBatchAnchor treats an existing anchor
		// for this bundleId as success, so a retry re-attests it rather than duplicating work.
		return nil, err
	}
	// Recorded before the settlement is sent, and persisted: from here on this validator is the
	// member's settler, and a restart must not make it mistake its own anchor for another's.
	verifyTx := chain.lastVerifyTx()
	o.noteOnDemandProgress(member, func(p *PendingBatchIntent) {
		p.AnchorProved = true
		if IsTransactionHash(anchorTx) {
			p.AnchorTx = anchorTx
		}
		if IsTransactionHash(verifyTx) {
			p.VerifyTx = verifyTx
		}
	})
	o.logf("[OD] chain=%d intent=%s quorum verified root 0x%x",
		chainID, member.IntentID, tree.Root[:8])

	return o.settleAndClassify(ctx, chain, member, tree, out)
}

// resolveUnderAttestedAnchor decides a member whose anchor is already attested, from this
// validator's own record and the chain. It returns false only when this validator attested the
// anchor itself and never sent a settlement, so it must settle now.
//
//	sent a settlement, it succeeded            -> Settled with that transaction (this node attests it)
//	sent a settlement, it reverted, leaf spent -> Released (another validator's settlement won)
//	sent a settlement, it reverted, leaf live  -> Reverted with that transaction (this node attests the failure)
//	sent a settlement, outcome not readable    -> Deferred
//	sent nothing, leaf spent                   -> Released (another validator settled it)
//	sent nothing, did not attest the anchor    -> Released (the validator that attested it settles it)
//	sent nothing, attested the anchor itself   -> false: settle
//	leaf state not readable                    -> Deferred
func (o *BatchOrchestrator) resolveUnderAttestedAnchor(
	ctx context.Context,
	chain onDemandChain,
	member *PendingBatchIntent,
	tree *BatchTree,
	out *OnDemandOutcome,
) bool {
	consumed, cerr := chain.memberLeafConsumed(ctx, member)
	if cerr != nil {
		// A failed read says nothing about the member. Keep it and read again next pass.
		out.Deferred = true
		o.logf("[OD] intent=%s anchor 0x%x attested; leaf state unreadable (%v) — deferring",
			member.IntentID, tree.BundleID[:8], cerr)
		return true
	}

	if own := member.SettlementTx; own != "" {
		found, mined, reverted, serr := chain.settlementStatus(ctx, own)
		switch {
		case serr != nil || !found || !mined:
			// Not readable yet, still pending, or not known to this RPC endpoint. None of these is
			// an outcome; the next pass reads it again.
			out.Deferred = true
			o.logf("[OD] intent=%s this validator's settlement %s has no readable outcome yet "+
				"(found=%t mined=%t err=%v) — deferring", member.IntentID, own, found, mined, serr)
		case !reverted:
			out.Settled = true
			out.TxHash = own
			o.logf("[OD] intent=%s this validator's settlement %s succeeded", member.IntentID, own)
			chain.reportOnDemandCosts(ctx, member, own)
			chain.recordLegProgress(ctx, []*PendingBatchIntent{member}, nil)
		case consumed:
			out.Released = true
			o.logf("[OD] intent=%s this validator's settlement %s reverted but the leaf is spent — "+
				"another validator's settlement executed it; releasing", member.IntentID, own)
		default:
			o.markReverted(ctx, chain, member, own, out)
		}
		return true
	}

	if consumed {
		out.Released = true
		o.logf("[OD] intent=%s anchor 0x%x attested and leaf spent by another validator's "+
			"settlement; releasing — that validator records it", member.IntentID, tree.BundleID[:8])
		return true
	}
	if !member.AnchorProved {
		out.Released = true
		o.logf("[OD] intent=%s anchor 0x%x attested by another validator, leaf unspent; releasing "+
			"— that validator settles it and records the outcome", member.IntentID, tree.BundleID[:8])
		return true
	}
	return false
}

// settleAndClassify sends the member's settlement under an attested anchor and classifies what
// happened.
func (o *BatchOrchestrator) settleAndClassify(
	ctx context.Context,
	chain onDemandChain,
	member *PendingBatchIntent,
	tree *BatchTree,
	out *OnDemandOutcome,
) (*OnDemandOutcome, error) {
	chainID := member.ChainID

	// N=1: the branch is empty and the root is the leaf.
	branch, berr := tree.BranchFor(0)
	if berr != nil {
		return nil, fmt.Errorf("branch error: %w", berr)
	}
	txHash, serr := chain.settleMember(ctx, member, tree, branch)
	if serr == nil {
		out.Settled = true
		out.TxHash = txHash
		o.logf("[OD] chain=%d intent=%s settled tx=%s (anchor gas %d, unamortised by design)",
			chainID, member.IntentID, txHash, out.GasAnchor)
		// Attribute cost. A solo intent is a one-member batch, so the anchor is "shared" across
		// exactly one member and it bears the whole cost — the same code path a 3-member batch
		// takes, which is what keeps the two from drifting apart.
		chain.reportOnDemandCosts(ctx, member, txHash)
		// One transaction settles every leg this member carries — measured on 2026-08-07, a 5-leg
		// on_demand intent produced exactly one settlement transaction. So a settled member has
		// completed all of its legs, not one.
		chain.recordLegProgress(ctx, []*PendingBatchIntent{member}, nil)
		return out, nil
	}

	// A gas-ceiling refusal is "too expensive right now", NOT "this can never work". Nothing
	// was submitted, so the leaf is untouched and the member can settle later.
	var gasCeil *ErrGasCeilingExceeded
	if errors.As(serr, &gasCeil) {
		if chain.memberPastDeadline(member) {
			o.logf("[OD] intent=%s gas ceiling %v but the intent has expired — failing",
				member.IntentID, serr)
			return out, serr
		}
		out.Deferred = true
		o.logf("[OD] intent=%s deferred: %v (leaf untouched; will retry)", member.IntentID, serr)
		return out, nil
	}

	// Sent, outcome not observed. Not a revert and not a failure: the transaction may still land.
	// The member keeps this validator's record of the send, and the next pass reads the outcome.
	var unknown *SettlementOutcomeUnknownError
	if errors.As(serr, &unknown) {
		out.Deferred = true
		o.logf("[OD] intent=%s settlement %s sent, outcome not observed (%v) — deferring",
			member.IntentID, txHash, unknown.Err)
		return out, nil
	}

	if errors.Is(serr, errSettlementReverted) {
		// A revert with the leaf SPENT is a lost race: another validator's settlement consumed the
		// leaf first and this one reverted on replay protection. The intent executed; it is not
		// this validator's to record, and reporting this revert would tell the gateway it failed.
		consumed, cerr := chain.memberLeafConsumed(ctx, member)
		if cerr != nil {
			out.Deferred = true
			o.logf("[OD] intent=%s settlement %s reverted; leaf state unreadable (%v) — deferring",
				member.IntentID, txHash, cerr)
			return out, nil
		}
		if consumed {
			out.Released = true
			o.logf("[OD] intent=%s settlement %s reverted because another validator's settlement "+
				"consumed the leaf first; releasing", member.IntentID, txHash)
			return out, nil
		}
		o.markReverted(ctx, chain, member, txHash, out)
		return out, nil
	}

	out.TxHash = txHash
	o.logf("[OD] chain=%d intent=%s FAILED: %v (tx=%s)", chainID, member.IntentID, serr, txHash)
	return out, serr
}

// markReverted records this validator's reverted settlement as the member's outcome: the gateway is
// told through the reverted vault_execute cost event, and the caller attests the failure with the
// transaction as its evidence.
func (o *BatchOrchestrator) markReverted(
	ctx context.Context,
	chain onDemandChain,
	member *PendingBatchIntent,
	txHash string,
	out *OnDemandOutcome,
) {
	out.Reverted = true
	out.TxHash = txHash
	o.logf("[OD] ❌ chain=%d intent=%s settlement %s REVERTED with the leaf unspent — the member "+
		"failed against this transaction", member.ChainID, member.IntentID, txHash)
	chain.reportOnDemandCosts(ctx, member, txHash)
	chain.recordLegProgress(ctx, nil, []*PendingBatchIntent{member})
}

// costMemberFor extracts the identifiers cost attribution needs from a settled member.
//
// The Accumulate transaction hash comes from the captured attestation and is the ONLY identifier
// the gateway and the validator both hold: IntentID is the validator's own, and the gateway keys
// intents by a different UUID entirely. Without it the gateway stores a cost it can never join
// to an intent, so measured gas never reaches settlement.
//
// The ADI URL comes from the member itself, which is authoritative — it is the same string
// hashed into the member's Merkle leaf and recomputed on chain by CertenAccountV7. It is NOT an
// org id: the validator cannot know the gateway's org UUID, and the one time this path supplied
// something org-shaped (the intent's created_by) every cost event 500'd on the uuid cast.
func costMemberFor(p *PendingBatchIntent, settleTx string) costMember {
	cm := costMember{
		IntentID: p.IntentID,
		ADIURL:   p.ADIURL,
		SettleTx: settleTx,
	}
	if att, ok := p.Attestation.(interface {
		CostAttribution() (accumTxHash string, orgID string)
	}); ok {
		cm.AccumTxHash, _ = att.CostAttribution()
	}
	return cm
}
