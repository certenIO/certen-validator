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
// idempotent path (anchorAlreadyAttested → leaf consumed) resolves it correctly on retry.

// OnDemandOutcome is what happened to a single intent-keyed member.
type OnDemandOutcome struct {
	// Settled is true only if the member's own transaction succeeded on chain.
	Settled bool
	// TxHash is the member's settlement transaction. Present even on a REVERT — a reverted
	// transaction is on chain and independently verifiable, and it is the evidence Phase 7
	// needs to record the failure rather than reporting nothing happened.
	TxHash string
	// BundleID and Root identify the anchor this member settled (or tried to) under.
	BundleID [32]byte
	Root     [32]byte
	// GasAnchor is what createBatchAnchor cost. Unamortised, by design: on-demand pays a whole
	// anchor for one intent, which is the trade being made for latency.
	GasAnchor uint64
	// Deferred is true when settlement was refused on the gas ceiling. The leaf is UNTOUCHED —
	// nothing was submitted — so the member must be retried later, never failed.
	Deferred bool
	// AlreadySettled is true when the anchor was already attested by a previous leader. Settled
	// then reflects the on-chain leaf state, not this node's work.
	AlreadySettled bool
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
	if o == nil || o.mempool == nil || o.ecm == nil {
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
	chainID := member.ChainID
	out := &OnDemandOutcome{}

	// ---- Screen the account BEFORE forming anything -------------------------
	// Same predicate the period path uses, and deterministic across validators because it reads
	// on-chain state every node sees identically.
	if err := o.memberAccountUsable(ctx, member); err != nil {
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

	// ---- ALREADY SETTLED ELSEWHERE? ----------------------------------------
	// Leadership fails over, so two nodes can legitimately reach the same member. The bundleId
	// is deterministic, so an existing AND attested anchor means someone already did this.
	//
	// Continuing would re-submit executeComprehensiveProof, which reverts on replay protection,
	// and the member would then be routed to fallback — re-executing an intent that already
	// moved funds. A double-spend produced by a retry is far worse than a skipped settle.
	if settled, serr := o.anchorAlreadyAttested(ctx, tree.BundleID); serr != nil {
		return nil, fmt.Errorf("checking whether anchor 0x%x already settled: %w", tree.BundleID[:8], serr)
	} else if settled {
		out.AlreadySettled = true
		// "Anchor attested" does NOT imply "member executed" — a previous leader can anchor and
		// attest, then die before settling. Observed live on the period path 2026-08-03. The
		// consumed leaf is the on-chain ground truth, so ask the account rather than assume.
		consumed, cerr := o.memberLeafConsumed(ctx, member)
		if cerr != nil {
			return nil, fmt.Errorf("anchor 0x%x already attested but the member's outcome is "+
				"unresolved: %w", tree.BundleID[:8], cerr)
		}
		out.Settled = consumed
		o.logf("[OD] chain=%d intent=%s anchor 0x%x already attested by another leader; leaf "+
			"consumed=%t", chainID, member.IntentID, tree.BundleID[:8], consumed)
		return out, nil
	}

	// ---- VERIFY: the deployed account computes the same leaf we did ---------
	if err := o.verifyLeavesAgainstAccounts(ctx, []*PendingBatchIntent{member}, tree); err != nil {
		return nil, err
	}

	// ---- Pin the nonce for the whole sequence -------------------------------
	if err := o.ecm.beginNonceSequence(ctx); err != nil {
		return nil, err
	}
	defer o.ecm.endNonceSequence()

	// ---- Create the anchor --------------------------------------------------
	anchorTx, gasUsed, err := o.createBatchAnchor(ctx, tree)
	if err != nil {
		return nil, fmt.Errorf("createBatchAnchor: %w", err)
	}
	out.GasAnchor = gasUsed
	o.logf("[OD] chain=%d intent=%s anchor created tx=%s gas=%d",
		chainID, member.IntentID, anchorTx, gasUsed)

	// ---- VERIFY: the deployed anchor accepts the leaf -----------------------
	if err := o.verifyLeavesAgainstAnchor(ctx, tree); err != nil {
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
	o.logf("[OD] chain=%d intent=%s quorum verified root 0x%x",
		chainID, member.IntentID, tree.Root[:8])

	// ---- Settle -------------------------------------------------------------
	// N=1: the branch is empty and the root is the leaf.
	branch, berr := tree.BranchFor(0)
	if berr != nil {
		return nil, fmt.Errorf("branch error: %w", berr)
	}
	txHash, serr := o.settleMember(ctx, member, tree, branch)
	out.TxHash = txHash
	if serr != nil {
		// A gas-ceiling refusal is "too expensive right now", NOT "this can never work". Nothing
		// was submitted, so the leaf is untouched and the member can settle later.
		var gasCeil *ErrGasCeilingExceeded
		if errors.As(serr, &gasCeil) {
			if o.memberPastDeadline(member) {
				o.logf("[OD] intent=%s gas ceiling %v but the intent has expired — failing",
					member.IntentID, serr)
				return out, serr
			}
			out.Deferred = true
			o.logf("[OD] intent=%s deferred: %v (leaf untouched; will retry)", member.IntentID, serr)
			return out, nil
		}
		o.logf("[OD] chain=%d intent=%s FAILED: %v (tx=%s)", chainID, member.IntentID, serr, txHash)
		return out, serr
	}

	out.Settled = true
	o.logf("[OD] chain=%d intent=%s settled tx=%s (anchor gas %d, unamortised by design)",
		chainID, member.IntentID, txHash, gasUsed)

	// Attribute cost. A solo intent is a one-member batch, so the anchor is "shared" across
	// exactly one member and it bears the whole cost — the same code path a 3-member batch
	// takes, which is what keeps the two from drifting apart.
	// verifyTx comes from the prover that just ran; empty when it did not reach a mined
	// transaction, in which case the verify leg is simply not reported rather than guessed.
	// on_demand by construction: this path is intent-keyed and never carries a second member,
	// so the whole anchor is this intent's own cost. That is the dearer product and must be
	// priced as such, not blended with batched observations.
	o.reportBatchCosts(ctx, chainID, anchorTx, o.lastVerifyTx(),
		[]costMember{costMemberFor(member, txHash)}, string(LaneOnDemand))

	// One transaction settles every leg this member carries — measured on 2026-08-07, a 5-leg
	// on_demand intent produced exactly one settlement transaction. So a settled member has
	// completed all of its legs, not one.
	o.recordLegProgress(ctx, []*PendingBatchIntent{member}, nil)
	return out, nil
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
