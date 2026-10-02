// Copyright 2026 Certen Protocol

package consensus

import (
	"errors"
	"fmt"
)

// =============================================================================
// Batch settlement: queued, or refused by name
// =============================================================================
//
// The batch path is the only way CERTEN settles an intent on its supported chains. An intent it
// cannot settle used to fall through to a per-intent path that fabricated its governance proof
// and fell back to retired contracts; owner decision 2026-09-26 replaced that with a refusal that
// says why. There are exactly three outcomes, and consensus must tell them apart:
//
//   - queued, including the same intent arriving again after it was queued (a workflow re-run is
//     not a refusal, and must never become a second execution);
//   - refused for good: the intent's own bytes cannot be settled, or it replays an operation
//     another intent already queued - its bytes are final on Accumulate, so no later pass helps;
//   - retried: CERTEN cannot settle on the chain right now (no anchor configured, no commit height
//     resolved). That is never the intent's defect, so it is never a permanent refusal.

// Admission outcomes. Defined here, beside BatchEnqueuer, because pkg/execution implements the
// interface and imports this package; it returns these errors wrapped.
var (
	// ErrMemberAlreadyQueued is the SAME intent arriving again for a chain it is already queued on.
	ErrMemberAlreadyQueued = errors.New("member already queued")

	// ErrOperationAlreadyQueued is a DIFFERENT intent carrying an operation already queued on the
	// chain: a replay.
	ErrOperationAlreadyQueued = errors.New("operation already queued by another intent")

	// ErrBatchUnavailable is CERTEN being unable to settle the member right now.
	ErrBatchUnavailable = errors.New("batch settlement unavailable")

	// ErrMemberAlreadyDecided is the SAME intent arriving again for a chain on which its member already
	// has a recorded outcome - settled, reverted, unobserved or never sent. Not a refusal: the member is
	// finished, and queueing it again could only execute it a second time (RB3-F34, RB3-F141).
	ErrMemberAlreadyDecided = errors.New("member already has an outcome")

	// ErrNoGovernanceCommitment is a member without a governance decision to commit to: the batch operation id
	// commits to every member's (RB4-F66). CERTEN not having established it is an outage, never the intent's
	// defect, so it is an ErrBatchUnavailable and the intent is retried.
	ErrNoGovernanceCommitment = fmt.Errorf("%w: no governance decision to commit to", ErrBatchUnavailable)

	// ErrNoAccumulateSetRoot is a member whose round's proof carries no committable Accumulate validator set (its L4
	// Directory leg): the V8.2 anchor commits the set each member was verified against (RB5 design D2). CERTEN's own
	// proof lacking it is an outage, never the intent's defect, so it is an ErrBatchUnavailable and retried.
	ErrNoAccumulateSetRoot = fmt.Errorf("%w: no committable Accumulate validator set", ErrBatchUnavailable)
)

// BatchRefusal is the batch path declining an intent. Permanent refusals are the intent's own
// defect and are recorded as permanently invalid; the rest are retried.
type BatchRefusal struct {
	Permanent bool
	Err       error
}

func (r *BatchRefusal) Error() string {
	if r.Permanent {
		return "refused by the batch path: " + r.Err.Error()
	}
	return "batch settlement unavailable, will retry: " + r.Err.Error()
}

func (r *BatchRefusal) Unwrap() error { return r.Err }

// refuse classifies an admission error. Only ErrBatchUnavailable is retryable.
func refuse(err error) *BatchRefusal {
	return &BatchRefusal{Permanent: !errors.Is(err, ErrBatchUnavailable), Err: err}
}

// batchMember is one chain's share of an intent, ready to queue.
type batchMember struct {
	legs    []BatchLeg
	chainID int64
	account [20]byte
	opID    [32]byte
	// after is set for a later member of a sequential intent: it waits on the member before it, and
	// is queued in the intent-keyed lane (onDemand) whatever the intent's lane.
	after    *SequencePredecessor
	onDemand bool
}

// batchPlan is how an intent will be queued: its members, the ADI their leaves bind, and the lane.
type batchPlan struct {
	adiURL   string
	onDemand bool
	members  []batchMember
}

// planBatch works out how the intent would be queued and checks every member against the
// enqueuer's own admission rules, without queueing anything. The same plan is used before the
// validator signs (checkBatchable) and at enqueue time, so the two cannot disagree.
func (bv *BFTValidator) planBatch(ci *CertenIntent, commitHeight uint64) (*batchPlan, error) {
	if bv.batchEnqueuer == nil {
		return nil, refuse(fmt.Errorf("%w: this validator has no batch settlement configured", ErrBatchUnavailable))
	}
	if ci == nil {
		return nil, refuse(errors.New("no intent"))
	}

	// One member PER CHAIN: each chain settles its own legs, under its own anchor, from its own
	// account, and the leaf binds chainid so two members of one intent cannot collide.
	chains, err := bv.batchChainsOfIntent(ci)
	if err != nil {
		return nil, refuse(fmt.Errorf("intent %s: %w", ci.IntentID, err))
	}
	if len(chains) == 0 {
		return nil, refuse(fmt.Errorf("intent %s has no legs", ci.IntentID))
	}

	// Executed as it declares, or refused with the declaration (declared_semantics.go).
	if err := CheckDeclaredSemantics(ci, ci.BlockTime); err != nil {
		return nil, refuse(fmt.Errorf("intent %s: %w", ci.IntentID, err))
	}

	// Settled on the anchor each leg declares, or refused naming both (declared_anchor.go, RB4-F9).
	if err := CheckDeclaredAnchors(ci, bv.batchEnqueuer.AnchorOf); err != nil {
		return nil, refuse(fmt.Errorf("intent %s: %w", ci.IntentID, err))
	}

	// The ADI URL is keccak'd into the member's Merkle leaf, and the account contract recomputes
	// that leaf from its OWN immutable adiURL; see memberADIURL.
	adiURL, err := memberADIURL(ci)
	if err != nil {
		return nil, refuse(fmt.Errorf("intent %s: %w", ci.IntentID, err))
	}

	// LANE ROUTING. proofClass decides WHICH MECHANISM settles the member - never WHETHER it is
	// queued. An unrecognised proofClass is refused: a member in the wrong lane on one node derives
	// a bundleId its peers never will.
	proofClass, err := ci.GetProofClass()
	if err != nil {
		return nil, refuse(fmt.Errorf("intent %s has no usable proof class: %w", ci.IntentID, err))
	}
	lane, err := onDemandLaneEnabled()
	if err != nil {
		// The deployment's configuration, not the intent: retried, never held against it.
		return nil, refuse(fmt.Errorf("%w: %v", ErrBatchUnavailable, err))
	}
	plan := &batchPlan{adiURL: adiURL, onDemand: proofClass == "on_demand" && lane}

	// A sequential cross-chain intent's members are queued in its declared order, each after the one
	// before it (declared_semantics.go; pkg/execution batch_sequence.go).
	order, err := DeclaredCrossChainOrder(ci)
	if err != nil {
		return nil, refuse(fmt.Errorf("intent %s: %w", ci.IntentID, err))
	}
	if order != nil {
		if len(order.Chains) != len(chains) {
			return nil, refuse(fmt.Errorf("intent %s: its declared order names %d chains, its members %d", ci.IntentID, len(order.Chains), len(chains)))
		}
		chains = append([]int64(nil), order.Chains...)
	}

	for i, ch := range chains {
		legs, chainID, account, opID, err := bv.batchInputsFromIntentForChain(ci, ch)
		if err != nil {
			return nil, refuse(fmt.Errorf("intent %s cannot be represented on chain %d: %w", ci.IntentID, ch, err))
		}
		m := batchMember{legs: legs, chainID: chainID, account: account, opID: opID, onDemand: plan.onDemand}
		if order != nil && i > 0 {
			prev := plan.members[i-1]
			m.after = &SequencePredecessor{ChainID: prev.chainID, OperationID: prev.opID, Position: i,
				ContinueOnFailure: order.ContinueOnFailure}
			m.onDemand = true
		}
		if err := bv.batchEnqueuer.CheckMember(m.onDemand, ci.IntentID, adiURL, chainID, account, opID, legs, commitHeight); err != nil {
			return nil, refuse(fmt.Errorf("intent %s on chain %d: %w", ci.IntentID, chainID, err))
		}
		plan.members = append(plan.members, m)
	}

	// Every member needs a deadline its failure can be final against (RB3-F49), and its commit time -
	// the intent's consensus block time - is what bounds it. Checked after every defect of the intent's
	// own, which is refused for good whatever its time; a time not yet read is CERTEN's condition, and
	// the intent is retried.
	if ci.BlockTime.IsZero() {
		return nil, refuse(fmt.Errorf("%w: intent %s's consensus block time is not known yet", ErrBatchUnavailable, ci.IntentID))
	}
	return plan, nil
}

// checkBatchable refuses, before anything is signed, an intent the batch path will not settle.
func (bv *BFTValidator) checkBatchable(ci *CertenIntent, commitHeight uint64) error {
	_, err := bv.planBatch(ci, commitHeight)
	return err
}

// refusalResult turns a batch refusal into the workflow's result: permanent refusals are marked
// permanently invalid so discovery records them once and stops; the rest are retried.
func (bv *BFTValidator) refusalResult(ci *CertenIntent, err error) *ExecutionTaskResult {
	intentID := ""
	if ci != nil {
		intentID = ci.IntentID
	}
	var r *BatchRefusal
	if errors.As(err, &r) && r.Permanent {
		bv.logger.Printf("🚫 [BATCH-REFUSED] intent %s: %v", intentID, err)
		return &ExecutionTaskResult{
			Success:    false,
			ExecutorID: bv.validatorID,
			Error:      fmt.Errorf("intent %s refused: %w: %w", intentID, ErrIntentPermanentlyInvalid, err),
		}
	}
	bv.logger.Printf("⏳ [BATCH-UNAVAILABLE] intent %s: %v", intentID, err)
	return &ExecutionTaskResult{
		Success:    false,
		ExecutorID: bv.validatorID,
		Error:      fmt.Errorf("intent %s not settled yet: %w", intentID, err),
	}
}
