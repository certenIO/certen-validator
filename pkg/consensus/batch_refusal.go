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
	plan := &batchPlan{adiURL: adiURL, onDemand: proofClass == "on_demand" && onDemandLaneEnabled()}

	for _, ch := range chains {
		legs, chainID, account, opID, err := bv.batchInputsFromIntentForChain(ci, ch)
		if err != nil {
			return nil, refuse(fmt.Errorf("intent %s cannot be represented on chain %d: %w", ci.IntentID, ch, err))
		}
		if err := bv.batchEnqueuer.CheckMember(plan.onDemand, ci.IntentID, adiURL, chainID, account, opID, legs, commitHeight); err != nil {
			return nil, refuse(fmt.Errorf("intent %s on chain %d: %w", ci.IntentID, chainID, err))
		}
		plan.members = append(plan.members, batchMember{legs: legs, chainID: chainID, account: account, opID: opID})
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
