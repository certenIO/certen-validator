// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"fmt"
	"strconv"

	"github.com/ethereum/go-ethereum/common"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/consensus"
)

// =============================================================================
// A member's settlement, bound to the member (RB3-F77)
// =============================================================================
//
// What a quorum attests for a member is one transaction on the member's chain. The gate used to accept
// any included transaction that emitted the committed events - it never asked whether the transaction
// was this member's settlement - and for a native value transfer it accepted any account execution
// whose inner calls carried no calldata. The revert and effects-shortfall verifiers already bound the
// transaction to the member; the success path, the one that says "it happened", did not.
//
// Every outcome is now proven against the same binding, taken from the user-signed intent exactly as
// the batch path anchored it (consensus.MemberLegsForChain): the transaction is sent to the member's
// account, executes exactly the committed calls in the committed order (native transfers included),
// under the intent's operationID, and - for an execution that went through - the account consumed the
// member's leaf in the inclusion-proven logs.

// CommittedLeg is one committed leg of a member: its call and the effects it committed (none for a
// native value transfer, whose effect is the call itself).
type CommittedLeg struct {
	Call   CommittedCall
	Events []ExpectedEvent
	State  []ExpectedStateSlot
}

// committedCalls is the member's calls in committed order.
func committedCalls(legs []CommittedLeg) []CommittedCall {
	out := make([]CommittedCall, 0, len(legs))
	for _, l := range legs {
		out = append(out, l.Call)
	}
	return out
}

// memberLegsFromSignedIntent is the member the user-signed intent (its four blobs) contributes on one
// chain: its legs with their committed effects, its source account and its operationID. The legs pass
// admission's own rules on the way (consensus.MemberLegsForChain): the execution commitment, a contract
// call only where this deployment executes them, and at least one well-formed committed event for it -
// its success would otherwise be indistinguishable from a no-op that did not revert.
func memberLegsFromSignedIntent(blobs [][]byte, chainID int64) ([]CommittedLeg, common.Address, [32]byte, error) {
	var opID [32]byte
	if len(blobs) < 4 {
		return nil, common.Address{}, opID, fmt.Errorf("signed intent incomplete (%d blobs)", len(blobs))
	}
	ci := &consensus.CertenIntent{IntentData: blobs[0], CrossChainData: blobs[1], GovernanceData: blobs[2], ReplayData: blobs[3]}
	legs, _, account, opID, err := consensus.MemberLegsForChain(ci, chainID)
	if err != nil {
		return nil, common.Address{}, opID, fmt.Errorf("the signed intent's member on chain %d: %w", chainID, err)
	}
	env, err := ci.ParseCrossChain()
	if err != nil {
		return nil, common.Address{}, opID, err
	}
	// MemberLegsForChain keeps the signed order of the legs on this chain; pair each with its payload.
	var payloads []*consensus.ExecutionPayload
	for _, l := range env.Legs {
		if l.ChainID == chainID {
			payloads = append(payloads, l.ExecutionPayload)
		}
	}
	if len(payloads) != len(legs) {
		return nil, common.Address{}, opID, fmt.Errorf("the signed intent's member on chain %d has %d legs but %d payloads", chainID, len(legs), len(payloads))
	}
	out := make([]CommittedLeg, 0, len(legs))
	for i, l := range legs {
		cl := CommittedLeg{Call: CommittedCall{Target: common.Address(l.Target), Value: l.Value, Data: l.Data}}
		for _, e := range payloads[i].ExpectedEvents {
			ev := ExpectedEvent{Contract: common.HexToAddress(e.Contract), Topic0: common.HexToHash(e.Topic0)}
			if e.DataHash != "" {
				ev.DataHash = [32]byte(common.HexToHash(e.DataHash))
			}
			cl.Events = append(cl.Events, ev)
		}
		for _, s := range payloads[i].ExpectedState {
			cl.State = append(cl.State, ExpectedStateSlot{Account: common.HexToAddress(s.Account),
				Slot: common.HexToHash(s.Slot), Value: common.HexToHash(s.Value)})
		}
		out = append(out, cl)
	}
	return out, common.Address(account), opID, nil
}

// signedMemberLegs fetches the USER-SIGNED intent a cycle or attestation names - never trusting a
// requester's copy - binds it to the intent id, and returns its member on the chain this validator
// itself observed.
func (o *UnifiedOrchestrator) signedMemberLegs(ctx context.Context, intentID, accTxHash, accAccountURL string, chainStrategy chain.ChainExecutionStrategy) ([]CommittedLeg, common.Address, [32]byte, error) {
	var none [32]byte
	if o.config.AccumulateQueryClient == nil {
		return nil, common.Address{}, none, fmt.Errorf("no Accumulate query client: the signed intent cannot be read")
	}
	// H1: an empty intent id would let a blob with no intent_id satisfy the binding below.
	if intentID == "" {
		return nil, common.Address{}, none, fmt.Errorf("no intent id")
	}
	if accTxHash == "" || accAccountURL == "" {
		return nil, common.Address{}, none, fmt.Errorf("no Accumulate intent pointer")
	}
	if chainStrategy == nil {
		return nil, common.Address{}, none, fmt.Errorf("no observed chain to select the member by")
	}
	chainID, err := strconv.ParseInt(chainStrategy.ChainID(), 10, 64)
	if err != nil {
		return nil, common.Address{}, none, fmt.Errorf("observed chain %q is not a numeric chain id", chainStrategy.ChainID())
	}
	blobs, err := o.config.AccumulateQueryClient.GetIntentBlobs(ctx, accTxHash, accAccountURL)
	if err != nil {
		return nil, common.Address{}, none, readErr(fmt.Errorf("fetch signed intent: %w", err))
	}
	if len(blobs) < 4 {
		return nil, common.Address{}, none, fmt.Errorf("signed intent incomplete (%d blobs)", len(blobs))
	}
	// Bind: the fetched signed intent MUST be the one named. A user cannot forge a signed intent
	// bearing another intent's id, so intent_id equality anchors trust.
	if got := intentIDFromBlob(blobs[0]); got != intentID {
		return nil, common.Address{}, none, fmt.Errorf("fetched intent_id %q != %q", got, intentID)
	}
	return memberLegsFromSignedIntent(blobs, chainID)
}

// observeMemberExecution proves that txHash is the member's execution: included in its block (RB-2),
// sent to the member's account, executing exactly the committed calls in order under the intent's
// operationID, and consuming the member's leaf in its inclusion-proven logs. It returns the observation
// and the leaf. The execution must have gone through (status 1); a revert is VerifyRevertedCall's.
func (o *ExternalChainObserver) observeMemberExecution(
	ctx context.Context,
	txHash common.Hash,
	legs []CommittedLeg,
	opID [32]byte,
	account common.Address,
) (*ExternalChainResult, [32]byte, error) {
	var leaf [32]byte
	if len(legs) == 0 {
		return nil, leaf, fmt.Errorf("no committed leg to hold the settlement to")
	}
	if account == (common.Address{}) {
		return nil, leaf, fmt.Errorf("no member account to bind the settlement to")
	}
	if opID == ([32]byte{}) {
		return nil, leaf, fmt.Errorf("no operationID to bind the settlement to")
	}
	// The transaction itself decides whether it can be the member's execution at all; only then is it
	// observed to finality and its inclusion proven.
	tx, _, err := o.ethClient.TransactionByHash(ctx, txHash)
	if err != nil || tx == nil {
		return nil, leaf, readErr(fmt.Errorf("fetch settlement %s: %v", txHash.Hex(), err))
	}
	if to := tx.To(); to == nil || *to != account {
		return nil, leaf, fmt.Errorf("settlement %s is not addressed to the member's account %s", txHash.Hex(), account.Hex())
	}
	exec, err := decodeAccountExecution(tx.Data())
	if err != nil {
		return nil, leaf, fmt.Errorf("settlement %s is not an account execution: %w", txHash.Hex(), err)
	}
	if err := requireChainGeneration(o.chainID, exec); err != nil {
		return nil, leaf, fmt.Errorf("settlement %s: %w", txHash.Hex(), err)
	}
	if err := matchCommittedCalls(exec.Calls, committedCalls(legs)); err != nil {
		return nil, leaf, fmt.Errorf("settlement %s: %w", txHash.Hex(), err)
	}
	if exec.OperationID != opID {
		return nil, leaf, fmt.Errorf("settlement %s carries operationID 0x%x, not the intent's 0x%x",
			txHash.Hex(), exec.OperationID[:8], opID[:8])
	}
	result, err := o.ObserveTransaction(ctx, txHash)
	if err != nil {
		return nil, leaf, fmt.Errorf("observe settlement %s: %w", txHash.Hex(), err)
	}
	if result.Status != 1 {
		return nil, leaf, fmt.Errorf("settlement %s did not execute (status=%d)", txHash.Hex(), result.Status)
	}
	if err := result.VerifyInclusionProofs(); err != nil {
		return nil, leaf, err
	}
	leaf, _, err = accountLeafAndAnchor(ctx, o.ethClient, account, exec)
	if err != nil {
		return nil, leaf, err
	}
	for _, lg := range result.Logs {
		if lg.Address == account && len(lg.Topics) >= 3 && lg.Topics[0] == leafConsumedTopic && lg.Topics[2] == common.Hash(leaf) {
			return result, leaf, nil
		}
	}
	return nil, leaf, fmt.Errorf("settlement %s does not consume the member's leaf 0x%x in its inclusion-proven logs", txHash.Hex(), leaf[:8])
}

// committedSlotsHold reports, per committed slot, whether it is proven, against the block's stateRoot,
// to hold the committed value. An error when no verifying proof could be read: neither presence nor
// absence is then established.
func (o *ExternalChainObserver) committedSlotsHold(ctx context.Context, result *ExternalChainResult, state []ExpectedStateSlot) ([]bool, error) {
	if len(state) == 0 {
		return nil, nil
	}
	return slotsHoldAt(o.fetchStateProofs(ctx, result.BlockNumber, result.StateRoot, state), result.StateRoot, state)
}

// slotsHoldAt is committedSlotsHold over proofs already read: each committed slot needs a proof that
// verifies against stateRoot, and holds when that proven value is the committed one.
func slotsHoldAt(proofs []*StateProof, stateRoot common.Hash, state []ExpectedStateSlot) ([]bool, error) {
	holds := make([]bool, len(state))
	for i, want := range state {
		var p *StateProof
		for _, sp := range proofs {
			if sp != nil && sp.Account == want.Account && sp.Slot == want.Slot {
				p = sp
				break
			}
		}
		if p == nil || !p.Verify(stateRoot) {
			return nil, readErr(fmt.Errorf("committed slot %d on %s has no verifying state proof", i, want.Account.Hex()))
		}
		holds[i] = p.Value == want.Value
	}
	return holds, nil
}

// VerifyExecutedCall is the success gate (RB-2/RB-4/RB-5, bound to the member - RB3-F77): txHash is the
// member's execution (observeMemberExecution), every committed event is among its inclusion-proven
// logs, and every committed slot is proven to hold its committed value. Any failure is an error: the
// caller must not attest a success.
func (o *ExternalChainObserver) VerifyExecutedCall(
	ctx context.Context,
	txHash common.Hash,
	legs []CommittedLeg,
	opID [32]byte,
	account common.Address,
) (*ExternalChainResult, error) {
	result, _, err := o.observeMemberExecution(ctx, txHash, legs, opID, account)
	if err != nil {
		return nil, err
	}
	for li, l := range legs {
		for ei, e := range l.Events {
			if !eventPresent(result.Logs, e) {
				return nil, fmt.Errorf("RB-4: committed event %d:%d not found in the inclusion-proven logs of %s", li, ei, txHash.Hex())
			}
		}
		holds, err := o.committedSlotsHold(ctx, result, l.State)
		if err != nil {
			return nil, err
		}
		for si, ok := range holds {
			if !ok {
				return nil, fmt.Errorf("RB-5: committed state slot %d:%d does not hold its committed value at %s", li, si, txHash.Hex())
			}
		}
	}
	return result, nil
}

// ClassifyMemberExecution is the member's execution as its batch outcome states it (RB5 D4): txHash is the member's
// execution (observeMemberExecution: its account, exactly its committed calls, its operationID, its leaf consumed, in a
// finalized, agreed, inclusion-proven receipt), and each committed effect is either proven present or proven absent.
// It returns the observation and the committed effects proven ABSENT, by (leg, index): events missing from the
// inclusion-proven logs, and slots proven, against the block's stateRoot, to hold another value. Nothing absent is
// the success VerifyExecutedCall accepts; something absent is the shortfall VerifyEffectsNotProven attests. An effect
// that can be proven neither present nor absent is an error: no outcome is stated on it.
func (o *ExternalChainObserver) ClassifyMemberExecution(
	ctx context.Context,
	txHash common.Hash,
	legs []CommittedLeg,
	opID [32]byte,
	account common.Address,
) (*ExternalChainResult, []CommittedEffect, []CommittedEffect, error) {
	result, _, err := o.observeMemberExecution(ctx, txHash, legs, opID, account)
	if err != nil {
		return nil, nil, nil, err
	}
	var missing, unset []CommittedEffect
	for li, l := range legs {
		for ei, e := range l.Events {
			if !eventPresent(result.Logs, e) {
				missing = append(missing, CommittedEffect{Leg: uint64(li), Index: uint64(ei)})
			}
		}
		holds, err := o.committedSlotsHold(ctx, result, l.State)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the committed state of settlement %s is proven neither present nor absent: %w", txHash.Hex(), err)
		}
		for si, ok := range holds {
			if !ok {
				unset = append(unset, CommittedEffect{Leg: uint64(li), Index: uint64(si)})
			}
		}
	}
	return result, missing, unset, nil
}
