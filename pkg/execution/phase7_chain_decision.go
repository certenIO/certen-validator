// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// =============================================================================
// Phase 7 ends only when the CHAIN decides (RB7 D7)
// =============================================================================
//
// Phase 7 observes a member's settlement transaction in its chain's finalized blocks. It used to give up on this
// machine's clock - an observation bound (ethrpc.FinalityBound) and the cycle's own deadline - and the cycle then
// recorded the member "unobserved", proof cycle "failed": an outcome decided by a local timeout. An observation now ends
// only on a chain fact, read through the chain's clock:
//
//	(a) the transaction is in a finalized, agreed block: observed - executed or reverted, the existing paths;
//	(b) the chain's finalized time is past the member's deadline and the finality margin, and no agreeing provider holds
//	    the transaction. Every settlement carries expiresAt <= the deadline (settlementExpiry), which the account enforces
//	    on both account generations (block.timestamp <= expiresAt; a v4 leaf also binds notAfter = the deadline), and
//	    block times never decrease: the transaction can never execute. The member's outcome is then its non-settlement,
//	    handed to the existing path (non_settlement_cycle.go), which attests from the chain - leaf unconsumed at a
//	    finalized block past the deadline - and writes it back; a leaf consumed by another transaction is that
//	    transaction's, and the non-settlement withdraws itself (errMemberSettled).
//
// Until (a) or (b), Phase 7 keeps observing: this machine's clock only bounds each attempt and re-triggers the next; on a
// chain whose blocks stop when idle the deadline is the heartbeat's horizon. A cycle stopped before the chain decided (a
// shutdown, a caller's own deadline) records nothing (errObservationUndecided). A receipt that is final but whose proof
// could not be built is the existing settled_unproven path (executed, proof pending) - not a timeout's verdict.

// errObservationUndecided: Phase 7 was stopped before the chain decided the observation. Nothing is recorded.
var errObservationUndecided = errors.New("the observation was stopped before the chain decided it")

// errSettlementHandedToNonSettlement: the chain decided the settlement transaction can never execute; the member's
// outcome is its non-settlement's to record (non_settlement_cycle.go), not this cycle's.
var errSettlementHandedToNonSettlement = errors.New("the settlement transaction never reached the finalized chain before " +
	"the member's deadline; its outcome is the member's non-settlement")

// phase7Retrigger spaces the observation attempts after one that the chain did not decide.
const phase7Retrigger = time.Minute

// phase7RetriggerInForce is the spacing in force; tests shorten it.
var phase7RetriggerInForce = phase7Retrigger

// phase7DecisionChain is what deciding an undecided observation reads of the member's chain.
type phase7DecisionChain interface {
	Finalized(ctx context.Context) (*types.Header, error)
	// SettlementReceipt is the transaction's receipt as the agreeing providers hold it: ethereum.NotFound when every
	// provider that answered holds none.
	SettlementReceipt(ctx context.Context, tx common.Hash) (*types.Receipt, error)
}

// clockDecisionChain reads through the chain's clock and its agreeing providers.
type clockDecisionChain struct{ c *ChainClock }

func (d clockDecisionChain) Finalized(ctx context.Context) (*types.Header, error) {
	return d.c.Finalized(ctx)
}

func (d clockDecisionChain) SettlementReceipt(ctx context.Context, tx common.Hash) (*types.Receipt, error) {
	src, err := d.c.source(ctx)
	if err != nil {
		return nil, err
	}
	r, ok := src.(interface {
		TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error)
	})
	if !ok {
		return nil, fmt.Errorf("chain %d's clock (%T) reads no agreed receipts", d.c.ChainID(), src)
	}
	return r.TransactionReceipt(ctx, tx)
}

func (o *UnifiedOrchestrator) phase7Chain(chainID int64) phase7DecisionChain {
	if o.phase7DecisionChain != nil {
		return o.phase7DecisionChain(chainID)
	}
	return clockDecisionChain{chainClockFor(chainID, "")}
}

// keptMember is the member of the cycle's intent in the tree this validator kept for the cycle's anchor (RB5 D4): its
// leaf, account and deadline, as this validator signed them.
func (o *UnifiedOrchestrator) keptMember(chainID int64, bundle [32]byte, intentID string) (*OutcomeTreeMember, error) {
	if o.config.OutcomeTrees == nil {
		return nil, fmt.Errorf("no kept outcome trees are wired")
	}
	t, err := o.config.OutcomeTrees.Load(chainID, bundle)
	if err != nil {
		return nil, fmt.Errorf("the kept tree of anchor 0x%x on chain %d: %w", bundle[:8], chainID, err)
	}
	for i := range t.Members {
		if t.Members[i].IntentID == intentID {
			return &t.Members[i], nil
		}
	}
	return nil, fmt.Errorf("the kept tree of anchor 0x%x on chain %d has no member of intent %s", bundle[:8], chainID, intentID)
}

// keptMemberByOperation is the member with this operation on chainID in any tree this validator kept: what a peer that
// no longer holds the member in its queues verifies a non-settlement claim from.
func (o *UnifiedOrchestrator) keptMemberByOperation(chainID int64, opID [32]byte) (*OutcomeTreeMember, bool) {
	if o.config.OutcomeTrees == nil {
		return nil, false
	}
	trees, err := o.config.OutcomeTrees.List()
	if err != nil {
		return nil, false
	}
	for _, t := range trees {
		if t.ChainID != chainID {
			continue
		}
		for i := range t.Members {
			if t.Members[i].OperationID == common.Hash(opID) {
				return &t.Members[i], true
			}
		}
	}
	return nil, false
}

// keptMemberFacts are a kept member's non-settlement facts.
func keptMemberFacts(intentID string, chainID int64, m *OutcomeTreeMember) (NonSettlementFacts, error) {
	if m.Deadline <= 0 {
		return NonSettlementFacts{}, fmt.Errorf("member of intent %s on chain %d has no deadline; its non-settlement can never be final",
			intentID, chainID)
	}
	return NonSettlementFacts{IntentID: intentID, ChainID: chainID, OperationID: m.OperationID, Account: m.Account,
		Leaf: m.Leaf, Deadline: time.Unix(m.Deadline, 0).UTC()}, nil
}

// settlementCanNeverExecute is decision (b): the chain's finalized time is past the member's deadline and the finality
// margin, and no agreeing provider holds the transaction. not-decided returns false with why; a read that fails decides
// nothing.
func (o *UnifiedOrchestrator) settlementCanNeverExecute(ctx context.Context, req *UnifiedProofCycleRequest, tx common.Hash) (bool, string, NonSettlementFacts, error) {
	var none NonSettlementFacts
	chainID, err := strconv.ParseInt(req.TargetChain, 10, 64)
	if err != nil {
		return false, "", none, fmt.Errorf("target chain %q is not a chain id", req.TargetChain)
	}
	m, err := o.keptMember(chainID, req.BundleID, req.IntentID)
	if err != nil {
		return false, "", none, err
	}
	facts, err := keptMemberFacts(req.IntentID, chainID, m)
	if err != nil {
		return false, "", none, err
	}
	horizon := facts.Deadline.Add(nonSettlementFinality)
	c := o.phase7Chain(chainID)
	fin, err := c.Finalized(ctx)
	if err != nil {
		return false, "", none, readErr(fmt.Errorf("reading the finalized block of chain %d: %w", chainID, err))
	}
	if int64(fin.Time) <= horizon.Unix() {
		awaitChainTime(chainID, fmt.Sprintf("the observation of %s", tx.Hex()), uint64(horizon.Unix()))
		return false, fmt.Sprintf("chain %d is finalized only to %s, not past the member's deadline %s and the margin", chainID,
			time.Unix(int64(fin.Time), 0).UTC().Format(time.RFC3339), facts.Deadline.Format(time.RFC3339)), none, nil
	}
	_, rerr := c.SettlementReceipt(ctx, tx)
	switch {
	case errors.Is(rerr, ethereum.NotFound):
		return true, fmt.Sprintf("chain %d's finalized block %d (time %s) is past the member's deadline %s and the margin, and no "+
			"agreeing provider holds settlement %s", chainID, fin.Number.Uint64(), time.Unix(int64(fin.Time), 0).UTC().Format(time.RFC3339),
			facts.Deadline.Format(time.RFC3339), tx.Hex()), facts, nil
	case rerr != nil:
		return false, "", none, readErr(fmt.Errorf("reading the receipt of %s: %w", tx.Hex(), rerr))
	default:
		return false, fmt.Sprintf("the providers hold a receipt of %s: it is observed again", tx.Hex()), none, nil
	}
}

// observeUntilTheChainDecides is Phase 7's observation of one transaction: (a), (b), or keep observing.
func (o *UnifiedOrchestrator) observeUntilTheChainDecides(ctx context.Context, cycle *activeCycle,
	chainStrategy chain.ChainExecutionStrategy, i int, txHash string) (*chain.ObservationResult, error) {
	req := cycle.Request
	tx := common.HexToHash(txHash)
	for attempt := 1; ; attempt++ {
		// This machine's clock bounds the attempt, and only re-triggers the next one.
		actx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout)
		obs, err := chainStrategy.ObserveTransaction(actx, txHash)
		cancel()
		if err == nil {
			return obs, nil // (a)
		}
		var unproven *chain.UnprovenSettlementError
		if errors.As(err, &unproven) {
			return nil, fmt.Errorf("observe transaction %d (%s): %w", i, txHash, err) // final receipt, proof pending
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("observe transaction %d (%s): %w: %v (last attempt: %v)", i, txHash, errObservationUndecided, ctx.Err(), err)
		}
		decided, why, facts, derr := o.settlementCanNeverExecute(ctx, req, tx)
		if derr == nil && decided {
			if herr := o.handToNonSettlement(req, facts, txHash, why); herr != nil {
				fmt.Printf("❌ [Phase 7] cycle %s: %s, but its non-settlement could not be queued (%v); observing again\n",
					req.CycleID, why, herr)
			} else {
				return nil, fmt.Errorf("observe transaction %d (%s): %w: %s", i, txHash, errSettlementHandedToNonSettlement, why)
			}
		}
		fmt.Printf("⏳ [Phase 7] cycle %s: transaction %s not decided by the chain after attempt %d (%v); %s; observing again in %s\n",
			req.CycleID, txHash, attempt, err, undecidedWhy(why, derr), phase7RetriggerInForce)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("observe transaction %d (%s): %w: %v", i, txHash, errObservationUndecided, ctx.Err())
		case <-time.After(phase7RetriggerInForce):
		}
	}
}

func undecidedWhy(why string, err error) string {
	if err != nil {
		return "the chain's decision could not be read: " + err.Error()
	}
	return why
}

// handToNonSettlement queues the member's non-settlement with the cycle's Accumulate reference (QueueNonSettlement's
// record, built from the kept tree's member: the member may have left this validator's queues once its settlement was
// sent).
func (o *UnifiedOrchestrator) handToNonSettlement(req *UnifiedProofCycleRequest, facts NonSettlementFacts, txHash, why string) error {
	if o.config.NonSettlements == nil {
		return fmt.Errorf("no non-settlement queue is configured")
	}
	rec := &NonSettlementRecord{
		Facts: facts, Cause: fmt.Sprintf("its settlement %s never reached the finalized chain: %s", txHash, why),
		AccountURL: req.AccumulateAccountURL, AccumTxHash: req.AccumulateTxHash, BVN: req.AccumulateBVN,
		MemberChains: commitmentInt64s(req.CommitmentData["memberChains"]),
		MemberLegs:   int(commitmentInt64(req.CommitmentData["memberLegs"])),
		ProofClass:   req.ProofClass,
		QueuedAt:     time.Now().UTC(),
	}
	if req.UserID != nil {
		rec.UserID = *req.UserID
	}
	return o.config.NonSettlements.Put(rec)
}

// phase7RecordsNothing reports whether a Phase 7 error leaves the member's outcome to someone else: the chain has not
// decided yet, or the non-settlement path now owns it.
func phase7RecordsNothing(err error) bool {
	return errors.Is(err, errObservationUndecided) || errors.Is(err, errSettlementHandedToNonSettlement)
}
