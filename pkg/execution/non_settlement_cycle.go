// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// MemberLookupFn finds this validator's own copy of a batch member, in either lane.
type MemberLookupFn func(chainID int64, operationID [32]byte) (*PendingBatchIntent, bool)

// nonSettlementGiveUp is how long past a member's deadline its non-settlement is retried. Peers verify
// the claim from their own copy of the member and prune members about two hours after their commit;
// a member's deadline is at most an hour after its commit, so past this no peer can verify it.
const nonSettlementGiveUp = 50 * time.Minute

// commitment keys a failure record carries (set by consensus's recordFailedProofCycle).
const (
	commitmentNonSettlementOperationID = "nonSettlementOperationID"
)

// QueueNonSettlement records a member failure for attestation (RB3-F49). The member's facts are
// computed now, from this validator's copy while it still holds it; the attestation waits until the
// chain is past the member's deadline.
func (o *UnifiedOrchestrator) QueueNonSettlement(req *UnifiedProofCycleRequest) error {
	if o.config.NonSettlements == nil || o.config.MemberLookup == nil || o.config.NonSettlementChain == nil {
		return fmt.Errorf("intent %s: no non-settlement queue configured - its failure cannot be recorded", req.IntentID)
	}
	chainID, err := strconv.ParseInt(req.TargetChain, 10, 64)
	if err != nil {
		return fmt.Errorf("intent %s: target chain %q is not a chain id", req.IntentID, req.TargetChain)
	}
	opHex, _ := req.CommitmentData[commitmentNonSettlementOperationID].(string)
	opBytes, err := hex.DecodeString(strings.TrimPrefix(opHex, "0x"))
	if err != nil || len(opBytes) != 32 {
		return fmt.Errorf("intent %s: failure record carries no operation id (%q)", req.IntentID, opHex)
	}
	var opID [32]byte
	copy(opID[:], opBytes)
	member, ok := o.config.MemberLookup(chainID, opID)
	if !ok {
		return fmt.Errorf("intent %s: its member on chain %d is not held here; its failure cannot be placed", req.IntentID, chainID)
	}
	facts, err := memberFacts(member)
	if err != nil {
		return fmt.Errorf("intent %s: %w", req.IntentID, err)
	}
	reason, _ := req.CommitmentData["reason"].(string)
	rec := &NonSettlementRecord{
		Facts: facts, Cause: reason,
		AccountURL: req.AccumulateAccountURL, AccumTxHash: req.AccumulateTxHash, BVN: req.AccumulateBVN,
		MemberChains: commitmentInt64s(req.CommitmentData["memberChains"]),
		MemberLegs:   int(commitmentInt64(req.CommitmentData["memberLegs"])),
		QueuedAt:     time.Now().UTC(),
	}
	if req.UserID != nil {
		rec.UserID = *req.UserID
	}
	if err := o.config.NonSettlements.Put(rec); err != nil {
		return fmt.Errorf("intent %s: queueing its failure: %w", req.IntentID, err)
	}
	fmt.Printf("[NON-SETTLEMENT] intent %s on chain %d queued (%s); attestable after %s\n",
		req.IntentID, chainID, reason, facts.Deadline.Add(nonSettlementFinality).Format(time.RFC3339))
	return nil
}

// RunNonSettlements attests queued failures as they become final, until ctx ends.
func (o *UnifiedOrchestrator) RunNonSettlements(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		o.processNonSettlements(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (o *UnifiedOrchestrator) processNonSettlements(ctx context.Context) {
	if o.config.NonSettlements == nil {
		return
	}
	for _, rec := range o.config.NonSettlements.All() {
		if ctx.Err() != nil {
			return
		}
		claim, obs, err := observeNonSettlement(ctx, o.config.NonSettlementChain, rec.Facts, rec.Cause)
		switch {
		case errors.Is(err, errNotYetAttestable):
			continue
		case errors.Is(err, errMemberSettled):
			// It settled after all - another validator's settlement, or this one's own that landed. That
			// settlement's cycle records it; a failure record here would contradict the chain.
			fmt.Printf("[NON-SETTLEMENT] intent %s on chain %d: its leaf is consumed - it settled; failure record withdrawn\n",
				rec.Facts.IntentID, rec.Facts.ChainID)
			o.removeNonSettlement(rec)
			continue
		case err != nil:
			o.retryNonSettlement(ctx, rec, err)
			continue
		}
		if cerr := o.runNonSettlementCycle(ctx, rec, claim, obs); cerr != nil {
			o.retryNonSettlement(ctx, rec, cerr)
			continue
		}
		o.removeNonSettlement(rec)
	}
}

func (o *UnifiedOrchestrator) removeNonSettlement(rec *NonSettlementRecord) {
	if err := o.config.NonSettlements.Remove(rec.Facts.IntentID, rec.Facts.ChainID); err != nil {
		fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: resolved, but its record could not be removed: %v\n",
			rec.Facts.IntentID, rec.Facts.ChainID, err)
	}
}

// retryNonSettlement keeps the record for the next pass - until no peer can verify it any more, when
// the failure to attest it is itself recorded, never left silent.
func (o *UnifiedOrchestrator) retryNonSettlement(ctx context.Context, rec *NonSettlementRecord, cause error) {
	rec.Attempts++
	rec.LastError = cause.Error()
	if time.Since(rec.Facts.Deadline) > nonSettlementGiveUp {
		fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: could not be attested in %d attempt(s) (%v); recorded unattested\n",
			rec.Facts.IntentID, rec.Facts.ChainID, rec.Attempts, cause)
		if err := o.recordMemberOutcome(ctx, nonSettlementCycle(rec, nil), database.MemberSettlementNone, database.MemberProofCycleFailed,
			fmt.Sprintf("%s; its non-settlement could not be attested: %v", rec.Cause, cause)); err != nil {
			// Neither the store nor the outbox kept the failure: keep the record, so the next pass records it.
			if pErr := o.config.NonSettlements.Put(rec); pErr != nil {
				fmt.Printf("❌ [NON-SETTLEMENT] intent %s: its unattested failure could not be recorded (%v) nor kept (%v)\n",
					rec.Facts.IntentID, err, pErr)
			}
			return
		}
		o.removeNonSettlement(rec)
		return
	}
	if err := o.config.NonSettlements.Put(rec); err != nil {
		fmt.Printf("❌ [NON-SETTLEMENT] intent %s: recording attempt %d: %v\n", rec.Facts.IntentID, rec.Attempts, err)
	}
}

// nonSettlementCycle is the proof cycle a non-settlement is attested and written back through.
func nonSettlementCycle(rec *NonSettlementRecord, claim *NonSettlementClaim) *activeCycle {
	chainID := strconv.FormatInt(rec.Facts.ChainID, 10)
	block := uint64(0)
	if claim != nil {
		block = claim.Block
	}
	cycleID := fmt.Sprintf("nonsettlement-%s-%s-%d", rec.Facts.IntentID, chainID, block)
	req := &UnifiedProofCycleRequest{
		IntentID: rec.Facts.IntentID, CycleID: cycleID, TargetChain: chainID, ProofClass: "on_cadence",
		AccumulateAccountURL: rec.AccountURL, AccumulateTxHash: rec.AccumTxHash, AccumulateBVN: rec.BVN,
		CommitmentData: map[string]interface{}{
			"memberChains": rec.MemberChains, "memberLegs": rec.MemberLegs,
			"outcome": "failed", "reason": rec.Cause,
		},
	}
	if rec.UserID != "" {
		u := rec.UserID
		req.UserID = &u
	}
	result := &UnifiedProofCycleResult{CycleID: cycleID, ChainID: chainID, StartedAt: time.Now().UTC()}
	// StartedAt, like any cycle's: the verification record's duration is measured from it. Without it
	// every non-settlement's verification record was refused as out of range, and a warning hid that.
	return &activeCycle{CycleID: cycleID, Request: req, Result: result, NonSettlement: claim, StartedAt: result.StartedAt}
}

// runNonSettlementCycle attests the non-settlement by quorum and writes it back.
func (o *UnifiedOrchestrator) runNonSettlementCycle(ctx context.Context, rec *NonSettlementRecord, claim *NonSettlementClaim, obs *chain.ObservationResult) error {
	cycle := nonSettlementCycle(rec, claim)
	cycle.Result.ObservationResults = []*chain.ObservationResult{obs}
	_, attestStrategy, err := o.config.Registry.GetStrategiesForChain(cycle.Request.TargetChain)
	if err != nil {
		return fmt.Errorf("strategies for chain %s: %w", cycle.Request.TargetChain, err)
	}
	if err := o.executePhase8(ctx, cycle, attestStrategy); err != nil {
		return fmt.Errorf("attesting the non-settlement: %w", err)
	}
	if err := o.executePhase9(ctx, cycle); err != nil {
		return fmt.Errorf("writing the non-settlement back: %w", err)
	}
	proofCycle := database.MemberProofCycleWritten
	if cycle.Result.WriteBackState != WriteBackWritten {
		proofCycle = database.MemberProofCycleFailed
	}
	if err := o.recordMemberOutcome(ctx, cycle, database.MemberSettlementNone, proofCycle, rec.Cause); err != nil {
		// Written back already: re-running the cycle would write it back twice. The store and the outbox
		// both refused the outcome - a double fault, reported as such (RB3-F78).
		fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: written back (%s) but its outcome was neither stored nor queued: %v\n",
			rec.Facts.IntentID, rec.Facts.ChainID, cycle.Result.WriteBackTxHash, err)
	}
	fmt.Printf("✅ [NON-SETTLEMENT] intent %s on chain %d: not settled by its deadline - attested at block %d and written back (%s)\n",
		rec.Facts.IntentID, rec.Facts.ChainID, claim.Block, cycle.Result.WriteBackTxHash)
	return nil
}

// handlePeerNonSettlement is a peer's side of a non-settlement: it verifies the claim from its OWN copy
// of the member and its OWN chain reads, and signs only a result it reproduces.
func (o *UnifiedOrchestrator) handlePeerNonSettlement(ctx context.Context, req *PeerAttestationRequest,
	fail func(string) (*PeerAttestationResponse, error)) (*PeerAttestationResponse, error) {
	msg := req.Message
	c := msg.NonSettlement
	if msg.IntentID == "" || msg.ResultHash == ([32]byte{}) {
		return fail("non-settlement message missing intent id or result hash")
	}
	if o.config.MemberLookup == nil || o.config.NonSettlementChain == nil {
		return fail("this validator cannot verify a non-settlement (not configured)")
	}
	if msg.TargetChain != strconv.FormatInt(c.ChainID, 10) {
		return fail(fmt.Sprintf("non-settlement for chain %d names target chain %q", c.ChainID, msg.TargetChain))
	}
	opBytes, err := hex.DecodeString(strings.TrimPrefix(c.OperationID, "0x"))
	if err != nil || len(opBytes) != 32 {
		return fail("non-settlement carries a malformed operation id")
	}
	var opID [32]byte
	copy(opID[:], opBytes)
	own, ok := o.config.MemberLookup(c.ChainID, opID)
	if !ok {
		return fail(fmt.Sprintf("member %s on chain %d is not held by this validator", c.OperationID, c.ChainID))
	}
	if own.IntentID != msg.IntentID {
		return fail(fmt.Sprintf("operation %s is intent %s here, not %s", c.OperationID, own.IntentID, msg.IntentID))
	}
	vctx, cancel := context.WithTimeout(ctx, o.config.ObservationTimeout)
	defer cancel()
	if err := verifyNonSettlementClaim(vctx, o.config.NonSettlementChain, own, msg); err != nil {
		return fail(fmt.Sprintf("non-settlement not reproduced: %v", err))
	}
	attestStrategy, err := o.config.Registry.GetAttestationStrategy(req.Scheme)
	if err != nil {
		return fail(fmt.Sprintf("unsupported scheme: %v", err))
	}
	att, err := attestStrategy.Sign(vctx, msg)
	if err != nil {
		return fail(fmt.Sprintf("sign failed: %v", err))
	}
	fmt.Printf("[Phase 8] Independently verified + attested the NON-SETTLEMENT of intent %s on chain %d at block %d\n",
		msg.IntentID, c.ChainID, c.Block)
	return &PeerAttestationResponse{CycleID: req.CycleID, Success: true, Attestation: att}, nil
}
