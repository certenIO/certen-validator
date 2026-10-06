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

// nonSettlementGiveUp is the ATTESTATION WINDOW of a member's non-settlement, in CHAIN time: from the moment the
// member's chain has a finalized block past its deadline and the finality margin (when the non-settlement becomes
// attestable), for this long more. A peer verifies a claim only from its own copy of the member (RB3-F49), and every
// validator keeps that copy - in the on-demand queue, the refused set and the period pool - until its chain is past
// the end of this window (BatchStack.pastAttestationWindow, RB7 D7). So inside the window a quorum can always verify
// the claim, and the requester keeps trying; past it every validator is free to drop its copy, a quorum is no longer
// assured, and the requester records that the non-settlement could not be attested. Both ends are judged on the
// member's chain's finalized time through its clock - never on this machine's clock, which only triggers the re-check.
const nonSettlementGiveUp = 50 * time.Minute

// nonSettlementWindowEnd is the end of a member's attestation window: deadline + finality margin + nonSettlementGiveUp.
func nonSettlementWindowEnd(deadline time.Time) time.Time {
	return deadline.Add(nonSettlementFinality + nonSettlementGiveUp)
}

// nonSettlementWindowClosed reports whether the member's chain has a finalized block past the end of its attestation
// window (nonSettlementGiveUp), naming that block. The wall clock only triggers the read; not past, the chain's clock is
// told the horizon (a heartbeat on a chain whose blocks stop when idle). A failed read decides nothing.
func (o *UnifiedOrchestrator) nonSettlementWindowClosed(ctx context.Context, rec *NonSettlementRecord) (bool, string, error) {
	end := nonSettlementWindowEnd(rec.Facts.Deadline)
	if time.Now().Before(end) {
		return false, "", nil
	}
	fin, err := o.config.NonSettlementChain.FinalizedHeader(ctx, rec.Facts.ChainID)
	if err != nil {
		return false, "", readErr(fmt.Errorf("reading the finalized block of chain %d: %w", rec.Facts.ChainID, err))
	}
	if int64(fin.Time) > end.Unix() {
		return true, fmt.Sprintf("chain %d's finalized block %d (time %s) is past the end of its attestation window %s",
			rec.Facts.ChainID, fin.Number.Uint64(), time.Unix(int64(fin.Time), 0).UTC().Format(time.RFC3339),
			end.UTC().Format(time.RFC3339)), nil
	}
	awaitChainTime(rec.Facts.ChainID, fmt.Sprintf("the attestation window of %s", rec.Facts.IntentID), uint64(end.Unix()))
	return false, "", nil
}

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
	refusal, _ := req.CommitmentData["refusal"].(string)
	rec := &NonSettlementRecord{
		Facts: facts, Cause: reason, Refusal: refusal,
		AccountURL: req.AccumulateAccountURL, AccumTxHash: req.AccumulateTxHash, BVN: req.AccumulateBVN,
		MemberChains: commitmentInt64s(req.CommitmentData["memberChains"]),
		MemberLegs:   int(commitmentInt64(req.CommitmentData["memberLegs"])),
		ProofClass:   req.ProofClass,
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
	if refusal != "" {
		// Refused by name: the outcome is known now and is recorded now, named, so the intent reads
		// refused_pending_attestation instead of in progress until its non-settlement is attested (RB6-F10).
		if err := o.recordMemberOutcome(context.Background(), nonSettlementCycle(rec, nil), database.MemberSettlementNone,
			database.MemberProofCycleRefused, reason); err != nil {
			fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: its refusal could not be recorded yet: %v\n", req.IntentID, chainID, err)
		}
	}
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
		claim, obs, err := observeNonSettlementAt(ctx, o.config.NonSettlementChain, rec.Facts, rec.Cause, rec.ClaimBlock)
		if err == nil && rec.ClaimBlock == 0 {
			// Pinned from now on, durably: a restart must not move the claim either (RB5-F46).
			rec.ClaimBlock = claim.Block
			if perr := o.config.NonSettlements.Put(rec); perr != nil {
				fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: pinning its claim at block %d: %v\n",
					rec.Facts.IntentID, rec.Facts.ChainID, claim.Block, perr)
			}
		}
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
	// Given up only once the member's CHAIN is past the end of its attestation window (nonSettlementGiveUp): before
	// that every validator still holds its copy and the claim stays verifiable, so it is tried again.
	closed, evidence, werr := o.nonSettlementWindowClosed(ctx, rec)
	if werr != nil {
		fmt.Printf("⚠️ [NON-SETTLEMENT] intent %s on chain %d: whether its attestation window is over could not be read (%v)\n",
			rec.Facts.IntentID, rec.Facts.ChainID, werr)
	}
	if closed {
		fmt.Printf("❌ [NON-SETTLEMENT] intent %s on chain %d: could not be attested in %d attempt(s) (%v) and %s; recorded unattested\n",
			rec.Facts.IntentID, rec.Facts.ChainID, rec.Attempts, cause, evidence)
		if err := o.recordMemberOutcome(ctx, nonSettlementCycle(rec, nil), database.MemberSettlementNone, database.MemberProofCycleFailed,
			fmt.Sprintf("%s; its non-settlement could not be attested (%v) before %s", rec.Cause, cause, evidence)); err != nil {
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
	// Every unattested attempt is said, with its cause (RB5-F46: they were silent, visible only in the queue file).
	fmt.Printf("⚠️ [NON-SETTLEMENT] intent %s on chain %d: attempt %d not attested (%v); retried\n",
		rec.Facts.IntentID, rec.Facts.ChainID, rec.Attempts, cause)
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
		IntentID: rec.Facts.IntentID, CycleID: cycleID, TargetChain: chainID, ProofClass: rec.ProofClass,
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
	return &activeCycle{CycleID: cycleID, Request: req, Result: result, NonSettlement: claim, StartedAt: result.StartedAt, Refusal: rec.Refusal}
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
	fail, notYet func(string) (*PeerAttestationResponse, error)) (*PeerAttestationResponse, error) {
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
		if errors.Is(err, ErrNotYetFinalized) {
			// The claim's (pinned) block is not final in this validator's view yet: asked again, not refused (RB5-F49).
			return notYet(fmt.Sprintf("non-settlement not reproducible yet: %v", err))
		}
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
