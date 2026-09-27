package execution

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
)

// RB3-F50: a multi-chain intent's status is derived from every chain member's outcome. Each member
// used to write the whole intent's status, so the first to finish decided it and the terminal guard
// froze it there - a later revert on the other chain could never be recorded.

// memberCycle is a finished member cycle as Phase 7-9 leave it.
func memberCycle(intentID, chainID string, members []int64, legs int, obs *chain.ObservationResult) *activeCycle {
	return &activeCycle{
		CycleID:   "cycle-" + chainID,
		StartedAt: time.Now().UTC(),
		Request: &UnifiedProofCycleRequest{
			IntentID: intentID, CycleID: "cycle-" + chainID, TargetChain: chainID,
			CommitmentData: map[string]interface{}{"memberChains": members, "memberLegs": legs},
		},
		Result: &UnifiedProofCycleResult{ChainID: chainID, ObservationResults: []*chain.ObservationResult{obs}},
	}
}

func settledObs(tx string) *chain.ObservationResult {
	return &chain.ObservationResult{TxHash: tx, IsFinalized: true, Status: 1}
}

func revertedObs(tx string) *chain.ObservationResult {
	return &chain.ObservationResult{TxHash: tx, IsFinalized: true, Status: 0}
}

func finish(ctx context.Context, o *UnifiedOrchestrator, c *activeCycle) {
	c.Result.WriteBackTxHash, c.Result.WriteBackState = "wb-"+c.Request.TargetChain, WriteBackWritten
	o.recordMemberOutcome(ctx, c, observedSettlement(c.Result.ObservationResults), database.MemberProofCycleWritten, "")
}

func lifecycleRow(t *testing.T, db *sql.DB, intentID string) (status string, done, failed int, msg string) {
	t.Helper()
	var m sql.NullString
	if err := db.QueryRow(`SELECT status, legs_completed, legs_failed, error_message FROM intent_lifecycle WHERE intent_id=$1`,
		intentID).Scan(&status, &done, &failed, &m); err != nil {
		t.Fatal(err)
	}
	return status, done, failed, m.String
}

func TestIntentStatus_OneMemberDoesNotDecideTheIntent(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	const id = "f50-two-chain"
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, id) })
	members := []int64{84532, 421614}

	finish(ctx, o, memberCycle(id, "84532", members, 2, settledObs("0xbase")))
	if status, done, _, _ := lifecycleRow(t, db, id); status == "complete" || status == "failed" || done != 2 {
		t.Fatalf("after Base settled alone: status %q legs_completed %d; the intent is still in progress", status, done)
	}

	finish(ctx, o, memberCycle(id, "421614", members, 1, revertedObs("0xarb")))
	status, done, failed, msg := lifecycleRow(t, db, id)
	if status != "failed" || done != 2 || failed != 1 {
		t.Fatalf("status %q done %d failed %d; a member that reverted fails the intent", status, done, failed)
	}
	if !strings.Contains(msg, "84532: settled") || !strings.Contains(msg, "421614: reverted") || !strings.Contains(msg, "0xarb") {
		t.Fatalf("error_message must name each chain's outcome: %q", msg)
	}
}

func TestIntentStatus_CompleteOnlyWhenEveryMemberSettledAndWasWritten(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	const id = "f50-both-settle"
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, id) })
	members := []int64{84532, 421614}

	// Reports in either order derive the same status.
	finish(ctx, o, memberCycle(id, "421614", members, 1, settledObs("0xarb")))
	finish(ctx, o, memberCycle(id, "84532", members, 1, settledObs("0xbase")))
	if status, done, failed, msg := lifecycleRow(t, db, id); status != "complete" || done != 2 || failed != 0 || msg != "" {
		t.Fatalf("status %q done %d failed %d msg %q; want complete", status, done, failed, msg)
	}
}

// A member whose write-back failed is not complete; the same member's later, written report replaces
// it and the intent is derived again.
func TestIntentStatus_ARetriedWriteBackIsDerivedAgain(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	const id = "f50-retry"
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, id) })

	c := memberCycle(id, "84532", []int64{84532}, 1, settledObs("0xbase"))
	o.recordMemberOutcome(ctx, c, database.MemberSettlementSettled, database.MemberProofCycleFailed, "phase 9 failed: quorum not met")
	if status, _, _, msg := lifecycleRow(t, db, id); status != "failed" || !strings.Contains(msg, "not written back") {
		t.Fatalf("a settlement not written back: status %q msg %q", status, msg)
	}
	finish(ctx, o, c)
	if status, _, _, _ := lifecycleRow(t, db, id); status != "complete" {
		t.Fatalf("after the write-back landed: status %q, want complete", status)
	}
}

func TestIntentStatus_AMemberSetThatDisagreesIsRefused(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	repo := database.NewIntentLifecycleRepository(database.NewClientFromDB(db))
	const id = "f50-set"
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, id) })

	if _, err := repo.RecordMemberOutcome(ctx, database.MemberOutcome{IntentID: id, ChainID: 84532, MemberChains: []int64{84532, 421614},
		Settlement: database.MemberSettlementSettled, ProofCycle: database.MemberProofCycleWritten, Legs: 1}); err != nil {
		t.Fatal(err)
	}
	_, err := repo.RecordMemberOutcome(ctx, database.MemberOutcome{IntentID: id, ChainID: 421614, MemberChains: []int64{421614},
		Settlement: database.MemberSettlementSettled, ProofCycle: database.MemberProofCycleWritten, Legs: 1})
	if !errors.Is(err, database.ErrMemberOutcomeInvalid) {
		t.Fatalf("a report naming another member set was accepted: %v", err)
	}
	_, err = repo.RecordMemberOutcome(ctx, database.MemberOutcome{IntentID: id, ChainID: 11155111, MemberChains: []int64{84532, 421614},
		Settlement: database.MemberSettlementSettled, ProofCycle: database.MemberProofCycleWritten, Legs: 1})
	if !errors.Is(err, database.ErrMemberOutcomeInvalid) {
		t.Fatalf("a chain outside the member set was accepted: %v", err)
	}
}

// Without a member set from consensus the outcome cannot be placed: nothing is written, nothing guessed.
func TestIntentStatus_NoMemberSetRecordsNothing(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	const id = "f50-no-set"
	s1Seed(ctx, t, db, id)
	c := memberCycle(id, "84532", nil, 0, settledObs("0xbase"))
	finish(ctx, o, c)
	if status, _, _, _ := lifecycleRow(t, db, id); status != "authorized" {
		t.Fatalf("an outcome with no member set changed the intent: %q", status)
	}
}

// RB3-F67: a member that settled and was written back, but whose committed effects are provably
// absent, did not do what the intent committed to - the intent is failed, and says why. Proven effects
// complete it.
func TestIntentStatus_ASettlementWithoutItsCommittedEffectsFailsTheIntent(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	members := []int64{84532, 421614}

	const failedID = "f67-effects-not-proven"
	s1Seed(ctx, t, db, failedID)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, failedID) })
	finish(ctx, o, memberCycle(failedID, "11155111", []int64{11155111, 84532}, 1, settledObs("0xsep")))
	short := memberCycle(failedID, "84532", []int64{11155111, 84532}, 1, settledObs("0xbase"))
	short.EffectsShortfall = shortfallClaim()
	finish(ctx, o, short)
	status, done, failed, msg := lifecycleRow(t, db, failedID)
	if status != "failed" || done != 1 || failed != 1 {
		t.Fatalf("status %q done %d failed %d; a settlement without its committed effects fails the intent", status, done, failed)
	}
	if !strings.Contains(msg, "84532: settled") || !strings.Contains(msg, "committed effects NOT proven") {
		t.Fatalf("error_message must say the Base member settled without its committed effects: %q", msg)
	}

	const okID = "f67-effects-proven"
	s1Seed(ctx, t, db, okID)
	t.Cleanup(func() { db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id=$1`, okID) })
	for _, c := range []*activeCycle{
		memberCycle(okID, "84532", members, 1, settledObs("0xbase")),
		memberCycle(okID, "421614", members, 1, settledObs("0xarb")),
	} {
		c.CommittedEffects = true
		c.VerifiedCalls = verifiedCallProofs{"proven": &ExternalChainResult{Status: 1}}
		finish(ctx, o, c)
	}
	if status, _, _, _ := lifecycleRow(t, db, okID); status != "complete" {
		t.Fatalf("status %q; proven effects complete the intent", status)
	}
	var proven sql.NullBool
	if err := db.QueryRow(`SELECT effects_proven FROM intent_member_outcomes WHERE intent_id=$1 AND chain_id=84532`, okID).Scan(&proven); err != nil || !proven.Valid || !proven.Bool {
		t.Fatalf("effects_proven stored %v (%v); want true", proven, err)
	}
}
