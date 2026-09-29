// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	attestation "github.com/certen/independant-validator/pkg/attestation/strategy"
	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/strategy"
)

// RB4-F59. Phase 9 submitted a write-back for whatever cycle reached it, and the proof bundle was stored before
// it, so a second proof cycle for a member already written back - re-driven, or re-discovered after a restart -
// wrote a second Accumulate entry and stored a second proof artifact for the same member. A member is written back
// once: a registered write-back stops another; a submission whose outcome is unknown stops another until that is
// established; one that failed before anything was sent does not.

// scriptedSubmitter answers each submission in turn with the scripted error, or a write-back receipt.
type scriptedSubmitter struct {
	errs []error
	n    int
}

func (s *scriptedSubmitter) SubmitTransaction(_ context.Context, _ *SyntheticTransaction) (string, error) {
	i := s.n
	s.n++
	if i < len(s.errs) && s.errs[i] != nil {
		return "", s.errs[i]
	}
	return fmt.Sprintf("acc://%064x@results.acme/data", i+1), nil
}

func (s *scriptedSubmitter) GetTransactionStatus(context.Context, string) (string, error) {
	return "", errors.New("the scripted submitter answers no status queries")
}

type writeBackFixture struct {
	db       *sql.DB
	repos    *database.Repositories
	o        *UnifiedOrchestrator
	sub      *scriptedSubmitter
	intentID string
	cycles   int
}

func newWriteBackFixture(t *testing.T, errs ...error) *writeBackFixture {
	t.Helper()
	db := s1OpenDB(t)
	repos := database.NewRepositories(database.NewClientFromDB(db))
	validator := fmt.Sprintf("f59-validator-%d", time.Now().UnixNano())
	_, key, _ := ed25519.GenerateKey(nil)
	sub := &scriptedSubmitter{errs: errs}
	f := &writeBackFixture{db: db, repos: repos, sub: sub, intentID: "f59-" + validator}
	f.o = &UnifiedOrchestrator{
		config: &UnifiedOrchestratorConfig{ValidatorID: validator, UnifiedRepo: repos.Unified, Repos: repos,
			ResultsPrincipal: "acc://results.acme/data", Ed25519Key: key, AccumulateClient: sub},
		resultChains: map[string]*ResultHashChain{},
		txBuilder:    NewSyntheticTxBuilder("acc://results.acme/data", validator, key),
	}
	t.Cleanup(func() {
		db.Exec(`DELETE FROM result_hash_chain_links WHERE observer_validator_id=$1`, validator)
		db.Exec(`DELETE FROM member_write_backs WHERE intent_id=$1`, f.intentID)
	})
	return f
}

// cycle is a new proof cycle, attested by quorum, for the fixture's one member.
func (f *writeBackFixture) cycle(t *testing.T) *activeCycle {
	t.Helper()
	facts, _ := memberFacts(nsMember())
	facts.IntentID = f.intentID
	claim, obs, err := observeNonSettlement(context.Background(), nsChainPast(facts.Deadline), facts, "its batch quorum was never reached")
	if err != nil {
		t.Fatal(err)
	}
	rec := &NonSettlementRecord{Facts: facts, Cause: claim.Cause, MemberChains: []int64{odChain}, MemberLegs: 1}
	c := nonSettlementCycle(rec, claim)
	f.cycles++
	c.CycleID = fmt.Sprintf("%s-%d", c.CycleID, f.cycles)
	c.Request.CycleID = c.CycleID
	c.Result.CycleID = c.CycleID
	c.Result.ObservationResults = []*chain.ObservationResult{obs}
	c.Result.ThresholdMet = true
	c.Result.AggregatedAttestation = &attestation.AggregatedAttestation{
		ThresholdMet: true, Verified: true, AchievedWeight: 700, TotalWeight: 700, ParticipantCount: 7}
	return c
}

func (f *writeBackFixture) registered(t *testing.T) *database.MemberWriteBack {
	t.Helper()
	w, err := f.repos.IntentLifecycle.MemberWriteBackOf(context.Background(), f.intentID, odChain)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// The defect through Phase 9's own entry point: two cycles for one member submitted two write-backs.
func TestAMemberIsWrittenBackOnce(t *testing.T) {
	f := newWriteBackFixture(t)
	ctx := context.Background()
	if err := f.o.executePhase9(ctx, f.cycle(t)); err != nil {
		t.Fatalf("the first write-back: %v", err)
	}
	second := f.cycle(t)
	err := f.o.executePhase9(ctx, second)
	if err == nil || f.sub.n != 1 {
		t.Fatalf("THE regression: a second cycle for a written-back member submitted a second write-back (submissions %d, err %v)", f.sub.n, err)
	}
	if second.Result.WriteBackState == WriteBackWritten {
		t.Fatalf("the refused cycle reads written")
	}
}

func TestASecondWriteBackIsRefusedByName(t *testing.T) {
	f := newWriteBackFixture(t)
	ctx := context.Background()
	first := f.cycle(t)
	if err := f.o.executePhase9(ctx, first); err != nil {
		t.Fatal(err)
	}
	w := f.registered(t)
	if w == nil || w.State != database.MemberWriteBackWritten || w.WriteBackTx != first.Result.WriteBackTxHash || w.CycleID != first.CycleID {
		t.Fatalf("the write-back is not registered as written by its cycle: %+v", w)
	}
	second := f.cycle(t)
	err := f.o.executePhase9(ctx, second)
	if !errors.Is(err, database.ErrMemberAlreadyWrittenBack) || second.Result.WriteBackState != WriteBackRefusedAlreadyWritten {
		t.Fatalf("want ErrMemberAlreadyWrittenBack / %s, got %v / %s", WriteBackRefusedAlreadyWritten, err, second.Result.WriteBackState)
	}
	if !strings.Contains(err.Error(), first.Result.WriteBackTxHash) {
		t.Fatalf("the refusal does not name the write-back already on Accumulate: %v", err)
	}
}

func TestAWriteBackNeverSentReleasesTheMember(t *testing.T) {
	f := newWriteBackFixture(t, fmt.Errorf("%w: insufficient credits: have 1, need 10", ErrWriteBackNotSent))
	ctx := context.Background()
	failed := f.cycle(t)
	if err := f.o.executePhase9(ctx, failed); err == nil {
		t.Fatal("a write-back that was not sent reads as written")
	}
	if w := f.registered(t); w == nil || w.State != database.MemberWriteBackNotSent || !strings.Contains(w.Reason, "insufficient credits") {
		t.Fatalf("an unsent write-back is registered as %+v; want not_sent, saying why", w)
	}
	retry := f.cycle(t)
	if err := f.o.executePhase9(ctx, retry); err != nil {
		t.Fatalf("a retry after a write-back that was never sent: %v", err)
	}
	if w := f.registered(t); w.State != database.MemberWriteBackWritten || w.CycleID != retry.CycleID {
		t.Fatalf("the retry's write-back is registered as %+v", w)
	}
}

func TestAWriteBackWithAnUnknownOutcomeStopsAnother(t *testing.T) {
	f := newWriteBackFixture(t, errors.New("failed to submit envelope: context deadline exceeded"))
	ctx := context.Background()
	unknown := f.cycle(t)
	err := f.o.executePhase9(ctx, unknown)
	if err == nil || unknown.Result.WriteBackState != WriteBackUnresolved {
		t.Fatalf("a submission with no answer: err %v, state %s; want %s", err, unknown.Result.WriteBackState, WriteBackUnresolved)
	}
	if w := f.registered(t); w == nil || w.State != database.MemberWriteBackClaimed || w.CycleID != unknown.CycleID {
		t.Fatalf("the unanswered submission's claim: %+v; want it kept", w)
	}
	next := f.cycle(t)
	err = f.o.executePhase9(ctx, next)
	if !errors.Is(err, database.ErrMemberWriteBackUnresolved) || f.sub.n != 1 || next.Result.WriteBackState != WriteBackRefusedUnresolved {
		t.Fatalf("a write-back after an unanswered one: err %v, submissions %d, state %s", err, f.sub.n, next.Result.WriteBackState)
	}
}

// A proof cycle for a member already written back does nothing - no observation, attestation, bundle or
// outcome - and says so; it does not record a failure over the member's written-back outcome.
func TestAProofCycleForAWrittenBackMemberDoesNothing(t *testing.T) {
	db := s1OpenDB(t)
	ctx := context.Background()
	o := s1Orchestrator(t, db)
	o.config.Registry = strategy.NewRegistry()
	id := fmt.Sprintf("f59-start-%d", time.Now().UnixNano())
	s1Seed(ctx, t, db, id)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM intent_member_outcomes WHERE intent_id = $1`, id)
		db.Exec(`DELETE FROM member_write_backs WHERE intent_id = $1`, id)
	})
	lifecycle := o.config.Repos.IntentLifecycle
	if err := lifecycle.ClaimMemberWriteBack(ctx, id, 84532, "cycle-earlier", "validator-6"); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.RecordMemberWriteBack(ctx, id, 84532, "cycle-earlier", "acc://"+strings.Repeat("ab", 32)+"@results.acme/data"); err != nil {
		t.Fatal(err)
	}
	req := memberCycle(id, "84532", []int64{84532}, 1, nil).Request
	req.ProofClass = string(LaneOnDemand)
	req.TxHashes = []string{"0x" + strings.Repeat("cd", 32)}
	_, err := o.StartProofCycle(ctx, req)
	if !errors.Is(err, database.ErrMemberAlreadyWrittenBack) {
		t.Fatalf("a proof cycle for a written-back member: want ErrMemberAlreadyWrittenBack, got %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM intent_member_outcomes WHERE intent_id = $1`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the refused cycle recorded an outcome (%d, %v)", n, err)
	}
}
