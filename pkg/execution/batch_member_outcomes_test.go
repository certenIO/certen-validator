package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/database"
)

// recordedOutcomes is a member outcome store keyed "intent/chain"; an absent key has no outcome.
type recordedOutcomes map[string]*database.RecordedMemberOutcome

func (r recordedOutcomes) MemberOutcomeOf(_ context.Context, intentID string, chainID int64) (*database.RecordedMemberOutcome, error) {
	return r[fmt.Sprintf("%s/%d", intentID, chainID)], nil
}

type unreadableOutcomes struct{}

func (unreadableOutcomes) MemberOutcomeOf(context.Context, string, int64) (*database.RecordedMemberOutcome, error) {
	return nil, errors.New("connection refused")
}

// RB3-F141: a member with a recorded outcome is finished. Re-driven - a restart's rewind, a retry after a
// commit the proposer did not see - it is answered as decided in every lane and queued nowhere, because the
// mempool forgot it when it was disposed and queueing it again would settle, attest and write it back twice.
func TestAMemberWithARecordedOutcomeIsNeverQueuedAgain(t *testing.T) {
	r, err := NewEVMChainResolver(&config.AnchorConfig{}, map[int64]common.Address{
		odChain:      common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
		seqPredChain: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	decided := &database.RecordedMemberOutcome{Settlement: database.MemberSettlementSettled, ProofCycle: database.MemberProofCycleWritten,
		SettlementTx: "0xabc", CycleID: "cycle-1", RecordedAt: time.Unix(1_800_000_100, 0)}
	s := &BatchStack{Incarnation: testIncarnation, Resolver: r, Mempool: NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64}),
		Orchestrators: map[int64]*BatchOrchestrator{odChain: {incarnation: testIncarnation, screen: acceptEveryAccount}, seqPredChain: {incarnation: testIncarnation, screen: acceptEveryAccount}},
		MemberOutcomes: recordedOutcomes{
			fmt.Sprintf("done/%d", seqPredChain): decided,
			fmt.Sprintf("done/%d", odChain):      decided,
		}}
	commit := time.Unix(1_800_000_000, 0).UTC()
	legsOn := func(c int64) []mirrorLeg {
		return []mirrorLeg{{LegID: "leg", ChainID: c, Target: tgt(1), Value: big.NewInt(1)}}
	}

	if err := s.EnqueueForBatch("done", "acc://a.acme", seqPredChain, acct(1), opid(3), legsOn(seqPredChain), testAtt, testGov, 100, "", commit, ""); !errors.Is(err, ErrMemberAlreadyDecided) {
		t.Fatalf("period lane: %v", err)
	}
	if err := s.EnqueueOnDemand("done", "acc://a.acme", odChain, acct(1), opid(4), legsOn(odChain), testAtt, testGov, 100, "", commit, ""); !errors.Is(err, ErrMemberAlreadyDecided) {
		t.Fatalf("intent-keyed lane: %v", err)
	}
	// A decided successor is answered before its predecessor - finished and gone - is looked for.
	after := consensus.SequencePredecessor{ChainID: seqPredChain, OperationID: opid(3), Position: 1}
	if err := s.EnqueueAfter("done", "acc://a.acme", odChain, acct(1), opid(4), legsOn(odChain), testAtt, testGov, 100, "", commit, "", after); !errors.Is(err, ErrMemberAlreadyDecided) {
		t.Fatalf("successor: %v", err)
	}
	if n := s.Mempool.PendingCount() + s.Mempool.OnDemandCount(); n != 0 {
		t.Fatalf("%d members queued for an intent that is finished", n)
	}

	// An undecided intent is queued as before.
	if err := s.EnqueueForBatch("new", "acc://a.acme", seqPredChain, acct(1), opid(5), legsOn(seqPredChain), testAtt, testGov, 100, "", commit, ""); err != nil {
		t.Fatalf("undecided member: %v", err)
	}

	// Without the store, or when it cannot be read, a finished member cannot be told from a new one:
	// nothing is queued, and the intent is retried rather than held against it.
	s.MemberOutcomes = nil
	if err := s.EnqueueForBatch("other", "acc://a.acme", seqPredChain, acct(1), opid(6), legsOn(seqPredChain), testAtt, testGov, 100, "", commit, ""); !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("unwired store: %v", err)
	}
	s.MemberOutcomes = unreadableOutcomes{}
	if err := s.EnqueueOnDemand("other", "acc://a.acme", odChain, acct(1), opid(6), legsOn(odChain), testAtt, testGov, 100, "", commit, ""); !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("unreadable store: %v", err)
	}
}
