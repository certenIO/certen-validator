package execution

import (
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Admission outcomes are typed, so consensus can tell a re-run from a replay from an outage
// =============================================================================
//
// Consensus refuses an intent the batch path cannot settle, by name. That is only correct if it
// can tell three things apart: the SAME intent arriving again (already queued - not a refusal,
// and never a second execution), a DIFFERENT intent carrying an operation already queued (a
// replay - refused for good), and CERTEN being unable to settle on the chain right now (an
// outage - retried, never blamed on the intent).

func twoChainStack(t *testing.T, a, b int64) *BatchStack {
	t.Helper()
	r, err := NewEVMChainResolver(&config.AnchorConfig{}, map[int64]common.Address{
		a: common.HexToAddress("0x3c0bf2dCC9D2945a933E36F8Ee1E10D8feEA9a32"),
		b: common.HexToAddress("0x4b9eA187772E115641Fd40F35BF7a84925e7A035"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &BatchStack{
		Resolver:       r,
		Mempool:        NewBatchMempool(BatchMempoolConfig{MaxBatchSize: 64}),
		Orchestrators:  map[int64]*BatchOrchestrator{a: {}, b: {}},
		MemberOutcomes: recordedOutcomes{},
	}
}

func admissionLeg(chainID int64) []mirrorLeg {
	return []mirrorLeg{{LegID: "l0", ChainID: chainID, Target: tgt(0xAA), Value: big.NewInt(1000)}}
}

func TestEnqueueForBatch_SameIntentAgainIsAlreadyQueued(t *testing.T) {
	s := stackForChain(t, 11155111)
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, "")
	if !errors.Is(err, ErrMemberAlreadyQueued) {
		t.Fatalf("re-enqueueing the same intent must report ErrMemberAlreadyQueued, got %v", err)
	}
	if s.Mempool.PendingCount() != 1 {
		t.Fatalf("pending=%d want 1", s.Mempool.PendingCount())
	}
}

func TestEnqueueOnDemand_SameIntentAgainIsAlreadyQueued(t *testing.T) {
	s := stackForChain(t, 11155111)
	if err := s.EnqueueOnDemand("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	err := s.EnqueueOnDemand("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, "")
	if !errors.Is(err, ErrMemberAlreadyQueued) {
		t.Fatalf("re-enqueueing the same on-demand intent must report ErrMemberAlreadyQueued, got %v", err)
	}
}

func TestEnqueue_OtherIntentWithAQueuedOperationIsAReplay(t *testing.T) {
	for _, onDemand := range []bool{false, true} {
		s := stackForChain(t, 11155111)
		enq := s.EnqueueForBatch
		if onDemand {
			enq = s.EnqueueOnDemand
		}
		if err := enq("first", "acc://a.acme", 11155111, acct(1), opid(7), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
			t.Fatal(err)
		}
		err := enq("second", "acc://a.acme", 11155111, acct(1), opid(7), admissionLeg(11155111), testAtt, testGov, 101, "", time.Time{}, "")
		if !errors.Is(err, ErrOperationAlreadyQueued) {
			t.Fatalf("onDemand=%v: a second intent with a queued operation must be ErrOperationAlreadyQueued, got %v", onDemand, err)
		}
		if !strings.Contains(err.Error(), "first") {
			t.Fatalf("onDemand=%v: the refusal must name the intent that holds the operation: %v", onDemand, err)
		}
	}
}

func TestEnqueue_UnconfiguredChainAndMissingHeightAreUnavailable(t *testing.T) {
	s := stackForChain(t, 11155111)
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 84532, acct(1), opid(1), admissionLeg(84532), testAtt, testGov, 100, "", time.Time{}, ""); !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("a chain with no orchestrator is CERTEN's outage, not the intent's defect: %v", err)
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 0, "", time.Time{}, ""); !errors.Is(err, ErrBatchUnavailable) {
		t.Fatalf("a member with no commit height is CERTEN's outage, not the intent's defect: %v", err)
	}
}

// CheckMember applies exactly the admission rules of the enqueue it mirrors, and adds nothing.
func TestCheckMember_AgreesWithEnqueueAndAddsNothing(t *testing.T) {
	type attempt struct {
		name         string
		chain        int64
		adi          string
		op           [32]byte
		legs         interface{}
		height       uint64
		wantAccepted bool
	}
	cases := []attempt{
		{"valid", 11155111, "acc://a.acme", opid(1), admissionLeg(11155111), 100, true},
		{"unconfigured chain", 84532, "acc://a.acme", opid(1), admissionLeg(84532), 100, false},
		{"no commit height", 11155111, "acc://a.acme", opid(1), admissionLeg(11155111), 0, false},
		{"no ADI URL", 11155111, "", opid(1), admissionLeg(11155111), 100, false},
		{"zero operation", 11155111, "acc://a.acme", [32]byte{}, admissionLeg(11155111), 100, false},
		{"malformed legs", 11155111, "acc://a.acme", opid(1), "not legs", 100, false},
		{"leg on another chain", 11155111, "acc://a.acme", opid(1), admissionLeg(84532), 100, false},
	}
	for _, onDemand := range []bool{false, true} {
		for _, c := range cases {
			check := stackForChain(t, 11155111)
			checkErr := check.CheckMember(onDemand, "i1", c.adi, c.chain, acct(1), c.op, c.legs, c.height)
			if check.Mempool.PendingCount() != 0 || check.Mempool.OnDemandCount() != 0 {
				t.Fatalf("%s (onDemand=%v): CheckMember added a member", c.name, onDemand)
			}
			enq := stackForChain(t, 11155111)
			var enqErr error
			if onDemand {
				enqErr = enq.EnqueueOnDemand("i1", c.adi, c.chain, acct(1), c.op, c.legs, testAtt, testGov, c.height, "", time.Time{}, "")
			} else {
				enqErr = enq.EnqueueForBatch("i1", c.adi, c.chain, acct(1), c.op, c.legs, testAtt, testGov, c.height, "", time.Time{}, "")
			}
			if (checkErr == nil) != c.wantAccepted || (enqErr == nil) != c.wantAccepted {
				t.Fatalf("%s (onDemand=%v): check=%v enqueue=%v, want accepted=%v", c.name, onDemand, checkErr, enqErr, c.wantAccepted)
			}
			if errors.Is(checkErr, ErrBatchUnavailable) != errors.Is(enqErr, ErrBatchUnavailable) {
				t.Fatalf("%s (onDemand=%v): check and enqueue classify differently: %v vs %v", c.name, onDemand, checkErr, enqErr)
			}
		}
	}
}

func TestCheckMember_ReportsAReplayBeforeAnythingIsAdded(t *testing.T) {
	s := stackForChain(t, 11155111)
	if err := s.EnqueueForBatch("first", "acc://a.acme", 11155111, acct(1), opid(7), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckMember(false, "second", "acc://a.acme", 11155111, acct(1), opid(7), admissionLeg(11155111), 101); !errors.Is(err, ErrOperationAlreadyQueued) {
		t.Fatalf("CheckMember must see the replay: %v", err)
	}
	// The same intent re-running is not a replay; its enqueue then reports ErrMemberAlreadyQueued.
	if err := s.CheckMember(false, "first", "acc://a.acme", 11155111, acct(1), opid(7), admissionLeg(11155111), 100); err != nil {
		t.Fatalf("CheckMember must accept the same intent re-running: %v", err)
	}
}

// Rolling a member back leaves the pool as if it had never been added - including its dedupe
// entry, or it could never be queued again.
func TestRemoveMember_RollsBackEitherLane(t *testing.T) {
	for _, onDemand := range []bool{false, true} {
		s := stackForChain(t, 11155111)
		enq := s.EnqueueForBatch
		if onDemand {
			enq = s.EnqueueOnDemand
		}
		if err := enq("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
			t.Fatal(err)
		}
		s.RemoveMember(onDemand, "i1", 11155111, opid(1))
		if s.Mempool.PendingCount() != 0 || s.Mempool.OnDemandCount() != 0 {
			t.Fatalf("onDemand=%v: member still pooled after rollback", onDemand)
		}
		if err := enq("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
			t.Fatalf("onDemand=%v: a rolled-back member could not be queued again: %v", onDemand, err)
		}
	}
}

// RB3-F38: dropping one chain's member of a multi-chain intent must not touch its member on
// another chain - that one would vanish while still marked as queued, and never settle. A drop is
// an outcome marked on the member (RB3-F54), keyed by member exactly as the removal was.
func TestMarkOutcome_TouchesOnlyTheMarkedChainsMember(t *testing.T) {
	s := twoChainStack(t, 11155111, 84532)
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 84532, acct(1), opid(1), admissionLeg(84532), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	onA := s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks)
	if len(onA) != 1 {
		t.Fatalf("precondition: one member on chain A, got %d", len(onA))
	}
	s.Mempool.MarkOutcome([]*PendingBatchIntent{{GovernanceCommitment: testGov, IntentID: "i1", ChainID: 11155111}}, MemberDropped)
	if got := s.Mempool.PendingCountForChain(84532); got != 1 {
		t.Fatalf("dropping chain A's member resolved chain B's member too (pending on B = %d)", got)
	}
	if got := s.Mempool.PendingCountForChain(11155111); got != 0 {
		t.Fatalf("chain A's member was not dropped (pending on A = %d)", got)
	}
	// It stays in its period, so the period's trees are what every validator derives.
	if got := s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks); len(got) != 1 || got[0].Outcome != MemberDropped {
		t.Fatalf("a dropped member must stay in its period with its outcome, got %+v", got)
	}
}

// The enqueue rollback (DropMembers) still removes outright, and only the named chain's member.
func TestDropMembers_RemovesOnlyTheDroppedChainsMember(t *testing.T) {
	s := twoChainStack(t, 11155111, 84532)
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 11155111, acct(1), opid(1), admissionLeg(11155111), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueForBatch("i1", "acc://a.acme", 84532, acct(1), opid(1), admissionLeg(84532), testAtt, testGov, 100, "", time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	onA := s.Mempool.PeriodMembers(11155111, 100, DefaultBatchPeriodBlocks)
	if len(onA) != 1 {
		t.Fatalf("precondition: one member on chain A, got %d", len(onA))
	}
	s.Mempool.DropMembers(onA)
	if got := s.Mempool.PendingCountForChain(84532); got != 1 {
		t.Fatalf("dropping chain A's member removed chain B's member too (pending on B = %d)", got)
	}
	if got := s.Mempool.PendingCountForChain(11155111); got != 0 {
		t.Fatalf("chain A's member was not dropped (pending on A = %d)", got)
	}
}

// opidOf gives each fixture intent its own operation ID. In production the operation ID is the
// canonical hash of all four intent blobs, and the intent ID is carried inside the intent blob, so
// two different intent IDs can never share an operation ID; a fixture that gives distinct intents
// one operation ID models a state that cannot occur, and the mempool now refuses it as a replay.
func opidOf(intentID string) [32]byte {
	var o [32]byte
	copy(o[:], crypto.Keccak256([]byte("fixture-operation:"+intentID)))
	return o
}
