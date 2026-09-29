package consensus

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB4-F55 repair. A member whose proof cycle failed has a recorded outcome, so the batch path never queues it
// again (RB3-F141) and nothing re-runs its proof cycle. Intent 000ac79a's base member settled on chain and was
// recorded failed by a cycle a fleet restart broke. The repair re-derives the member's round exactly as discovery
// does (re-processing the intent) and, at that one decided member - only when a repair names it - runs the
// member's proof cycle on its settlement, from the snapshot the round captured. Nothing is invented: a snapshot
// that lacks what the proof cycle binds is refused by name.

type startedRepair struct {
	att     *PendingAttestation
	tx      string
	chainID int64
	lane    string
}

func repairValidator(t *testing.T, f *fakeEnqueuer) (*BFTValidator, *[]startedRepair) {
	t.Helper()
	bv := refusalValidator(f)
	var started []startedRepair
	bv.memberRepairStart = func(_ context.Context, att *PendingAttestation, tx string, chainID int64, lane string) {
		started = append(started, startedRepair{att, tx, chainID, lane})
	}
	return bv, &started
}

// A round's values as consensus would have them: the committed block's bundle, commitment and governance root,
// and G0-G2.
func committedRound(ci *CertenIntent) func(bv *BFTValidator) error {
	vb := &ValidatorBlock{BundleID: "0x" + strings.Repeat("0a", 32), OperationCommitment: "0x" + strings.Repeat("0b", 32)}
	vb.GovernanceProof.MerkleRoot = "0x" + strings.Repeat("0c", 32)
	return func(bv *BFTValidator) error {
		return bv.enqueueForBatch(ci, &proof.CertenProof{}, vb, 10007772, &proof.G0Result{}, &proof.G1Result{}, &proof.G2Result{},
			"bls-signature", []string{"validator-signature"}, "G2", 10007772)
	}
}

// repairIntent is an intent as discovery delivers it: with the Accumulate transaction that carries it.
func repairIntent(t *testing.T, id string, chains ...int64) *CertenIntent {
	ci := batchableIntent(t, id, chains...)
	ci.TransactionHash = "db0236d87fa3c0fd8e6f1c21cba1ce7527bf592c5f727632ad7f329cacbe0e48"
	return ci
}

func decided(f *fakeEnqueuer, chains ...int64) {
	for _, c := range chains {
		f.addErr[c] = fmt.Errorf("%w: recorded", ErrMemberAlreadyDecided)
	}
}

func TestANamedDecidedMemberIsReDrivenFromItsRederivedRound(t *testing.T) {
	f := newFakeEnqueuer()
	bv, started := repairValidator(t, f)
	ci := repairIntent(t, "000ac79a-repair", 84532, 421614)
	decided(f, 84532, 421614)

	reach, disarm := bv.ArmMemberRepair(MemberRepair{IntentID: ci.IntentID, ChainID: 84532, SettlementTx: "0xc409", Apply: true})
	defer disarm()
	if err := committedRound(ci)(bv); err != nil {
		t.Fatalf("the re-derived round: %v", err)
	}

	if len(*started) != 1 {
		t.Fatalf("THE regression: the named decided member's proof cycle ran %d times, want 1 (and never the other member)", len(*started))
	}
	s := (*started)[0]
	if s.chainID != 84532 || s.tx != "0xc409" || s.lane != "on_cadence" || s.att.IntentID != ci.IntentID ||
		s.att.BundleIDHex == "" || s.att.GovernanceProofRoot == "" || s.att.OperationCommitment == "" || s.att.G2Proof == nil {
		t.Fatalf("the proof cycle was not started from the round's snapshot: %+v / %+v", s, s.att)
	}
	select {
	case r := <-reach:
		if r.Err != nil || !r.Started || r.Snapshot.BundleID != s.att.BundleIDHex || r.Snapshot.Lane != "on_cadence" {
			t.Fatalf("the repair was told %+v", r)
		}
	default:
		t.Fatal("the repair was not told its member was reached")
	}
}

func TestADecidedMemberNoRepairNamesIsNotReDriven(t *testing.T) {
	f := newFakeEnqueuer()
	bv, started := repairValidator(t, f)
	ci := repairIntent(t, "000ac79a-unnamed", 84532)
	decided(f, 84532)
	if err := committedRound(ci)(bv); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 0 {
		t.Fatal("a decided member was re-driven without a repair naming it")
	}
}

func TestARepairIsUsedOnce(t *testing.T) {
	f := newFakeEnqueuer()
	bv, started := repairValidator(t, f)
	ci := repairIntent(t, "000ac79a-once", 84532)
	decided(f, 84532)
	_, disarm := bv.ArmMemberRepair(MemberRepair{IntentID: ci.IntentID, ChainID: 84532, SettlementTx: "0xc409", Apply: true})
	defer disarm()
	round := committedRound(ci)
	if err := round(bv); err != nil {
		t.Fatal(err)
	}
	if err := round(bv); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 1 {
		t.Fatalf("one repair re-drove the member %d times", len(*started))
	}
}

func TestADryRunRepairReportsTheSnapshotAndStartsNothing(t *testing.T) {
	f := newFakeEnqueuer()
	bv, started := repairValidator(t, f)
	ci := repairIntent(t, "000ac79a-dry", 84532)
	decided(f, 84532)
	reach, disarm := bv.ArmMemberRepair(MemberRepair{IntentID: ci.IntentID, ChainID: 84532, SettlementTx: "0xc409"})
	defer disarm()
	if err := committedRound(ci)(bv); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 0 {
		t.Fatal("a dry run started a proof cycle")
	}
	r := <-reach
	if r.Err != nil || r.Started || r.Snapshot.GovernanceRoot == "" || r.Snapshot.OperationCommitment == "" || !r.Snapshot.GovernanceLevels {
		t.Fatalf("a dry run reports %+v", r)
	}
}

func TestARoundWithoutWhatTheProofCycleBindsIsRefusedByName(t *testing.T) {
	f := newFakeEnqueuer()
	bv, started := repairValidator(t, f)
	ci := repairIntent(t, "000ac79a-incomplete", 84532)
	decided(f, 84532)
	reach, disarm := bv.ArmMemberRepair(MemberRepair{IntentID: ci.IntentID, ChainID: 84532, SettlementTx: "0xc409", Apply: true})
	defer disarm()
	// No committed block and no governance levels: nothing to bind the proof cycle to.
	if err := bv.enqueueForBatch(ci, nil, nil, 7, nil, nil, nil, "", nil, "", 7); err != nil {
		t.Fatal(err)
	}
	if len(*started) != 0 {
		t.Fatal("a proof cycle was started from a round that binds nothing")
	}
	r := <-reach
	if r.Err == nil || r.Started || !strings.Contains(r.Err.Error(), "bundle") || !strings.Contains(r.Err.Error(), "G0") {
		t.Fatalf("an incomplete round must be refused naming what it lacks: %+v", r)
	}
}
