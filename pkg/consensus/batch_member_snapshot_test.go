package consensus

import (
	"testing"
	"time"
)

// RB3-F47: every chain member of one intent was queued holding the SAME *PendingAttestation. Each
// member then records its own outcome on it (RunBatchMemberAttestation sets TargetChainOutcome,
// RunBatchMemberRefusal sets TargetChainFailed and FailureReason) while its sibling's cycle reads
// them - one chain's result could stand in for the other's. A dropped member whose refusal read its
// sibling's Confirmed was taken as "reported settled with no settlement transaction" and its
// failure was never recorded.

type snapshotEnqueuer struct {
	*fakeEnqueuer
	atts map[int64]interface{}
}

func (s *snapshotEnqueuer) EnqueueForBatch(intentID, adi string, chainID int64, acct [20]byte, op [32]byte, legs, att interface{},
	h uint64, p string, bt time.Time, tx string) error {
	s.atts[chainID] = att
	return s.fakeEnqueuer.EnqueueForBatch(intentID, adi, chainID, acct, op, legs, att, h, p, bt, tx)
}

func TestEnqueueForBatch_EachChainMemberHasItsOwnSnapshot(t *testing.T) {
	e := &snapshotEnqueuer{fakeEnqueuer: newFakeEnqueuer(), atts: map[int64]interface{}{}}
	if err := enqueue(refusalValidator(e), batchableIntent(t, "i1", 84532, 421614)); err != nil {
		t.Fatal(err)
	}
	base, _ := e.atts[84532].(*PendingAttestation)
	arb, _ := e.atts[421614].(*PendingAttestation)
	if base == nil || arb == nil {
		t.Fatalf("members not queued with a snapshot: %v", e.atts)
	}
	if base == arb {
		t.Fatal("two chain members share one snapshot - one chain's outcome overwrites the other's")
	}
	base.TargetChainOutcome = TargetChainConfirmedOutcome
	arb.TargetChainOutcome = TargetChainFailed
	arb.FailureReason = "dropped"
	if base.TargetChainOutcome != TargetChainConfirmedOutcome || base.FailureReason != "" {
		t.Fatal("recording one member's outcome changed its sibling's")
	}
	if base.IntentID != "i1" || arb.IntentID != "i1" || !base.Replayed || !arb.Replayed {
		t.Fatal("each member's snapshot must still be the intent's")
	}
}
