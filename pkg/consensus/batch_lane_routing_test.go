package consensus

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// Lane routing is source-checked in the same style as batch_enqueue_every_validator_test.go:
// the properties that matter are about WHICH CALL is reachable under WHICH CONDITION, and a
// stub-driven test would pass just as happily with the guard removed.

// laneSource is the enqueue (batch_quorum_prover.go) together with the plan it follows
// (batch_refusal.go), where the lane is chosen.
func laneSource(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	for _, f := range []string{"batch_quorum_prover.go", "batch_refusal.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		out.Write(b)
	}
	return out.String()
}

// proofClass must select the MECHANISM, never whether to enqueue. Routing on_demand off the
// batch path entirely cannot settle a CertenAccountV7 account: _authorizeLeaf computes only the
// batch-form leaf. This is the same invariant TestEnqueueIsNotGatedOnProofClass protects, now
// that a proofClass check legitimately exists in the function.
func TestOnDemandRoutesToADifferentLaneNotOffThePath(t *testing.T) {
	src := laneSource(t)
	if !strings.Contains(src, "EnqueueOnDemand(") {
		t.Fatal("no EnqueueOnDemand call — on_demand intents are not routed to the intent-keyed lane")
	}
	if !strings.Contains(src, "EnqueueForBatch(") {
		t.Fatal("no EnqueueForBatch call — the on_cadence period lane is gone")
	}
	// No arm may simply skip enqueueing: a sequential intent's later member, the intent-keyed lane
	// and the period lane are the arms of one choice, and each arm enqueues.
	arm := strings.Index(src, "case m.after != nil:\n\t\t\tenqErr = bv.batchEnqueuer.EnqueueAfter(")
	if arm < 0 {
		t.Fatal("the sequential successor arm does not enqueue")
	}
	window := src[arm:min(arm+1200, len(src))]
	if !strings.Contains(window, "case m.onDemand:\n\t\t\tenqErr = bv.batchEnqueuer.EnqueueOnDemand(") {
		t.Fatal("the on-demand arm does not enqueue")
	}
	if !strings.Contains(window, "default:\n\t\t\tenqErr = bv.batchEnqueuer.EnqueueForBatch(") {
		t.Fatal("the period arm does not enqueue")
	}
}

// An unrecognised proofClass must be refused, never defaulted into a lane: a member in the wrong
// lane on one node derives a bundleId its peers never will. (It used to "fall back" to the
// per-intent path, which is gone; the refusal is permanent because the class is in the intent's
// final bytes.)
func TestUnknownProofClassIsRefusedRatherThanDefaulted(t *testing.T) {
	ci := batchableIntent(t, "i-weird-class", 84532)
	ci.IntentData = []byte(`{"intent_id":"i-weird-class","proof_class":"sometimes"}`)
	f := newFakeEnqueuer()
	err := refusalValidator(f).enqueueForBatch(ci, nil, nil, 7, nil, nil, nil, "", nil, "", 7)
	var r *BatchRefusal
	if !errors.As(err, &r) || !r.Permanent {
		t.Fatalf("an unrecognised proof class must be a permanent refusal, got %v", err)
	}
	if f.adds != 0 {
		t.Fatal("an intent with an unrecognised proof class was queued into a lane")
	}
}

// The lane must be OFF by default, so deploying this code changes nothing until the flag is set.
func TestOnDemandLaneIsOffByDefault(t *testing.T) {
	t.Setenv("ON_DEMAND_INTENT_KEYED", "")
	if on, err := onDemandLaneEnabled(); on || err != nil {
		t.Fatalf("the on-demand lane is enabled (%v, %v) with the flag unset; deploying would change "+
			"settlement behaviour immediately", on, err)
	}
	for _, v := range []string{"false", "0", "no", "off"} {
		t.Setenv("ON_DEMAND_INTENT_KEYED", v)
		if on, err := onDemandLaneEnabled(); on || err != nil {
			t.Fatalf("ON_DEMAND_INTENT_KEYED=%q: (%v, %v); want off", v, on, err)
		}
	}
	for _, v := range []string{"true", "TRUE", "True", " true ", "1", "on"} {
		t.Setenv("ON_DEMAND_INTENT_KEYED", v)
		if on, err := onDemandLaneEnabled(); !on || err != nil {
			t.Fatalf("ON_DEMAND_INTENT_KEYED=%q: (%v, %v); want on", v, on, err)
		}
	}
	// RB3-F71 sweep: a value that is not a switch is refused by name. It used to read as "off".
	t.Setenv("ON_DEMAND_INTENT_KEYED", "TRUE-ish")
	if _, err := onDemandLaneEnabled(); err == nil || !strings.Contains(err.Error(), "ON_DEMAND_INTENT_KEYED") {
		t.Fatalf("ON_DEMAND_INTENT_KEYED=TRUE-ish was not refused by name: %v", err)
	}
}

// With the flag off, an on_demand intent must take the period path — the exact behaviour it has
// today. That is what makes the deploy a no-op and the flag flip the only behavioural change.
func TestFlagOffKeepsOnDemandOnThePeriodPath(t *testing.T) {
	src := laneSource(t)
	if !strings.Contains(src, "lane, err := onDemandLaneEnabled()") ||
		!strings.Contains(src, `proofClass == "on_demand" && lane`) {
		t.Fatal("the on-demand lane is not gated on the flag; deploying would immediately " +
			"change how on_demand intents settle")
	}
}

// Both lanes must elect over the SAME roster, or two nodes could each believe they lead.
func TestBothLanesShareOneRoster(t *testing.T) {
	got := BatchLeaderRoster()
	want := batchLeaderRoster()
	if len(got) != len(want) {
		t.Fatalf("exported roster has %d entries, internal has %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("roster mismatch at %d: %q vs %q", i, got[i], want[i])
		}
	}
}
