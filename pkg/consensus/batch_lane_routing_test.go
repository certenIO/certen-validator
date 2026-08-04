package consensus

import (
	"os"
	"strings"
	"testing"
)

// Lane routing is source-checked in the same style as batch_enqueue_every_validator_test.go:
// the properties that matter are about WHICH CALL is reachable under WHICH CONDITION, and a
// stub-driven test would pass just as happily with the guard removed.

func laneSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("batch_quorum_prover.go")
	if err != nil {
		t.Fatalf("reading batch_quorum_prover.go: %v", err)
	}
	return string(b)
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
	// Neither branch may simply skip enqueueing.
	enq := strings.Index(src, "onDemand := proofClass ==")
	if enq < 0 {
		t.Fatal("lane selection not found")
	}
	window := src[enq:min(enq+900, len(src))]
	if strings.Contains(window, "return true") && !strings.Contains(window, "enqErr") {
		t.Fatal("the lane branch can return success without enqueueing anything")
	}
}

// An unrecognised proofClass must fall back, never default into a lane. A member in the wrong
// lane on one node derives a bundleId its peers never will.
func TestUnknownProofClassFallsBackRatherThanDefaulting(t *testing.T) {
	src := laneSource(t)
	if !strings.Contains(src, "GetProofClass()") {
		t.Fatal("proof class is not resolved before routing")
	}
	i := strings.Index(src, "proofClass, pcErr := certenIntent.GetProofClass()")
	if i < 0 {
		t.Fatal("proof class resolution not found in enqueueForBatch")
	}
	window := src[i:min(i+400, len(src))]
	if !strings.Contains(window, "return false") {
		t.Fatal("a proof class that cannot be resolved does not fall back; it would default " +
			"into a lane")
	}
}

// The lane must be OFF by default, so deploying this code changes nothing until the flag is set.
func TestOnDemandLaneIsOffByDefault(t *testing.T) {
	t.Setenv("ON_DEMAND_INTENT_KEYED", "")
	if onDemandLaneEnabled() {
		t.Fatal("the on-demand lane is enabled with the flag unset; deploying would change " +
			"settlement behaviour immediately")
	}
	for _, v := range []string{"false", "0", "no", "off", "TRUE-ish"} {
		t.Setenv("ON_DEMAND_INTENT_KEYED", v)
		if onDemandLaneEnabled() {
			t.Fatalf("ON_DEMAND_INTENT_KEYED=%q enabled the lane; only \"true\" may", v)
		}
	}
	for _, v := range []string{"true", "TRUE", "True", " true "} {
		t.Setenv("ON_DEMAND_INTENT_KEYED", v)
		if !onDemandLaneEnabled() {
			t.Fatalf("ON_DEMAND_INTENT_KEYED=%q did not enable the lane", v)
		}
	}
}

// With the flag off, an on_demand intent must take the period path — the exact behaviour it has
// today. That is what makes the deploy a no-op and the flag flip the only behavioural change.
func TestFlagOffKeepsOnDemandOnThePeriodPath(t *testing.T) {
	src := laneSource(t)
	if !strings.Contains(src, `proofClass == "on_demand" && onDemandLaneEnabled()`) {
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
