package execution

import "testing"

// The lane names ARE the proof classes the gateway prices on.
//
// reportBatchCosts sends string(LaneOnCadence) / string(LaneOnDemand) straight through to the
// gateway's cost-event ingest, which validates `proof_class` against an enum of exactly
// "on_demand" and "on_cadence" and backs it with a CHECK constraint on cost_events.
//
// So these constants are not internal names — they are a wire contract with another service.
// Renaming a lane for internal clarity would make every cost event 400 at ingest, and because
// reporting is asynchronous and WAL-backed that failure surfaces as "this chain has no cost
// data" rather than as an error on the settle path: the chain quietly becomes unpriceable while
// settlement keeps succeeding. That is the same silent-failure shape that left the fee layer
// with no measurements for weeks.
func TestLaneNamesMatchGatewayProofClassEnum(t *testing.T) {
	for _, tc := range []struct {
		lane BatchLane
		want string
	}{
		{LaneOnCadence, "on_cadence"},
		{LaneOnDemand, "on_demand"},
	} {
		if got := string(tc.lane); got != tc.want {
			t.Fatalf("lane %q must serialise as %q for the gateway's proof_class enum; "+
				"changing it breaks cost ingest for every intent on this lane", got, tc.want)
		}
	}
}

// The two lanes must stay distinct. If they ever collapsed to the same string the gateway would
// price both classes from one pooled history — the exact defect that carrying proof_class was
// introduced to fix, silently restored.
func TestLanesAreDistinctClasses(t *testing.T) {
	if string(LaneOnCadence) == string(LaneOnDemand) {
		t.Fatal("on_cadence and on_demand must remain distinct; a shared value re-pools the " +
			"two cost histories and misprices both classes")
	}
}
