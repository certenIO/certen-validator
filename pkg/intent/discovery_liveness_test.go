package intent

import (
	"testing"
	"time"
)

// The 2026-08-05 outage: ACCUMULATE_URL pointed at a dead port, GetLatestBlock failed on the
// first line of every tick, the watermark froze for hours, and every container still reported
// healthy. These tests pin the signal that makes that state visible.

// A node that has just booted has never advanced. Reporting it as stalled would make the alert
// fire on every restart, and an alert that cries wolf is one nobody reads — which is how the
// original outage stayed hidden.
func TestStatusNotStalledBeforeFirstAdvance(t *testing.T) {
	st := DiscoveryStatus{Started: false, SecondsSinceAdvance: 9999}
	if st.Stalled(2 * time.Minute) {
		t.Fatal("a node that has never advanced was reported stalled; this fires on every boot")
	}
}

// The TIME dimension of the rule, holding lag fixed above the floor so only staleness varies.
//
// Lag is deliberately set here: an earlier version of this test left it at zero, which made it
// pass against a rule that ignored lag entirely — the rule that then reported every healthy
// caught-up validator as STALLED in production. A test that constructs an impossible state
// (behind by nothing, yet expected to alarm) will happily bless the wrong behaviour.
func TestStatusStalledOnlyPastThreshold(t *testing.T) {
	cases := []struct {
		name    string
		seconds float64
		want    bool
	}{
		{"just advanced", 0, false},
		{"one missed tick", 5, false},
		{"under threshold", 119, false},
		{"at threshold", 120, false},
		{"past threshold", 121, true},
		{"the real outage", 3 * 3600, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := DiscoveryStatus{
				Started:             true,
				LagBlocks:           StallLagFloor + 1, // behind, so only staleness is under test
				SecondsSinceAdvance: tc.seconds,
			}
			if got := st.Stalled(2 * time.Minute); got != tc.want {
				t.Fatalf("Stalled(%vs, lag=%d) = %v, want %v",
					tc.seconds, st.LagBlocks, got, tc.want)
			}
		})
	}
}

// Status must be readable and correct straight off a constructed discovery service, including
// before any poll has succeeded — that is exactly the state the outage produced.
func TestStatusReflectsFrozenWatermark(t *testing.T) {
	id := &IntentDiscovery{}

	// Never polled, never advanced: lag unknown (head 0), not stalled, not started.
	st := id.Status()
	if st.Started || st.Stalled(time.Minute) {
		t.Fatal("a service that never ran should be 'starting', not stalled")
	}
	if st.ChainHead != 0 {
		t.Fatalf("ChainHead = %d before any successful poll, want 0", st.ChainHead)
	}

	// Simulate: polls succeeded and the head moved on, but processing froze 10 minutes ago.
	id.lastProcessedBlock = 6395432
	id.chainHead = 6416600
	id.lastAdvanceAt = time.Now().Add(-10 * time.Minute)

	st = id.Status()
	if !st.Started {
		t.Fatal("Started should be true once the watermark has advanced at least once")
	}
	if st.LagBlocks != 6416600-6395432 {
		t.Fatalf("LagBlocks = %d, want %d", st.LagBlocks, 6416600-6395432)
	}
	if !st.Stalled(2 * time.Minute) {
		t.Fatalf("10 minutes without advance was not reported stalled (seconds=%.0f)",
			st.SecondsSinceAdvance)
	}
}

// A catching-up node has a huge lag but IS advancing. It must not be reported stalled, or every
// recovery would page. Lag and staleness are different signals and only staleness means dead.
func TestLargeLagWhileAdvancingIsNotStalled(t *testing.T) {
	id := &IntentDiscovery{
		lastProcessedBlock: 6396328,
		chainHead:          6417584,
		lastAdvanceAt:      time.Now(), // advancing right now
	}
	st := id.Status()
	if st.LagBlocks == 0 {
		t.Fatal("test setup: expected a large lag")
	}
	if st.Stalled(2 * time.Minute) {
		t.Fatalf("a node catching up (lag %d, advancing now) was reported stalled",
			st.LagBlocks)
	}
}

// A failing head poll must be distinguishable from an idle chain. Without this the operator
// cannot tell "cannot reach Accumulate" from "nothing is happening".
func TestStatusSurfacesPollError(t *testing.T) {
	id := &IntentDiscovery{lastPollErr: `Post "https://kermit.accumulatenetwork.io/v3": EOF`}
	if got := id.Status().LastPollError; got == "" {
		t.Fatal("poll error was not surfaced; an endpoint outage looks like an idle chain")
	}

	id.lastPollErr = ""
	if got := id.Status().LastPollError; got != "" {
		t.Fatalf("LastPollError = %q after a successful poll, want empty", got)
	}
}

// Lag must never underflow. chainHead can legitimately trail the watermark by the confirmLag
// window, and a uint64 underflow there would publish a garbage gauge reading ~1.8e19.
func TestLagNeverUnderflows(t *testing.T) {
	id := &IntentDiscovery{lastProcessedBlock: 100, chainHead: 98}
	if got := id.Status().LagBlocks; got != 0 {
		t.Fatalf("LagBlocks = %d when head trails the watermark, want 0", got)
	}
}

// THE false positive this rule exists to prevent, observed live 2026-08-05.
//
// A caught-up node stops advancing because the watermark is capped at the finalize ceiling
// (head - confirmLag). Every validator in the fleet reported STALLED within ~2 minutes of
// catching up, while the chain was healthy and producing ~46 blocks/min. An alert that fires on
// healthy nodes is one nobody reads — the exact failure mode that let the original outage hide.
func TestCaughtUpNodeIsNeverStalledHoweverLongItSitsStill(t *testing.T) {
	for _, lag := range []uint64{0, 1, 2, 5, StallLagFloor} {
		st := DiscoveryStatus{Started: true, LagBlocks: lag, SecondsSinceAdvance: 3600}
		if st.Stalled(2 * time.Minute) {
			t.Fatalf("lag=%d idle=1h reported STALLED; a caught-up node legitimately stops "+
				"advancing and must not page", lag)
		}
	}
}

// The real thing must still fire: behind AND frozen.
func TestBehindAndFrozenIsStillStalled(t *testing.T) {
	st := DiscoveryStatus{Started: true, LagBlocks: StallLagFloor + 1, SecondsSinceAdvance: 121}
	if !st.Stalled(2 * time.Minute) {
		t.Fatal("a node behind the head and not advancing was NOT reported stalled — this is " +
			"the outage case the metric exists for")
	}
	// The 2026-08-05 outage shape: thousands behind, frozen for hours.
	outage := DiscoveryStatus{Started: true, LagBlocks: 12577, SecondsSinceAdvance: 3 * 3600}
	if !outage.Stalled(2 * time.Minute) {
		t.Fatal("the real outage shape was not reported stalled")
	}
}

// Being behind is not on its own a stall — that is a node catching up, and it must not page.
func TestBehindButAdvancingIsNotStalled(t *testing.T) {
	st := DiscoveryStatus{Started: true, LagBlocks: 12577, SecondsSinceAdvance: 3}
	if st.Stalled(2 * time.Minute) {
		t.Fatal("a node actively catching up was reported stalled; every recovery would page")
	}
}

// A node that boots straight into a dead upstream never advances and never learns a head, so its
// lag reads 0 and the lag floor suppresses the stall signal. LastPollError must carry that case,
// or a total outage at boot would be silent.
func TestBootIntoDeadUpstreamIsCoveredByPollError(t *testing.T) {
	st := DiscoveryStatus{
		Started:       false,
		LagBlocks:     0,
		ChainHead:     0,
		LastPollError: `Post "https://kermit.accumulatenetwork.io/v3": EOF`,
	}
	if st.Stalled(2 * time.Minute) {
		t.Fatal("test premise: the lag floor should suppress Stalled here")
	}
	if st.LastPollError == "" {
		t.Fatal("LastPollError must be the signal for a boot-into-dead-upstream, since neither " +
			"lag nor staleness can see it")
	}
}
