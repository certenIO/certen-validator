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
			st := DiscoveryStatus{Started: true, SecondsSinceAdvance: tc.seconds}
			if got := st.Stalled(2 * time.Minute); got != tc.want {
				t.Fatalf("Stalled(%vs) = %v, want %v", tc.seconds, got, tc.want)
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
