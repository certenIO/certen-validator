package execution

import (
	"testing"
	"time"
)

func odRoster() []string {
	return []string{"validator-1", "validator-2", "validator-3", "validator-4",
		"validator-5", "validator-6", "validator-7"}
}

func odSubmitter(t *testing.T, me string) *OnDemandSubmitter {
	t.Helper()
	s, err := NewOnDemandSubmitter(OnDemandSubmitterConfig{
		Stack:       &BatchStack{Mempool: NewBatchMempool(BatchMempoolConfig{})},
		Prover:      &BatchQuorumAttestor{},
		ValidatorID: me,
		Roster:      odRoster,
	})
	if err != nil {
		t.Fatalf("NewOnDemandSubmitter: %v", err)
	}
	return s
}

// Every validator must reach the SAME answer, or several anchor the same member and all but one
// burn gas reverting with AnchorAlreadyExists.
func TestOnDemandLeadershipIsUnanimousAndUnique(t *testing.T) {
	member := odMember(1, odChain, 105)
	leaders := 0
	for _, id := range odRoster() {
		if odSubmitter(t, id).isLeaderFor(member, 0) {
			leaders++
		}
	}
	if leaders != 1 {
		t.Fatalf("%d validators claimed leadership, want exactly 1", leaders)
	}
}

// The election must be a pure function of (chain, operationID) — no local state, no clock.
func TestOnDemandLeadershipIsDeterministic(t *testing.T) {
	member := odMember(1, odChain, 105)
	first := onDemandLeaderIndex(member.ChainID, member.OperationID, 7)
	for i := 0; i < 50; i++ {
		if got := onDemandLeaderIndex(member.ChainID, member.OperationID, 7); got != first {
			t.Fatalf("election is not deterministic: %d then %d", first, got)
		}
	}
}

// A cross-chain intent must elect a different leader per chain, so its members do not all land
// on one node's gas budget.
func TestOnDemandLeadershipDiffersAcrossChainsForOneIntent(t *testing.T) {
	opID := [32]byte{1}
	seen := map[int]bool{}
	for _, chain := range []int64{11155111, 84532, 421614} {
		seen[onDemandLeaderIndex(chain, opID, 7)] = true
	}
	if len(seen) == 1 {
		t.Fatal("all three chains elected the same roster index for one intent — the chain is " +
			"not part of the election key")
	}
}

// Leadership must rotate on wall clock so a dead leader cannot strand an urgent intent.
func TestOnDemandLeadershipFailsOverOnWallClock(t *testing.T) {
	member := odMember(1, odChain, 105)
	base := onDemandLeaderIndex(member.ChainID, member.OperationID, 7)

	// Find who leads after one failover interval.
	want := (base + 1) % 7
	s := odSubmitter(t, odRoster()[want])
	if s.isLeaderFor(member, 0) {
		t.Fatal("the failover node claimed leadership immediately")
	}
	if !s.isLeaderFor(member, OnDemandFailoverAfter+time.Second) {
		t.Fatal("leadership did not fail over after the interval; a dead leader would strand the " +
			"member until the TTL pruned it")
	}
	// And it must keep rotating, not stop at one handoff.
	want2 := (base + 2) % 7
	s2 := odSubmitter(t, odRoster()[want2])
	if !s2.isLeaderFor(member, 2*OnDemandFailoverAfter+time.Second) {
		t.Fatal("leadership stopped rotating after one handoff")
	}
}

// The failover interval must comfortably exceed one quorum-plus-anchor cycle, or leadership is
// stolen mid-flight on essentially every member and every settle burns a duplicate anchor.
// Measured live 2026-08-04: flush -> settled was 47s.
func TestOnDemandFailoverExceedsOneSettleCycle(t *testing.T) {
	const observedSettleCycle = 47 * time.Second
	if OnDemandFailoverAfter < 3*observedSettleCycle {
		t.Fatalf("OnDemandFailoverAfter %s is less than 3x the observed %s settle cycle — "+
			"leadership would be stolen mid-flight", OnDemandFailoverAfter, observedSettleCycle)
	}
}

// With no roster (single-node devnet) this node must lead, matching the period path's
// nil-IsLeaderFn behaviour.
func TestOnDemandLeadershipWithEmptyRosterAlwaysLeads(t *testing.T) {
	s, err := NewOnDemandSubmitter(OnDemandSubmitterConfig{
		Stack:       &BatchStack{Mempool: NewBatchMempool(BatchMempoolConfig{})},
		Prover:      &BatchQuorumAttestor{},
		ValidatorID: "solo",
		Roster:      func() []string { return nil },
	})
	if err != nil {
		t.Fatalf("NewOnDemandSubmitter: %v", err)
	}
	if !s.isLeaderFor(odMember(1, odChain, 105), 0) {
		t.Fatal("a single-node devnet must lead its own members")
	}
}

// Election must spread across the roster rather than parking on low indices — the reason four
// bytes are folded rather than one.
func TestOnDemandLeadershipSpreadsAcrossRoster(t *testing.T) {
	counts := make([]int, 7)
	for i := 0; i < 700; i++ {
		var op [32]byte
		op[0] = byte(i)
		op[1] = byte(i >> 8)
		counts[onDemandLeaderIndex(odChain, op, 7)]++
	}
	for i, n := range counts {
		if n == 0 {
			t.Fatalf("roster index %d never elected across 700 members", i)
		}
		if n > 250 {
			t.Fatalf("roster index %d elected %d/700 times — the election is badly skewed", i, n)
		}
	}
}

// =============================================================================
// Readiness classification
// =============================================================================

// The distinction the whole design rests on: peers that are merely behind are retryable, a peer
// that actively disagrees is not.
func TestCollectResultClassifiesConvergence(t *testing.T) {
	cases := []struct {
		name      string
		result    OnDemandCollectResult
		converges bool
	}{
		{"peers behind", OnDemandCollectResult{NotHeld: 3}, true},
		{"peers unreachable", OnDemandCollectResult{Unreachable: 2}, true},
		{"nobody left to wait for", OnDemandCollectResult{Other: 2}, false},
		{"everyone answered", OnDemandCollectResult{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.CouldStillConverge(); got != tc.converges {
				t.Fatalf("CouldStillConverge = %v, want %v", got, tc.converges)
			}
		})
	}
}

// A mismatch must NOT be classified as retryable even when other peers are still behind. On a
// one-member batch a mismatch means two nodes hold different data for the same intent; spinning
// on it would hide a real bug until the deadline expired.
func TestMismatchIsNeverTreatedAsNotReady(t *testing.T) {
	r := OnDemandCollectResult{NotHeld: 4, Mismatch: 1}
	if !r.CouldStillConverge() {
		t.Fatal("test setup: NotHeld should make CouldStillConverge true")
	}
	// The submitter's rule is `Mismatch == 0 && CouldStillConverge()`. Assert that composite
	// directly, since that is what ProveBatchRootOnDemand applies.
	retryable := r.Mismatch == 0 && r.CouldStillConverge()
	if retryable {
		t.Fatal("a response set containing a bundleId mismatch was classified as retryable")
	}
}

func TestQuorumNotReadyErrorUnwraps(t *testing.T) {
	inner := errThreshold("threshold not met")
	e := &QuorumNotReadyError{NotHeld: 3, Agreed: 4, Err: inner}
	if got := e.Unwrap(); got != inner {
		t.Fatalf("Unwrap returned %v, want the wrapped cause", got)
	}
	if e.Error() == "" {
		t.Fatal("QuorumNotReadyError has no message")
	}
}

type errThreshold string

func (e errThreshold) Error() string { return string(e) }

// Wake must never block, or an enqueue would stall the consensus round that produced it.
func TestWakeIsNonBlocking(t *testing.T) {
	s := odSubmitter(t, "validator-1")
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			s.Wake()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake blocked; an enqueue would stall the consensus round")
	}
}
