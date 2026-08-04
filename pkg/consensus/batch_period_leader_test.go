package consensus

import (
	"testing"
)

// =============================================================================
// Batch period leadership
// =============================================================================
//
// Leader election is what stops all seven validators racing to anchor the same period. If they
// disagreed, either two would anchor (one reverting AnchorAlreadyExists after paying gas) or
// none would (the period never settles). Both failures are silent from a single node's view,
// so these tests assert the properties across the whole set at once.

func validatorFor(id string) *BFTValidator {
	return &BFTValidator{validatorID: id}
}

// EXACTLY ONE leader per (chain, period). Not "at least one" — a second leader means duplicate
// anchors and wasted gas; zero means the period is stranded.
func TestBatchPeriodLeader_ExactlyOnePerPeriod(t *testing.T) {
	t.Setenv("BATCH_LEADER_VALIDATORS",
		"validator-1,validator-2,validator-3,validator-4,validator-5,validator-6,validator-7")

	chains := []int64{11155111, 84532, 421614}
	for _, chainID := range chains {
		for cutoff := uint64(10); cutoff <= 2000; cutoff += 10 {
			leaders := 0
			for i := 1; i <= 7; i++ {
				if validatorFor(validatorIDForIndex(i)).IsBatchPeriodLeader(chainID, cutoff, 0) {
					leaders++
				}
			}
			if leaders != 1 {
				t.Fatalf("chain %d cutoff %d elected %d leaders, want exactly 1",
					chainID, cutoff, leaders)
			}
		}
	}
}

// Roster ORDER must not change the answer. Validators read the roster from an env var, and a
// list written in a different order on one node would elect a different leader there — the
// exact class of silent divergence this design exists to remove.
func TestBatchPeriodLeader_RosterOrderDoesNotMatter(t *testing.T) {
	const chainID = int64(11155111)

	t.Setenv("BATCH_LEADER_VALIDATORS", "validator-1,validator-2,validator-3")
	forward := make([]string, 0, 50)
	for cutoff := uint64(10); cutoff <= 500; cutoff += 10 {
		forward = append(forward, leaderAmong(t, []string{"validator-1", "validator-2", "validator-3"}, chainID, cutoff))
	}

	t.Setenv("BATCH_LEADER_VALIDATORS", "validator-3,validator-1,validator-2")
	for i, cutoff := 0, uint64(10); cutoff <= 500; cutoff, i = cutoff+10, i+1 {
		got := leaderAmong(t, []string{"validator-1", "validator-2", "validator-3"}, chainID, cutoff)
		if got != forward[i] {
			t.Fatalf("cutoff %d: reordering the roster changed the leader (%s -> %s)",
				cutoff, forward[i], got)
		}
	}
}

// Leadership must rotate rather than parking every period's anchor gas on one node.
func TestBatchPeriodLeader_Rotates(t *testing.T) {
	t.Setenv("BATCH_LEADER_VALIDATORS",
		"validator-1,validator-2,validator-3,validator-4,validator-5,validator-6,validator-7")

	seen := map[string]int{}
	for cutoff := uint64(10); cutoff <= 5000; cutoff += 10 {
		seen[leaderAmong(t, allSeven(), 11155111, cutoff)]++
	}
	if len(seen) != 7 {
		t.Fatalf("only %d of 7 validators ever led; anchor gas would concentrate", len(seen))
	}
	// Rough balance: no validator should take more than double its fair share. A biased
	// selection (e.g. one hash byte modulo 7) shows up here.
	fair := 500 / 7
	for id, n := range seen {
		if n > fair*2 {
			t.Fatalf("%s led %d of 500 periods (fair share ~%d); the selection is biased",
				id, n, fair)
		}
	}
}

// Different chains must not all elect the same leader for the same height, or one node carries
// every chain's anchor for that period.
func TestBatchPeriodLeader_VariesByChain(t *testing.T) {
	t.Setenv("BATCH_LEADER_VALIDATORS",
		"validator-1,validator-2,validator-3,validator-4,validator-5,validator-6,validator-7")

	differs := false
	for cutoff := uint64(10); cutoff <= 1000; cutoff += 10 {
		a := leaderAmong(t, allSeven(), 11155111, cutoff)
		b := leaderAmong(t, allSeven(), 84532, cutoff)
		if a != b {
			differs = true
			break
		}
	}
	if !differs {
		t.Fatal("chainID does not influence leadership; every chain would elect the same node")
	}
}

// A node not in the roster must never consider itself leader.
func TestBatchPeriodLeader_UnknownValidatorNeverLeads(t *testing.T) {
	t.Setenv("BATCH_LEADER_VALIDATORS", "validator-1,validator-2,validator-3")
	stranger := validatorFor("validator-99")
	for cutoff := uint64(10); cutoff <= 1000; cutoff += 10 {
		if stranger.IsBatchPeriodLeader(11155111, cutoff, 0) {
			t.Fatalf("a validator outside the roster claimed leadership at cutoff %d", cutoff)
		}
	}
}

// =============================================================================
// Observed consensus height
// =============================================================================

// The cutoff source must never rewind. A lower late-arriving height would let a period that
// already flushed be re-formed, which reverts AnchorAlreadyExists and hides the real fault.
func TestObservedConsensusHeight_IsMonotonic(t *testing.T) {
	bv := validatorFor("validator-1")
	if h := bv.ObservedConsensusHeight(); h != 0 {
		t.Fatalf("fresh validator reports height %d, want 0", h)
	}
	bv.noteConsensusHeight(100)
	bv.noteConsensusHeight(42) // out of order, must be ignored
	bv.noteConsensusHeight(7)
	if h := bv.ObservedConsensusHeight(); h != 100 {
		t.Fatalf("height rewound to %d; a lower observation must never lower the cutoff", h)
	}
	bv.noteConsensusHeight(101)
	if h := bv.ObservedConsensusHeight(); h != 101 {
		t.Fatalf("height %d did not advance to 101", h)
	}
}

// ---- helpers ----------------------------------------------------------------

func allSeven() []string {
	return []string{
		"validator-1", "validator-2", "validator-3", "validator-4",
		"validator-5", "validator-6", "validator-7",
	}
}

func validatorIDForIndex(i int) string {
	return []string{
		"", "validator-1", "validator-2", "validator-3", "validator-4",
		"validator-5", "validator-6", "validator-7",
	}[i]
}

// leaderAmong asks every candidate and asserts exactly one says yes.
func leaderAmong(t *testing.T, ids []string, chainID int64, cutoff uint64) string {
	t.Helper()
	var leader string
	n := 0
	for _, id := range ids {
		if validatorFor(id).IsBatchPeriodLeader(chainID, cutoff, 0) {
			leader = id
			n++
		}
	}
	if n != 1 {
		t.Fatalf("chain %d cutoff %d elected %d leaders among %v, want exactly 1",
			chainID, cutoff, n, ids)
	}
	return leader
}
