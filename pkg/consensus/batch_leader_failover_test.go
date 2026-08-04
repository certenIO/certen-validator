package consensus

import "testing"

// Exactly one node leads a period at any elapsed offset, and rotation eventually reaches every
// node — so a period whose elected leader is down is still reachable.
func TestBatchLeaderFailoverRotatesAndStaysUnique(t *testing.T) {
	const chainID = int64(84532)
	const period = uint64(6356400)

	roster := batchLeaderRoster()
	if len(roster) == 0 {
		t.Fatal("empty roster")
	}

	seen := map[string]bool{}
	// Walk enough failover intervals to cover the whole roster.
	for i := uint64(0); i < uint64(len(roster))*batchLeaderFailoverPeriods; i += batchLeaderFailoverPeriods {
		leaders := 0
		for _, id := range roster {
			bv := &BFTValidator{validatorID: id}
			if bv.IsBatchPeriodLeader(chainID, period, i) {
				leaders++
				seen[id] = true
			}
		}
		if leaders != 1 {
			t.Fatalf("elapsed=%d: %d leaders, want exactly 1", i, leaders)
		}
	}
	if len(seen) != len(roster) {
		t.Fatalf("rotation reached %d of %d nodes; a period could stay stuck", len(seen), len(roster))
	}
}

// Leadership must NOT move before the failover interval, or a slow flush gets stolen mid-flight.
func TestBatchLeaderStableWithinInterval(t *testing.T) {
	const chainID = int64(84532)
	const period = uint64(6356400)
	roster := batchLeaderRoster()

	var first string
	for _, id := range roster {
		if (&BFTValidator{validatorID: id}).IsBatchPeriodLeader(chainID, period, 0) {
			first = id
		}
	}
	if first == "" {
		t.Fatal("no leader at elapsed=0")
	}
	for i := uint64(1); i < batchLeaderFailoverPeriods; i++ {
		for _, id := range roster {
			isLeader := (&BFTValidator{validatorID: id}).IsBatchPeriodLeader(chainID, period, i)
			if isLeader != (id == first) {
				t.Fatalf("elapsed=%d: leadership moved to %q before the interval elapsed", i, id)
			}
		}
	}
}
