package ethrpc

import "testing"

// The depth is the chain's own, from the catalogue: the live chains keep RecentStateDepth, byte for byte; only a chain the
// catalogue says is final the moment a block exists reads at its head.
func TestRecentStateDepthIsTheChainsOwn(t *testing.T) {
	for _, id := range []int64{11155111, 84532, 421614, 0, 999999} {
		if got := RecentStateDepthFor(id); got != RecentStateDepth {
			t.Errorf("chain %d reads state %d blocks below its head, want %d", id, got, RecentStateDepth)
		}
	}
	if got := RecentStateDepthFor(2017); got != 0 {
		t.Errorf("Telcoin Adiri reads state %d blocks below its head, want 0", got)
	}
}
