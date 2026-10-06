package supportedchains

import "testing"

// RB7 D7: only a chain whose blocks stop when it is idle may have a heartbeat. Telcoin Adiri's do; the three live chains'
// never do.
func TestOnlyTelcoinAdiriProducesBlocksOnlyWithTraffic(t *testing.T) {
	for _, c := range All {
		if c.BlocksOnlyWithTraffic != (c.ID == 2017) {
			t.Fatalf("chain %d (%s): BlocksOnlyWithTraffic=%v", c.ID, c.Name, c.BlocksOnlyWithTraffic)
		}
	}
}
