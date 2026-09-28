package config

import "testing"

// RB3-F26: the configuration claims a chain only when CERTEN settles on it and it is configured. It used
// to add a default Ethereum chain whatever it was, and any configured chain whether supported or not.
func TestTheConfigurationClaimsOnlyConfiguredSupportedChains(t *testing.T) {
	c := &AnchorConfig{}
	c.Network.Ethereum.ChainID = 1
	c.Network.EVMChains = map[int64]*EVMChainConfig{
		84532:    {ChainID: 84532, RPCURL: "http://base"},
		11155420: {ChainID: 11155420, RPCURL: "http://optimism-sepolia"}, // retired
	}
	if got := c.GetSupportedChainIDs(); len(got) != 1 || got[0] != 84532 {
		t.Fatalf("supported chains %v, want only base-sepolia", got)
	}
	for _, id := range []int64{1, 11155420, 11155111} {
		if c.IsChainSupported(id) {
			t.Fatalf("chain %d is claimed", id)
		}
	}
}
