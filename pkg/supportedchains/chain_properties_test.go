package supportedchains

import (
	"os"
	"strings"
	"testing"
)

// RB7 D7: only a chain whose blocks stop when it is idle may have a heartbeat. Telcoin Adiri's do; the three live chains'
// never do.
func TestOnlyTelcoinAdiriProducesBlocksOnlyWithTraffic(t *testing.T) {
	for _, c := range All {
		if c.BlocksOnlyWithTraffic != (c.ID == 2017) {
			t.Fatalf("chain %d (%s): BlocksOnlyWithTraffic=%v", c.ID, c.Name, c.BlocksOnlyWithTraffic)
		}
	}
}

// RB7 D8: Adiri is pinned to the genesis of its current incarnation. The three live chains are not pinned: Base Sepolia's
// production provider set includes sepolia.base.org, which serves no block 0 ("pruned history unavailable: requested 0,
// earliest available 46000000", read 2026-10-05), so not every provider can agree on a genesis.
func TestTheGenesisPins(t *testing.T) {
	for _, c := range All {
		t.Setenv(c.GenesisEnv(), "")
		if err := os.Unsetenv(c.GenesisEnv()); err != nil {
			t.Fatal(err)
		}
		h, pinned, err := c.PinnedGenesis()
		if err != nil {
			t.Fatalf("chain %d: %v", c.ID, err)
		}
		switch c.ID {
		case 2017:
			if !pinned || h != "0x3577ee7223cf0d9a1da1293fd12a47e0e45bb97afcd0427bccd4954cb704baef" {
				t.Fatalf("Adiri pinned=%v to %s", pinned, h)
			}
		default:
			if pinned {
				t.Fatalf("chain %d is pinned to %s", c.ID, h)
			}
		}
	}
	if c, _ := Lookup(2017); c.GenesisEnv() != "CERTEN_CHAIN_GENESIS_2017" {
		t.Fatalf("env %s", c.GenesisEnv())
	}
}

// Re-pinning after a reset is configuration: CERTEN_CHAIN_GENESIS_<id> overrides the catalogue, and a value that is not
// a block hash is refused by name, never taken as "unpinned".
func TestTheGenesisPinIsChangedOnlyByAWellFormedValue(t *testing.T) {
	c, _ := Lookup(2017)
	t.Setenv(c.GenesisEnv(), " 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ")
	if h, pinned, err := c.PinnedGenesis(); err != nil || !pinned || h != "0x"+strings.Repeat("a", 64) {
		t.Fatalf("override: %s %v %v", h, pinned, err)
	}
	for _, bad := range []string{"", "0x1234", strings.Repeat("a", 64), "0x" + strings.Repeat("0", 64), "0x" + strings.Repeat("g", 64)} {
		t.Setenv(c.GenesisEnv(), bad)
		if h, pinned, err := c.PinnedGenesis(); err == nil || pinned || !strings.Contains(err.Error(), c.GenesisEnv()) {
			t.Fatalf("%q: %s pinned=%v err=%v", bad, h, pinned, err)
		}
	}
	// A pin for a chain the catalogue does not hold is a misconfiguration, named.
	t.Setenv(GenesisEnvFor(1), "0x"+strings.Repeat("b", 64))
	if _, _, err := PinnedGenesisOf(1); err == nil {
		t.Fatal("a pin for an uncatalogued chain was accepted")
	}
	// A live chain may be pinned by configuration too.
	t.Setenv(GenesisEnvFor(84532), "0x0dcc9e089e30b90ddfc55be9a37dd15bc551aeee999d2e2b51414c54eaf934e4")
	if h, pinned, err := PinnedGenesisOf(84532); err != nil || !pinned || !strings.HasPrefix(h, "0x0dcc9e08") {
		t.Fatalf("live chain pinned by configuration: %s %v %v", h, pinned, err)
	}
}
