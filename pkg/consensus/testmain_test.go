package consensus

import (
	"os"
	"testing"

	"github.com/certen/independant-validator/internal/testvalset"
)

// liveSettlementChains is CERTEN_SETTLEMENT_CHAINS as all seven production validators carry it (2026-10-05).
const liveSettlementChains = "11155111,84532,421614"

// Tests sign for the registered validator set, configured as the node requires (RB3-F21), and run with the enabled
// chains production runs with, unless the run names its own.
func TestMain(m *testing.M) {
	testvalset.Configure()
	if os.Getenv("CERTEN_SETTLEMENT_CHAINS") == "" {
		_ = os.Setenv("CERTEN_SETTLEMENT_CHAINS", liveSettlementChains)
	}
	os.Exit(m.Run())
}
