// Copyright 2026 Certen Protocol

package arbposted

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// The embedded pins file is the one the validator builds and verifies under: its arb_sepolia section carries the keys of the sibling
// finalized kind (confirm_path, proxy_slots) and must still load here, not be refused as pin_mismatch{section} (found by the
// RB11-B2B2b end-to-end test, where every Arbitrum l1_posted level answered pin_mismatch under the embedded pins).
func TestTheEmbeddedPinsLoadForTheArbitrumPostedKind(t *testing.T) {
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	a, err := loadArbPins(pins)
	if err != nil || a == nil || a.ChainID != finality.ChainArbitrumSepolia {
		t.Fatalf("the embedded arb_sepolia section does not load: %v", err)
	}
}
