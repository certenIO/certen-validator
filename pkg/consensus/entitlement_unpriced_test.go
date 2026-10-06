package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// RB4-F6: the entitlement cost ceiling binds from execution rules v14. Before, a ceiling that touched a chain the
// epoch published no cost basis for - or whose basis was negative or overflowed - was SKIPPED (entitlement_cost.go
// told the caller to), so an unpriced chain spent without a ceiling.

// pricedFixture is gateFixture with a cost basis in the signed header: the config, the evidence for gatePayer, and the
// signing key.
func pricedFixture(t *testing.T, costBasis ...entitlement.ChainCostBasis) (EntitlementConfig, *entitlement.Evidence) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	set := &entitlement.Set{Leaves: []entitlement.Leaf{activeLeaf(gatePayer)}}
	setHash, err := set.SetHash()
	if err != nil {
		t.Fatal(err)
	}
	hdr := entitlement.Header{Epoch: 7, Root: set.Root(), SetHash: setHash, NativeUSDMicro: 3000 * 1_000_000,
		IssuedAtUnix: gateNow - 60, NotAfterUnix: gateNow + 3600, KeyID: "k1", CostBasis: costBasis}
	hdr.Signature = hex.EncodeToString(ed25519.Sign(priv, hdr.SigningBytes()))
	proof, leaf, ok := set.BuildProof(gatePayer)
	if !ok {
		t.Fatal("no proof for the payer")
	}
	return EntitlementConfig{Mode: EntitlementEnforce, Keys: entitlement.KeySet{"k1": pub}},
		&entitlement.Evidence{Header: hdr, Leaf: leaf, Proof: proof}
}

// pricedBlock is a block for gatePayer carrying ev, with the given legs per chain.
func pricedBlock(ev *entitlement.Evidence, legs map[int64]int) *ValidatorBlock {
	vb := blockWithLegs(legs)
	vb.BundleID = "bundle-1"
	vb.AccumulateAnchorReference.AccountURL = gatePayer
	vb.EntitlementEvidence = ev
	return vb
}

func TestAnUnpricedChainIsRefusedByNameFromV14(t *testing.T) {
	// Base Sepolia is priced; Arbitrum Sepolia, which the block also settles on, is not.
	cfg, ev := pricedFixture(t, entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000, PerLegMicroUSD: 500})
	vb := pricedBlock(ev, map[int64]int{84532: 1, 421614: 1})

	// Rules before v14 (and every block below the v14 activation): the ceiling is skipped, as it always was.
	if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != "" {
		t.Fatalf("below v14 the verdict changed: %q %v", reason, err)
	}

	cfg.RequireCostBasis = true
	reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
	if err == nil || reason != entitlement.ReasonUnpriced {
		t.Fatalf("v14 admitted a ceiling over an unpriced chain: %q %v", reason, err)
	}
	if !strings.Contains(err.Error(), "ENTITLEMENT_UNPRICED") || !strings.Contains(err.Error(), "[421614]") {
		t.Fatalf("the refusal does not name the code and the chain: %v", err)
	}

	// Observe mode reports it and decides nothing.
	cfg.Mode = EntitlementObserve
	if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != entitlement.ReasonUnpriced {
		t.Fatalf("observe: %q %v", reason, err)
	}
}

func TestAnEpochWithNoBasisAtAllIsUnpricedFromV14(t *testing.T) {
	cfg, ev := pricedFixture(t) // a v1 header: no cost basis
	vb := pricedBlock(ev, map[int64]int{11155111: 1})
	if _, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("below v14: %v", err)
	}
	cfg.RequireCostBasis = true
	if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err == nil || reason != entitlement.ReasonUnpriced {
		t.Fatalf("v14: %q %v", reason, err)
	}
}

func TestANegativeOrOverflowingBasisIsRefusedFromV14(t *testing.T) {
	for name, tc := range map[string]struct {
		basis entitlement.ChainCostBasis
		legs  int
	}{
		"negative base":    {entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: -1, PerLegMicroUSD: 1}, 1},
		"negative per-leg": {entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1, PerLegMicroUSD: -1}, 2},
		"overflow":         {entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1, PerLegMicroUSD: maxInt64 / 2}, 4},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, ev := pricedFixture(t, tc.basis)
			vb := pricedBlock(ev, map[int64]int{84532: tc.legs})
			if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != "" {
				t.Fatalf("below v14 the verdict changed: %q %v", reason, err)
			}
			cfg.RequireCostBasis = true
			if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err == nil || reason != entitlement.ReasonCostBasisInvalid {
				t.Fatalf("v14 admitted a basis no bound can be computed from: %q %v", reason, err)
			}
		})
	}
}

func TestAPricedCeilingStillDecidesFromV14(t *testing.T) {
	cfg, ev := pricedFixture(t,
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000_000, PerLegMicroUSD: 500_000},
		entitlement.ChainCostBasis{ChainID: 421614, BaseMicroUSD: 1_000_000, PerLegMicroUSD: 500_000})
	cfg.RequireCostBasis = true
	// 2.0M + 1.0M = 3.0M against a 5M ceiling: affordable.
	if _, err := VerifyEntitlement(pricedBlock(ev, map[int64]int{84532: 3, 421614: 1}), gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("an affordable, fully priced block was refused: %v", err)
	}
	// 4.5M + 1.0M = 5.5M: over the ceiling.
	reason, err := VerifyEntitlement(pricedBlock(ev, map[int64]int{84532: 8, 421614: 1}), gatePayer, gateNow, cfg)
	if err == nil || reason != entitlement.ReasonCeiling {
		t.Fatalf("an over-ceiling block: %q %v", reason, err)
	}
	// A block that settles nothing is a known zero, priced or not.
	if _, err := VerifyEntitlement(pricedBlock(ev, nil), gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("a block with no chain targets: %v", err)
	}
}

// The reason a block is refused names the same chain on every node: chains are walked in id order.
func TestTheUnpricedChainsAreNamedInOrder(t *testing.T) {
	_, ev := pricedFixture(t, entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1})
	vb := pricedBlock(ev, map[int64]int{421614: 1, 84532: 1, 11155111: 2})
	for range 50 {
		if got := UnpricedChains(vb, ev.Header); len(got) != 2 || got[0] != 421614 || got[1] != 11155111 {
			t.Fatalf("unpriced chains %v", got)
		}
	}
}
