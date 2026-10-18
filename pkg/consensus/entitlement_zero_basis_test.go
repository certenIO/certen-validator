package consensus

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// PV2-F3: the live entitlement epoch listed Telcoin Adiri (2017) with base_micro_usd 0 and per_leg_micro_usd 0, and the
// binding ceiling (rules v14, RB4-F6) counted that entry as a price: the chain's worst-case cost summed to 0, so every
// intent on it passed any ceiling - the unpriced-chain bypass v14 exists to close, reached through a present entry instead
// of a missing one. A basis is a bound; zero is not one.
//
// Rules v14 was already deciding blocks when this was found, and it counts a listed zero as a price. Changing that verdict
// inside v14 would decide the same bytes two ways on a chain whose history may hold such a block, so the reading is a rule
// of v15: it applies from the height after the accepted cross-partition activation (EntitlementConfig.RequireBoundingBasis,
// set by the app from the committed activation), and v14 is kept exactly until then. Rules before v14 skip the ceiling for
// such a block and still do. abci_zero_basis_test.go proves the app sets the flag from the committed activation.

// zeroBasisCases are the entries that are no bound for the block that multiplies them.
var zeroBasisCases = map[string]struct {
	basis entitlement.ChainCostBasis
	legs  int
}{
	"zero base and zero per-leg, one leg (the live Adiri entry)":   {entitlement.ChainCostBasis{ChainID: 2017}, 1},
	"zero base, positive per-leg":                                  {entitlement.ChainCostBasis{ChainID: 2017, PerLegMicroUSD: 500}, 1},
	"positive base, zero per-leg, two legs: the extra leg is free": {entitlement.ChainCostBasis{ChainID: 2017, BaseMicroUSD: 1_000}, 2},
}

func TestAZeroBasisIsUnpricedFromV15AndNotBefore(t *testing.T) {
	for name, tc := range zeroBasisCases {
		t.Run(name, func(t *testing.T) {
			cfg, ev := pricedFixture(t, tc.basis)
			vb := pricedBlock(ev, map[int64]int{2017: tc.legs})

			// Below v14 the ceiling is skipped for this block, as it always was.
			if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != "" {
				t.Fatalf("below v14 the verdict changed: %q %v", reason, err)
			}

			// Under v14 a listed zero is a price: the sum is a bound and the block passes the ceiling, byte for byte the
			// verdict v14 returned when it began deciding blocks.
			cfg.RequireCostBasis = true
			if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != "" {
				t.Fatalf("v14's verdict over a listed zero changed: %q %v", reason, err)
			}
			if _, ok, werr := WorstCaseCostMicroUSD(vb, ev.Header); !ok || werr != nil {
				t.Fatalf("v14's worst case over a listed zero changed: ok=%v err=%v", ok, werr)
			}
			if got := UnpricedChains(vb, ev.Header); len(got) != 0 {
				t.Fatalf("v14 names a listed chain unpriced: %v", got)
			}

			// From v15 the zero is no bound: the chain is unpriced, named.
			cfg.RequireBoundingBasis = true
			reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
			if err == nil || reason != entitlement.ReasonUnpriced {
				t.Fatalf("v15 admitted a ceiling over a chain whose published basis is not a bound: %q %v", reason, err)
			}
			if !strings.Contains(err.Error(), "ENTITLEMENT_UNPRICED") || !strings.Contains(err.Error(), "[2017]") {
				t.Fatalf("the refusal does not name the code and the chain: %v", err)
			}
			worst, ok, werr := WorstCaseCostMicroUSDBounded(vb, ev.Header)
			if ok || werr != nil || worst != 0 {
				t.Fatalf("a zero basis produced a bound: %d ok=%v err=%v", worst, ok, werr)
			}
			if got := UnpricedChainsBounded(vb, ev.Header); len(got) != 1 || got[0] != 2017 {
				t.Fatalf("the chain is not named unpriced: %v", got)
			}

			// The v15 reading never reaches a block below v14: without the binding ceiling the zero is skipped as before.
			cfg.RequireCostBasis = false
			if reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg); err != nil || reason != "" {
				t.Fatalf("the v15 reading was applied below v14: %q %v", reason, err)
			}
		})
	}
}

// A zero per-leg is a bound for a chain with a single leg: nothing repeats, so nothing is left unpriced. Refusing it would
// refuse affordable work for a figure the block never multiplies.
func TestAZeroPerLegBasisStillBoundsASingleLegBlock(t *testing.T) {
	cfg, ev := pricedFixture(t, entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000})
	cfg.RequireCostBasis = true
	cfg.RequireBoundingBasis = true
	if reason, err := VerifyEntitlement(pricedBlock(ev, map[int64]int{84532: 1}), gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("a single leg on a chain with a positive base and no per-leg figure was refused: %q %v", reason, err)
	}
	worst, ok, err := WorstCaseCostMicroUSDBounded(pricedBlock(ev, map[int64]int{84532: 1}), ev.Header)
	if err != nil || !ok || worst != 1_000 {
		t.Fatalf("worst case %d ok=%v err=%v; want the base, 1000", worst, ok, err)
	}
}

// The same block over a fully priced epoch is decided as before, and a zero chain the block does not touch changes nothing.
func TestAZeroBasisOnAChainTheBlockDoesNotTouchIsIrrelevant(t *testing.T) {
	cfg, ev := pricedFixture(t,
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 1_000_000, PerLegMicroUSD: 500_000},
		entitlement.ChainCostBasis{ChainID: 2017}) // listed at zero, but this block settles on 84532 only
	cfg.RequireCostBasis = true
	cfg.RequireBoundingBasis = true
	if _, err := VerifyEntitlement(pricedBlock(ev, map[int64]int{84532: 3}), gatePayer, gateNow, cfg); err != nil {
		t.Fatalf("an affordable block on a priced chain was refused because another chain is listed at zero: %v", err)
	}
	// And one that does touch it is refused, with the zero chain named among the unpriced in ascending order.
	vb := pricedBlock(ev, map[int64]int{84532: 1, 2017: 1, 421614: 1})
	reason, err := VerifyEntitlement(vb, gatePayer, gateNow, cfg)
	if err == nil || reason != entitlement.ReasonUnpriced {
		t.Fatalf("%q %v", reason, err)
	}
	if got := UnpricedChainsBounded(vb, ev.Header); len(got) != 2 || got[0] != 2017 || got[1] != 421614 {
		t.Fatalf("unpriced chains %v; want [2017 421614] (the zero one and the missing one, ascending)", got)
	}
}

// A negative basis is still invalid, not unpriced, wherever it sits in chain order, under v14 and v15 alike.
func TestANegativeBasisIsStillInvalidNotUnpriced(t *testing.T) {
	cfg, ev := pricedFixture(t, entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: -1, PerLegMicroUSD: 1})
	cfg.RequireCostBasis = true
	for _, bound := range []bool{false, true} {
		cfg.RequireBoundingBasis = bound
		if reason, err := VerifyEntitlement(pricedBlock(ev, map[int64]int{84532: 1}), gatePayer, gateNow, cfg); err == nil || reason != entitlement.ReasonCostBasisInvalid {
			t.Fatalf("requireBound=%v: %q %v", bound, reason, err)
		}
	}
}
