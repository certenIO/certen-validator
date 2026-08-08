package consensus

import (
	"testing"

	"github.com/certen/independant-validator/pkg/entitlement"
)

// The cost bound decides whether work is REFUSED, so every case here is about
// erring in the safe direction: refuse only what provably exceeds the ceiling,
// and never refuse because a number was missing.

func blockWithLegs(chainLegs map[int64]int) *ValidatorBlock {
	vb := &ValidatorBlock{}
	for chainID, n := range chainLegs {
		for i := 0; i < n; i++ {
			vb.CrossChainProof.ChainTargets = append(
				vb.CrossChainProof.ChainTargets, ChainTarget{ChainID: chainID})
		}
	}
	return vb
}

func basis(entries ...entitlement.ChainCostBasis) entitlement.Header {
	return entitlement.Header{CostBasis: entries}
}

// One leg costs the base. The marginal only applies from the second leg on,
// because legs ride together in a single settlement transaction per chain.
func TestSingleLegCostsTheBase(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 1})
	h := basis(entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000, PerLegMicroUSD: 2000})

	got, ok, err := WorstCaseCostMicroUSD(vb, h)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got != 5000 {
		t.Fatalf("got %d, want 5000 (base only)", got)
	}
}

// Additional legs on the SAME chain add the marginal, not another base.
//
// Charging a full base per leg is what the estimator did before 2026-08-07 and
// it over-bounds badly: at five legs it would claim 25,000 against a true 13,000,
// refusing intents that are comfortably affordable.
func TestAdditionalLegsAddOnlyTheMarginal(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 5})
	h := basis(entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000, PerLegMicroUSD: 2000})

	got, _, err := WorstCaseCostMicroUSD(vb, h)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(5000 + 4*2000); got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

// Each chain pays its own base: a multi-chain intent runs a full anchor, verify
// and execution on every chain it touches. Verified on production 2026-08-07,
// where a 2-chain intent produced all three legs on both chains.
func TestEachChainPaysItsOwnBase(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 1, 421614: 1})
	h := basis(
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000, PerLegMicroUSD: 2000},
		entitlement.ChainCostBasis{ChainID: 421614, BaseMicroUSD: 9000, PerLegMicroUSD: 3000},
	)

	got, _, err := WorstCaseCostMicroUSD(vb, h)
	if err != nil {
		t.Fatal(err)
	}
	if got != 14000 {
		t.Fatalf("got %d, want 14000 (both bases)", got)
	}
}

// A chain with no published basis makes the bound UNKNOWN, not zero.
//
// Zero would let an unpriced chain slip past the ceiling entirely — add one leg
// on a chain the gateway has not measured and the whole intent prices as free.
func TestMissingBasisReportsUnknownRatherThanZero(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 1, 999999: 1})
	h := basis(entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000})

	_, ok, err := WorstCaseCostMicroUSD(vb, h)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a chain with no basis must report ok=false, never a bound that omits it")
	}
}

// A block touching no chain bounds to zero, and that IS a bound.
//
// Distinct from the missing-basis case: nothing will execute, so nothing can be
// spent. Conflating the two would either refuse harmless blocks or admit
// unpriced ones.
func TestNoChainTargetsIsAKnownZero(t *testing.T) {
	got, ok, err := WorstCaseCostMicroUSD(&ValidatorBlock{}, basis())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v — an empty block is bounded, not unknown", ok, err)
	}
	if got != 0 {
		t.Fatalf("got %d, want 0", got)
	}
}

// Overflow is reported, never wrapped.
//
// A wrapped multiplication produces a small positive number, which would admit
// an intent precisely because its cost was absurd.
func TestOverflowIsReportedNotWrapped(t *testing.T) {
	// FOUR legs, so extra=3 against a per-leg of maxInt64/2. Three legs would
	// NOT overflow — (maxInt64/2)*2 is maxInt64-1 — and an earlier version of
	// this test asserted overflow on exactly that case and failed, correctly.
	vb := blockWithLegs(map[int64]int{84532: 4})
	h := basis(entitlement.ChainCostBasis{
		ChainID: 84532, BaseMicroUSD: 1, PerLegMicroUSD: maxInt64 / 2,
	})

	if _, ok, err := WorstCaseCostMicroUSD(vb, h); err == nil && ok {
		t.Fatal("overflow must not produce a usable bound")
	}
}

// The boundary the case above sits next to: the largest product that does NOT
// overflow must still produce a usable bound. A guard that trips here would
// refuse legitimate work rather than prevent a wrap.
func TestLargestNonOverflowingBoundIsStillUsable(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 3}) // extra = 2
	h := basis(entitlement.ChainCostBasis{
		ChainID: 84532, BaseMicroUSD: 0, PerLegMicroUSD: maxInt64 / 2,
	})

	got, ok, err := WorstCaseCostMicroUSD(vb, h)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v — this product fits and must be reported", ok, err)
	}
	if want := (maxInt64 / 2) * 2; got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

// A negative basis is rejected rather than treated as a discount.
func TestNegativeBasisIsRejected(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 1})
	h := basis(entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: -1})

	if _, _, err := WorstCaseCostMicroUSD(vb, h); err == nil {
		t.Fatal("a negative cost basis must be an error, not a credit")
	}
}

// The bound must not depend on the order chains appear in the header.
func TestBoundIsIndependentOfBasisOrder(t *testing.T) {
	vb := blockWithLegs(map[int64]int{84532: 2, 421614: 3})
	a := basis(
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000, PerLegMicroUSD: 2000},
		entitlement.ChainCostBasis{ChainID: 421614, BaseMicroUSD: 9000, PerLegMicroUSD: 3000},
	)
	b := basis(
		entitlement.ChainCostBasis{ChainID: 421614, BaseMicroUSD: 9000, PerLegMicroUSD: 3000},
		entitlement.ChainCostBasis{ChainID: 84532, BaseMicroUSD: 5000, PerLegMicroUSD: 2000},
	)

	x, _, _ := WorstCaseCostMicroUSD(vb, a)
	y, _, _ := WorstCaseCostMicroUSD(vb, b)
	if x != y {
		t.Fatalf("order-dependent bound: %d vs %d — every validator must agree", x, y)
	}
}
