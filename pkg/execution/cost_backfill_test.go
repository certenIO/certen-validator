package execution

import (
	"testing"

	"github.com/certen/independant-validator/pkg/billing"
)

// A wrong leg is worse than a missing one: it does not fail, it silently skews the per-leg
// medians the gas estimator prices from. These pin the only inference the backfill makes.

// Confirmed across 209 EVM samples whose gas profile matches the three transactions:
// anchor ~290k, verify ~446k (largest, executeComprehensiveProof), vault_execute ~132k.
func TestBackfillLegMappingForThreeRowCycles(t *testing.T) {
	cases := map[int]string{
		1: billing.LegAnchor,
		2: billing.LegVerify,
		3: billing.LegVaultExecute,
	}
	for step, want := range cases {
		if got := backfillLegForStep(step, 3); got != want {
			t.Errorf("step %d in a 3-row cycle = %q, want %q", step, got, want)
		}
	}
}

// THE trap. A one-row cycle also uses workflow_step 1, but there it is the SETTLEMENT, not the
// anchor — verified against intent 719b0e95 on 2026-08-05, whose single row was step 1 carrying
// the vault_execute transaction (144,884 gas on base-sepolia).
//
// Labelling those as "anchor" would have mislabelled real money on 76 one-row and 39 two-row
// cycles spanning February to August.
func TestBackfillRefusesToGuessOutsideThreeRowCycles(t *testing.T) {
	for _, rowsInCycle := range []int{0, 1, 2, 4, 5} {
		for step := 1; step <= 3; step++ {
			if got := backfillLegForStep(step, rowsInCycle); got != "" {
				t.Fatalf("step %d in a %d-row cycle returned %q; the leg is ambiguous there and "+
					"must be skipped, not guessed", step, rowsInCycle, got)
			}
		}
	}
}

// An unrecognised step must never fall through to a default leg.
func TestBackfillRejectsUnknownStep(t *testing.T) {
	for _, step := range []int{0, 4, 9, -1} {
		if got := backfillLegForStep(step, 3); got != "" {
			t.Fatalf("unknown step %d mapped to %q", step, got)
		}
	}
}

// The backfill must emit only legs the gateway's enum accepts, or every event 400s on schema
// validation. execute_legs is deliberately NOT among them — it has no on-chain transaction.
func TestBackfillEmitsOnlyAcceptedLegs(t *testing.T) {
	accepted := map[string]bool{
		billing.LegAnchor: true, billing.LegVerify: true,
		billing.LegVaultExecute: true, billing.LegOther: true,
	}
	for step := 1; step <= 3; step++ {
		leg := backfillLegForStep(step, 3)
		if !accepted[leg] {
			t.Fatalf("step %d produced %q, which the gateway leg enum does not accept", step, leg)
		}
		if leg == billing.LegExecuteLegs {
			t.Fatal("backfill emitted execute_legs; there is no such transaction")
		}
	}
}
