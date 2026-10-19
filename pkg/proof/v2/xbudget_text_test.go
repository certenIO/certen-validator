// Copyright 2026 Certen Protocol

package proofv2

import (
	"os"
	"strings"
	"testing"
)

// RB9-F5 package F5-4b (V-I D1): the derivation text states the real numbers.

// The D6 derivation text states the numbers the test derives: 27,626 + 1,880 + 4 x 165 x 13 = 38,086 (the test measures 29,507 + 8,580 =
// 38,087), rounded up to 40,000 with no further step.
func TestBudgetDerivationTextStatesTheRealNumbers(t *testing.T) {
	if got := 4 * ValidatorSignatureBytes * (BudgetedValidators - MeasuredValidators); got != 8580 {
		t.Fatalf("4 records x %d x (%d-%d) = %d, want 8580", ValidatorSignatureBytes, BudgetedValidators, MeasuredValidators, got)
	}
	if 27_626+1_880+8_580 != 38_086 || FixedEvidenceBytes != 40_000 {
		t.Fatalf("27,626 + 1,880 + 8,580 is not 38,086 or FixedEvidenceBytes is not 40,000")
	}
	for _, path := range []string{"xbudget.go", "../../../docs/proof/G1_CROSS_PARTITION.md"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Comment line breaks and markdown wrapping may split the sentence; compare on single spaces without the comment markers.
		text := strings.Join(strings.Fields(strings.ReplaceAll(string(raw), "\n//", " ")), " ")
		for _, want := range []string{"27,626 + 1,880 + 8,580 = 38,086", "40,000"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s does not state %q", path, want)
			}
		}
		for _, bad := range []string{"33,796", "rounded up to 35,000", "further 5,000", "one further step"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s still states the false derivation %q", path, bad)
			}
		}
	}
}
