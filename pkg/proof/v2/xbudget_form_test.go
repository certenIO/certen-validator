// Copyright 2026 Certen Protocol

package proofv2

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// RB9-F5 package F5-4b (V-I D1, D2): the 2.0 budget values stay named, evidence 2.0 keeps its capture check exactly, and the derivation text
// states the real numbers.

// closureOf returns one page whose encoding, with the (nil) votes' encoding, is exactly total bytes.
func closureOf(t *testing.T, total int) []PageState {
	t.Helper()
	enc := func(pages []PageState) int {
		n := 0
		for i := range pages {
			raw, err := json.Marshal(&pages[i])
			if err != nil {
				t.Fatal(err)
			}
			n += len(raw)
		}
		raw, err := json.Marshal([]Vote(nil))
		if err != nil {
			t.Fatal(err)
		}
		return n + len(raw)
	}
	pages := []PageState{{URL: "acc://a.acme/book/1"}}
	base := enc(pages)
	if total < base {
		t.Fatalf("total %d is below the empty page (%d)", total, base)
	}
	pages[0].State = strings.Repeat("a", total-base)
	if got := enc(pages); got != total {
		t.Fatalf("calibration: %d, want %d", got, total)
	}
	return pages
}

// The evidence 2.0 values are named and are the ones evidence 2.0 was always judged with (RB9-F5 invariant 2: nothing on the 2.0 path moves).
func TestBudget20ConstantsAreTheOnesEvidence20WasJudgedWith(t *testing.T) {
	if FixedEvidenceBytes20 != 760_000 || CertificateReserve20 != 96<<10 || MaxEvidenceBytes20 != 950_272 {
		t.Fatalf("2.0 budget: fixed %d reserve %d max %d, want 760000 / 98304 / 950272", FixedEvidenceBytes20, CertificateReserve20, MaxEvidenceBytes20)
	}
	if MaxEvidenceBytes20 != ConsensusTxLimit-CertificateReserve20 {
		t.Fatalf("MaxEvidenceBytes20 %d is not the limit less the 2.0 reserve", MaxEvidenceBytes20)
	}
}

// A 2.0 capture whose pages and votes are in the gap between the 2.0 threshold (950,272 - 760,000 = 190,272) and the 2.1 threshold
// (720,896 - 40,000 = 680,896) is refused g1_closure_exceeds_budget as before, with the 2.0 limit in the text; the same closure as 2.1 passes the
// evidence budget. At the 2.0 threshold exactly it passes; one byte over it is refused. Evidence 2.0 is not judged as a whole certificate (the
// check never was).
func TestClosureBudget20IsRefusedInTheGapAsBefore(t *testing.T) {
	old := MaxEvidenceBytes20 - FixedEvidenceBytes20
	if old != 190_272 || MaxEvidenceBytes-FixedEvidenceBytes != 680_896 {
		t.Fatalf("thresholds %d / %d, want 190272 / 680896", old, MaxEvidenceBytes-FixedEvidenceBytes)
	}
	if err := CheckClosureBudget(Version, closureOf(t, old), nil, "BVN1", 50); err != nil {
		t.Fatalf("a 2.0 closure exactly at its threshold: %v", err)
	}
	for _, total := range []int{old + 1, 300_000, 450_000, 680_896} {
		err := CheckClosureBudget(Version, closureOf(t, total), nil, "BVN1", 50)
		var ns *NamedState
		if !errors.As(err, &ns) || ns.Code != StateClosureExceedsBudget || ns.Partition != "BVN1" || ns.Block != 50 ||
			!strings.Contains(ns.Detail, "pages=1 limit=950272") || !strings.Contains(ns.Detail, "760000-byte fixed part") {
			t.Fatalf("a 2.0 closure of %d bytes in the gap: %v, want g1_closure_exceeds_budget{pages=1,limit=950272} at BVN1 block 50", total, err)
		}
		// The same closure as evidence 2.1 is inside its evidence budget (its fixed part is the anchored form's 40,000).
		if err := CheckClosureBudget(Version21, closureOf(t, total), nil, "BVN1", 50); err != nil {
			var cs *CertifyState
			if errors.As(err, &cs) && cs.Code == StateCertificateBudget {
				continue // the whole-certificate check of the 2.1 form may refuse it by its own name; never the 2.0 name
			}
			t.Fatalf("a 2.1 closure of %d bytes (inside its %d threshold): %v", total, MaxEvidenceBytes-FixedEvidenceBytes, err)
		}
	}
	// 2.1 keeps its own threshold and name.
	err := CheckClosureBudget(Version21, closureOf(t, MaxEvidenceBytes-FixedEvidenceBytes+1), nil, "BVN1", 50)
	var ns *NamedState
	if !errors.As(err, &ns) || ns.Code != StateClosureExceedsBudget || !strings.Contains(ns.Detail, "pages=1 limit=720896") {
		t.Fatalf("a 2.1 closure over its threshold: %v", err)
	}
}

// A document form the budget does not know is an error, never a default.
func TestClosureBudgetRefusesAnUnknownDocumentForm(t *testing.T) {
	if err := CheckClosureBudget("3.0", closureOf(t, 1000), nil, "BVN1", 50); err == nil || !strings.Contains(err.Error(), `"3.0"`) {
		t.Fatalf("an unknown evidence version: %v", err)
	}
}
