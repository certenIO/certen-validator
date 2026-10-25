// Copyright 2026 Certen Protocol

package adiri

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 OPS-A2 item 9: the table index of the evidence is one byte; a 257th distinct committee is refused by name and never wraps to table 0.
func TestTableIndexRefusesA257thCommitteeByNameAndNeverWraps(t *testing.T) {
	var ti tableIndex
	committee := func(i int) [][]byte { return [][]byte{{byte(i >> 8), byte(i), 1}} }
	for i := 0; i < 256; i++ {
		got, err := ti.of(committee(i))
		if err != nil || int(got) != i {
			t.Fatalf("committee %d: index %d, %v", i, got, err)
		}
	}
	if got, err := ti.of(committee(3)); err != nil || got != 3 {
		t.Fatalf("a known committee keeps its index: %d %v", got, err)
	}
	_, err := ti.of(committee(256))
	st, named := finality.AsNamed(err)
	if !named || st.Code != finality.CodeEvidenceTooLarge || st.Fields["part"] != "committee_tables" || st.Fields["limit"] != uint64(256) || st.Fields["count"] != uint64(257) {
		t.Fatalf("the 257th committee: %v", err)
	}
	if len(ti.tables) != 256 {
		t.Fatalf("%d tables after a refusal", len(ti.tables))
	}
}
