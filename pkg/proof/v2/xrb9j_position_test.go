// Copyright 2026 Certen Protocol

package proofv2

import (
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// RB9 verifier round VA, note (e): the position a receipt fixes is decoded from its Right flags in O(log n) - for a chain far beyond
// what a linear scan could cover.
func TestJ1ReceiptPositionsAreDecodedDirectlyForAHugeChain(t *testing.T) {
	n := uint64(1)<<40 + 1<<20 + 12345
	for _, p := range []uint64{0, 1, 12344, 1<<20 + 7, 1<<40 - 1, 1 << 40, 1<<40 + 1<<20 + 12344} {
		flags := receiptFlags(p, n)
		r := &merkle.Receipt{}
		for _, f := range flags {
			r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: f})
		}
		got := receiptPositions(r, n)
		if len(got) != 1 || got[0] != p {
			t.Fatalf("position %d of %d decoded as %v", p, n, got)
		}
	}
}
