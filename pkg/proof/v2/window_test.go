// Copyright 2026 Certen Protocol

package proofv2

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

func windowEntries(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("window"), uint64(i)))
		out[i] = h[:]
	}
	return out
}

// windowPrefixes are main-chain stretches a combined update receipt can carry before its root-chain part: every shape of flags up to three
// steps, because the verifier is not told where the root-chain part begins.
func windowPrefixes() [][]*merkle.ReceiptEntry {
	var out [][]*merkle.ReceiptEntry
	for l := 0; l <= 3; l++ {
		for m := 0; m < 1<<l; m++ {
			var p []*merkle.ReceiptEntry
			for i := 0; i < l; i++ {
				p = append(p, &merkle.ReceiptEntry{Right: m>>i&1 == 1, Hash: windowEntries(8)[i+l]})
			}
			out = append(out, p)
		}
	}
	return out
}

// V-E A2(c): the root-chain position of an update is fixed by the Right flags of the END of its receipt and the signed tree size n, whatever
// main-chain steps come before. For every tree size up to 70, every leaf and every prefix shape, the position decodes to exactly the leaf's.
func TestRootChainLeafIndexIsFixedByTheReceiptTail(t *testing.T) {
	for n := 1; n <= 70; n++ {
		entries := windowEntries(n)
		for p := 0; p < n; p++ {
			r := trackedReceipt(entries, p)
			for _, pre := range windowPrefixes() {
				got, ok := rootChainLeafIndex(append(append([]*merkle.ReceiptEntry(nil), pre...), r.Entries...), uint64(n))
				if !ok || got != uint64(p) {
					t.Fatalf("n=%d p=%d prefix=%d steps: decoded %d ok=%v", n, p, len(pre), got, ok)
				}
			}
		}
	}
}

// A path that is not the root-chain path of any leaf of a tree of the signed size does not decompose: a tail of Right steps where the
// larger peaks need non-Right ones, a receipt of a larger tree, and one that is too short.
func TestRootChainLeafIndexRefusesWhatDoesNotDecompose(t *testing.T) {
	right := func(k int) []*merkle.ReceiptEntry {
		var out []*merkle.ReceiptEntry
		for i := 0; i < k; i++ {
			out = append(out, &merkle.ReceiptEntry{Right: true, Hash: windowEntries(1)[0]})
		}
		return out
	}
	// n = 7 has peaks 4, 2, 1: the leaf of the 1-peak is reached by two non-Right steps; an all-Right path of any length that is not a first-peak
	// or second-peak shape has no decoding.
	if _, ok := rootChainLeafIndex(nil, 7); ok {
		t.Fatal("an empty path decomposed for 7 leaves")
	}
	if _, ok := rootChainLeafIndex(right(1), 7); ok {
		t.Fatal("one Right step decomposed for 7 leaves")
	}
	if _, ok := rootChainLeafIndex(right(2), 7); ok {
		t.Fatal("two Right steps decomposed for 7 leaves: the first peak needs two inner steps and the combining step")
	}
	if _, ok := rootChainLeafIndex(right(3), 0); ok {
		t.Fatal("a tree of no leaves decomposed")
	}
	// A receipt shaped for 200 leaves, read against a tree of 70.
	entries := windowEntries(200)
	bad := 0
	for p := 0; p < 200; p++ {
		r := trackedReceipt(entries, p)
		if got, ok := rootChainLeafIndex(r.Entries, 70); !ok || got != uint64(p) {
			bad++
		}
	}
	if bad == 0 {
		t.Fatal("every leaf of a 200-leaf tree decodes to itself against a tree of 70")
	}
	if _, ok := rootChainLeafIndex([]*merkle.ReceiptEntry{nil}, 4); ok {
		t.Fatal("a null step decomposed")
	}
}
