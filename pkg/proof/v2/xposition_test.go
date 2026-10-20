// Copyright 2026 Certen Protocol

package proofv2

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// trackedReceipt builds the receipt of entry p of a chain by watching merkle.State.AddEntry carry it upward and Anchor fold the
// peaks - Accumulate's own algorithm replayed step by step, independent of the closed form receiptFlags.
func trackedReceipt(entries [][]byte, p int) *merkle.Receipt {
	type node struct {
		hash []byte
		has  bool
	}
	comb := func(left, right []byte) []byte {
		s := sha256.Sum256(append(append([]byte{}, left...), right...))
		return s[:]
	}
	var pending []*node
	r := &merkle.Receipt{Start: entries[p]}
	for i, e := range entries {
		cur := &node{hash: e, has: i == p}
		for lvl := 0; ; lvl++ {
			if lvl == len(pending) {
				pending = append(pending, nil)
			}
			if pending[lvl] == nil {
				pending[lvl] = cur
				break
			}
			left := pending[lvl] // the slot's hash is the left child, the carried one the right
			if left.has {
				r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: true, Hash: cur.hash})
			}
			if cur.has {
				r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: false, Hash: left.hash})
			}
			cur = &node{hash: comb(left.hash, cur.hash), has: left.has || cur.has}
			pending[lvl] = nil
		}
	}
	var acc *node
	for _, v := range pending {
		if v == nil {
			continue
		}
		if acc == nil {
			acc = v
			continue
		}
		if acc.has {
			r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: false, Hash: v.hash})
		}
		if v.has {
			r.Entries = append(r.Entries, &merkle.ReceiptEntry{Right: true, Hash: acc.hash})
		}
		acc = &node{hash: comb(v.hash, acc.hash), has: acc.has || v.has}
	}
	r.Anchor = acc.hash
	return r
}

// Positions are fixed by a receipt's shape given the chain's height: for every chain up to 70 entries and every entry, the receipt
// Accumulate's algorithm builds validates, ends at the chain's anchor, and decodes to exactly the entry's position - so the position
// the arrival derivation uses is established by the receipt, not claimed.
func TestReceiptPositionIsFixedByTheReceiptShape(t *testing.T) {
	for n := 1; n <= 70; n++ {
		entries := make([][]byte, n)
		for i := range entries {
			h := sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i)))
			entries[i] = h[:]
		}
		st := new(merkle.State)
		for _, e := range entries {
			st.AddEntry(e)
		}
		for p := 0; p < n; p++ {
			r := trackedReceipt(entries, p)
			if string(r.Anchor) != string(st.Anchor()) || !r.Validate(nil) {
				t.Fatalf("n=%d p=%d: the tracked receipt does not validate to the chain's anchor", n, p)
			}
			got := receiptPositions(r, uint64(n))
			if len(got) != 1 || got[0] != uint64(p) {
				t.Fatalf("n=%d p=%d: the receipt decodes to positions %v", n, p, got)
			}
		}
	}
}
