// Copyright 2026 Certen Protocol
//
// The window of an update (V-E A2(c), PROOF_V2 s4.3): "each update's window is checked against the block its main-chain entry was recorded
// in". An update the Directory serves carries a combined receipt, from the transaction through the network or globals account's main chain
// into that chain's anchor, and from that anchor through the root chain to the root the anchor signs. The anchor entry is a leaf of the root
// chain, appended in the block the transaction executed in, so its position lies in (the previous anchor's RootChainIndex, this anchor's
// RootChainIndex]. The position is not a field the signed anchor carries and Receipt.StartIndex is not authenticated by anything the receipt
// hashes; it is read from the shape of the receipt (which side each sibling is on) given the signed tree size n = RootChainIndex + 1.

package proofv2

import (
	"encoding/hex"
	"math"
	"strconv"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// rootChainLeafIndex returns the root-chain position of the leaf the end of entries is the path of, in a root chain of size leaves. The
// root chain's anchor combines its peaks from the smallest up, a larger peak on the left, so the root-chain part of a path is, from the
// leaf: one step per level inside the leaf's perfect subtree (the offset's bits, Right when the bit is 0), then one Right step when smaller
// peaks exist, then one non-Right step per larger peak. Main-chain steps may come before it; where the root-chain part begins is read from
// the END, and it is unique: when the leaf's peak has smaller peaks the step before the trailing non-Right run is Right, and the run is
// exactly the number of larger peaks; otherwise the run is at least the number of larger peaks of the smallest peak. ok is false for a path
// that is the root-chain path of no leaf of a tree of that size.
func rootChainLeafIndex(entries []*merkle.ReceiptEntry, size uint64) (uint64, bool) {
	if size == 0 {
		return 0, false
	}
	for _, e := range entries {
		if e == nil {
			return 0, false
		}
	}
	var heights []uint
	for h := 63; h >= 0; h-- {
		if size>>uint(h)&1 == 1 {
			heights = append(heights, uint(h))
		}
	}
	peaks := len(heights)
	run := 0
	for run < len(entries) && !entries[len(entries)-1-run].Right {
		run++
	}
	larger, last := peaks-1, true
	if run < peaks-1 {
		larger, last = run, false
	}
	k := int(heights[larger])
	width := k + larger
	if !last {
		width++ // the Right step that combines the smaller peaks
	}
	if len(entries) < width {
		return 0, false
	}
	part := entries[len(entries)-width:]
	if !last && !part[k].Right {
		return 0, false
	}
	var index uint64
	for j := 0; j < larger; j++ {
		index += uint64(1) << heights[j]
	}
	for j := 0; j < k; j++ {
		if !part[j].Right {
			index += uint64(1) << uint(j)
		}
	}
	return index, true
}

// updateWindow is the window an update must lie in: the root chain positions in (prev, this], judged at the anchor of Directory minor
// block block. prevKnown is false when the previous anchor's RootChainIndex is not established (a spine restored from a checkpoint recorded
// before the field existed), which leaves the window's lower bound unproven.
type updateWindow struct {
	prev      uint64
	prevKnown bool
	this      uint64
	block     uint64
}

// check judges one update whose receipt already validates and ends at the anchor's root chain anchor. The refusal is
// certify_update_unproven{principal, txHash, anchorBlock}.
func (w *updateWindow) check(principal string, txHash []byte, entries []*merkle.ReceiptEntry) error {
	state := func() error {
		return certifyState(StateCertifyUpdateUnproven, principal, hex.EncodeToString(txHash), strconv.FormatUint(w.block, 10))
	}
	if !w.prevKnown || w.this == math.MaxUint64 {
		return state()
	}
	idx, ok := rootChainLeafIndex(entries, w.this+1)
	if !ok || idx <= w.prev || idx > w.this {
		return state()
	}
	return nil
}
