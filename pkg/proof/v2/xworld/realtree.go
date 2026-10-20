// Copyright 2026 Certen Protocol
//
// Real root-chain positions for the update-bearing items of a certify chain (V-E A2(c)). An item's update receipt is a combined receipt as the
// Directory serves it: the transaction through the account's main chain (two steps here) to the account's chain anchor, that anchor as a
// LEAF of the root chain, and the root chain's path to the root the item's anchor signs. The root chain of an item holds windowBase + (64 x
// (position + 1)) leaves: a stand-in for the chain before this walk (a perfect subtree of windowBase leaves whose hash is the previous root,
// the larger peak a combined root always has) and a real tree of 64 x (position + 1) leaves, built with Accumulate's own merkle.State, of
// which the last 64 are this item's window. The anchor signs RootChainIndex = windowBase + 64 x (position + 1) - 1, so the update's position
// is read from the receipt's shape and lies in (the previous item's RootChainIndex, this one's].

package xworld

import (
	"bytes"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// Leaf placements of an update in the root chain.
const (
	// LeafInWindow (the default): the update's leaf is appended in the item's own window.
	LeafInWindow = ""
	// LeafBefore: the leaf lies in the previous item's window (a replay of an update that was recorded earlier); needs a position of 1 or more.
	LeafBefore = "before"
	// LeafAfter: the leaf lies beyond the tree the anchor signs (the receipt is that of a tree one leaf larger than RootChainIndex + 1).
	LeafAfter = "after"
	// LeafShape: the receipt's path is not the root chain path of any leaf of a tree of the signed size (too short).
	LeafShape = "shape"
)

const (
	windowBase  = 4096
	windowWidth = 64
)

// rootChainIndexAt is the RootChainIndex an item at position pos of a windowed chain signs.
func rootChainIndexAt(pos int) uint64 { return uint64(windowBase + windowWidth*(pos+1) - 1) }

// peaksOf returns the sizes (heights) of the peaks of n leaves, largest first.
func peakHeights(n int) []uint {
	var hs []uint
	for h := 62; h >= 0; h-- {
		if n>>uint(h)&1 == 1 {
			hs = append(hs, uint(h))
		}
	}
	return hs
}

func perfect(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	half := len(leaves) / 2
	return h2(perfect(leaves[:half]), perfect(leaves[half:]))
}

// treeReceipt is the receipt of leaf p of a tree of the given leaves, built as Accumulate's merkle.State combines them (a larger peak on the
// left of the combined smaller ones); it panics when its anchor is not merkle.State's.
func treeReceipt(leaves [][]byte, p int) *merkle.Receipt {
	hs := peakHeights(len(leaves))
	var peaks [][]byte
	start := 0
	pk, pStart := -1, 0
	for i, h := range hs {
		size := 1 << h
		peaks = append(peaks, perfect(leaves[start:start+size]))
		if p >= start && p < start+size {
			pk, pStart = i, start
		}
		start += size
	}
	var steps []step
	sub := leaves[pStart : pStart+(1<<hs[pk])]
	off := p - pStart
	for len(sub) > 1 {
		half := len(sub) / 2
		if off < half {
			steps = append(steps, step{true, perfect(sub[half:])})
			sub = sub[:half]
		} else {
			steps = append(steps, step{false, perfect(sub[:half])})
			sub, off = sub[half:], off-half
		}
	}
	for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 { // the steps above were taken from the top of the subtree down; a receipt goes from the leaf up
		steps[i], steps[j] = steps[j], steps[i]
	}
	if pk < len(peaks)-1 {
		acc := peaks[len(peaks)-1]
		for i := len(peaks) - 2; i > pk; i-- {
			acc = h2(peaks[i], acc)
		}
		steps = append(steps, step{true, acc})
	}
	for i := pk - 1; i >= 0; i-- {
		steps = append(steps, step{false, peaks[i]})
	}
	r := rcpt(leaves[p], steps...)
	st := new(merkle.State)
	for _, l := range leaves {
		st.AddEntry(l)
	}
	if !bytes.Equal(r.Anchor, st.Anchor()) {
		panic(fmt.Sprintf("xworld: the receipt of leaf %d of %d does not end at Accumulate's anchor", p, len(leaves)))
	}
	return r
}

func windowPad(i int) []byte { return seed(fmt.Sprintf("window pad %d", i)) }

// windowedUpdates returns the item's tree entry e (the root of its real lower tree: the item's root is h2(prev, e)) and the updates it
// carries, each with the combined receipt that ends at that root.
func windowedUpdates(it ChainItem, label string, prev []byte, rec chainRecords, pos int) ([]byte, []*api.NetworkUpdateProof) {
	tx, txh := updateTx(it.Update, rec, label)
	main1, main2 := seed(label+" main chain 1"), seed(label+" main chain 2")
	mainPart := rcpt(txh, step{true, main1}, step{false, main2})
	leaf := mainPart.Anchor // the account's chain anchor, the root chain's leaf
	at := windowWidth*pos + 5
	width := windowWidth * (pos + 1)
	var e []byte
	var rootPart []step
	switch it.Leaf {
	case LeafShape:
		s := step{true, seed(label + " short path")}
		e = h2(leaf, s.hash)
		rootPart = []step{s}
	default:
		switch it.Leaf {
		case LeafBefore:
			if pos < 1 {
				panic("xworld: LeafBefore needs an item at position 1 or later")
			}
			at = 5
		case LeafAfter:
			at, width = width, width+1
		}
		leaves := make([][]byte, width)
		for i := range leaves {
			leaves[i] = windowPad(i)
		}
		leaves[at] = leaf
		low := treeReceipt(leaves, at)
		e = low.Anchor
		for _, en := range low.Entries {
			rootPart = append(rootPart, step{en.Right, en.Hash})
		}
	}
	rootPart = append(rootPart, step{false, prev})
	var steps []step
	for _, en := range mainPart.Entries {
		steps = append(steps, step{en.Right, en.Hash})
	}
	steps = append(steps, rootPart...)
	n := max(it.Repeat, 1)
	var ups []*api.NetworkUpdateProof
	for i := 0; i < n; i++ {
		ups = append(ups, &api.NetworkUpdateProof{Transaction: tx, Receipt: rcpt(txh, steps...)})
	}
	return e, ups
}

// rciOf is the RootChainIndex an item at position pos signs: the real one in a windowed chain, 0 (the synthetic default, the minor block) in any
// other.
func rciOf(windowed bool, pos int) uint64 {
	if !windowed {
		return 0
	}
	return rootChainIndexAt(pos)
}
