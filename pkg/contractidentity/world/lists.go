// Copyright 2026 Certen Protocol

package world

import "fmt"

// BlockLists returns the consensus encodings of every transaction and every receipt of a block of the world, in index order, by block name
// (BlockAttestParent, BlockAttest, "between.<i>", BlockSettle). A capture that reads a whole block (RB12-GOCAPTURE-3b: the transaction list
// of the attestation block and the receipts trie of its proof) is served from them. The slices are copies.
func (w *World) BlockLists(name string) (txs, receipts [][]byte, err error) {
	var b *block
	switch {
	case name == BlockAttestParent:
		b = w.d.bParent
	case name == BlockAttest:
		b = w.d.bAtt
	case name == BlockSettle:
		b = w.d.bSet
	default:
		var i int
		if _, e := fmt.Sscanf(name, "between.%d", &i); e != nil || i < 0 || i >= len(w.d.between) {
			return nil, nil, fmt.Errorf("world: no block %q", name)
		}
		b = w.d.between[i]
	}
	for _, t := range b.wires {
		txs = append(txs, append([]byte(nil), t...))
	}
	for _, r := range b.receipts {
		receipts = append(receipts, append([]byte(nil), r...))
	}
	return txs, receipts, nil
}
