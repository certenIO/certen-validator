// Copyright 2026 Certen Protocol

package proofv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

func residualEntries(n int, tag string) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte(tag), uint64(i)))
		out[i] = h[:]
	}
	return out
}

func residualAnchor(es [][]byte) []byte {
	st := new(merkle.State)
	for _, e := range es {
		st.AddEntry(e)
	}
	return st.Anchor()
}

// V-K D1: the RESIDUAL of the update window, pinned so that the TypeScript port mirrors exactly what is and is not established. The window
// bounds the root-chain position of the main-chain anchor the receipt is proven into; it does not bind the block the update's OWN main-chain
// entry was recorded in. An old entry (3, recorded when the network account's main chain had 4 entries, root-chain leaf 10) re-proven into a
// LATER main-chain anchor (the leaf 90 of a later block, in the later window (79, 99]) is a valid combined receipt that hashes to the signed
// root and decodes to a position inside the later window: the window check ACCEPTS it. The honest receipt of the same entry (leaf 10) is
// refused in that window. What keeps the final set exact is not this check but the distinct-hash replay set, the height equality and the
// content equality of the proven accounts (evidence.go); binding the entry itself is a consensus-format decision queued for the owner.
func TestWindowResidualALateProofOfAnOldEntryIsNotExcluded(t *testing.T) {
	main := residualEntries(20, "main chain")
	root := residualEntries(100, "root chain")
	root[10] = residualAnchor(main[:4])  // the main chain anchor when entry 3 was recorded
	root[90] = residualAnchor(main[:20]) // the main chain anchor of a later block, in the later window
	n := len(root)
	rootAnchor := residualAnchor(root)
	w := &updateWindow{prev: 79, prevKnown: true, this: 99, block: 1}

	// The late proof: entry 3 proven into the later main chain anchor and on through the root chain to leaf 90.
	late, err := merkle.Hasher(main).Receipt(3, 19).Combine(merkle.Hasher(root).Receipt(90, n-1))
	if err != nil {
		t.Fatal(err)
	}
	if !late.Validate(nil) || !bytes.Equal(late.Start, main[3]) || !bytes.Equal(late.Anchor, rootAnchor) {
		t.Fatal("the late proof is not a valid combined receipt from the old entry to the signed root")
	}
	if idx, ok := rootChainLeafIndex(late.Entries, uint64(n)); !ok || idx != 90 {
		t.Fatalf("the late proof decodes to (%d, %v), want leaf 90 of the root chain", idx, ok)
	}
	if err := w.check("acc://dn.acme/network", main[3], late.Entries); err != nil {
		t.Fatalf("RESIDUAL CHANGED: the late proof of an old entry is now refused (%v); if the entry is bound, the owner decision, the PR text, window.go's header and the TypeScript port change with it", err)
	}

	// The honest receipt of the same entry, proven into the main chain anchor of its own block (4 entries, root chain leaf 10), is in an earlier
	// window and is refused there.
	honest, err := merkle.Hasher(main[:4]).Receipt(3, 3).Combine(merkle.Hasher(root).Receipt(10, n-1))
	if err != nil {
		t.Fatal(err)
	}
	if !honest.Validate(nil) || !bytes.Equal(honest.Anchor, rootAnchor) {
		t.Fatal("the honest receipt is not a valid combined receipt to the signed root")
	}
	if idx, ok := rootChainLeafIndex(honest.Entries, uint64(n)); !ok || idx != 10 {
		t.Fatalf("the honest receipt decodes to (%d, %v), want leaf 10", idx, ok)
	}
	if err := w.check("acc://dn.acme/network", main[3], honest.Entries); err == nil {
		t.Fatal("the honest receipt of an entry recorded in an earlier window was accepted in the later window")
	}
	// ... and in a window that contains its leaf (the same signed tree, a previous anchor below leaf 10) it is accepted.
	own := &updateWindow{prev: 9, prevKnown: true, this: 99, block: 1}
	if err := own.check("acc://dn.acme/network", main[3], honest.Entries); err != nil {
		t.Fatalf("the honest receipt is refused in its own window: %v", err)
	}
}
