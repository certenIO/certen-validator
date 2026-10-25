// Copyright 2026 Certen Protocol

package arbfinal

import (
	"bytes"
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12 EPSILON stage 2 (EPS-MUTKILL-1): checkNodeBounds judged directly. The bound is inclusive (a node of exactly max_node_bytes is
// carried), a node above it that no proof path reads is refused with its length and its position in the NODES order, and the FIRST such
// node is the one named.

func TestCheckNodeBoundsNamesTheFirstOversizedNodeOutsideTheProofPathsAndCarriesNodesAtTheBound(t *testing.T) {
	const max = 8
	mk := func(n int) []byte { return bytes.Repeat([]byte{byte(n)}, n) }
	var kHeader finality.HeaderFields // zero roots: no node is on a proof path

	refused := func(nodes [][]byte, wantCount, wantIndex uint64) {
		t.Helper()
		err := checkNodeBounds(kHeader, Evidence{Nodes: nodes}, max)
		var se *finality.StateError
		if !errors.As(err, &se) {
			t.Fatalf("nodes of %d: no state error: %v", len(nodes), err)
		}
		want := string(finality.NewState(finality.CodeEvidenceTooLarge, "part", "nodes", "count", wantCount, "limit", uint64(max), "index", wantIndex).Canonical())
		if got := string(se.Canonical()); got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	}
	carried := func(nodes [][]byte) {
		t.Helper()
		if err := checkNodeBounds(kHeader, Evidence{Nodes: nodes}, max); err != nil {
			t.Errorf("%d nodes within the bound were refused: %v", len(nodes), err)
		}
	}

	// Only oversized nodes: the first is named.
	refused([][]byte{mk(9), mk(10)}, 9, 0)
	refused([][]byte{mk(10), mk(9)}, 10, 0)
	// A single oversized node.
	refused([][]byte{mk(9)}, 9, 0)
	// A node of exactly the bound is carried and is not the one named: the oversized node after it is.
	refused([][]byte{mk(8), mk(9)}, 9, 1)
	refused([][]byte{mk(3), mk(8), mk(12), mk(9)}, 12, 2)
	// Small nodes first, then an oversized one.
	refused([][]byte{mk(3), mk(9)}, 9, 1)

	carried(nil)
	carried([][]byte{})
	carried([][]byte{mk(1)})
	carried([][]byte{mk(8)})
	carried([][]byte{mk(3), mk(8), mk(7)})
}
