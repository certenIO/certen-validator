// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"testing"

	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

// V-K D3: the update window is judged on every path that walks a minor-root record of a 2.1 document, not only the anchored certify items. A
// continuous certify item and a set check hop (check.hops), anchored and continuous, carry an update whose root chain leaf lies in the previous
// item's window: each is refused certify_update_unproven{principal, txHash, the item's anchor block}. The same documents with the update inside
// its window are verified.
func TestUpdateWindowIsJudgedOnTheContinuousPathAndOnTheSetChecksHops(t *testing.T) {
	g := func(anchored bool, leaf string) xworld.ChainItem {
		return xworld.ChainItem{Anchored: anchored, Update: xworld.UpdateGlobalsB, Leaf: leaf}
	}
	h := func(anchored bool, leaf string) xworld.ChainItem {
		return xworld.ChainItem{Anchored: anchored, Update: xworld.UpdateGenesisGlobals, Leaf: leaf}
	}
	end := xworld.ChainItem{Anchored: true}
	cases := []struct {
		name  string
		chain *xworld.Chain
		want  string // "": verified; else the anchor block of the refusal
	}{
		{"continuous certify items, in the window", &xworld.Chain{Items: []xworld.ChainItem{g(false, xworld.LeafInWindow), h(false, xworld.LeafInWindow)}, Final: end}, ""},
		{"continuous certify item before the window", &xworld.Chain{Items: []xworld.ChainItem{g(false, xworld.LeafInWindow), h(false, xworld.LeafBefore)}, Final: end}, "120"},
		{"continuous certify item after the window", &xworld.Chain{Items: []xworld.ChainItem{g(false, xworld.LeafAfter)}, Final: end}, "110"},
		{"continuous certify item with a receipt that does not decompose", &xworld.Chain{Items: []xworld.ChainItem{g(false, xworld.LeafShape)}, Final: end}, "110"},
		{"anchored hop, in the window", &xworld.Chain{Final: end, Hops: []xworld.ChainItem{g(true, xworld.LeafInWindow), {Anchored: true}}}, ""},
		{"anchored hop before the window (a leaf of the previous hop's window)", &xworld.Chain{Final: end, Hops: []xworld.ChainItem{g(true, xworld.LeafInWindow), h(true, xworld.LeafBefore), {Anchored: true}}}, "320"},
		{"anchored hop after the window", &xworld.Chain{Final: end, Hops: []xworld.ChainItem{g(true, xworld.LeafAfter), {Anchored: true}}}, "310"},
		{"continuous hop before the window", &xworld.Chain{Final: end, Hops: []xworld.ChainItem{g(false, xworld.LeafInWindow), h(false, xworld.LeafBefore), {Anchored: true}}}, "320"},
		{"continuous hop with a receipt that does not decompose", &xworld.Chain{Final: end, Hops: []xworld.ChainItem{g(false, xworld.LeafShape), {Anchored: true}}}, "310"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := buildChain(t, c.chain)
			_, err := verify21(t, b)
			if c.want == "" {
				if err != nil {
					t.Fatalf("a document with its updates inside their windows is refused: %v", err)
				}
				return
			}
			wantUnproven(t, err, c.want)
		})
	}
}
