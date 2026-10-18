// Copyright 2026 Certen Protocol

package proofv2_test

import (
	"errors"
	"testing"

	"github.com/certen/independant-validator/pkg/ledger"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
	"github.com/certen/independant-validator/pkg/proof/v2/xworld"
)

func leafItem(kind, leaf string) xworld.ChainItem {
	return xworld.ChainItem{Anchored: true, Update: kind, Leaf: leaf}
}

func wantUnproven(t *testing.T, err error, block string) {
	t.Helper()
	var cs *proofv2.CertifyState
	if !errors.As(err, &cs) || cs.Code != proofv2.StateCertifyUpdateUnproven || len(cs.Fields) != 3 ||
		cs.Fields[0] != "acc://dn.acme/globals" || len(cs.Fields[1]) != 64 || cs.Fields[2] != block {
		t.Fatalf("refused with %v, want certify_update_unproven{acc://dn.acme/globals,<txHash>,%s}", err, block)
	}
}

// V-E A2(c): an update's root-chain position, read from its receipt's shape and the signed tree size, must lie in (the previous anchor's
// RootChainIndex, this anchor's]. The verdicts, on the walk of the anchored form.
func TestUpdateWindowIsJudgedAgainstTheBlockItWasRecordedIn(t *testing.T) {
	g := func(leaf string) xworld.ChainItem { return leafItem(xworld.UpdateGlobalsB, leaf) }
	h := func(leaf string) xworld.ChainItem { return leafItem(xworld.UpdateGenesisGlobals, leaf) }
	cases := []struct {
		name  string
		items []xworld.ChainItem
		want  string // "": verified; else the anchor block of the refusal of the LAST item
	}{
		{"inside the window", []xworld.ChainItem{g(xworld.LeafInWindow), h(xworld.LeafInWindow)}, ""},
		{"before the window (a leaf of the previous item's window)", []xworld.ChainItem{g(xworld.LeafInWindow), h(xworld.LeafBefore)}, "120"},
		{"after the window (a receipt of a larger tree than the signed one)", []xworld.ChainItem{g(xworld.LeafAfter)}, "110"},
		{"a receipt that does not decompose for the signed tree size", []xworld.ChainItem{g(xworld.LeafShape)}, "110"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := buildChain(t, &xworld.Chain{Items: c.items, Final: xworld.ChainItem{Anchored: true}})
			sp, recs, links := spineAt1(t, b)
			var err error
			for i := range c.items {
				if err = sp.AdvanceAnchored(recs[i], links[i]); err != nil {
					break
				}
			}
			if c.want == "" {
				if err != nil {
					t.Fatalf("an update inside its window is refused: %v", err)
				}
				return
			}
			wantUnproven(t, err, c.want)
		})
	}
}

// V-E A2(c), gate: a spine restored from a checkpoint recorded before the field existed does not know the previous anchor's RootChainIndex, so
// the lower bound of the first window is unproven and the first update is refused by name; one restored from a checkpoint that holds it is
// judged on its merits.
func TestWindowLowerBoundNeedsTheCheckpointsRootChainIndex(t *testing.T) {
	b := buildChain(t, &xworld.Chain{Items: []xworld.ChainItem{leafItem(xworld.UpdateGlobalsB, xworld.LeafInWindow)}, Final: xworld.ChainItem{Anchored: true}})
	_, recs, links := spineAt1(t, b)
	g, set, err := proofv2.AcceptSpineGenesis(b.Inputs, b.Pin, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range []bool{false, true} {
		l := &ledger.AccumulateSpineLog{Genesis: g, Sets: []ledger.AccumulateSpineSet{set}}
		cps, sets, err := proofv2.ExtendSpineCounting(l, b.Archive.Majors, 2, gate)
		if err != nil {
			t.Fatal(err)
		}
		l.Checkpoints, l.Sets = cps, append(l.Sets, sets...)
		sp, err := proofv2.SpineAt(l, 1)
		if err != nil {
			t.Fatal(err)
		}
		err = sp.AdvanceAnchored(recs[0], links[0])
		if gate {
			if err != nil {
				t.Fatalf("a checkpoint that holds the RootChainIndex (%d) refuses an update inside its window: %v", cps[0].RootChainIndex, err)
			}
			continue
		}
		wantUnproven(t, err, "110")
	}
}
