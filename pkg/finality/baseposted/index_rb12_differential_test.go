// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-TRAIN3-INT (V-INT3 N-I1): the index path must end a search that found no channel exactly as the window reader does. The two tail steps
// of search (the recorded gaps with the evidence of a gone one, and the determinate l1_posted_not_found of a complete window, authentic()
// first) are ONE function used by both; this differential asserts it. Same leg, same store, canonical bytes of what Build answers.

type diffAnswer struct {
	pending string
	state   []byte
}

func (a diffAnswer) String() string {
	if a.pending != "" {
		return "pending " + a.pending
	}
	if a.state == nil {
		return "nothing"
	}
	return string(a.state)
}

// diffBuild runs Build for the leg whose origin is origin and returns what it answered.
func diffBuild(t *testing.T, st finality.CaptureStore, origin uint64, pol finality.PrefixPolicy, lying bool, indexed bool, bp *Pins) diffAnswer {
	t.Helper()
	s, l2 := rbLeg(t, origin)
	if lying {
		l2 = fixedL2{txs: [][]byte{l1InfoDeposit(origin+7, [32]byte{9})}} // a provider that answers another block than the header commits to
	}
	b := rbBuilder(t, st, l2)
	b.Prefix = pol
	if indexed {
		b.Index = NewIndexReader(st, bp, 0)
	}
	_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if pend != nil {
		return diffAnswer{pending: pend.Reason}
	}
	if se, ok := finality.AsNamed(err); ok {
		return diffAnswer{state: se.Canonical()}
	}
	if err != nil {
		return diffAnswer{state: []byte("error: " + err.Error())}
	}
	return diffAnswer{}
}

func TestRB12IndexedAndWindowSearchesEndAMissIdentically(t *testing.T) {
	ctx := context.Background()
	chain := uint64(Chain)
	pol := finality.PrefixPolicy{MaxBlocks: 10_000}
	type scenario struct {
		name   string
		origin func() uint64
		pol    finality.PrefixPolicy
		lying  bool
		setup  func(t *testing.T, st finality.CaptureStore, origin uint64)
		want   string // a substring the answer must hold, so the case cannot pass by both paths being silent
	}
	below := uint64(rbFirstBlock - 20_000)
	inside := uint64(rbFirstBlock + 100)
	fillWindow := func(t *testing.T, st finality.CaptureStore, origin uint64) {
		for n := origin; n <= origin+3600; n++ {
			rawFillRow(t, st, n)
		}
	}
	cases := []scenario{
		{"S1 below the scan, prefix off", func() uint64 { return below }, finality.PrefixPolicy{}, false, nil, "l1_capture_not_covering"},
		{"S1b below the scan, over budget", func() uint64 { return below }, finality.PrefixPolicy{MaxBlocks: 10}, false, nil, "over_budget"},
		{"S1c below the scan, below the floor", func() uint64 { return below }, finality.PrefixPolicy{MaxBlocks: 10_000, Floor: rbFirstBlock - 100}, false, nil, "below_floor"},
		{"S2 prefix recorded", func() uint64 { return below }, pol, false, nil, "l1_capture_gap"},
		{"S3 prefix partly filled", func() uint64 { return below }, pol, false, func(t *testing.T, st finality.CaptureStore, origin uint64) {
			for n := origin; n < origin+100; n++ {
				rawFillRow(t, st, n)
			}
		}, "l1_capture_gap"},
		{"S4 prefix filled, window complete", func() uint64 { return below }, pol, false, fillWindow, "l1_posted_not_found"},
		{"S5 complete window inside the scan", func() uint64 { return inside }, pol, false, nil, "l1_posted_not_found"},
		{"S6 unavailable_proven with its evidence", func() uint64 { return inside }, pol, false, func(t *testing.T, st finality.CaptureStore, origin uint64) {
			rawGapRow(t, st, origin+10, origin+20, "blob_unavailable")
			for n := origin + 10; n <= origin+20; n++ {
				if err := finality.RecordGapSlot(ctx, st, chain, n, 777+n); err != nil {
					t.Fatal(err)
				}
				if err := finality.RecordGapEnd(ctx, st, chain, n, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"h1", "h2"}}); err != nil {
					t.Fatal(err)
				}
			}
		}, "blob_archive"},
		{"S7 a lying L2 provider, complete window", func() uint64 { return inside }, pol, true, nil, "l2_block_content_mismatch"},
		{"S7b a lying L2 provider, below the scan", func() uint64 { return below }, pol, true, nil, "l2_block_content_mismatch"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := rbStore(t, rbFirstBlock, 1000, true)
			origin := c.origin()
			if c.setup != nil {
				c.setup(t, st, origin)
			}
			_, bp := idxPins(t)
			stepAll(t, newIdx(st, bp, IndexConfig{}), rbFirstBlock+5*999+200)
			diffBuild(t, st, origin, c.pol, c.lying, false, bp) // the first ask may record a request; the question is asked again below
			w := diffBuild(t, st, origin, c.pol, c.lying, false, bp)
			i := diffBuild(t, st, origin, c.pol, c.lying, true, bp)
			if fmt.Sprint(w) != fmt.Sprint(i) {
				t.Fatalf("the index path ends the miss differently:\n window  %s\n indexed %s", w, i)
			}
			if got := w.String(); len(got) == 0 || !strings.Contains(got, c.want) {
				t.Fatalf("the scenario does not reach the answer it is about (%q): %s", c.want, got)
			}
		})
	}
}
