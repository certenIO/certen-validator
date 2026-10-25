// Copyright 2026 Certen Protocol

package baseposted

import (
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-F14: the verifier judges the sequencing window on the completing frame alone (R12-SPEC-Q1), so a streamed channel can have frames below
// the epoch of its batch. Both readers of the builder (the window reader and the index reader) must find such a channel.
func TestRB12F14AStreamedChannelWithFramesBelowTheEpochIsFoundByBothReaders(t *testing.T) {
	pins, bp := idxPins(t)
	st := NewMemStore()
	A := channelFrames("A", 1_790_100_000, 30, 1000, 4) // frames in blocks 1010, 1012, 1014, 1016
	for i, n := range []uint64{1010, 1012, 1014, 1016} {
		shapeBlock{number: n, hash: shapeHash(n, 0), txs: []shapeTx{{blob: false, datas: [][]byte{payloadOf(A[i])}}}}.put(t, st, bp)
	}
	for _, c := range []uint64{1031, 1400} {
		var cv [8]byte
		cv[6], cv[7] = byte(c>>8), byte(c)
		if err := st.Put(ctxBG(), finality.CaptureKey{Chain: uint64(Chain), L1Block: c, Item: finality.CaptureCursorItem}, cv[:]); err != nil {
			t.Fatal(err)
		}
	}
	ix := newIdx(st, bp, IndexConfig{ReconcileEvery: 1})
	if rep := stepAll(t, ix, 1400); rep.Entries != 1 || rep.Open != 0 {
		t.Fatalf("one complete channel: %+v", rep)
	}
	for _, c := range []struct {
		name    string
		epoch   uint64
		indexed bool
	}{
		{"window reader, the first two frames below the epoch", 1013, false},
		{"index reader, the first two frames below the epoch", 1013, true},
		{"window reader, every frame below the epoch", 1020, false},
		{"index reader, every frame below the epoch", 1020, true},
		{"window reader, the epoch below the first frame (as before)", 1000, false},
		{"index reader, the epoch below the first frame (as before)", 1000, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &Builder{Pins: pins, Store: st, L2: fixedL2{txs: [][]byte{l1InfoDeposit(c.epoch, [32]byte{9})}}}
			if c.indexed {
				b.Index = NewIndexReader(st, bp, 0)
			}
			sr, err := b.search(ctxBG(), bp, finality.HeaderFields{Number: 5, Timestamp: 1_790_100_000 + 20}, finality.NewHold(ctxBG(), uint64(Chain), "t"))
			if err != nil || sr.ch == nil || len(sr.frameTxs) != 4 {
				t.Fatalf("the channel of the leg was not found: %v %v", sr.ch, err)
			}
		})
	}
}

func TestRB12F14TheLeadIsTheChannelTimeoutInForceForTheFrames(t *testing.T) {
	bp := &Pins{ChannelTimeout: 300, ChannelTimeoutGranite: 50, GraniteTime: 1_723_478_400}
	for _, c := range []struct {
		name   string
		l2Time uint64
		want   uint64
	}{
		{"long after Granite", 1_792_400_000, 50},
		{"exactly the margin after Granite", 1_723_478_400 + 3600, 50},
		{"inside the margin after Granite", 1_723_478_400 + 3599, 300},
		{"before Granite", 1_700_000_000, 300},
	} {
		if got := streamLead(bp, c.l2Time); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if got := streamLead(&Pins{ChannelTimeout: 300, ChannelTimeoutGranite: 50}, 1_792_400_000); got != 300 {
		t.Errorf("no Granite pin: %d, want the larger timeout", got)
	}
}
