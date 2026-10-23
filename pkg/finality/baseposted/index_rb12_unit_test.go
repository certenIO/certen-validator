// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// The pure steps of the index, pinned at their boundaries.

func TestRB12IndexCoverageRunHoldsExactlyItsTimestamps(t *testing.T) {
	r := covRun{First: 100, Count: 3}
	for _, c := range []struct {
		ts   uint64
		step uint64
		want bool
	}{{100, 2, true}, {102, 2, true}, {104, 2, true}, {106, 2, false}, {98, 2, false}, {101, 2, false}, {103, 2, false}, {0, 2, false},
		{100, 0, false}, {104, 1, false}, {102, 1, true}} {
		if got := r.covers(c.ts, c.step); got != c.want {
			t.Fatalf("covers(%d, step %d) = %v, want %v", c.ts, c.step, got, c.want)
		}
	}
	if (covRun{First: 100}).covers(100, 2) {
		t.Fatal("an empty run covers nothing")
	}
}

func TestRB12IndexRunsBreakAtAGapATypeAnEpochAndANonIncreasingTimestamp(t *testing.T) {
	b := func(ts uint64, typ uint8, epoch uint64) Batch {
		return Batch{Timestamp: ts, Type: typ, EpochNum: epoch}
	}
	runs, tmin, tmax, ok := runsOf([]Batch{b(10, 0, 5), b(12, 0, 5), b(14, 0, 5)}, 2)
	if !ok || len(runs) != 1 || runs[0] != (covRun{First: 10, Count: 3, Type: 0, Epoch: 5}) || tmin != 10 || tmax != 14 {
		t.Fatalf("contiguous: %+v %d %d %v", runs, tmin, tmax, ok)
	}
	cases := []struct {
		name string
		in   []Batch
		want []covRun
	}{
		{"a gap", []Batch{b(10, 0, 5), b(14, 0, 5)}, []covRun{{10, 1, 0, 5}, {14, 1, 0, 5}}},
		{"an epoch change", []Batch{b(10, 0, 5), b(12, 0, 6)}, []covRun{{10, 1, 0, 5}, {12, 1, 0, 6}}},
		{"a type change", []Batch{b(10, 0, 5), b(12, 1, 5)}, []covRun{{10, 1, 0, 5}, {12, 1, 1, 5}}},
		{"a repeated timestamp", []Batch{b(10, 0, 5), b(10, 0, 5)}, []covRun{{10, 1, 0, 5}, {10, 1, 0, 5}}},
		{"a step back", []Batch{b(12, 0, 5), b(10, 0, 5)}, []covRun{{12, 1, 0, 5}, {10, 1, 0, 5}}},
	}
	for _, c := range cases {
		got, tmin, tmax, ok := runsOf(c.in, 2)
		if !ok || len(got) != len(c.want) {
			t.Fatalf("%s: %+v", c.name, got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: run %d = %+v, want %+v", c.name, i, got[i], c.want[i])
			}
		}
		if tmin != 10 || (tmax != 14 && tmax != 12 && tmax != 10) {
			t.Fatalf("%s: range %d..%d", c.name, tmin, tmax)
		}
	}
	// the range is the smallest and the largest timestamp whatever their order
	if _, tmin, tmax, _ := runsOf([]Batch{b(30, 0, 1), b(10, 0, 1), b(20, 0, 1)}, 2); tmin != 10 || tmax != 30 {
		t.Fatalf("range %d..%d", tmin, tmax)
	}
	// more runs than an entry stores: the range is still named, the runs are not stored
	many := make([]Batch, 0, maxRuns+5)
	for i := 0; i < maxRuns+5; i++ {
		many = append(many, b(1000+uint64(i)*10, 0, 1))
	}
	runs, tmin, tmax, ok = runsOf(many, 2)
	if ok || len(runs) != maxRuns || tmin != 1000 || tmax != 1000+uint64(maxRuns+4)*10 {
		t.Fatalf("overflow: ok=%v runs=%d range %d..%d", ok, len(runs), tmin, tmax)
	}
	if _, _, _, ok := runsOf(many[:maxRuns], 2); !ok {
		t.Fatal("exactly maxRuns runs fit")
	}
	if runs, _, _, ok := runsOf(nil, 2); !ok || len(runs) != 0 {
		t.Fatal("no batches, no runs")
	}
}

func TestRB12IndexCompleteIsTheVerifiersRuleOnOrderedFrames(t *testing.T) {
	f := func(n uint16, last bool) frameRef { return frameRef{Number: n, Last: last} }
	for _, c := range []struct {
		name string
		in   []frameRef
		want bool
	}{
		{"none", nil, false},
		{"one closing frame", []frameRef{f(0, true)}, true},
		{"two frames", []frameRef{f(0, false), f(1, true)}, true},
		{"does not start at 0", []frameRef{f(1, true)}, false},
		{"a gap", []frameRef{f(0, false), f(2, true)}, false},
		{"never closes", []frameRef{f(0, false), f(1, false)}, false},
		{"closes in the middle", []frameRef{f(0, true), f(1, true)}, false},
		{"a duplicate", []frameRef{f(0, false), f(0, false), f(1, true)}, false},
		{"out of order", []frameRef{f(1, false), f(0, true)}, false},
	} {
		if got := complete(c.in); got != c.want {
			t.Fatalf("%s: complete = %v", c.name, got)
		}
	}
}

func TestRB12IndexTransactionsOfAChannelAreDistinctAndInCaptureOrder(t *testing.T) {
	h1, h2 := [32]byte{1}, [32]byte{2}
	fr := []frameRef{
		{Block: 10, Hash: h1, TxIndex: 0, Blobs: 6}, {Block: 10, Hash: h1, TxIndex: 0, Blobs: 6}, // two frames of one transaction
		{Block: 10, Hash: h1, TxIndex: 1, Blobs: 1}, {Block: 10, Hash: h2, TxIndex: 1, Blobs: 1}, // the same index under another hash is another transaction
		{Block: 11, Hash: h1, TxIndex: 1, Blobs: 2},
	}
	got := txsOf(fr)
	want := []entryTx{{10, h1, 0, 6}, {10, h1, 1, 1}, {10, h2, 1, 1}, {11, h1, 1, 2}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("tx %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRB12IndexFrameTableOrdersLikeFindChannelAndForgetsOldBlocks(t *testing.T) {
	h1, h2 := [32]byte{1}, [32]byte{2}
	id := [16]byte{7}
	dg := func(block uint64, hash [32]byte, txs ...digestTx) *blockDigest {
		return &blockDigest{Block: block, Hash: hash, Txs: txs}
	}
	fr := func(n uint16, last bool) digestFrame { return digestFrame{ID: id, Number: n, Last: last, Len: 1} }
	ft := newFrameTable()
	// added out of order: later block first
	ft.add(1, dg(20, h1, digestTx{Index: 0, Frames: []digestFrame{fr(2, true)}}))
	ft.add(1, dg(10, h2, digestTx{Index: 0, Frames: []digestFrame{fr(1, false)}}))
	ft.add(1, dg(10, h1, digestTx{Index: 0, Frames: []digestFrame{fr(0, false)}}, digestTx{Index: 1, Frames: []digestFrame{fr(5, false), fr(6, false)}}))
	ft.add(1, dg(10, h1, digestTx{Index: 0, Frames: []digestFrame{fr(0, false)}})) // the same block again changes nothing
	got := ft.byCh[id]
	wantNums := []uint16{0, 5, 6, 1, 2} // block 10 hash 1 (tx 0, tx 1 frames 5,6), block 10 hash 2, block 20
	if len(got) != len(wantNums) {
		t.Fatalf("%d frames: %+v", len(got), got)
	}
	for i, n := range wantNums {
		if got[i].Number != n {
			t.Fatalf("frame %d is number %d, want %d (%+v)", i, got[i].Number, n, got)
		}
	}
	if complete(got) {
		t.Fatal("a table with duplicated and skipped numbers is not a complete channel")
	}
	if ft.openChannels() != 1 {
		t.Fatalf("open channels %d", ft.openChannels())
	}
	ft.prune(11) // block 10 is forgotten, block 20 stays
	if got := ft.byCh[id]; len(got) != 1 || got[0].Block != 20 || len(ft.digests) != 1 {
		t.Fatalf("after prune: %+v %d", got, len(ft.digests))
	}
	ft.prune(21)
	if len(ft.byCh) != 0 || len(ft.digests) != 0 {
		t.Fatal("everything below 21 is forgotten")
	}
	a, b := frameRef{Block: 1}, frameRef{Block: 2}
	if !a.less(b) || b.less(a) || a.less(a) {
		t.Fatal("blocks order frames")
	}
	if !(frameRef{Hash: [32]byte{1}}).less(frameRef{Hash: [32]byte{2}}) || !(frameRef{TxPos: 1}).less(frameRef{TxPos: 2}) || !(frameRef{FrameIdx: 1}).less(frameRef{FrameIdx: 2}) {
		t.Fatal("hash, transaction position and frame position order frames")
	}
}

func TestRB12IndexPinsDigestChangesWithEveryPinThatDecidesDecoding(t *testing.T) {
	_, bp := idxPins(t)
	base := pinsDigest(bp)
	if base != pinsDigest(bp) {
		t.Fatal("not deterministic")
	}
	for name, mut := range map[string]func(p Pins) Pins{
		"chain id":   func(p Pins) Pins { p.ChainID++; return p },
		"genesis":    func(p Pins) Pins { p.L2GenesisTime++; return p },
		"block time": func(p Pins) Pins { p.L2BlockTime++; return p },
		"rlp bound":  func(p Pins) Pins { p.MaxRLPBytesPerChannel++; return p },
	} {
		p := mut(*bp)
		if pinsDigest(&p) == base {
			t.Fatalf("%s does not change the digest", name)
		}
	}
	// the pins that do not decide decoding do not change it
	p := *bp
	p.SeqWindowSize++
	if pinsDigest(&p) != base {
		t.Fatal("the sequencing window does not decide how a channel is decoded")
	}
}

func TestRB12IndexRowsRoundTripAndRefuseDamage(t *testing.T) {
	k := finality.CaptureKey{Chain: 84532, L1Block: 7, L1Hash: [32]byte{1}}
	d := &blockDigest{Block: 7, Hash: [32]byte{1}, Txs: []digestTx{{Index: 3, Blobs: 2, Kind: kindBlob, Frames: []digestFrame{{ID: [16]byte{9}, Number: 4, Last: true, Len: 1234}}}}}
	enc := d.encode()
	got, err := decodeDigest(k, enc)
	if err != nil || len(got.Txs) != 1 || len(got.Txs[0].Frames) != 1 || got.Txs[0].Frames[0] != d.Txs[0].Frames[0] || got.Txs[0].Index != 3 || got.Txs[0].Blobs != 2 || got.Txs[0].Kind != kindBlob {
		t.Fatalf("digest round trip: %+v %v", got, err)
	}
	if !bytes.Equal(got.encode(), enc) {
		t.Fatal("digest encoding is not canonical")
	}
	e := &chanEntry{Status: entryDecoded, ID: [16]byte{9}, FirstBlock: 5, FirstTx: 1, NFrames: 3, TMin: 10, TMax: 20,
		Txs: []entryTx{{5, [32]byte{1}, 1, 2}}, Runs: []covRun{{First: 10, Count: 6, Type: 1, Epoch: 4}}}
	ee, err := decodeEntry(e.encode())
	if err != nil || ee.ID != e.ID || ee.NFrames != 3 || len(ee.Txs) != 1 || ee.Txs[0] != e.Txs[0] || len(ee.Runs) != 1 || ee.Runs[0] != e.Runs[0] || ee.TMin != 10 || ee.TMax != 20 || ee.FirstBlock != 5 || ee.FirstTx != 1 {
		t.Fatalf("entry round trip: %+v %v", ee, err)
	}
	if !bytes.Equal(ee.encode(), e.encode()) {
		t.Fatal("entry encoding is not canonical")
	}
	bad := func(b []byte, f func([]byte) []byte) []byte { return f(append([]byte(nil), b...)) }
	for name, row := range map[string][]byte{
		"short":    enc[:5],
		"empty":    nil,
		"flipped":  bad(enc, func(b []byte) []byte { b[2] ^= 1; return b }),
		"checksum": bad(enc, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
		"trailing bytes": func() []byte {
			b := append(append([]byte(nil), enc[:len(enc)-8]...), 0)
			return append(b, sumTrailer(b)...)
		}(),
	} {
		if _, err := decodeDigest(k, row); err == nil {
			t.Fatalf("digest %s must be refused", name)
		}
	}
	ebytes := e.encode()
	for name, row := range map[string][]byte{
		"short":    ebytes[:5],
		"flipped":  bad(ebytes, func(b []byte) []byte { b[9] ^= 1; return b }),
		"checksum": bad(ebytes, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
	} {
		if _, err := decodeEntry(row); err == nil {
			t.Fatalf("entry %s must be refused", name)
		}
	}
	// a status or version outside the set is refused even with a good checksum
	for name, mut := range map[string]func(*chanEntry){"status 0": func(x *chanEntry) { x.Status = 0 }, "status 4": func(x *chanEntry) { x.Status = 4 }} {
		x := *e
		mut(&x)
		if _, err := decodeEntry(x.encode()); err == nil {
			t.Fatalf("entry %s must be refused", name)
		}
	}
}

// The gap rule at its boundary: a later captured channel counts only once the capture is GapMargin blocks past its closing block.
func TestRB12IndexMissIsAGapOnlyWhenTheCaptureIsAMarginPastALaterChannel(t *testing.T) {
	_, bp := idxPins(t)
	st := NewMemStore()
	r := NewIndexReader(st, bp, 0)
	id := chanLabelID("later")
	names := []entryName{{Key: finality.CaptureKey{Chain: uint64(Chain), L1Block: 1100}, TMin: 5000, TMax: 5100, ID: id}}
	for _, c := range []struct {
		capHi uint64
		gap   bool
	}{{1100 + DefaultGapMargin - 1, false}, {1100 + DefaultGapMargin, true}, {1099, false}, {0, false}} {
		mc, err := r.classifyMiss(ctxBG(), 4000, 1000, c.capHi, names)
		if err != nil || (mc.gap != nil) != c.gap {
			t.Fatalf("capture at %d: gap=%v err=%v", c.capHi, mc.gap, err)
		}
	}
	// no later channel: nothing to explain the missing one yet
	if mc, _ := r.classifyMiss(ctxBG(), 9999, 1000, 5000, names); mc.gap != nil {
		t.Fatal("a timestamp after every captured channel is not a gap")
	}
	// the margin is configurable
	r.GapMargin = 10
	if mc, _ := r.classifyMiss(ctxBG(), 4000, 1000, 1110, names); mc.gap == nil {
		t.Fatal("a configured margin of 10 must apply")
	}
	// the named interval: from the channel below to the channel above
	names = append(names, entryName{Key: finality.CaptureKey{Chain: uint64(Chain), L1Block: 1040}, TMin: 3000, TMax: 3900, ID: chanLabelID("below")})
	mc, err := r.classifyMiss(ctxBG(), 4000, 1000, 2000, names)
	if err != nil || mc.gap == nil {
		t.Fatalf("%v %v", mc.gap, err)
	}
	f := mc.gap.Fields
	if f["from_l1"] != uint64(1040) || f["to_l1"] != uint64(1100) || f["l2_from"] != 3900+bp.L2BlockTime || f["l2_to"] != 5000-bp.L2BlockTime || f["l2_timestamp"] != uint64(4000) {
		t.Fatalf("the gap names its interval: %v", f)
	}
}
