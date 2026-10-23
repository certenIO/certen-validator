// Copyright 2026 Certen Protocol

package baseposted

import (
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

func idxPins(t testing.TB) (*finality.Pins, *Pins) {
	t.Helper()
	pins, err := finality.EmbeddedPins()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	return pins, bp
}

// scaleWorld is the production-shaped world at scale s (1 = the live table: 1,851 channels over ~19,000 L1 blocks, 1.6 GB), with the three
// live capture holes (229, 73 and 385 L1 blocks) placed where they are in the live table.
func scaleWorld(t testing.TB, bp *Pins, s float64) *shapeWorld {
	t.Helper()
	n := int(1851 * s)
	stride := uint64(10/s + 0.5)
	if stride < 1 {
		stride = 1
	}
	w := newShapeWorld(t, bp, n, stride)
	toChan := func(l1 uint64) int { return int((l1 - w.First) / w.Stride) }
	for _, h := range [][2]uint64{{11975926, 11976155}, {11976373, 11976446}, {11976620, 11977005}} {
		a, b := toChan(h[0]), toChan(h[1])
		if b >= n {
			b = n - 1
		}
		if a <= b && a < n {
			w.Holes = append(w.Holes, [2]int{a, b})
		}
	}
	return w
}

// RB12-INDEX-A: the cost of a build is the cost of ITS channel. The read (bytes, rows, keys) and the peak heap of a build are the same
// at 0.5, 1.5, 5 and 10 times the live table and density, for a leg whose channel is captured and for a leg that sits in a capture hole.
func TestRB12IndexBuildCostIsIndependentOfTableAndDensity(t *testing.T) {
	_, bp := idxPins(t)
	var foundBytes []int64
	for _, s := range []float64{0.5, 1.5, 5, 10} {
		w := scaleWorld(t, bp, s)
		meter := &meterStore{CaptureStore: w}
		cFound := w.N / 3
		tsFound, originFound := w.legAt(cFound, 17)
		l2 := fixedL2{txs: [][]byte{l1InfoDeposit(originFound, [32]byte{9})}}
		upTo := w.numberOf(w.N-1) + 200
		b := newScaleBuilder(t, w, meter, bp, upTo, l2)
		sr, err, c := measureSearch(t, b, meter, bp, tsFound)
		t.Logf("scale %.1fx (%d channels, stride %d, %d MB stored): found leg: read %d KB in %d rows, %d keys listed, peak heap +%d KB, %s",
			s, w.N, w.Stride, w.StoredBytes()>>20, c.bytes>>10, c.gets, c.keys, c.heap>>10, c.wall)
		if err != nil || sr.ch == nil || sr.ch.ID != chanLabelID("shape/"+strconv.Itoa(cFound)) || len(sr.frameTxs) != 2 {
			t.Fatalf("scale %.1f: the channel of the leg is not found: err=%v ch=%v txs=%d", s, err, sr.ch, len(sr.frameTxs))
		}
		if c.bytes > 2<<20 || c.heap > 48<<20 || c.keys > 8192 {
			t.Fatalf("scale %.1fx: a build of one channel read %d bytes (%d rows, %d keys) with a peak heap of %d bytes: it must cost the channel (about 1 MB), not the window or the table", s, c.bytes, c.gets, c.keys, c.heap)
		}
		foundBytes = append(foundBytes, c.bytes)
		// the median buildable leg over 40 legs spread across the table (RB12 threshold: <= 50 MB read and <= 30 s at 10x density)
		var reads []int64
		var walls []time.Duration
		for i := 0; i < 40; i++ {
			cc := (i*w.N)/40 + 1
			if cc >= w.N || w.inHole(cc) {
				continue
			}
			ts, org := w.legAt(cc, (i*7)%shapePerChan)
			b.L2 = fixedL2{txs: [][]byte{l1InfoDeposit(org, [32]byte{9})}}
			sr, err, lc := measureSearch(t, b, meter, bp, ts)
			if err != nil || sr.ch == nil {
				t.Fatalf("scale %.1fx: leg of channel %d: %v %v", s, cc, sr.ch, err)
			}
			reads, walls = append(reads, lc.bytes), append(walls, lc.wall)
		}
		sort.Slice(reads, func(i, j int) bool { return reads[i] < reads[j] })
		sort.Slice(walls, func(i, j int) bool { return walls[i] < walls[j] })
		medRead, medWall := reads[len(reads)/2], walls[len(walls)/2]
		t.Logf("scale %.1fx: median of %d legs: read %d KB, wall %s (max read %d KB, max wall %s)", s, len(reads), medRead>>10, medWall, reads[len(reads)-1]>>10, walls[len(walls)-1])
		if medRead > 50<<20 || medWall > 30*time.Second {
			t.Fatalf("scale %.1fx: the median buildable leg read %d bytes in %s (threshold 50 MB and 30 s)", s, medRead, medWall)
		}
		// a leg that sits in the first capture hole: a named gap, decided from the index without reading a channel
		h := w.Holes[0]
		cHole := (h[0] + h[1]) / 2
		tsHole, originHole := w.legAt(cHole, 5)
		b.L2 = fixedL2{txs: [][]byte{l1InfoDeposit(originHole, [32]byte{9})}}
		_, err, c = measureSearch(t, b, meter, bp, tsHole)
		t.Logf("scale %.1fx: hole leg: read %d KB in %d rows, %d keys listed, peak heap +%d KB, %s, state %v", s, c.bytes>>10, c.gets, c.keys, c.heap>>10, c.wall, err)
		if st, ok := finality.AsNamed(err); !ok || st.Code != "l1_capture_gap" {
			t.Fatalf("scale %.1fx: a leg inside a capture hole must be the named state l1_capture_gap, got %v", s, err)
		}
		if c.bytes > 4<<20 || c.heap > 48<<20 {
			t.Fatalf("scale %.1fx: naming a hole read %d bytes with a peak heap of %d bytes", s, c.bytes, c.heap)
		}
	}
	lo, hi := foundBytes[0], foundBytes[0]
	for _, v := range foundBytes {
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	if float64(hi) > 1.10*float64(lo) {
		t.Fatalf("the bytes a build reads vary with the scale: %v", foundBytes)
	}
}
