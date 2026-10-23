// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-A equivalence: evidence built through the index is byte-identical to evidence built by the window read, and both verify.
// The worlds are the real published evidence (finality_base_posted1 valid_a and valid_b: real blobs, real light-client chain, real spine)
// rebuilt as capture rows, surrounded by production-shaped noise channels.

type realCase struct{ ev, leg string }

var realCases = []realCase{{"evidence/valid_a.bin", "legs/a.json"}, {"evidence/valid_b.bin", "legs/b.json"}}

func realWorldPins(t testing.TB, w *buildWorld) *Pins {
	t.Helper()
	bp, err := ParsePins(w.pins)
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

func frameBlocks(w *buildWorld) (lo, hi uint64) {
	lo = ^uint64(0)
	for n := range w.blocks {
		if n < lo {
			lo = n
		}
		if n > hi {
			hi = n
		}
	}
	return lo, hi
}

// addNoise puts production-shaped channels around the real frames: one per L1 block every 7 blocks, on blocks that are not the real ones,
// with timestamps far from the leg's, plus an interleaved two-channel pair that spans several blocks.
func addNoise(t testing.TB, w *buildWorld, bp *Pins, perSide int) {
	t.Helper()
	lo, hi := frameBlocks(w)
	n := 0
	put := func(num uint64, v int, txs ...shapeTx) {
		if _, real := w.blocks[num]; real {
			return
		}
		shapeBlock{number: num, hash: shapeHash(num, v), txs: txs}.put(t, w.store, bp)
	}
	for i := 1; i <= perSide; i++ {
		for _, num := range []uint64{lo - uint64(i)*7, hi + uint64(i)*7} {
			label := "noise/" + strconv.Itoa(n)
			fr := channelFrames(label, 1_700_000_000+uint64(n)*500, 20, num-2, 3)
			put(num, 0, shapeTx{blob: false, datas: [][]byte{payloadOf(fr[0], fr[1])}}, shapeTx{blob: false, datas: [][]byte{payloadOf(fr[2])}})
			n++
		}
	}
	// interleaved over three blocks: A0,B0 | B1,A1 | A2(last),B2(last)
	A := channelFrames("noise/A", 1_701_000_000, 20, hi+2, 3)
	B := channelFrames("noise/B", 1_701_100_000, 20, hi+2, 3)
	put(hi+100, 0, shapeTx{datas: [][]byte{payloadOf(A[0], B[0])}})
	put(hi+101, 0, shapeTx{datas: [][]byte{payloadOf(B[1])}}, shapeTx{datas: [][]byte{payloadOf(A[1])}})
	put(hi+105, 0, shapeTx{datas: [][]byte{payloadOf(A[2])}}, shapeTx{datas: [][]byte{payloadOf(B[2])}})
}

func indexedBuilder(t testing.TB, w *buildWorld, bp *Pins) *Builder {
	t.Helper()
	_, hi := frameBlocks(w)
	upTo := hi + 300
	ix := NewIndexer(w.store, bp, 0, IndexConfig{ReconcileEvery: 1})
	stepAll(t, ix, upTo)
	b := w.builder()
	b.Index = NewIndexReader(w.store, bp, 0)
	return b
}

func TestRB12IndexEvidenceIsByteIdenticalToTheWindowReaderOnTheRealPublishedEvidence(t *testing.T) {
	for _, c := range realCases {
		for _, noise := range []int{0, 12} {
			t.Run(fmt.Sprintf("%s/noise%d", c.ev, noise), func(t *testing.T) {
				w := newBuildWorld(t, c.ev, c.leg)
				bp := realWorldPins(t, w)
				if noise > 0 {
					addNoise(t, w, bp, noise)
				}
				lo, hi := frameBlocks(w)
				// SPEC-Q1: where the real frames lie relative to the origin of the batch (recorded, not assumed)
				_, bt := func() (int, *Batch) {
					b := &Builder{Store: w.store}
					all, err := b.loadRange(context.Background(), bp, 0, finality.MaxCaptureBlock, nil)
					if err != nil {
						t.Fatal(err)
					}
					ch, _, bt, _ := findChannel(all, bp, w.refTimestamp(t))
					if ch == nil {
						t.Fatal("the published channel is not found by the window reader")
					}
					return 0, bt
				}()
				t.Logf("frames lie in L1 blocks %d..%d; the batch's origin (EpochNum) is %d: frames %d..%d blocks after it", lo, hi, bt.EpochNum, lo-bt.EpochNum, hi-bt.EpochNum)
				if lo < bt.EpochNum {
					t.Fatalf("SPEC-Q1 evidence: a real channel has a frame (%d) before its origin (%d)", lo, bt.EpochNum)
				}
				wb := w.builder()
				t0 := time.Now()
				winAd, pend, err := w.build(t, wb)
				winWall := time.Since(t0)
				if err != nil || pend != nil || winAd == nil {
					t.Fatalf("the window reader does not build the published evidence: %v %v", pend, err)
				}
				ib := indexedBuilder(t, w, bp)
				t0 = time.Now()
				idxAd, pend, err := w.build(t, ib)
				t.Logf("whole Build (search, spine, assemble, Kind.Verify with KZG) on the real evidence: window reader %s, index %s", winWall, time.Since(t0))
				if err != nil || pend != nil || idxAd == nil {
					t.Fatalf("the index path does not build: %v %v", pend, err)
				}
				if !bytes.Equal(winAd.Evidence, idxAd.Evidence) {
					t.Fatalf("the evidence differs: window %d bytes, index %d bytes", len(winAd.Evidence), len(idxAd.Evidence))
				}
				if !bytes.Equal(idxAd.Evidence, w.ev) {
					t.Fatal("the index path does not rebuild the published evidence")
				}
				// both verify: the kind's verifier accepts the evidence on its own
				if _, err := (Kind{}).Verify(w.pins, w.ref, idxAd.Evidence); err != nil {
					t.Fatalf("the verifier refuses the index path's evidence: %v", err)
				}
			})
		}
	}
}

// refTimestamp is the L2 timestamp of the leg.
func (w *buildWorld) refTimestamp(t testing.TB) uint64 {
	t.Helper()
	h, err := finality.ReadHeader(w.ref.HeaderRLP)
	if err != nil {
		t.Fatal(err)
	}
	return h.Timestamp
}

// ---- outcomes on damaged captures are the same named outcomes ----

func cloneStore(t testing.TB, src *editStore) *editStore {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	dst := newEditStore()
	for k, v := range src.rows {
		dst.rows[k] = append([]byte(nil), v...)
	}
	return dst
}

func (w *buildWorld) withStore(st *editStore) *buildWorld {
	c := *w
	c.store = st
	return &c
}

func describe(ad *finality.Addendum, pend *finality.PendingState, err error) string {
	switch {
	case ad != nil:
		return "addendum"
	case pend != nil:
		return "pending:" + pend.Reason
	}
	if s, ok := finality.AsNamed(err); ok {
		return "state:" + s.Code
	}
	return fmt.Sprintf("error:%v", err)
}

func TestRB12IndexAndWindowReaderGiveTheSameOutcomeOnDamagedCaptures(t *testing.T) {
	type damage struct {
		name   string
		mutate func(t *testing.T, w *buildWorld, st *editStore)
		want   string // both paths
		// wantIndex, when set, is the index path's outcome where it differs by name from the window reader's
		wantIndex string
	}
	last := func(w *buildWorld) (uint64, [32]byte) {
		_, hi := frameBlocks(w)
		return hi, w.blocks[hi]
	}
	first := func(w *buildWorld) (uint64, [32]byte) {
		lo, _ := frameBlocks(w)
		return lo, w.blocks[lo]
	}
	dropBlock := func(st *editStore, n uint64, h [32]byte) {
		st.mu.Lock()
		defer st.mu.Unlock()
		for k := range st.rows {
			if k.L1Block == n && k.L1Hash == h {
				delete(st.rows, k)
			}
		}
	}
	damages := []damage{
		{"intact", func(*testing.T, *buildWorld, *editStore) {}, "addendum", ""},
		{"truncated: the block of the closing frame was never captured", func(t *testing.T, w *buildWorld, st *editStore) {
			n, h := last(w)
			dropBlock(st, n, h)
		}, "pending:l1_posted_unproven", ""},
		{"truncated: the block of the first frame was never captured", func(t *testing.T, w *buildWorld, st *editStore) {
			n, h := first(w)
			dropBlock(st, n, h)
		}, "pending:l1_posted_unproven", ""},
		{"duplicate frames: a reorged twin of a frame block under another hash", func(t *testing.T, w *buildWorld, st *editStore) {
			n, h := last(w)
			st.mu.Lock()
			twin := map[finality.CaptureKey][]byte{}
			for k, v := range st.rows {
				if k.L1Block == n && k.L1Hash == h {
					k.L1Hash = shapeHash(n, 9)
					twin[k] = v
				}
			}
			for k, v := range twin {
				st.rows[k] = v
			}
			st.mu.Unlock()
		}, "pending:l1_posted_unproven", ""},
		{"the closing block's completion row (syscfg, the capturer's last put) is gone", func(t *testing.T, w *buildWorld, st *editStore) {
			n, h := last(w)
			st.mu.Lock()
			delete(st.rows, CaptureKey{Chain: uint64(Chain), L1Block: n, L1Hash: h, Item: ItemSysCfg})
			st.mu.Unlock()
		}, "state:batcher_state_unavailable", "pending:l1_posted_unproven"},
	}
	for _, c := range realCases[:1] {
		for _, d := range damages {
			t.Run(d.name, func(t *testing.T) {
				base := newBuildWorld(t, c.ev, c.leg)
				bp := realWorldPins(t, base)
				addNoise(t, base, bp, 4)
				w := base.withStore(cloneStore(t, base.store))
				d.mutate(t, w, w.store)
				winAd, winPend, winErr := w.build(t, w.builder())
				ib := indexedBuilder(t, w, bp)
				idxAd, idxPend, idxErr := w.build(t, ib)
				gw, gi := describe(winAd, winPend, winErr), describe(idxAd, idxPend, idxErr)
				t.Logf("window: %s | index: %s", gw, gi)
				wantI := d.want
				if d.wantIndex != "" {
					wantI = d.wantIndex
				}
				if gw != d.want || gi != wantI {
					t.Fatalf("want %s from the window reader and %s from the index, got window %s, index %s", d.want, wantI, gw, gi)
				}
				if winAd != nil && !bytes.Equal(winAd.Evidence, idxAd.Evidence) {
					t.Fatal("the evidence differs")
				}
			})
		}
	}
}

// ---- production-shaped synthetic stores: the channel found, the transactions and the batch are the window reader's ----

func TestRB12IndexSearchEqualsTheWindowReaderOnProductionShapedStores(t *testing.T) {
	_, bp := idxPins(t)
	pins, _ := idxPins(t)
	w := newShapeWorld(t, bp, 120, 10)
	w.ForkAt = 40 // a reorged height inside the table, as the live table has one
	upTo := w.numberOf(w.N-1) + 200
	stepAll(t, newIdx(w, bp, IndexConfig{BlocksPerStep: 1 << 20}), upTo)
	cases := []struct {
		name string
		c, k int
		want string // "same": identical channel, transactions and batch; "miss": neither finds it
	}{
		{"first channel", 0, 0, "same"}, {"a middle channel, first batch", 60, 0, "same"}, {"a middle channel, last batch", 61, shapePerChan - 1, "same"},
		{"the last channel", w.N - 1, 30, "same"},
		{"inside the reorged height: duplicate frames, neither path can serve it", 40, 3, "miss"},
	}
	for _, tc := range cases {
		ts, origin := w.legAt(tc.c, tc.k)
		l2 := fixedL2{txs: [][]byte{l1InfoDeposit(origin, [32]byte{9})}}
		win := &Builder{Pins: pins, Store: w, L2: l2}
		idx := &Builder{Pins: pins, Store: w, L2: l2, Index: NewIndexReader(w, bp, 0)}
		hdr := finality.HeaderFields{Number: 5, Timestamp: ts}
		sw, errW := win.search(ctxBG(), bp, hdr, nil)
		si, errI := idx.search(ctxBG(), bp, hdr, nil)
		if tc.want == "miss" {
			// the window reader finds nothing (pending); the index names what it sees: the interval no complete channel covers and the 14
			// frames of the twin blocks that belong to no complete channel
			g, ok := finality.AsNamed(errI)
			if errW != nil || sw.ch != nil || si.ch != nil || !ok || g.Code != finality.CodeCaptureGap || g.Fields["partial_frames"] != uint64(14) {
				t.Fatalf("%s: window %v %v index %v %v", tc.name, sw.ch, errW, si.ch, errI)
			}
			continue
		}
		if errW != nil || errI != nil {
			t.Fatalf("%s: window %v index %v", tc.name, errW, errI)
		}
		if sw.ch == nil || si.ch == nil || sw.ch.ID != si.ch.ID || len(sw.frameTxs) != len(si.frameTxs) || sw.bt.Type != si.bt.Type || sw.bt.EpochNum != si.bt.EpochNum {
			t.Fatalf("%s: window %+v index %+v", tc.name, sw.ch, si.ch)
		}
		for i := range sw.frameTxs {
			a, b := sw.frameTxs[i], si.frameTxs[i]
			if a.key != b.key || a.index != b.index || !bytes.Equal(a.raw, b.raw) || len(a.blobs) != len(b.blobs) {
				t.Fatalf("%s: tx %d differs", tc.name, i)
			}
			for j := range a.blobs {
				if !bytes.Equal(a.blobs[j].Raw, b.blobs[j].Raw) || a.blobs[j].Commitment != b.blobs[j].Commitment || a.blobs[j].Proof != b.blobs[j].Proof {
					t.Fatalf("%s: blob %d/%d differs", tc.name, i, j)
				}
			}
		}
		// the span of the frames (what Build turns into the spine) is the same
		minW, maxW := frameBlockRange(sw.frameTxs, sw.bt)
		minI, maxI := frameBlockRange(si.frameTxs, si.bt)
		if minW != minI || maxW != maxI {
			t.Fatalf("%s: spine range differs", tc.name)
		}
	}
}

// ---- the trust model: a wrong or missing index row never produces an addendum ----

func TestRB12IndexCorruptionNeverAcceptsAndIsAlwaysNamed(t *testing.T) {
	c := realCases[0]
	type corrupt struct {
		name string
		do   func(t *testing.T, w *buildWorld, st *editStore, bp *Pins)
		// want: a state code or pending reason, or "verified" when the damage is harmless and the evidence must still be the published one
		want string
	}
	// the entry of the leg's channel, found the way the reader finds it
	realEntry := func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) (CaptureKey, *chanEntry) {
		ts := w.refTimestamp(t)
		r := NewIndexReader(st, bp, 0)
		hit, _, err := r.Find(ctxBG(), ts, 0, finality.MaxCaptureBlock-1, &ioCount{})
		if err != nil || hit == nil {
			t.Fatalf("the real channel has no entry: %v %v", hit, err)
		}
		return hit.key, hit.entry
	}
	reput := func(st *editStore, k CaptureKey, e *chanEntry) {
		st.mu.Lock()
		defer st.mu.Unlock()
		nk := k
		nk.Item = channelItem(1, e.TMin, e.TMax, e.ID)
		delete(st.rows, k)
		st.rows[nk] = e.encode()
	}
	cases := []corrupt{
		{"missing entry", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, _ := realEntry(t, w, st, bp)
			st.mu.Lock()
			delete(st.rows, k)
			st.mu.Unlock()
		}, "pending:l1_posted_unproven"},
		{"entry bytes flipped (checksum)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, _ := realEntry(t, w, st, bp)
			st.mu.Lock()
			st.rows[k][20] ^= 0xff
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"entry truncated", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, _ := realEntry(t, w, st, bp)
			st.mu.Lock()
			st.rows[k] = st.rows[k][:len(st.rows[k])/2]
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"entry written under other pins", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			e.Pins[0] ^= 1
			reput(st, k, e)
		}, "state:index_inconsistent"},
		{"entry names another channel (id differs from its name)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			name, _ := parseEntryName(1, k)
			e.ID[0] ^= 1
			st.mu.Lock()
			st.rows[k] = e.encode()
			st.mu.Unlock()
			_ = name
		}, "state:index_inconsistent"},
		{"entry lists a transaction that is not a frame of the channel (extra tx)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			e.Txs = append(e.Txs, e.Txs[0])
			st.mu.Lock()
			st.rows[k] = e.encode()
			st.mu.Unlock()
		}, "state:" + CodeChannelIncomplete},
		{"entry drops a transaction", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			e.Txs = e.Txs[1:]
			st.mu.Lock()
			st.rows[k] = e.encode()
			st.mu.Unlock()
		}, "state:" + CodeChannelIncomplete},
		{"entry names a blob count the rows do not have", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			e.Txs[0].Blobs++
			st.mu.Lock()
			st.rows[k] = e.encode()
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"entry claims a timestamp the channel does not carry", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			ts := w.refTimestamp(t)
			e.Runs = []covRun{{First: ts, Count: 1, Type: 0, Epoch: e.Runs[0].Epoch}}
			e.TMin, e.TMax = ts, ts
			reput(st, k, e)
		}, "verified"}, // the channel DOES carry the timestamp here (it is the real one): the run is a truthful subset; the evidence must be the published bytes
		{"entry's origin is wrong (span batches only: moves the spine, not the verdict)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			for i := range e.Runs {
				e.Runs[i].Type = 1
				e.Runs[i].Epoch = 1
			}
			st.mu.Lock()
			st.rows[k] = e.encode()
			st.mu.Unlock()
		}, "verified-or-named"},
		{"a capture row the entry names is gone (transaction)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			_ = k
			tx := e.Txs[0]
			st.mu.Lock()
			delete(st.rows, CaptureKey{Chain: uint64(Chain), L1Block: tx.Block, L1Hash: tx.Hash, Item: ItemTx(tx.Index)})
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"a blob row the entry names is gone", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			_, e := realEntry(t, w, st, bp)
			tx := e.Txs[0]
			st.mu.Lock()
			delete(st.rows, CaptureKey{Chain: uint64(Chain), L1Block: tx.Block, L1Hash: tx.Hash, Item: ItemBlob(tx.Index, int(tx.Blobs)-1)})
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"a blob row's bytes are altered", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			_, e := realEntry(t, w, st, bp)
			tx := e.Txs[0]
			st.mu.Lock()
			st.rows[CaptureKey{Chain: uint64(Chain), L1Block: tx.Block, L1Hash: tx.Hash, Item: ItemBlob(tx.Index, 0)}][100] ^= 1
			st.mu.Unlock()
		}, "state:" + CodeBlobMismatch},
		{"duplicate-after-close marker", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			k, e := realEntry(t, w, st, bp)
			mk := k
			mk.Item = markerItem(1, e.ID)
			st.mu.Lock()
			st.rows[mk] = []byte("dup")
			st.mu.Unlock()
		}, "state:index_inconsistent"},
		{"the index cursor row is gone (the index has not run)", func(t *testing.T, w *buildWorld, st *editStore, bp *Pins) {
			ek, _ := realEntry(t, w, st, bp)
			st.mu.Lock()
			for k := range st.rows {
				if k.Item == finality.IndexCursorItem(1, FamilyBaseInbox) {
					delete(st.rows, k)
				}
			}
			delete(st.rows, ek)
			st.mu.Unlock()
		}, "pending:l1_posted_unproven"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := newBuildWorld(t, c.ev, c.leg)
			bp := realWorldPins(t, base)
			addNoise(t, base, bp, 3)
			ib := indexedBuilder(t, base, bp)
			tc.do(t, base, base.store, bp)
			ad, pend, err := base.build(t, ib)
			got := describe(ad, pend, err)
			t.Logf("-> %s", got)
			if ad != nil {
				// whatever the damage, an addendum is only ever evidence the kind's verifier accepts on its own, and for this world it is the published one
				if _, verr := (Kind{}).Verify(base.pins, base.ref, ad.Evidence); verr != nil {
					t.Fatalf("the index path produced evidence the verifier refuses: %v", verr)
				}
				if !bytes.Equal(ad.Evidence, base.ev) && tc.want != "verified-or-named" {
					t.Fatalf("the index path produced other evidence than the published")
				}
			}
			switch tc.want {
			case "verified":
				if got != "addendum" {
					t.Fatalf("want an addendum, got %s", got)
				}
			case "verified-or-named":
				if got != "addendum" && (ad != nil || (pend == nil && err == nil)) {
					t.Fatalf("got %s", got)
				}
			default:
				if got != tc.want {
					t.Fatalf("want %s, got %s", tc.want, got)
				}
			}
		})
	}
}

var _ = ethproof.Settlement{}
var _ context.Context
