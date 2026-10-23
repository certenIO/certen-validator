// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-CAPTURE-GAP, hole-aware coverage (F13, live 2026-10-23).
//
// The capture cursor says "the loop scanned up to here"; it said so over ~684 blocks the loop had given up on, so a leg whose batch was
// posted in such a run was told "not posted yet" for ever. These tests write the durable gap rows by their documented BYTES (not through
// the package's own writer), so they also pin the row format: a gap is keyed at (chain, from, zero hash, "gap/<to>/<class>") and holds
// "CGAP1" || u64 from || u64 to || LP(class), a fill is "gapfill/<block>" under the block's hash, an end is "gapend/<block>/<kind>".

func rawGapRow(t *testing.T, st finality.CaptureStore, from, to uint64, class string) {
	t.Helper()
	b := []byte("CGAP1")
	b = binary.BigEndian.AppendUint64(b, from)
	b = binary.BigEndian.AppendUint64(b, to)
	b = binary.BigEndian.AppendUint32(b, uint32(len(class)))
	b = append(b, class...)
	if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: from, Item: fmt.Sprintf("gap/%d/%s", to, class)}, b); err != nil {
		t.Fatal(err)
	}
}

func rawFillRow(t *testing.T, st finality.CaptureStore, block uint64) {
	t.Helper()
	b := []byte("CGFL1")
	b = binary.BigEndian.AppendUint64(b, block)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0)
	var h [32]byte
	h[0] = 0xf1
	if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: block, L1Hash: h, Item: fmt.Sprintf("gapfill/%d", block)}, b); err != nil {
		t.Fatal(err)
	}
}

const gcLeg = rbFirstBlock + 5*100 // origin of the leg: the 100th captured block

// A leg whose window holds an open gap and whose channel is not in the captured rows is NOT "pending": the batch may lie in the gap.
func TestRB12GapAnOpenGapInTheWindowOfALegIsANamedStateNotAForeverPending(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg+40, gcLeg+120, "state_proof_unavailable")
	s, l2 := rbLeg(t, gcLeg)
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	se, named := finality.AsNamed(err)
	if pend != nil || !named || se.Code != "l1_capture_gap" {
		t.Fatalf("want the named state l1_capture_gap, got pend=%v err=%v", pend, err)
	}
	for _, f := range []string{"chain", "kind", "from", "to", "gap_state", "ranges", "blocks", "epoch_l1_block", "window_end_l1_block", "archive_provider"} {
		if _, ok := se.Fields[f]; !ok {
			t.Errorf("the state carries what it was judged at: missing %s in %v", f, se)
		}
	}
	if se.Fields["from"] != uint64(gcLeg+40) || se.Fields["to"] != uint64(gcLeg+120) || se.Fields["gap_state"] != "open" ||
		se.Fields["blocks"] != uint64(81) || se.Fields["ranges"] != uint64(1) || se.Fields["epoch_l1_block"] != uint64(gcLeg) || se.Fields["archive_provider"] != "unset" {
		t.Errorf("%v", se)
	}
}

// The state is named by the part of the gap INSIDE the leg's window, not by the whole gap.
func TestRB12GapTheStateNamesTheGapClippedToTheWindow(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	s, l2 := rbLeg(t, gcLeg)
	end := uint64(gcLeg) + 3600 // the pins' sequencer window
	rawGapRow(t, st, end-10, end+500, "outage_unscanned")
	_, _, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	se, named := finality.AsNamed(err)
	if !named || se.Code != "l1_capture_gap" || se.Fields["from"] != end-10 || se.Fields["to"] != end || se.Fields["blocks"] != uint64(11) {
		t.Fatalf("want l1_capture_gap clipped to the window [%d,%d], got %v", end-10, end, err)
	}
}

// A gap outside the window changes nothing for the leg.
func TestRB12GapAGapOutsideTheWindowLeavesTheLegPending(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg-500, gcLeg-100, "outage_unscanned")
	rawGapRow(t, st, gcLeg+9000, gcLeg+9100, "outage_unscanned")
	s, l2 := rbLeg(t, gcLeg)
	_, pend, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("pend=%v err=%v", pend, err)
	}
}

// A gap that has been filled (every block of it recorded as scanned) is closed: the leg is covered again and pending for what it is.
func TestRB12GapAFilledGapIsCoveringAgain(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg+40, gcLeg+60, "state_proof_unavailable")
	s, l2 := rbLeg(t, gcLeg)
	b := rbBuilder(t, st, l2)
	if _, _, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted); err == nil {
		t.Fatal("open gap: want the named state")
	}
	for n := uint64(gcLeg + 40); n < gcLeg+60; n++ { // one block short of closing
		rawFillRow(t, st, n)
	}
	_, _, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_gap" || se.Fields["from"] != uint64(gcLeg+60) || se.Fields["to"] != uint64(gcLeg+60) {
		t.Fatalf("one open block is left: %v", err)
	}
	rawFillRow(t, st, gcLeg+60)
	_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("a closed gap is covering: pend=%v err=%v", pend, err)
	}
}

// A terminal end (proved unavailable, or past retention) is named in the state, so the operator sees it will not heal by waiting;
// an open block anywhere in the window outranks it, because the backfill is still working there.
func TestRB12GapTerminalEndsAreNamedAndAnOpenBlockOutranksThem(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg+40, gcLeg+42, "blob_unavailable")
	endRow := func(block uint64, kind string) {
		var h [32]byte
		h[0] = byte(block)
		b := []byte("CGEND1")
		b = binary.BigEndian.AppendUint64(b, block)
		b = binary.BigEndian.AppendUint32(b, uint32(len(kind)))
		b = append(b, kind...)
		b = binary.BigEndian.AppendUint32(b, 1) // reason "r"
		b = append(b, 'r')
		b = binary.BigEndian.AppendUint32(b, 0) // no providers
		if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: block, L1Hash: h, Item: fmt.Sprintf("gapend/%d/%s", block, kind)}, b); err != nil {
			t.Fatal(err)
		}
	}
	s, l2 := rbLeg(t, gcLeg)
	b := rbBuilder(t, st, l2)
	endRow(gcLeg+40, "retention_expired")
	endRow(gcLeg+41, "unavailable_proven")
	_, _, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" || se.Fields["from"] != uint64(gcLeg+42) {
		t.Fatalf("block %d is still open: %v", gcLeg+42, err)
	}
	endRow(gcLeg+42, "unavailable_proven")
	_, _, err = b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "unavailable_proven" {
		t.Fatalf("every block ended: the proved unavailability outranks the expiry, got %v", err)
	}
}

// Pre-capture legs stay l1_capture_not_covering, and a gap row does not turn that into a gap state.
func TestRB12GapPreCaptureLegsKeepTheirOwnState(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, rbFirstBlock-30000, rbFirstBlock-100, "outage_unscanned")
	s, l2 := rbLeg(t, rbFirstBlock-20_000)
	_, _, err := rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_not_covering" {
		t.Fatalf("a leg below the first cursor row is judged by the cursor, not by the gap: %v", err)
	}
}

// The gap rows are read by key and range: a leg's build never loads a gap row's bytes, so 200 old gaps cost it nothing.
func TestRB12GapTheLookupReadsOnlyTheGapRowsOfTheWindow(t *testing.T) {
	judge := func(oldGaps int) (reads int64, err error) {
		st := rbStore(t, rbFirstBlock, 300, true)
		for i := 0; i < oldGaps; i++ { // old one-block gaps far below the window
			rawGapRow(t, st, rbFirstBlock+uint64(i), rbFirstBlock+uint64(i), "state_proof_unavailable")
		}
		rawGapRow(t, st, gcLeg+40, gcLeg+41, "state_proof_unavailable")
		s, l2 := rbLeg(t, gcLeg)
		before := st.gets.Load()
		_, _, err = rbBuilder(t, st, l2).Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
		return st.gets.Load() - before, err
	}
	few, err := judge(0)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_gap" || se.Fields["blocks"] != uint64(2) {
		t.Fatalf("%v", err)
	}
	many, err := judge(200)
	if se, named := finality.AsNamed(err); !named || se.Code != "l1_capture_gap" || se.Fields["blocks"] != uint64(2) {
		t.Fatalf("%v", err)
	}
	if many != few {
		t.Fatalf("200 old gap rows changed the rows the build reads: %d -> %d", few, many)
	}
}

// A channel that IS complete in the captured rows builds whatever gaps lie elsewhere in the window: the verifier, not the gap
// bookkeeping, decides the evidence.
func TestRB12GapACompleteChannelBuildsAndVerifiesDespiteGapsInItsWindow(t *testing.T) {
	w := newBuildWorld(t, "evidence/valid_a.bin", "legs/a.json")
	base, pend, err := w.build(t, w.builder())
	if err != nil || pend != nil || base == nil {
		t.Fatalf("baseline: %v %v %v", base, pend, err)
	}
	origin, lo, hi := w.originAndFrameSpan(t)
	w.putCursor(t, origin, hi+300)
	if lo > origin {
		rawGapRow(t, w.store, origin, lo-1, "outage_unscanned") // inside the sequencer window, before the frames
	}
	rawGapRow(t, w.store, hi+100, hi+200, "state_proof_unavailable") // after them
	ad, pend, err := w.build(t, w.builder())
	if err != nil || pend != nil || ad == nil {
		t.Fatalf("a complete channel builds despite gaps elsewhere in its window: %v %v %v", ad, pend, err)
	}
	if string(ad.Evidence) != string(base.Evidence) {
		t.Fatal("the evidence differs from the baseline")
	}
}

// originAndFrameSpan is the L1 origin the leg's first deposit names and the lowest and highest frame block of its channel.
func (w *buildWorld) originAndFrameSpan(t *testing.T) (origin, lo, hi uint64) {
	t.Helper()
	o, _, ok := l1Info(w.body.Deposits[0])
	if !ok {
		t.Fatal("the first deposit is not an L1-info deposit")
	}
	for i, f := range w.body.Frames {
		if i == 0 || f.L1Block < lo {
			lo = f.L1Block
		}
		if f.L1Block > hi {
			hi = f.L1Block
		}
	}
	return o, lo, hi
}

// putCursor writes the capture loop's cursor rows: the first at block first, the latest at block last.
func (w *buildWorld) putCursor(t *testing.T, first, last uint64) {
	t.Helper()
	for _, blk := range []uint64{first, last} {
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], blk)
		if err := w.store.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: blk, Item: "runtime/cursor"}, v[:]); err != nil {
			t.Fatal(err)
		}
	}
}

// RB12-GO-INT D4 (V-T2): a leg inside a gap whose channel is not captured is HELD and asked again every poll. Each ask used to read the
// whole window (up to ~300 MB of rows) before the gap lookup. The answer of a held ask depends on the captured inbox rows of the window,
// the recorded gaps of the window and the leg's own L2 time; when none of them has changed since the last held ask the answer is the
// same, and it is returned after the key-only lookups (the gap pieces and the inbox keys of the window), reading no row.
func TestRB12GOINTAHeldAskReadsNoRowWhileTheStoreHasNotChanged(t *testing.T) {
	st := rbStore(t, rbFirstBlock, 300, true)
	rawGapRow(t, st, gcLeg+40, gcLeg+120, "state_proof_unavailable")
	s, l2 := rbLeg(t, gcLeg)
	b := rbBuilder(t, st, l2)
	ask := func() (*finality.StateError, int64, int64) {
		bytes0, gets0 := st.bytes.Load(), st.gets.Load()
		_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
		se, named := finality.AsNamed(err)
		if pend != nil || !named || se.Code != "l1_capture_gap" {
			t.Fatalf("want l1_capture_gap, got pend=%v err=%v", pend, err)
		}
		return se, st.bytes.Load() - bytes0, st.gets.Load() - gets0
	}
	first, b1, g1 := ask()
	if b1 == 0 || g1 == 0 {
		t.Fatalf("the first ask of a window reads it once (%d bytes, %d rows): the fixture is not exercising the window read", b1, g1)
	}
	for i := 0; i < 5; i++ {
		again, bytesRead, rows := ask()
		if bytesRead != 0 || rows != 0 {
			t.Fatalf("held ask %d read %d bytes in %d rows of a window that did not change: it must cost the key lookups only", i+2, bytesRead, rows)
		}
		if again.Error() != first.Error() {
			t.Fatalf("the repeated answer differs: %s vs %s", again.Error(), first.Error())
		}
	}
	// the gap closes: the answer must follow the store, not the memory of the last ask
	for n := gcLeg + 40; n <= gcLeg+120; n++ {
		rawFillRow(t, st, uint64(n))
	}
	_, pend, err := b.Build(context.Background(), s, haveIncludedOnly, finality.LevelL1Posted)
	if err != nil || pend == nil || pend.Reason != "l1_posted_unproven" {
		t.Fatalf("with the gap filled the leg is plain pending, got pend=%v err=%v", pend, err)
	}
	// a new gap piece inside the window changes the answer too
	rawGapRow(t, st, gcLeg+200, gcLeg+210, "state_proof_unavailable")
	se, _, _ := ask()
	if se.Fields["from"] != uint64(gcLeg+200) {
		t.Fatalf("a gap recorded after the last held ask must be seen: %v", se)
	}
	// and so does a newly captured inbox block of the window
	bytes0 := st.bytes.Load()
	var h [32]byte
	h[0] = 0xee
	if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: gcLeg + 3, L1Hash: h, Item: ItemInbox}, []byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	_, nb, _ := ask()
	if nb == 0 || st.bytes.Load() == bytes0 {
		t.Fatal("a captured block that appeared in the window since the last held ask must make the next ask read it")
	}
}
