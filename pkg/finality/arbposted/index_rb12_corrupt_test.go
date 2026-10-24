// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// ixOverlay is a store whose rows can be damaged on read: replaced, unreadable although listed, or gone.
type ixOverlay struct {
	finality.CaptureStore
	over map[finality.CaptureKey][]byte
	hide map[finality.CaptureKey]bool
	gone map[finality.CaptureKey]bool
}

func newOverlay(inner finality.CaptureStore) *ixOverlay {
	return &ixOverlay{CaptureStore: inner, over: map[finality.CaptureKey][]byte{}, hide: map[finality.CaptureKey]bool{}, gone: map[finality.CaptureKey]bool{}}
}

func (o *ixOverlay) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if o.hide[k] || o.gone[k] {
		return nil, false, nil
	}
	if b, ok := o.over[k]; ok {
		return b, true, nil
	}
	return o.CaptureStore.Get(ctx, k)
}

func (o *ixOverlay) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]finality.CaptureKey, error) {
	ks, err := o.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
	if err != nil {
		return nil, err
	}
	out := ks[:0:0]
	for _, k := range ks {
		if !o.gone[k] {
			out = append(out, k)
		}
	}
	return out, nil
}

func (w *ixWorld) entryKey(n uint64) finality.CaptureKey {
	w.t.Helper()
	ks, err := w.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, ixItem(1, ixEntry)+"/")
	if err != nil {
		w.t.Fatal(err)
	}
	for _, k := range ks {
		if nm, ok := parseEntryName(1, k); ok && nm.N == n {
			return k
		}
	}
	w.t.Fatalf("no entry for batch %d", n)
	return finality.CaptureKey{}
}

// idxOver asks the indexed reader over a damaged view of the world's store.
func (w *ixWorld) idxOver(o *ixOverlay, ts uint64, txs [][]byte) outcome {
	w.t.Helper()
	r, err := NewIndexReader(o, w.pins, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	b := &Builder{Store: o, Pins: w.pins, Index: r}
	loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(txs), w.arb)
	switch {
	case err != nil:
		return outcome{State: stateOf(err)}
	case pend != nil:
		return outcome{State: pend.Reason}
	}
	return outcome{N: loc.rec.N, Block: loc.rec.L1Block}
}

func reasonOf(s string) string {
	i := strings.Index(s, `"reason":"`)
	if i < 0 {
		return ""
	}
	s = s[i+len(`"reason":"`):]
	return s[:strings.Index(s, `"`)]
}

// The damage cases. For each, the indexed reader over the damaged store must end in a NAMED state or a pending, and when it does return a
// batch it is exactly the batch the reference returns on the undamaged store: never a different accept.
func TestRB12ArbIndexCorruptionIsNamedAndNeverAcceptsAnotherBatch(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	const ts = ixT0 + 300
	leg := legs["d1"] // the message of batch 203
	want := w.ref(ts, leg)
	if want.N != 203 {
		t.Fatalf("the reference serves %s", want)
	}
	if got := w.idx(w.reader(), ts, leg); got != want {
		t.Fatalf("the undamaged index serves %s, the reference %s", got, want)
	}
	ek := w.entryKey(203)
	good, _, _ := w.store.Get(context.Background(), ek)
	other := w.entryKey(204)
	otherBytes, _, _ := w.store.Get(context.Background(), other)
	bk := withItem(ek, capture.ItemBatch(203))
	batchRow, _, _ := w.store.Get(context.Background(), bk)
	entry, err := decodeEntry(good)
	if err != nil {
		t.Fatal(err)
	}
	reencode := func(f func(e *arbEntry)) []byte {
		e := *entry
		e.Fps = append([][8]byte(nil), entry.Fps...)
		f(&e)
		return e.encode()
	}

	type tc struct {
		name   string
		damage func(o *ixOverlay)
		reason string // the index_inconsistent reason, or "" for a pending / other named state
		state  string // a substring of the canonical state, or the pending reason
	}
	cases := []tc{
		{"entry listed but unreadable", func(o *ixOverlay) { o.hide[ek] = true }, finality.IndexRowMissing, ""},
		{"entry flipped byte", func(o *ixOverlay) { b := append([]byte(nil), good...); b[len(b)/2] ^= 0x40; o.over[ek] = b }, finality.IndexEntryCorrupt, ""},
		{"entry truncated", func(o *ixOverlay) { o.over[ek] = good[:len(good)-9] }, finality.IndexEntryCorrupt, ""},
		{"entry zero length", func(o *ixOverlay) { o.over[ek] = []byte{} }, finality.IndexEntryCorrupt, ""},
		{"entry unknown version", func(o *ixOverlay) {
			b := append([]byte(nil), good...)
			b[0] = 9
			o.over[ek] = append(b[:len(b)-8], sumTrailer(b[:len(b)-8])...)
		}, finality.IndexEntryCorrupt, ""},
		{"entry bad checksum", func(o *ixOverlay) { b := append([]byte(nil), good...); b[len(b)-1] ^= 1; o.over[ek] = b }, finality.IndexEntryCorrupt, ""},
		{"entry of another pins digest", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.Pins = [8]byte{1, 2, 3} }) }, finality.IndexPinsChanged, ""},
		{"swapped entry (the bytes of batch 204)", func(o *ixOverlay) { o.over[ek] = otherBytes }, finality.IndexRowsDisagree, ""},
		{"entry that names another block (wrong locator)", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.L1Block++ }) }, finality.IndexRowsDisagree, ""},
		{"entry that names another hash (wrong locator)", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.L1Hash[0] ^= 1 }) }, finality.IndexRowsDisagree, ""},
		{"entry altered time bounds", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.MaxTs++ }) }, finality.IndexRowsDisagree, ""},
		{"entry that lacks the fingerprint (a silent miss)", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.Fps = nil }) }, "", PendingAwaitingBatchPost},
		{"entry that lists a wrong fingerprint only", func(o *ixOverlay) {
			o.over[ek] = reencode(func(e *arbEntry) { e.Fps = [][8]byte{messageFp([][]byte{leg[0]})} })
		}, "", ""},
		{"entry that says the batch is skipped", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.Status = entrySkipped; e.Fps = nil }) }, "", PendingAwaitingBatchPost},
		{"entry that says the batch overflows", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.Status = entryOverflow; e.Fps = nil }) }, finality.IndexCoverageOverflow, ""},
		{"entry with another batch row hash", func(o *ixOverlay) { o.over[ek] = reencode(func(e *arbEntry) { e.RowSum[0] ^= 1 }) }, finality.IndexRowsDisagree, ""},
		{"batch row altered", func(o *ixOverlay) { o.over[bk] = append(append([]byte(nil), batchRow...), 0) }, finality.IndexRowsDisagree, ""},
		{"batch row missing", func(o *ixOverlay) { o.hide[bk] = true }, finality.IndexRowMissing, ""},
		{"quarantine record", func(o *ixOverlay) { o.over[withItem(ek, quarantineItem(1, 203))] = []byte("self_check_mismatch") }, finality.IndexSelfCheckMismatch, ""},
		{"blob row missing", func(o *ixOverlay) { o.hide[withItem(ek, capture.ItemBlob(203, 0))] = true }, "", `"code":"l1_blob_unavailable"`},
		{"entry gone (not listed)", func(o *ixOverlay) { o.gone[ek] = true }, "", PendingAwaitingBatchPost},
		{"index cursor gone", func(o *ixOverlay) {
			for k := range w.indexRows() {
				if k.Item == finality.IndexCursorItem(1, FamilyArb) {
					o.gone[k] = true
				}
			}
		}, "", PendingAwaitingBatchPost},
	}
	for _, c := range cases {
		o := newOverlay(w.store)
		c.damage(o)
		got := w.idxOver(o, ts, leg)
		if got.N != 0 && got != want {
			t.Errorf("%s: ACCEPTED %s, the reference serves %s", c.name, got, want)
			continue
		}
		switch {
		case c.reason != "":
			if got.N != 0 || !strings.Contains(got.State, `"code":"index_inconsistent"`) || reasonOf(got.State) != c.reason {
				t.Errorf("%s: want index_inconsistent{%s}, got %s", c.name, c.reason, got)
			}
		case c.state != "":
			if got.N != 0 || !strings.Contains(got.State, c.state) {
				t.Errorf("%s: want %s, got %s", c.name, c.state, got)
			}
		default:
			// the damage cannot be told from the rows alone: the outcome is a pending or the batch the reference serves
			if got.N != 0 && got != want {
				t.Errorf("%s: %s", c.name, got)
			}
		}
	}
}

// The self-check names a damage the lookup cannot see (an entry that lacks a fingerprint), and quarantines the entry for every reader.
func TestRB12ArbIndexSelfCheckNamesAnEntryThatLiesAndQuarantinesIt(t *testing.T) {
	w, legs := ixPopulation(t)
	w.index(IndexConfig{})
	ek := w.entryKey(203)
	good, _, _ := w.store.Get(context.Background(), ek)
	e, _ := decodeEntry(good)
	e.Fps = nil
	// a lying entry under a new generation cannot be written into the insert-only store: the check runs over an overlay that lies
	o := newOverlay(w.store)
	o.over[ek] = e.encode()
	ix2, err := NewIndexer(o, w.pins, 0, IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ix2.SelfCheckReport(context.Background(), 100)
	if st, named := finality.AsNamed(err); !named || st.Code != finality.CodeIndexInconsistent || st.Fields["reason"] != finality.IndexSelfCheckMismatch {
		t.Fatalf("the self-check did not name the lying entry: %v (%+v)", err, res)
	}
	if res.Mismatches != 1 || res.Entries == 0 {
		t.Fatalf("result %+v", res)
	}
	// the quarantine record is in the (overlay's inner) store, shared: a reader refuses the entry by name
	if _, ok, _ := w.store.Get(context.Background(), withItem(ek, quarantineItem(1, 203))); !ok {
		t.Fatal("no quarantine record")
	}
	got := w.idx(w.reader(), ixT0+300, legs["d1"])
	if got.N != 0 || reasonOf(got.State) != finality.IndexSelfCheckMismatch {
		t.Fatalf("a quarantined entry is served: %s", got)
	}
	// the undamaged rows pass the same check
	if res, err := w.indexer(IndexConfig{SelfCheckSample: 100, ReconcileSpan: 1 << 20}).SelfCheckReport(context.Background(), 100); err != nil || res.Mismatches != 0 || res.Entries == 0 {
		t.Fatalf("a clean store fails the self-check: %v %+v", err, res)
	}
}
