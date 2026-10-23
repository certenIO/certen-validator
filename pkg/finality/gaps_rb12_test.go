// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// RB12-CAPTURE-GAP (F13, live 2026-10-23). The Base capturer gave up on every block it could not capture within 96 blocks and moved its
// cursor on: ~684 L1 blocks (three runs: 228, 72 and 384 blocks between captured inbox blocks 11975926/11976155, 11976373/11976446 and
// 11976620/11977005) were never captured, and nothing durable said so. The records below are the durable statement: insert-only,
// deterministic, coalesced into ranges, closed by a new record and never by an update.

const gapChain = uint64(ChainBaseSepolia)

func newGapStore() *MemCaptureStore { return NewMemCaptureStore() }

func TestRB12GapRecordsAreInsertOnlyDeterministicAndCoalesced(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	// single blocks and a run, recorded in any order, by any number of validators: the same rows
	for _, blk := range []uint64{105, 101, 103, 102, 104, 101} {
		if err := RecordGap(ctx, st, gapChain, blk, blk, GapStateProofUnavailable); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordGap(ctx, st, gapChain, 200, 230, GapOutageUnscanned); err != nil {
		t.Fatal(err)
	}
	if err := RecordGap(ctx, st, gapChain, 200, 230, GapOutageUnscanned); err != nil {
		t.Fatalf("recording the same gap twice is a no-op: %v", err)
	}
	got, err := GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	if err != nil {
		t.Fatal(err)
	}
	want := []GapRange{
		{From: 101, To: 105, State: GapOpen, Classes: []GapClass{GapStateProofUnavailable}},
		{From: 200, To: 230, State: GapOpen, Classes: []GapClass{GapOutageUnscanned}},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("coalesced ranges\n got %v\nwant %v", got, want)
	}
	// every gap row is keyed at the zero hash (a gap is about no particular block hash) and its item names its end and class
	ks, _ := st.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, GapItemPrefix)
	if len(ks) != 6 { // 101..105 and 200-230
		t.Fatalf("the rows of the gaps: %v", ks)
	}
	for _, k := range ks {
		if k.L1Hash != ([32]byte{}) || !strings.HasPrefix(k.Item, "gap/") {
			t.Fatalf("a gap row is keyed at the zero hash under gap/: %v", k)
		}
		if err := CheckCaptureItem(k.Item); err != nil {
			t.Fatal(err)
		}
	}
	// a second class on the same block is a second row, never a conflict
	if err := RecordGap(ctx, st, gapChain, 103, 103, GapBlobUnavailable); err != nil {
		t.Fatalf("another class on the same block: %v", err)
	}
	got, _ = GapsIn(ctx, st, gapChain, 103, 103)
	if len(got) != 1 || len(got[0].Classes) != 2 {
		t.Fatalf("both classes are reported: %v", got)
	}
	// the bytes are a function of (from, to, class) alone: two stores written in different orders hold identical rows
	st2 := newGapStore()
	_ = RecordGap(ctx, st2, gapChain, 200, 230, GapOutageUnscanned)
	for _, blk := range []uint64{101, 102, 103, 104, 105} {
		_ = RecordGap(ctx, st2, gapChain, blk, blk, GapStateProofUnavailable)
	}
	_ = RecordGap(ctx, st2, gapChain, 103, 103, GapBlobUnavailable)
	if !sameStoreRows(t, ctx, st, st2) {
		t.Fatal("the gap rows of two writers differ")
	}
	// refused inputs: an inverted range, an unknown class
	if err := RecordGap(ctx, st, gapChain, 9, 8, GapOutageUnscanned); err == nil {
		t.Fatal("an inverted range is refused")
	}
	if err := RecordGap(ctx, st, gapChain, 9, 9, GapClass("open")); err == nil {
		t.Fatal("a class outside the closed set is refused")
	}
}

func sameStoreRows(t *testing.T, ctx context.Context, a, b *MemCaptureStore) bool {
	t.Helper()
	ka, _ := a.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, "")
	kb, _ := b.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, "")
	if len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
		x, _, _ := a.Get(ctx, ka[i])
		y, _, _ := b.Get(ctx, kb[i])
		if !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}

func TestRB12AFillClosesABlockByANewRecordAndNeverByAnUpdate(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	_ = RecordGap(ctx, st, gapChain, 300, 305, GapStateProofUnavailable)
	before, _ := st.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, "")
	h := [32]byte{7}
	if err := RecordGapFill(ctx, st, gapChain, 302, h, true); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapFill(ctx, st, gapChain, 302, h, true); err != nil {
		t.Fatalf("the same fill twice is a no-op: %v", err)
	}
	got, _ := GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	if fmt.Sprint(got) != fmt.Sprint([]GapRange{
		{From: 300, To: 301, State: GapOpen, Classes: []GapClass{GapStateProofUnavailable}},
		{From: 303, To: 305, State: GapOpen, Classes: []GapClass{GapStateProofUnavailable}},
	}) {
		t.Fatalf("a filled block splits the range: %v", got)
	}
	// the earlier rows are untouched: the fill is a new row
	after, _ := st.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, GapItemPrefix)
	if len(after) != len(before) {
		t.Fatalf("gap rows changed: %d -> %d", len(before), len(after))
	}
	// a fill under another hash (a reorged height) is another row; the block stays closed
	if err := RecordGapFill(ctx, st, gapChain, 302, [32]byte{8}, false); err != nil {
		t.Fatal(err)
	}
	// a block that has no inbox transactions is a legitimate fill (the scan found nothing to capture)
	if err := RecordGapFill(ctx, st, gapChain, 300, h, false); err != nil {
		t.Fatal(err)
	}
	got, _ = GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	if len(got) != 2 || got[0].From != 301 || got[0].To != 301 {
		t.Fatalf("after filling 300: %v", got)
	}
	// totals
	tot, err := GapTotalsOf(ctx, st, gapChain)
	if err != nil {
		t.Fatal(err)
	}
	if tot.Open != 4 || tot.Filled != 2 {
		t.Fatalf("totals %+v, want 4 open (301,303,304,305) and 2 filled (300,302)", tot)
	}
}

func TestRB12ATerminalGapStatesAreNamedAndCarryTheirProvidersAndAFillSupersedesThem(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	_ = RecordGap(ctx, st, gapChain, 400, 402, GapBlobUnavailable)
	e := GapEnd{Kind: GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"b.example", "a.example"}}
	if err := RecordGapEnd(ctx, st, gapChain, 401, e); err != nil {
		t.Fatal(err)
	}
	// the same end recorded by another validator with the providers in another order is the same record
	e2 := GapEnd{Kind: GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a.example", "b.example"}}
	if err := RecordGapEnd(ctx, st, gapChain, 401, e2); err != nil {
		t.Fatal(err)
	}
	if ks, _ := st.ListByRange(ctx, gapChain, 401, 401, GapEndPrefix); len(ks) != 1 {
		t.Fatalf("one end record for identical content, got %v", ks)
	}
	if err := RecordGapEnd(ctx, st, gapChain, 402, GapEnd{Kind: GapRetentionExpired, Reason: "blob_retention_elapsed", Providers: []string{"a.example"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	var states []string
	for _, g := range got {
		states = append(states, fmt.Sprintf("%d-%d:%s", g.From, g.To, g.State))
	}
	if fmt.Sprint(states) != "[400-400:open 401-401:unavailable_proven 402-402:retention_expired]" {
		t.Fatalf("states %v", states)
	}
	ends, err := GapEndsOf(ctx, st, gapChain, 401)
	if err != nil || len(ends) != 1 || strings.Join(ends[0].Providers, ",") != "a.example,b.example" {
		t.Fatalf("the end record names its providers sorted: %v %v", ends, err)
	}
	// a later fill (a provider that has the data after all) supersedes the terminal state
	if err := RecordGapFill(ctx, st, gapChain, 401, [32]byte{1}, true); err != nil {
		t.Fatal(err)
	}
	got, _ = GapsIn(ctx, st, gapChain, 401, 401)
	if len(got) != 0 {
		t.Fatalf("a filled block is closed whatever else was recorded: %v", got)
	}
	// refused
	if err := RecordGapEnd(ctx, st, gapChain, 400, GapEnd{Kind: GapOpen, Reason: "x"}); err == nil {
		t.Fatal("open is not an end")
	}
	if err := RecordGapEnd(ctx, st, gapChain, 400, GapEnd{Kind: GapUnavailableProven}); err == nil {
		t.Fatal("an end names its reason")
	}
}

func TestRB12ANotesCarryRedactedProviderTextAndNeverConflict(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	secret := "https://user:hunter2@node.example/v2/ABCDEF0123456789ABCDEF0123456789?apikey=SECRETKEY"
	if err := RecordGapNote(ctx, st, gapChain, 500, GapStateProofUnavailable, "eth_getProof "+secret+": missing trie node"); err != nil {
		t.Fatal(err)
	}
	if err := RecordGapNote(ctx, st, gapChain, 500, GapStateProofUnavailable, "another text of another validator"); err != nil {
		t.Fatalf("a different text is a different note, not a conflict: %v", err)
	}
	ks, _ := st.ListByRange(ctx, gapChain, 500, 500, GapNotePrefix)
	if len(ks) != 2 {
		t.Fatalf("notes: %v", ks)
	}
	for _, k := range ks {
		b, _, _ := st.Get(ctx, k)
		if bytes.Contains(b, []byte("hunter2")) || bytes.Contains(b, []byte("SECRETKEY")) {
			t.Fatalf("a credential reached a stored note: %q", b)
		}
	}
}

// The store of the live system, in shape: an inbox block every 5-19 blocks from 11958043 to 11977349, and the three outage runs
// removed. The audit finds exactly those three runs, between the inbox blocks on both sides, and nothing else.
func TestRB12ASpacingAuditFindsTheThreeProductionHolesAndNothingElse(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	holes := [][2]uint64{{11975926, 11976155}, {11976373, 11976446}, {11976620, 11977005}} // consecutive captured rows around a hole
	skip := func(n uint64) bool {
		for _, h := range holes {
			if n > h[0] && n < h[1] {
				return true
			}
		}
		return false
	}
	step := []uint64{12, 12, 11, 13, 12, 7, 12, 16, 12, 12}
	n, i := uint64(11958043), 0
	var rows int
	for n <= 11977349 {
		if !skip(n) {
			if err := st.Put(ctx, CaptureKey{Chain: gapChain, L1Block: n, L1Hash: [32]byte{byte(n), byte(n >> 8)}, Item: "inbox"}, []byte{1}); err != nil {
				t.Fatal(err)
			}
			rows++
		}
		n += step[i%len(step)]
		i++
	}
	for _, h := range holes { // the captured rows on both sides of each hole, as production has them
		_ = st.Put(ctx, CaptureKey{Chain: gapChain, L1Block: h[0], L1Hash: [32]byte{1, byte(h[0])}, Item: "inbox"}, []byte{1})
		_ = st.Put(ctx, CaptureKey{Chain: gapChain, L1Block: h[1], L1Hash: [32]byte{1, byte(h[1])}, Item: "inbox"}, []byte{1})
	}
	found, err := AuditSpacing(ctx, st, gapChain, "inbox", 11958043, 11977349, 40)
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]uint64
	for _, g := range found {
		got = append(got, [2]uint64{g.From, g.To})
		if g.State != GapOpen || len(g.Classes) != 1 || g.Classes[0] != GapSpacingUnproven {
			t.Fatalf("an audited range is open with class spacing_unproven: %+v", g)
		}
	}
	want := [][2]uint64{{11975927, 11976154}, {11976374, 11976445}, {11976621, 11977004}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audit ranges %v, want %v", got, want)
	}
	// the audit RECORDED them: the store now answers
	open, _ := GapsIn(ctx, st, gapChain, 0, MaxCaptureBlock)
	var blocks uint64
	for _, g := range open {
		blocks += g.To - g.From + 1
	}
	if blocks != 228+72+384 {
		t.Fatalf("open blocks %d, want %d", blocks, 228+72+384)
	}
	// idempotent: a second audit writes nothing new
	n1, _ := st.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, "")
	if _, err := AuditSpacing(ctx, st, gapChain, "inbox", 11958043, 11977349, 40); err != nil {
		t.Fatal(err)
	}
	n2, _ := st.ListByRange(ctx, gapChain, 0, MaxCaptureBlock, "")
	if len(n1) != len(n2) {
		t.Fatalf("a repeated audit wrote rows: %d -> %d", len(n1), len(n2))
	}
	// a range whose blocks are all scanned (filled) is not reported again by a later audit
	for b := uint64(11976374); b <= 11976445; b++ {
		_ = RecordGapFill(ctx, st, gapChain, b, [32]byte{9}, false)
	}
	again, _ := AuditSpacing(ctx, st, gapChain, "inbox", 11958043, 11977349, 40)
	for _, g := range again {
		if g.From == 11976374 {
			t.Fatalf("a scanned run is not suspected again: %+v", g)
		}
	}
}

func TestRB12AGapsInClipsToTheAskedWindowAndIsBounded(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	_ = RecordGap(ctx, st, gapChain, 1000, 2000, GapOutageUnscanned)
	got, _ := GapsIn(ctx, st, gapChain, 1500, 1600)
	if len(got) != 1 || got[0].From != 1500 || got[0].To != 1600 {
		t.Fatalf("clipped: %v", got)
	}
	if got, _ := GapsIn(ctx, st, gapChain, 2001, 3000); len(got) != 0 {
		t.Fatalf("outside: %v", got)
	}
	if got, _ := GapsIn(ctx, st, gapChain, 0, 999); len(got) != 0 {
		t.Fatalf("below: %v", got)
	}
	// another chain's gaps are not this chain's
	if got, _ := GapsIn(ctx, st, uint64(ChainArbitrumSepolia), 0, MaxCaptureBlock); len(got) != 0 {
		t.Fatalf("another chain: %v", got)
	}
	// a store that fails to list is an error, never an empty answer ("no gaps")
	if _, err := GapsIn(ctx, failingStore{st}, gapChain, 0, 10); err == nil {
		t.Fatal("a failing store is an error")
	}
}

type failingStore struct{ CaptureStore }

func (failingStore) ListByRange(context.Context, uint64, uint64, uint64, string) ([]CaptureKey, error) {
	return nil, errors.New("store down")
}
