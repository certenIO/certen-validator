// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
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

// The state a leg in a gap is judged at conforms to the registry, with the attempt fields the upgrader adds to every failed status, and a
// gap_state outside the closed set does not.
func TestRB12AGapStateConformsToTheRegistryWithItsAttemptFields(t *testing.T) {
	reg := loadRegistry(t)
	st := NewState("l1_capture_gap", "chain", uint64(ChainBaseSepolia), "kind", "base-sepolia/l1_posted/v1", "from", uint64(11975927), "to", uint64(11976154),
		"gap_state", string(GapOpen), "ranges", uint64(3), "blocks", uint64(684), "epoch_l1_block", uint64(11976000), "window_end_l1_block", uint64(11979600), "archive_provider", "unset")
	if msg := conforms(reg, st); msg != "" {
		t.Fatalf("%s", msg)
	}
	var s BuilderStatus
	s.State = st
	s.noteAttempt(3, time.Unix(1_800_000_000, 0))
	if msg := conforms(reg, s.State); msg != "" {
		t.Fatalf("with the upgrader's attempt fields: %s", msg)
	}
	bad := NewState("l1_capture_gap", "chain", uint64(1), "kind", "k", "from", uint64(1), "to", uint64(2), "gap_state", "closed", "ranges", uint64(1), "blocks", uint64(2),
		"epoch_l1_block", uint64(1), "window_end_l1_block", uint64(2), "archive_provider", "set")
	if msg := conforms(reg, bad); !strings.Contains(msg, "closed set") {
		t.Fatalf("a gap_state outside the closed set must not conform: %q", msg)
	}
	for _, g := range []GapState{GapOpen, GapUnavailableProven, GapRetentionExpired} {
		if !strings.Contains(fmt.Sprint(reg.States["l1_capture_gap"].Enums["gap_state"]), string(g)) {
			t.Errorf("the registry's closed set lacks %s", g)
		}
	}
}

// ---- the mutation gate's kills ----

type faultStore struct {
	CaptureStore
	failList map[string]bool // prefix -> the listing fails
	failPut  map[string]bool // item prefix -> the Put fails
}

func (f faultStore) ListByRange(ctx context.Context, chain, from, to uint64, prefix string) ([]CaptureKey, error) {
	if f.failList[prefix] {
		return nil, errors.New("store down: " + prefix)
	}
	return f.CaptureStore.ListByRange(ctx, chain, from, to, prefix)
}

func (f faultStore) Put(ctx context.Context, k CaptureKey, b []byte) error {
	for p := range f.failPut {
		if strings.HasPrefix(k.Item, p) {
			return errors.New("store down: put " + p)
		}
	}
	return f.CaptureStore.Put(ctx, k, b)
}

// Two gaps one block apart are two gaps: the block between them is not in any gap.
func TestRB12AGapsSeparatedByOneBlockAreNotMerged(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	_ = RecordGap(ctx, st, gapChain, 10, 11, GapOutageUnscanned)
	_ = RecordGap(ctx, st, gapChain, 13, 14, GapOutageUnscanned)
	got, _ := GapsIn(ctx, st, gapChain, 0, 100)
	if fmt.Sprint(got) != "[10-11:open[outage_unscanned] 13-14:open[outage_unscanned]]" {
		t.Fatalf("%v", got)
	}
	// and two that touch are one
	_ = RecordGap(ctx, st, gapChain, 15, 16, GapBlobUnavailable)
	got, _ = GapsIn(ctx, st, gapChain, 0, 100)
	if fmt.Sprint(got) != "[10-11:open[outage_unscanned] 13-16:open[blob_unavailable,outage_unscanned]]" {
		t.Fatalf("adjacent gaps are one run, the classes are the sorted union of the rows that cover it: %v", got)
	}
	// a malformed row is an error, never skipped
	bad := newGapStore()
	_ = bad.Put(ctx, CaptureKey{Chain: gapChain, L1Block: 50, Item: "gap/40/outage_unscanned"}, []byte("x"))
	if _, err := GapsIn(ctx, bad, gapChain, 0, 100); err == nil {
		t.Fatal("a gap row that ends before it starts is malformed")
	}
	// the window starts inside, ends before: both clip
	one := newGapStore()
	_ = RecordGap(ctx, one, gapChain, 10, 20, GapOutageUnscanned)
	if got, _ := GapsIn(ctx, one, gapChain, 21, 30); len(got) != 0 {
		t.Fatalf("a window that starts after the gap sees nothing: %v", got)
	}
	if got, _ := GapsIn(ctx, one, gapChain, 20, 30); len(got) != 1 || got[0].From != 20 || got[0].To != 20 {
		t.Fatalf("a window that starts on the last block of the gap sees that block: %v", got)
	}
}

// Adjacent blocks in one terminal state are one run; blocks in different states, or with a closed block between, are not.
func TestRB12ATerminalRunsMergeOnlyWhenAdjacentAndOfOneState(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	_ = RecordGap(ctx, st, gapChain, 400, 410, GapBlobUnavailable)
	end := func(b uint64, k GapState) {
		if err := RecordGapEnd(ctx, st, gapChain, b, GapEnd{Kind: k, Reason: "r", Providers: []string{"a"}}); err != nil {
			t.Fatal(err)
		}
	}
	end(400, GapUnavailableProven)
	end(401, GapUnavailableProven)
	end(402, GapRetentionExpired)
	end(404, GapRetentionExpired)
	_ = RecordGapFill(ctx, st, gapChain, 403, [32]byte{1}, true)
	// block 405 has both kinds recorded, in either order: the proved unavailability outranks the expiry
	end(405, GapRetentionExpired)
	end(405, GapUnavailableProven)
	end(406, GapUnavailableProven)
	end(406, GapRetentionExpired)
	got, _ := GapsIn(ctx, st, gapChain, 0, 1000)
	var s []string
	for _, g := range got {
		s = append(s, fmt.Sprintf("%d-%d:%s", g.From, g.To, g.State))
	}
	want := "[400-401:unavailable_proven 402-402:retention_expired 404-404:retention_expired 405-406:unavailable_proven 407-410:open]"
	if fmt.Sprint(s) != want {
		t.Fatalf("\n got %v\nwant %s", s, want)
	}
}

// A store that fails to list is an error whichever listing fails, and a malformed bookkeeping row is an error, never ignored.
func TestRB12AGapReadsNeverAnswerNoGapsForAStoreOrARowTheyCannotRead(t *testing.T) {
	ctx := context.Background()
	base := newGapStore()
	_ = RecordGap(ctx, base, gapChain, 100, 110, GapOutageUnscanned)
	for _, prefix := range []string{GapItemPrefix, GapFillPrefix, GapEndPrefix} {
		if _, err := GapsIn(ctx, faultStore{CaptureStore: base, failList: map[string]bool{prefix: true}}, gapChain, 0, 1000); err == nil {
			t.Errorf("a failing %s listing was answered as no gaps", prefix)
		}
	}
	for _, item := range []string{"gapfill/x", "gapend/x/unavailable_proven", "gapend/105/weird_kind", "gap/105/not_a_class", "gap/zz/outage_unscanned", "gap/105"} {
		st := newGapStore()
		_ = RecordGap(ctx, st, gapChain, 100, 110, GapOutageUnscanned)
		if err := st.Put(ctx, CaptureKey{Chain: gapChain, L1Block: 105, Item: item}, []byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err := GapsIn(ctx, st, gapChain, 0, 1000); err == nil {
			t.Errorf("a malformed row %q was ignored", item)
		}
	}
}

// The audit suspects a run only when it is LONGER than the spacing, only between blocks of exactly the audited item, and it reports the
// store's failures.
func TestRB12AAuditSpacingBoundaryItemAndFailures(t *testing.T) {
	ctx := context.Background()
	st := newGapStore()
	put := func(b uint64, item string, h byte) {
		if err := st.Put(ctx, CaptureKey{Chain: gapChain, L1Block: b, L1Hash: [32]byte{h}, Item: item}, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	put(100, "inbox", 1)
	put(140, "inbox", 2)  // spacing 40: not longer than 40
	put(141, "inbox", 3)  // spacing 1
	put(141, "inbox", 4)  // the same block under another hash
	put(182, "inbox", 5)  // spacing 41: longer than 40
	put(150, "inboxx", 6) // another item under the same prefix: not an inbox block, must not split the run
	put(160, "hdr", 7)
	got, err := AuditSpacing(ctx, st, gapChain, "inbox", 0, 1000, 40)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[142-181:open[spacing_unproven]]" {
		t.Fatalf("only the run longer than the spacing: %v", got)
	}
	// failures: the listing of the item, the recording of the gap, the reading back
	if _, err := AuditSpacing(ctx, faultStore{CaptureStore: st, failList: map[string]bool{"inbox": true}}, gapChain, "inbox", 0, 1000, 40); err == nil {
		t.Error("a failing item listing was swallowed")
	}
	fresh := newGapStore()
	for i, b := range []uint64{10, 100} {
		_ = fresh.Put(ctx, CaptureKey{Chain: gapChain, L1Block: b, L1Hash: [32]byte{byte(i + 1)}, Item: "inbox"}, []byte{1})
	}
	if _, err := AuditSpacing(ctx, faultStore{CaptureStore: fresh, failPut: map[string]bool{"gap/": true}}, gapChain, "inbox", 0, 1000, 40); err == nil {
		t.Error("a gap that could not be recorded was swallowed")
	}
	if _, err := AuditSpacing(ctx, faultStore{CaptureStore: fresh, failList: map[string]bool{GapItemPrefix: true}}, gapChain, "inbox", 0, 1000, 40); err == nil {
		t.Error("a failing read-back was swallowed")
	}
}
