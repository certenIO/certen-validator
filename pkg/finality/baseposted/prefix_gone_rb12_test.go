// Copyright 2026 Certen Protocol

package baseposted

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-ARCHIVE-BACKFILL, unavailable_proven: the evidence, the cadence, the pruned answer.

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/beacon_gone/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixedAnswer(code int, body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write(body)
	}))
}

// The two real provider classes say "gone" differently: Lodestar 404, Teku 400 "Insufficient data columns" (recorded answers). Both are
// the statement "this node has not got it"; any other 400 is not.
func TestRB12PrefixPrunedAnswersOfBothProviderClassesAreGoneAndOtherBadRequestsAreNot(t *testing.T) {
	lode := fixedAnswer(404, readFixture(t, "lodestar_404_columns_not_in_db.json"))
	teku := fixedAnswer(400, readFixture(t, "teku_400_insufficient_columns.json"))
	other := fixedAnswer(400, []byte(`{"code":400,"message":"BAD_REQUEST: block is pre-Deneb and has no blobs"}`))
	defer lode.Close()
	defer teku.Close()
	defer other.Close()
	_, err := (&BeaconHTTP{Bases: []string{teku.URL, lode.URL}}).Blobs(context.Background(), 11_290_000)
	if g, ok := BlobsGone(err); !ok || g.Endpoints != 2 {
		t.Fatalf("a Teku 400 and a Lodestar 404 are two hosts saying gone: %v", err)
	}
	if _, err = (&BeaconHTTP{Bases: []string{teku.URL, other.URL}}).Blobs(context.Background(), 5); err == nil {
		t.Fatal("no blobs")
	} else if _, ok := BlobsGone(err); ok {
		t.Fatalf("a 400 about something else is not proof: %v", err)
	}
	if !prunedAnswer(400, []byte("Insufficient data columns")) || prunedAnswer(500, readFixture(t, "teku_400_insufficient_columns.json")) ||
		prunedAnswer(404, nil) || prunedAnswer(400, nil) {
		t.Fatal("the pruned answer is a 400 with that message and nothing else")
	}
}

type orderStore struct {
	finality.CaptureStore
	items []string
}

func (o *orderStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	o.items = append(o.items, k.Item)
	return o.CaptureStore.Put(ctx, k, b)
}

func TestRB12PrefixAnEndIsNeverVisibleWithoutItsSlotAndNeedsOne(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := &orderStore{CaptureStore: NewMemStore()}
	_ = finality.RecordGap(ctx, st.CaptureStore, c, 70, 70, finality.GapBlobUnavailable)
	now, adv := bfClock()
	slot := (uint64(bfEpoch.Unix())-1655733600)/12 - 3600
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) { return [32]byte{}, false, blobFailure(n, slot, true) }}
	w := &Backfiller{Chain: c, Store: st, Capturer: sc, Providers: []string{"a.example", "b.example"}, Policy: bfPolicy(), Now: now}
	for i := 0; i < 12; i++ {
		_, _ = w.Step(ctx, 1)
		adv(20 * time.Minute)
	}
	slotAt, endAt := -1, -1
	for i, it := range st.items {
		if it == "gapslot/70" {
			slotAt = i
		}
		if it == "gapend/70/unavailable_proven" {
			endAt = i
		}
	}
	if slotAt < 0 || endAt < 0 || slotAt > endAt {
		t.Fatalf("the slot row precedes the end row: %v", st.items)
	}
	if got, ok, _ := finality.GapSlotOf(ctx, st, c, 70); !ok || got != slot {
		t.Fatalf("slot %d %v", got, ok)
	}
	// a failure that names no beacon slot is never turned into an end
	st2 := NewMemStore()
	_ = finality.RecordGap(ctx, st2, c, 70, 70, finality.GapBlobUnavailable)
	now2, adv2 := bfClock()
	noSlot := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		s := finality.NewState("l1_blob_unavailable", "l1_block", n, "versioned_hashes", "0x01", "http_status", uint64(404))
		return [32]byte{}, false, &CaptureFailure{Block: n, State: s, Err: &StatusError{Status: 404, Gone: true, Endpoints: 2}}
	}}
	w2 := &Backfiller{Chain: c, Store: st2, Capturer: noSlot, Providers: []string{"a", "b"}, Policy: bfPolicy(), Now: now2}
	for i := 0; i < 12; i++ {
		_, _ = w2.Step(ctx, 1)
		adv2(20 * time.Minute)
	}
	if ends, _ := st2.ListByRange(ctx, c, 0, finality.MaxCaptureBlock, finality.GapEndPrefix); len(ends) != 0 {
		t.Fatalf("an end without a slot: %v", ends)
	}
}

func TestRB12PrefixALegWhoseWindowCannotCompleteNamesTheGoneSlotsTheHostsAndTheArchiveThatWouldCloseIt(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	ask() // the request
	for n := origin; n <= origin+3600; n++ {
		if n != origin+10 {
			rawFillRow(t, st, n)
		}
	}
	// block origin+10: proven unavailable by two hosts at beacon slot 11111; block origin+20: captured with a header (served)
	if err := finality.RecordGapSlot(ctx, st, c, origin+10, 11111); err != nil {
		t.Fatal(err)
	}
	if err := finality.RecordGapEnd(ctx, st, c, origin+10, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"h1", "h2"}}); err != nil {
		t.Fatal(err)
	}
	hdr, _ := rlp.EncodeToBytes(&types.Header{Number: big.NewInt(1), Time: 1655733600 + 12*5000, Difficulty: big.NewInt(0), BaseFee: big.NewInt(1)})
	var h [32]byte
	h[0] = 0x77
	var w finality.Writer
	w.Count(0)
	_ = st.Put(ctx, CaptureKey{Chain: c, L1Block: origin + 20, L1Hash: h, Item: ItemHeader}, hdr)
	_ = st.Put(ctx, CaptureKey{Chain: c, L1Block: origin + 20, L1Hash: h, Item: ItemInbox}, w.Bytes())
	se, _ := ask()
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "unavailable_proven" {
		t.Fatalf("%v", se)
	}
	want := map[string]any{"needs": "blob_archive", "newest_gone_l1_block": origin + 10, "newest_gone_slot": uint64(11111), "gone_hosts": uint64(2), "oldest_served_slot": uint64(5000)}
	for k, v := range want {
		if se.Fields[k] != v {
			t.Errorf("%s = %v want %v (%v)", k, se.Fields[k], v, se)
		}
	}
	// an open piece in the window outranks it: the backfill is still working, nothing is said about an archive
	st2 := rbStore(t, rbFirstBlock, 300, true)
	_, ask2 := pxBuilder(t, st2, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	ask2()
	rawFillRow(t, st2, origin+5)
	if se2, _ := ask2(); se2 == nil || se2.Fields["gap_state"] != "open" || se2.Fields["needs"] != nil {
		t.Fatalf("%v", se2)
	}
}

func TestRB12PrefixBlocksProvenUnavailableAreAskedAgainOncePerDayNewestOfEachRunFirst(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, c, 70, 72, finality.GapBlobUnavailable)
	_ = finality.RecordGap(ctx, st, c, 90, 91, finality.GapBlobUnavailable)
	for _, n := range []uint64{70, 71, 72, 90, 91} {
		_ = finality.RecordGapSlot(ctx, st, c, n, 100)
		_ = finality.RecordGapEnd(ctx, st, c, n, finality.GapEnd{Kind: finality.GapUnavailableProven, Reason: "beacon_404_every_provider", Providers: []string{"a", "b"}})
	}
	now, adv := bfClock()
	gone := true
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		if gone {
			return [32]byte{}, false, blobFailure(n, 100, true)
		}
		return okCap(n, call)
	}}
	w := &Backfiller{Chain: c, Store: st, Capturer: sc, Providers: []string{"a", "b"}, Policy: bfPolicy(), Now: now}
	_, _ = w.Step(ctx, 8) // the first step of a process starts the day: nothing is asked
	if len(sc.calls) != 0 {
		t.Fatalf("%v", sc.calls)
	}
	adv(24*time.Hour - time.Second)
	_, _ = w.Step(ctx, 8)
	if len(sc.calls) != 0 {
		t.Fatalf("one second early: %v", sc.calls)
	}
	adv(time.Second)
	_, _ = w.Step(ctx, 8)
	if len(sc.calls) != 2 || sc.calls[72] != 1 || sc.calls[91] != 1 {
		t.Fatalf("the newest block of each run is asked: %v", sc.calls)
	}
	adv(time.Hour)
	_, _ = w.Step(ctx, 8)
	if len(sc.calls) != 2 {
		t.Fatalf("still gone: nothing else is asked until the next day: %v", sc.calls)
	}
	// the day after, the data is served again: the probe fills, and every block proven unavailable is then asked
	adv(24 * time.Hour)
	gone = false
	for steps := 0; steps < 10; steps++ {
		if rep, _ := w.Step(ctx, 8); rep.Attempted == 0 {
			break
		}
		adv(time.Minute)
	}
	if open, _ := finality.GapsIn(ctx, st, c, 0, 1000); len(open) != 0 {
		t.Fatalf("a probe that is served re-opens the whole run, which then fills: %v", open)
	}
}

func TestRB12PrefixWindowStatesAreCountedByWhatTheyNeed(t *testing.T) {
	wins := []finality.PrefixWindow{{From: 100, To: 199}, {From: 300, To: 399}, {From: 500, To: 599}, {From: 700, To: 799}, {From: 900, To: 999}}
	pieces := []finality.GapRange{
		{From: 150, To: 160, State: finality.GapOpen},
		{From: 350, To: 350, State: finality.GapUnavailableProven}, {From: 360, To: 361, State: finality.GapOpen},
		{From: 520, To: 520, State: finality.GapRetentionExpired},
		{From: 750, To: 750, State: finality.GapRetentionExpired}, {From: 751, To: 751, State: finality.GapUnavailableProven},
	}
	got := PrefixWindowStates(wins, pieces)
	if got[PrefixWindowOpen] != 1 || got[PrefixWindowUnavailableProven] != 2 || got[PrefixWindowRetentionExpired] != 1 || got[PrefixWindowComplete] != 1 {
		t.Fatalf("%v", got)
	}
}

func TestRB12PrefixOnFillIsToldOfEveryClosedBlockAndOnlyThose(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, c, 10, 13, finality.GapCapturePrefix)
	var told []uint64
	oc := &orderCap{fail: map[uint64]bool{12: true}}
	now, _ := bfClock()
	w := &Backfiller{Chain: c, Store: st, Capturer: oc, Policy: bfPolicy(), Now: now, OnFill: func(n uint64, _ bool) { told = append(told, n) }}
	_, _ = w.Step(ctx, 8)
	if fmt.Sprint(told) != "[10 11 13]" {
		t.Fatalf("%v", told)
	}
}

// A header row that does not parse is not evidence of a slot: the state is still the gap state with the evidence the store does hold.
func TestRB12PrefixAnUnparsableHeaderRowLeavesOutTheServedSlotAndKeepsTheRestOfTheEvidence(t *testing.T) {
	ctx := context.Background()
	c := uint64(Chain)
	st := rbStore(t, rbFirstBlock, 300, true)
	origin := uint64(rbFirstBlock - 20_000)
	_, ask := pxBuilder(t, st, origin, finality.PrefixPolicy{MaxBlocks: 10_000})
	ask()
	for n := origin; n <= origin+3600; n++ {
		if n != origin+10 {
			rawFillRow(t, st, n)
		}
	}
	_ = finality.RecordGapSlot(ctx, st, c, origin+10, 11111)
	_ = finality.RecordGapEnd(ctx, st, c, origin+10, finality.GapEnd{Kind: finality.GapRetentionExpired, Reason: "blob_retention_elapsed", Providers: []string{"h1"}})
	var h [32]byte
	h[0] = 0x78
	var w finality.Writer
	w.Count(0)
	_ = st.Put(ctx, CaptureKey{Chain: c, L1Block: origin + 20, L1Hash: h, Item: ItemHeader}, []byte("not a header"))
	_ = st.Put(ctx, CaptureKey{Chain: c, L1Block: origin + 20, L1Hash: h, Item: ItemInbox}, w.Bytes())
	se, _ := ask()
	if se == nil || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "retention_expired" || se.Fields["needs"] != "blob_archive" ||
		se.Fields["newest_gone_slot"] != uint64(11111) || se.Fields["gone_hosts"] != uint64(1) {
		t.Fatalf("%v", se)
	}
	if _, has := se.Fields["oldest_served_slot"]; has {
		t.Fatalf("no slot is invented from a row that is not a header: %v", se)
	}
}
