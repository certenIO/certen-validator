// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/baseposted/kzgsetup"
)

// RB12-CAPTURE-GAP, the backfill (F13). A backfill is the same capture, run later: its rows must be BYTE-IDENTICAL to the rows the live
// capture writes for the same block, so that seven validators sharing one database can fill the same gap in any order and the
// insert-only store accepts every duplicate.

var bfEpoch = time.Unix(1_800_000_000, 0).UTC()

func bfClock() (func() time.Time, func(d time.Duration)) {
	now := bfEpoch
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

func bfPolicy() BackfillPolicy {
	return BackfillPolicy{BackoffBase: time.Minute, BackoffMax: 16 * time.Minute, GoneObservations: 3, GoneSpan: 30 * time.Minute,
		Retention: 4096 * 32 * 12 * time.Second, GenesisTime: 1655733600, SlotSeconds: 12}
}

func nonBookkeepingRows(t *testing.T, st finality.CaptureStore) map[string][]byte {
	t.Helper()
	ctx := context.Background()
	ks, _ := st.ListByRange(ctx, uint64(Chain), 0, finality.MaxCaptureBlock, "")
	out := map[string][]byte{}
	for _, k := range ks {
		if strings.HasPrefix(k.Item, "gap") || strings.HasPrefix(k.Item, "runtime/") {
			continue
		}
		b, _, _ := st.Get(ctx, k)
		out[k.String()] = b
	}
	return out
}

func TestRB12BackfillRowsAreByteIdenticalToLiveCaptureRows(t *testing.T) {
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blk, blob := blobBlock(t, kz, 1000, []byte("frame data"))
	ctx := context.Background()

	// live: the capture loop's call
	live := NewMemStore()
	lc := &Capturer{Chain: uint64(Chain), Pins: newPins(), L1: &fakeL1{blk: blk}, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: live, GenesisTime: 1655733600, SlotSeconds: 12}
	if ok, err := lc.CaptureBlock(ctx, 1000); err != nil || !ok {
		t.Fatalf("live: %v %v", ok, err)
	}

	// backfill: a gap record, then the worker, over a store that already holds other rows and a DIFFERENT provider topology (the proof
	// comes from another source object): the bytes depend on the chain's data, not on who served it or when
	bf := NewMemStore()
	if err := finality.RecordGap(ctx, bf, uint64(Chain), 998, 1002, finality.GapStateProofUnavailable); err != nil {
		t.Fatal(err)
	}
	now, _ := bfClock()
	cap2 := &Capturer{Chain: uint64(Chain), Pins: newPins(), L1: &fakeL1{blk: blk}, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: bf, GenesisTime: 1655733600, SlotSeconds: 12}
	w := &Backfiller{Chain: uint64(Chain), Store: bf, Capturer: CapturerOf(cap2), Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	rep, err := w.Step(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Filled != 5 || rep.Open != 0 {
		t.Fatalf("report %+v, want the five blocks of 998-1002 filled", rep)
	}
	a, b := nonBookkeepingRows(t, live), nonBookkeepingRows(t, bf)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("row sets differ: live %d, backfill %d", len(a), len(b))
	}
	for k, v := range a {
		if !bytes.Equal(v, b[k]) {
			t.Fatalf("row %s differs between the live capture and the backfill", k)
		}
	}
	// the block with inbox transactions is closed by a fill that names its hash; the others by fills that say there was nothing to capture
	open, _ := finality.GapsIn(ctx, bf, uint64(Chain), 0, finality.MaxCaptureBlock)
	if len(open) != 0 {
		t.Fatalf("still open: %v", open)
	}
	fills, _ := bf.ListByRange(ctx, uint64(Chain), 0, finality.MaxCaptureBlock, finality.GapFillPrefix)
	if len(fills) != 5 {
		t.Fatalf("fills: %v", fills)
	}
	for _, f := range fills {
		if f.L1Block == 1000 && f.L1Hash != blk.Hash {
			t.Fatalf("the fill of the captured block names its hash: %v", f)
		}
	}
	// a second validator filling the same gap writes the same rows: identical duplicates are accepted
	w2 := &Backfiller{Chain: uint64(Chain), Store: bf, Capturer: CapturerOf(cap2), Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	if err := finality.RecordGap(ctx, bf, uint64(Chain), 1000, 1000, finality.GapStateProofUnavailable); err != nil {
		t.Fatal(err)
	}
	rep, err = w2.Step(ctx, 10)
	if err != nil || rep.Failed != 0 {
		t.Fatalf("a duplicate fill by another validator: %+v %v", rep, err)
	}
}

type scriptCap struct {
	calls  map[uint64]int
	script func(n uint64, call int) (hash [32]byte, inbox bool, err error)
}

func (s *scriptCap) CaptureBlockHash(_ context.Context, n uint64) ([32]byte, bool, error) {
	if s.calls == nil {
		s.calls = map[uint64]int{}
	}
	s.calls[n]++
	return s.script(n, s.calls[n])
}

func okCap(n uint64, _ int) ([32]byte, bool, error) { return [32]byte{0xaa, byte(n)}, false, nil }

func TestRB12BackfillIsBoundedPerStepAndPicksOpenBlocksOnly(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 10, 29, finality.GapOutageUnscanned)
	_ = finality.RecordGapFill(ctx, st, uint64(Chain), 12, [32]byte{1}, true) // another validator did this one
	sc := &scriptCap{script: okCap}
	now, _ := bfClock()
	w := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: sc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	rep, err := w.Step(ctx, 4)
	if err != nil || rep.Attempted != 4 || rep.Filled != 4 || rep.Open != 15 {
		t.Fatalf("a step is bounded: %+v %v", rep, err)
	}
	if sc.calls[12] != 0 {
		t.Fatalf("a block another validator filled is not captured again")
	}
	for rep.Open > 0 {
		if rep, err = w.Step(ctx, 6); err != nil {
			t.Fatal(err)
		}
	}
	if len(sc.calls) != 19 {
		t.Fatalf("each of the 19 open blocks was captured: %d", len(sc.calls))
	}
	if tot, _ := finality.GapTotalsOf(ctx, st, uint64(Chain)); tot.Open != 0 || tot.Filled != 20 {
		t.Fatalf("%+v", tot)
	}
}

func TestRB12BackfillBlockPickIsRandomisedSoSevenValidatorsDoNotFillTheSameBlocksInStep(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 100, 199, finality.GapOutageUnscanned)
	now, _ := bfClock()
	first := map[uint64]bool{}
	for v := 0; v < 7; v++ {
		sc := &scriptCap{script: okCap}
		w := &Backfiller{Chain: uint64(Chain), Store: NewMemStore(), Capturer: sc, Policy: bfPolicy(), Now: now}
		_ = finality.RecordGap(ctx, w.Store, uint64(Chain), 100, 199, finality.GapOutageUnscanned)
		if _, err := w.Step(ctx, 1); err != nil {
			t.Fatal(err)
		}
		for n := range sc.calls {
			first[n] = true
		}
	}
	if len(first) < 3 {
		t.Fatalf("seven validators with the default pick started on only %d distinct blocks of 100", len(first))
	}
}

func stateProofFailure(n uint64, text string) error {
	s := finality.NewState("batcher_state_unavailable", "l1_block", n)
	return &CaptureFailure{Block: n, State: s, Err: errors.New(text)}
}

func TestRB12BackfillFailureBacksOffKeepsRetryingAndNeverGivesUpOnAStateProof(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 50, 50, finality.GapStateProofUnavailable)
	now, adv := bfClock()
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		if call < 12 {
			return [32]byte{}, false, stateProofFailure(n, fmt.Sprintf("eth_getProof https://u:pw@node.example/?apikey=KEY%d: historical state is not available", call))
		}
		return okCap(n, call)
	}}
	w := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: sc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	var attempts []time.Duration
	t0 := now()
	for i := 0; i < 200 && sc.calls[50] < 12; i++ {
		rep, err := w.Step(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Attempted == 1 {
			attempts = append(attempts, now().Sub(t0))
		}
		adv(time.Minute)
	}
	if sc.calls[50] != 12 {
		t.Fatalf("the block was tried %d times, want 12 (11 failures then success): it is never given up", sc.calls[50])
	}
	// the wait doubles from the base to the cap: 1, 2, 4, 8, 16, 16 ... minutes between attempts
	var gaps []time.Duration
	for i := 1; i < len(attempts); i++ {
		gaps = append(gaps, attempts[i]-attempts[i-1])
	}
	if gaps[0] < time.Minute || gaps[1] < 2*time.Minute || gaps[2] < 4*time.Minute || gaps[3] < 8*time.Minute || gaps[4] < 16*time.Minute {
		t.Fatalf("backoff gaps %v do not double", gaps)
	}
	for _, g := range gaps {
		if g > 16*time.Minute+61*time.Second {
			t.Fatalf("a gap of %v exceeds the cap", g)
		}
	}
	// during the failures the block stayed open with a class, a redacted note and NO terminal record
	if ends, _ := st.ListByRange(ctx, uint64(Chain), 0, finality.MaxCaptureBlock, finality.GapEndPrefix); len(ends) != 0 {
		t.Fatalf("a state proof that a provider cannot serve is not proof of unavailability: %v", ends)
	}
	notes, _ := st.ListByRange(ctx, uint64(Chain), 50, 50, finality.GapNotePrefix)
	if len(notes) == 0 {
		t.Fatal("the provider text of a failure is kept as a note")
	}
	for _, k := range notes {
		b, _, _ := st.Get(ctx, k)
		if bytes.Contains(b, []byte("pw@")) || bytes.Contains(b, []byte("KEY")) {
			t.Fatalf("a credential reached a note: %q", b)
		}
	}
	if open, _ := finality.GapsIn(ctx, st, uint64(Chain), 0, finality.MaxCaptureBlock); len(open) != 0 {
		t.Fatalf("filled at the end: %v", open)
	}
}

func blobFailure(n, slot uint64, gone bool) error {
	s := finality.NewState("l1_blob_unavailable", "l1_block", n, "versioned_hashes", "0x01", "beacon_slot", slot, "http_status", uint64(404))
	var cause error = errors.New("beacon blob answer HTTP 503")
	if gone {
		cause = &StatusError{Status: 404, Gone: true, Endpoints: 2}
	}
	return &CaptureFailure{Block: n, State: s, Err: cause}
}

func TestRB12BackfillGivesUpOnlyOnProvenUnavailabilityWithinRetentionAndNamesItsProviders(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 70, 71, finality.GapBlobUnavailable)
	now, adv := bfClock()
	slotNow := (uint64(bfEpoch.Unix()) - 1655733600) / 12
	slot := slotNow - 3600 // 12 hours old: well inside the retention
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		if n == 70 {
			return [32]byte{}, false, blobFailure(n, slot, true) // every provider says 404/410
		}
		return [32]byte{}, false, blobFailure(n, slot, false) // a provider error: not proof of anything
	}}
	pol := bfPolicy()
	w := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: sc, Providers: []string{"beacon-b.example", "beacon-a.example"}, Policy: pol, Now: now, Pick: func(int) int { return 0 }}
	// two observations of "gone" over 30+ minutes are not enough: three are required
	for i := 0; i < 2; i++ {
		if _, err := w.Step(ctx, 2); err != nil {
			t.Fatal(err)
		}
		adv(20 * time.Minute)
	}
	if ends, _ := st.ListByRange(ctx, uint64(Chain), 0, finality.MaxCaptureBlock, finality.GapEndPrefix); len(ends) != 0 {
		t.Fatalf("two observations are not proof: %v", ends)
	}
	for i := 0; i < 8; i++ {
		if _, err := w.Step(ctx, 2); err != nil {
			t.Fatal(err)
		}
		adv(20 * time.Minute)
	}
	got, _ := finality.GapsIn(ctx, st, uint64(Chain), 70, 71)
	if len(got) != 2 || got[0].State != finality.GapUnavailableProven && got[1].State != finality.GapUnavailableProven || got[0].From != 70 || got[0].State != finality.GapUnavailableProven || got[1].State != finality.GapOpen {
		t.Fatalf("block 70 is proven unavailable, 71 (a 503) is still open: %v", got)
	}
	ends, _ := finality.GapEndsOf(ctx, st, uint64(Chain), 70)
	if len(ends) != 1 || ends[0].Kind != finality.GapUnavailableProven || strings.Join(ends[0].Providers, ",") != "beacon-a.example,beacon-b.example" || ends[0].Reason == "" {
		t.Fatalf("the end names its providers and reason: %+v", ends)
	}
	// a terminal block is not tried again while the provider set is the same ...
	calls := sc.calls[70]
	for i := 0; i < 4; i++ {
		_, _ = w.Step(ctx, 2)
		adv(time.Hour)
	}
	if sc.calls[70] != calls {
		t.Fatalf("an ended block was tried again by the same providers: %d -> %d", calls, sc.calls[70])
	}
	// ... and is tried again when a provider is added (a new provider may have the data); success supersedes the end
	w.Providers = []string{"beacon-a.example", "beacon-b.example", "beacon-c.example"}
	sc.script = func(n uint64, call int) ([32]byte, bool, error) { return okCap(n, call) }
	for i := 0; i < 4; i++ {
		_, _ = w.Step(ctx, 2)
		adv(20 * time.Minute)
	}
	if open, _ := finality.GapsIn(ctx, st, uint64(Chain), 70, 71); len(open) != 0 {
		t.Fatalf("a new provider filled block 70 and the fill supersedes the end: %v", open)
	}
}

func TestRB12BackfillMarksRetentionExpiredOnlyWhenTheBlobsAreGoneAndOlderThanRetention(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 80, 82, finality.GapBlobUnavailable)
	now, _ := bfClock()
	slotNow := (uint64(bfEpoch.Unix()) - 1655733600) / 12
	oldSlot := slotNow - 4096*32 - 64 // past the 4096-epoch retention
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		switch n {
		case 80:
			return [32]byte{}, false, blobFailure(n, oldSlot, true) // gone and old: expired
		case 81:
			return [32]byte{}, false, blobFailure(n, oldSlot, false) // old, but the providers erred: nothing is established
		default:
			return [32]byte{}, false, blobFailure(n, slotNow-100, true) // gone but recent: needs the observation rule
		}
	}}
	w := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: sc, Providers: []string{"b.example"}, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
	if _, err := w.Step(ctx, 3); err != nil {
		t.Fatal(err)
	}
	got, _ := finality.GapsIn(ctx, st, uint64(Chain), 80, 82)
	var states []string
	for _, g := range got {
		states = append(states, fmt.Sprintf("%d-%d:%s", g.From, g.To, g.State))
	}
	if fmt.Sprint(states) != "[80-80:retention_expired 81-82:open]" {
		t.Fatalf("states %v", states)
	}
}

func TestRB12BackfillRefusesAConflictingRowByNameAndLeavesTheGapOpen(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	_ = finality.RecordGap(ctx, st, uint64(Chain), 90, 90, finality.GapStateProofUnavailable)
	now, _ := bfClock()
	sc := &scriptCap{script: func(n uint64, call int) ([32]byte, bool, error) {
		return [32]byte{}, false, &CaptureFailure{Block: n, State: finality.NewState("capture_row_conflict", "chain", uint64(Chain), "l1_block", n), Err: finality.ErrCaptureConflict}
	}}
	var logged []string
	w := &Backfiller{Chain: uint64(Chain), Store: st, Capturer: sc, Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 },
		Logf: func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }}
	rep, err := w.Step(ctx, 1)
	if err != nil || rep.Failed != 1 || rep.Conflicts != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if open, _ := finality.GapsIn(ctx, st, uint64(Chain), 90, 90); len(open) != 1 {
		t.Fatalf("a conflict does not close the gap: %v", open)
	}
	if fills, _ := st.ListByRange(ctx, uint64(Chain), 90, 90, finality.GapFillPrefix); len(fills) != 0 {
		t.Fatalf("no fill is recorded for a conflicting capture: %v", fills)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "capture_row_conflict") {
		t.Fatalf("the conflict is logged by name: %v", logged)
	}
}

func TestRB12CapturerOfReturnsTheFailureWithItsNamedStateAndTheHash(t *testing.T) {
	kz, err := kzgsetup.Load(pinnedSetup)
	if err != nil {
		t.Fatal(err)
	}
	blk, blob := blobBlock(t, kz, 1000, []byte("x"))
	ctx := context.Background()
	st := NewMemStore()
	l1 := &fakeL1{blk: blk, failProof: true}
	c := &Capturer{Chain: uint64(Chain), Pins: newPins(), L1: l1, Beacon: fakeBeacon{blobs: [][]byte{blob}}, Store: st, GenesisTime: 1655733600, SlotSeconds: 12}
	bc := CapturerOf(c)
	_, _, err = bc.CaptureBlockHash(ctx, 1000)
	var cf *CaptureFailure
	if !errors.As(err, &cf) || cf.State == nil || cf.State.Code != "batcher_state_unavailable" || ClassOfFailure(err) != finality.GapStateProofUnavailable {
		t.Fatalf("want a CaptureFailure with batcher_state_unavailable, got %v", err)
	}
	l1.failProof = false
	h, inbox, err := bc.CaptureBlockHash(ctx, 1000)
	if err != nil || !inbox || h != blk.Hash {
		t.Fatalf("%x %v %v", h, inbox, err)
	}
	h, inbox, err = bc.CaptureBlockHash(ctx, 999)
	if err != nil || inbox || h != (L1BlockData{Number: 999}).Hash {
		t.Fatalf("an empty block is scanned and reports the hash its provider gave: %x %v %v", h, inbox, err)
	}
	// the wrapper does not disturb the capturer's own Record hook
	if c.Record != nil {
		t.Fatal("CapturerOf must not install a hook on the capturer it wraps")
	}
}

func TestRB12ClassOfFailureNamesTheKindOfFailure(t *testing.T) {
	cases := []struct {
		err  error
		want finality.GapClass
	}{
		{&CaptureFailure{State: finality.NewState("batcher_state_unavailable", "l1_block", uint64(1)), Err: errors.New("x")}, finality.GapStateProofUnavailable},
		{&CaptureFailure{State: finality.NewState("l1_blob_unavailable", "l1_block", uint64(1)), Err: errors.New("x")}, finality.GapBlobUnavailable},
		{&BlockFetchError{Block: 1, Err: errors.New("x")}, finality.GapBlockUnavailable},
		{fmt.Errorf("wrapped: %w", &BlockFetchError{Block: 1, Err: errors.New("x")}), finality.GapBlockUnavailable},
		{errors.New("baseposted: the re-encoded header does not hash to the block hash"), finality.GapCaptureFailed},
		{&CaptureFailure{State: finality.NewState("capture_row_conflict", "l1_block", uint64(1)), Err: finality.ErrCaptureConflict}, finality.GapCaptureFailed},
	}
	for i, c := range cases {
		if got := ClassOfFailure(c.err); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

// BeaconHTTP proves a blob "gone" only when EVERY endpoint answered 404/410 on every route; anything else is the last error as before.
func TestRB12BeaconHTTPReportsGoneOnlyWhenEveryEndpointSaidGone(t *testing.T) {
	status := func(code int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
	}
	a, b, c := status(404), status(410), status(503)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	_, err := (&BeaconHTTP{Bases: []string{a.URL, b.URL}}).Blobs(context.Background(), 5)
	gone, ok := BlobsGone(err)
	if !ok || gone.Endpoints != 2 || (gone.Status != 404 && gone.Status != 410) {
		t.Fatalf("two endpoints, all 404/410: want the gone evidence, got %v", err)
	}
	if se, isStatus := err.(*StatusError); !isStatus || se.Status != gone.Status {
		t.Fatalf("a gone answer is still a *StatusError for the callers that assert it: %v", err)
	}
	_, err = (&BeaconHTTP{Bases: []string{a.URL, c.URL}}).Blobs(context.Background(), 5)
	if _, ok := BlobsGone(err); ok {
		t.Fatalf("one endpoint answered 503: that is not proof of anything: %v", err)
	}
	_, err = (&BeaconHTTP{Bases: nil}).Blobs(context.Background(), 5)
	if _, ok := BlobsGone(err); ok {
		t.Fatalf("no endpoint configured is not proof either: %v", err)
	}
}

// ---- the real evidence: a leg whose batch lies in a hole ----

func TestRB12GapRealEvidenceLegInAHoleIsNamedThenBackfilledThenBuildsTheSameEvidence(t *testing.T) {
	for _, c := range []struct{ ev, leg string }{{"evidence/valid_a.bin", "legs/a.json"}, {"evidence/valid_b.bin", "legs/b.json"}} {
		w := newBuildWorld(t, c.ev, c.leg)
		ctx := context.Background()
		base, pend, err := w.build(t, w.builder())
		if err != nil || pend != nil || base == nil {
			t.Fatalf("%s baseline: %v %v %v", c.ev, base, pend, err)
		}
		origin, lo, hi := w.originAndFrameSpan(t)
		// the outage: every row of the frame blocks is missing, the cursor says the loop went past, and the loop recorded the hole
		saved := w.takeRows(lo-1, hi+1)
		if len(saved) == 0 {
			t.Fatal("no rows in the frame span")
		}
		w.putCursor(t, origin, hi+50)
		if err := finality.RecordGap(ctx, w.store, uint64(Chain), lo-1, hi+1, finality.GapStateProofUnavailable); err != nil {
			t.Fatal(err)
		}
		_, pend, err = w.build(t, w.builder())
		se, named := finality.AsNamed(err)
		if pend != nil || !named || se.Code != "l1_capture_gap" || se.Fields["gap_state"] != "open" || se.Fields["from"] != lo-1 {
			t.Fatalf("%s: a leg in the hole must be the named state, got pend=%v err=%v", c.ev, pend, err)
		}
		// the backfill (here: a capturer that re-reads the blocks from the chain, i.e. restores the rows) fills it
		now, _ := bfClock()
		bf := &Backfiller{Chain: uint64(Chain), Store: w.store, Capturer: w.restorer(saved), Policy: bfPolicy(), Now: now, Pick: func(int) int { return 0 }}
		for i := 0; i < 100; i++ {
			rep, err := bf.Step(ctx, 7)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Open == 0 {
				break
			}
		}
		if open, _ := finality.GapsIn(ctx, w.store, uint64(Chain), 0, finality.MaxCaptureBlock); len(open) != 0 {
			t.Fatalf("%s: still open after the backfill: %v", c.ev, open)
		}
		got, pend, err := w.build(t, w.builder())
		if err != nil || pend != nil || got == nil {
			t.Fatalf("%s: after the backfill the leg builds and verifies: %v %v %v", c.ev, got, pend, err)
		}
		if !bytes.Equal(got.Evidence, base.Evidence) {
			t.Fatalf("%s: the evidence built after the backfill differs from the baseline", c.ev)
		}
	}
}

// takeRows removes every row of the L1 blocks [from, to] from the world's store and returns them.
func (w *buildWorld) takeRows(from, to uint64) map[CaptureKey][]byte {
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	out := map[CaptureKey][]byte{}
	for k, v := range w.store.rows {
		if k.Chain == uint64(Chain) && k.L1Block >= from && k.L1Block <= to && !strings.HasPrefix(k.Item, "gap") && !strings.HasPrefix(k.Item, "runtime/") {
			out[k] = v
			delete(w.store.rows, k)
		}
	}
	return out
}

// restorer is a BlockCapturer that puts back the saved rows of the block it is asked for.
func (w *buildWorld) restorer(saved map[CaptureKey][]byte) BlockCapturer {
	return &scriptCap{script: func(n uint64, _ int) ([32]byte, bool, error) {
		var hash [32]byte
		inbox := false
		for k, v := range saved {
			if k.L1Block != n {
				continue
			}
			if err := w.store.Put(context.Background(), k, v); err != nil {
				return hash, false, err
			}
			hash = k.L1Hash
			if k.Item == ItemInbox {
				inbox = true
			}
		}
		if hash == ([32]byte{}) {
			hash = [32]byte{0xee, byte(n)}
		}
		return hash, inbox, nil
	}}
}
