// Copyright 2026 Certen Protocol

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/finalitytest"
	"github.com/certen/independant-validator/pkg/finality/legacyhdr"
	"github.com/certen/independant-validator/pkg/metrics"
)

// ---- fixtures: the real Arbitrum Sepolia blocks (four legs of one chain), each as the legacy component production holds ----

var arbLegacyFixtures = []string{"arbitrum_sepolia_313235886", "arbitrum_sepolia_315455204", "arbitrum_sepolia_315677780", "arbitrum_sepolia_315690738"}

type lgFix struct {
	cand   legacyhdr.Candidate
	header []byte
	proof  string
}

func legacyFix(t *testing.T, fixture string, n int) lgFix {
	t.Helper()
	s := finalitytest.Settlement(t, fixture)
	comp := finalitytest.ProductionLegacyExecutionProof(t, s)
	raw, err := json.Marshal(comp)
	if err != nil {
		t.Fatal(err)
	}
	proof := fmt.Sprintf("00000000-0000-0000-0000-%012d", n)
	l, err := legacyhdr.ParseLeg(proof, fmt.Sprintf("b0000000-0000-0000-0000-%012d", n), raw)
	if err != nil {
		t.Fatal(err)
	}
	return lgFix{cand: legacyhdr.Candidate{Leg: l}, header: append([]byte(nil), s.Included.Header...), proof: proof}
}

func arbLegs(t *testing.T) []lgFix {
	t.Helper()
	var out []lgFix
	for i, f := range arbLegacyFixtures {
		out = append(out, legacyFix(t, f, i+1))
	}
	return out
}

// lgLister serves candidates in pages the way the database lister does: limit proofs per page, next = the cursor, "" at the end.
type lgLister struct {
	mu    sync.Mutex
	cands []legacyhdr.Candidate
	pages int
	err   error
}

func (l *lgLister) LegacyLegs(_ context.Context, chain uint64, after string, limit int) ([]legacyhdr.Candidate, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pages++
	if l.err != nil {
		return nil, "", l.err
	}
	start := 0
	if after != "" {
		fmt.Sscanf(after, "%d", &start)
	}
	end := start + limit
	next := ""
	if end < len(l.cands) {
		next = fmt.Sprint(end)
	} else {
		end = len(l.cands)
	}
	return append([]legacyhdr.Candidate(nil), l.cands[start:end]...), next, nil
}

func (l *lgLister) set(c []legacyhdr.Candidate) {
	l.mu.Lock()
	l.cands = c
	l.mu.Unlock()
}

// lgSource answers by block hash from a table and counts and records the asks.
type lgSource struct {
	mu     sync.Mutex
	by     map[common.Hash]func() ([]byte, error)
	asked  []common.Hash
	onCall func()
}

func (s *lgSource) HeaderByHash(_ context.Context, chain uint64, h common.Hash) ([]byte, error) {
	s.mu.Lock()
	s.asked = append(s.asked, h)
	f := s.by[h]
	cb := s.onCall
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
	if f == nil {
		return nil, &legacyhdr.Unserved{Chain: chain, Hash: h, Asked: 1, NotServed: 1}
	}
	return f()
}

func (s *lgSource) calls() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.asked) }

func serves(h []byte) func() ([]byte, error) { return func() ([]byte, error) { return h, nil } }

// lgClock is a manual clock: waits answer at once and move the time by the wait (nothing sleeps).
type lgClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *lgClock) loop() loopClock {
	return loopClock{
		Now: func() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t },
		After: func(d time.Duration) <-chan time.Time {
			ch := make(chan time.Time, 1)
			ch <- time.Time{}
			return ch
		},
	}
}
func (c *lgClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type lgRig struct {
	loop   *LegacyHeaderLoop
	lister *lgLister
	src    *lgSource
	store  *finality.MemCaptureStore
	status *rtStatus
	clock  *lgClock
	logs   *rtLog
	legs   []lgFix
}

const arbChain = 421614

// newRig is a loop over the four Arbitrum legs, every block served by the source unless a test changes the table.
func newRig(t *testing.T) *lgRig {
	t.Helper()
	legs := arbLegs(t)
	r := &lgRig{lister: &lgLister{}, src: &lgSource{by: map[common.Hash]func() ([]byte, error){}}, store: finality.NewMemCaptureStore(),
		status: &rtStatus{}, clock: &lgClock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}, logs: &rtLog{}, legs: legs}
	for _, l := range legs {
		r.lister.cands = append(r.lister.cands, l.cand)
		r.src.by[l.cand.Leg.BlockHash] = serves(l.header)
	}
	r.loop = &LegacyHeaderLoop{ChainID: arbChain, Legs: r.lister, Source: r.src, Store: r.store, Status: r.status,
		Targets: []finality.Level{finality.LevelL1Posted, finality.LevelFinalized}, Budget: finality.NewMemoryBudget(finality.DefaultMemoryBudget),
		HeapInUse: func() uint64 { return 0 }, Logf: r.logs.logf, Clock: r.clock.loop(), PerTick: 10, PageSize: 2}
	return r
}

func (r *lgRig) tick(t *testing.T) {
	t.Helper()
	if err := r.loop.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
}

func (r *lgRig) wantCounts(t *testing.T, pending, rec, unserved, invalid int) {
	t.Helper()
	c := r.loop.Counts()
	if c[LegacyPending] != pending || c[LegacyReconstructed] != rec || c[LegacyUnserved] != unserved || c[LegacyInvalid] != invalid {
		t.Fatalf("counts = %v; want pending %d reconstructed %d unserved %d invalid %d", c, pending, rec, unserved, invalid)
	}
}

func TestLegacyLoopReconstructsAndKeepsEveryHeaderAndAnotherValidatorFetchesNothing(t *testing.T) {
	r := newRig(t)
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
	if r.src.calls() != 4 {
		t.Fatalf("source asked %d times, want once per leg", r.src.calls())
	}
	for _, l := range r.legs {
		got, ok, _ := r.store.Get(context.Background(), l.cand.Leg.Key())
		if !ok || !bytes.Equal(got, l.header) {
			t.Fatalf("leg %s: the stored row is not the verified header", l.proof)
		}
		if _, has := r.status.row(l.proof, finality.LevelFinalized); has {
			t.Fatalf("leg %s: a reconstructed leg got a status row (the upgrader writes its own)", l.proof)
		}
	}
	// a second tick of the same loop asks nothing
	r.tick(t)
	if r.src.calls() != 4 {
		t.Fatalf("a settled leg was asked again: %d calls", r.src.calls())
	}
	// another validator (a fresh loop over the same insert-only store) verifies the stored rows and fetches nothing
	other := newRig(t)
	other.store = r.store
	other.loop.Store = r.store
	other.tick(t)
	other.wantCounts(t, 0, 4, 0, 0)
	if other.src.calls() != 0 {
		t.Fatalf("a header already stored was fetched again: %d calls", other.src.calls())
	}
}

func TestLegacyLoopJudgesTheLowestBlocksFirstAndNoMoreThanPerTick(t *testing.T) {
	r := newRig(t)
	r.loop.PerTick = 3
	r.tick(t)
	r.wantCounts(t, 1, 3, 0, 0)
	var blocks []uint64
	for _, h := range r.src.asked {
		for _, l := range r.legs {
			if l.cand.Leg.BlockHash == h {
				blocks = append(blocks, l.cand.Leg.BlockNumber)
			}
		}
	}
	if len(blocks) != 3 || !(blocks[0] < blocks[1] && blocks[1] < blocks[2]) {
		t.Fatalf("asked blocks %v: not the lowest three ascending", blocks)
	}
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
}

func TestLegacyLoopNamesAnUnservedBlockWritesItsStatusAndBacksOffExactly(t *testing.T) {
	r := newRig(t)
	victim := r.legs[1].cand.Leg
	r.src.by[victim.BlockHash] = nil // not served by any provider
	r.tick(t)
	r.wantCounts(t, 0, 3, 1, 0)
	for _, target := range []finality.Level{finality.LevelL1Posted, finality.LevelFinalized} {
		row, ok := r.status.row(r.legs[1].proof, target)
		if !ok || row.Class != finality.BuilderUnavailable || row.State == nil {
			t.Fatalf("status of %s = %+v ok %v", target, row, ok)
		}
		st := row.State
		if st.Code != finality.CodeIncludedUnavailable || st.Fields["reason"] != finality.IncludedLegacyHeaderUnserved ||
			st.Fields["chain"] != uint64(arbChain) || st.Fields["block"] != victim.BlockNumber || st.Fields["proof_id"] != r.legs[1].proof {
			t.Fatalf("status state = %v", st)
		}
	}
	if _, has := r.status.row(r.legs[0].proof, finality.LevelFinalized); has {
		t.Fatal("a reconstructed leg has a status row")
	}
	if _, ok, _ := r.store.Get(context.Background(), victim.Key()); ok {
		t.Fatal("a header row exists for an unserved block")
	}
	// backoff: RetryMin (default 10m) after the first failure, doubled per attempt, capped at RetryMax; N-1 waits do not ask, N asks
	asks := func() int { return r.src.calls() }
	base := asks()
	r.clock.advance(10*time.Minute - time.Nanosecond)
	r.tick(t)
	if asks() != base {
		t.Fatal("asked again one nanosecond before the first backoff ended")
	}
	r.clock.advance(time.Nanosecond)
	r.tick(t)
	if asks() != base+1 {
		t.Fatalf("not asked again when the backoff ended: %d", asks()-base)
	}
	// second failure: 20 minutes
	r.clock.advance(20*time.Minute - time.Nanosecond)
	r.tick(t)
	if asks() != base+1 {
		t.Fatal("asked before the doubled backoff ended")
	}
	r.clock.advance(time.Nanosecond)
	// the provider serves it now: the leg completes and its header is kept
	r.src.by[victim.BlockHash] = serves(r.legs[1].header)
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
	if got, ok, _ := r.store.Get(context.Background(), victim.Key()); !ok || !bytes.Equal(got, r.legs[1].header) {
		t.Fatal("the late-served header was not stored")
	}
}

func TestLegacyLoopBackoffIsCappedAtRetryMax(t *testing.T) {
	r := newRig(t)
	r.loop.RetryMin, r.loop.RetryMax = time.Minute, 5*time.Minute
	r.src.by[r.legs[0].cand.Leg.BlockHash] = nil
	r.tick(t)
	for i, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		before := r.src.calls()
		r.clock.advance(want - time.Nanosecond)
		r.tick(t)
		if r.src.calls() != before {
			t.Fatalf("attempt %d: asked before %s", i+1, want)
		}
		r.clock.advance(time.Nanosecond)
		r.tick(t)
		if r.src.calls() != before+1 {
			t.Fatalf("attempt %d: not asked after %s", i+1, want)
		}
	}
}

// A header that is the block's own but that the stored component contradicts is kept (it is true chain data, not fetched again) and
// the leg is named invalid with the check that failed.
func TestLegacyLoopNamesALegWhoseStoredComponentContradictsTheBlock(t *testing.T) {
	r := newRig(t)
	bad := r.legs[2].cand
	bad.Leg.ReceiptsRoot[0] ^= 0xff // the bundle states a receipts root the block does not have
	r.lister.set([]legacyhdr.Candidate{r.legs[0].cand, r.legs[1].cand, bad, r.legs[3].cand})
	r.tick(t)
	r.wantCounts(t, 0, 3, 0, 1)
	row, ok := r.status.row(r.legs[2].proof, finality.LevelFinalized)
	if !ok || row.State == nil || row.State.Code != finality.CodeIncludedInvalid || row.State.Fields["check"] != legacyhdr.CheckStoredRoots ||
		row.State.Fields["chain"] != uint64(arbChain) || row.State.Fields["block"] != bad.Leg.BlockNumber {
		t.Fatalf("status = %+v", row)
	}
	if _, ok, _ := r.store.Get(context.Background(), bad.Leg.Key()); !ok {
		t.Fatal("the block's own header was not kept")
	}
	before := r.src.calls()
	r.tick(t)
	if r.src.calls() != before {
		t.Fatal("a leg judged invalid was fetched again")
	}
}

func TestLegacyLoopNamesALegacyComponentItCannotReadAndNeverFetchesIt(t *testing.T) {
	r := newRig(t)
	broken := legacyhdr.Candidate{Leg: legacyhdr.Leg{ProofID: r.legs[0].proof, BundleID: "b"}, Err: finality.NewState(finality.CodeIncludedInvalid, "proof_id", r.legs[0].proof, "cause", "the stored execution proof has no usable block_hash")}
	r.lister.set([]legacyhdr.Candidate{broken, r.legs[1].cand})
	r.tick(t)
	r.wantCounts(t, 0, 1, 0, 1)
	row, ok := r.status.row(r.legs[0].proof, finality.LevelL1Posted)
	if !ok || row.State.Code != finality.CodeIncludedInvalid {
		t.Fatalf("status = %+v", row)
	}
	if r.src.calls() != 1 {
		t.Fatalf("the unreadable leg was asked of a provider: %d calls", r.src.calls())
	}
}

func TestLegacyLoopRefusesAStoredRowThatIsNotTheBlockAndNeverTrustsIt(t *testing.T) {
	r := newRig(t)
	l := r.legs[0].cand.Leg
	// another validator (or a bug) stored other bytes under this header's key: insert-only, so they stay; the loop must not accept them
	if err := r.store.Put(context.Background(), l.Key(), r.legs[1].header); err != nil {
		t.Fatal(err)
	}
	r.tick(t)
	r.wantCounts(t, 0, 3, 0, 1)
	row, _ := r.status.row(r.legs[0].proof, finality.LevelFinalized)
	if row.State == nil || row.State.Fields["check"] != legacyhdr.CheckHeaderHash {
		t.Fatalf("status = %+v", row)
	}
	// and a Put that loses a race to different bytes is the named conflict, not a success
	r2 := newRig(t)
	r2.loop.Store = conflictStore{r2.store}
	r2.tick(t)
	r2.wantCounts(t, 0, 0, 0, 4)
	row, _ = r2.status.row(r2.legs[0].proof, finality.LevelFinalized)
	if row.State == nil || row.State.Fields["check"] != "store_conflict" {
		t.Fatalf("status = %+v", row)
	}
}

type conflictStore struct{ finality.CaptureStore }

func (conflictStore) Put(context.Context, finality.CaptureKey, []byte) error {
	return fmt.Errorf("%w: raced", finality.ErrCaptureConflict)
}

type failingStore struct {
	finality.CaptureStore
	get, put error
}

func (f failingStore) Get(ctx context.Context, k finality.CaptureKey) ([]byte, bool, error) {
	if f.get != nil {
		return nil, false, f.get
	}
	return f.CaptureStore.Get(ctx, k)
}
func (f failingStore) Put(ctx context.Context, k finality.CaptureKey, b []byte) error {
	if f.put != nil {
		return f.put
	}
	return f.CaptureStore.Put(ctx, k, b)
}

// A store that cannot be read or written is no verdict about the leg: it stays pending, writes no status, and the text is redacted.
func TestLegacyLoopStoreFailuresJudgeNothing(t *testing.T) {
	for name, st := range map[string]func(s finality.CaptureStore) finality.CaptureStore{
		"get": func(s finality.CaptureStore) finality.CaptureStore {
			return failingStore{s, errors.New("connection refused"), nil}
		},
		"put": func(s finality.CaptureStore) finality.CaptureStore {
			return failingStore{s, nil, errors.New("disk full")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.loop.Store = st(r.store)
			r.tick(t)
			r.wantCounts(t, 4, 0, 0, 0)
			if r.status.n != 0 {
				t.Fatalf("a store failure wrote %d status rows", r.status.n)
			}
		})
	}
}

func TestLegacyLoopMemoryBudgetIsExactAndAlwaysReleased(t *testing.T) {
	// the scan reserves legacyScanReserve: one byte less and nothing is listed, judged or fetched
	r := newRig(t)
	r.loop.Budget = finality.NewMemoryBudget(legacyScanReserve - 1)
	err := r.loop.Tick(context.Background())
	if n, ok := finality.AsNamed(err); !ok || n.Code != finality.CodeMemoryBudget {
		t.Fatalf("Tick = %v, want finality_memory_budget_exceeded", err)
	}
	if r.src.calls() != 0 || r.loop.Budget.Used() != 0 {
		t.Fatalf("calls %d, reserved %d", r.src.calls(), r.loop.Budget.Used())
	}
	// exactly the scan reserve: scan and legs run, everything is given back
	r = newRig(t)
	r.loop.Budget = finality.NewMemoryBudget(legacyScanReserve)
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
	if r.loop.Budget.Used() != 0 {
		t.Fatalf("%d bytes still reserved after the tick", r.loop.Budget.Used())
	}
	// the leg reserve: with legacyLegReserve-1 bytes free the leg is not started and stays due; with legacyLegReserve free it runs
	for _, free := range []int64{legacyLegReserve - 1, legacyLegReserve} {
		r = newRig(t)
		r.loop.Budget = finality.NewMemoryBudget(legacyScanReserve)
		if err := r.loop.scan(context.Background()); err != nil {
			t.Fatal(err)
		}
		r.loop.scanned, r.loop.lastScan = true, r.clock.t
		hold, err := r.loop.Budget.Reserve(arbChain, "test-hold", legacyScanReserve-free)
		if err != nil {
			t.Fatal(err)
		}
		r.tick(t)
		hold()
		if free == legacyLegReserve-1 {
			r.wantCounts(t, 4, 0, 0, 0)
			if r.src.calls() != 0 {
				t.Fatalf("a leg was fetched without its reservation: %d calls", r.src.calls())
			}
		} else {
			r.wantCounts(t, 0, 4, 0, 0)
		}
		if r.loop.Budget.Used() != 0 {
			t.Fatalf("%d bytes still reserved", r.loop.Budget.Used())
		}
	}
}

func TestLegacyLoopReleasesItsReservationWhenTheSourcePanics(t *testing.T) {
	r := newRig(t)
	r.src.onCall = func() { panic("provider library bug") }
	func() {
		defer func() { _ = recover() }() // the capture supervisor recovers a panicking loop and restarts it
		_ = r.loop.Tick(context.Background())
	}()
	if r.loop.Budget.Used() != 0 {
		t.Fatalf("a panicking leg leaked %d reserved bytes", r.loop.Budget.Used())
	}
}

func TestLegacyLoopHeapGateIsExact(t *testing.T) {
	r := newRig(t)
	gate := finality.HeapGate(r.loop.Budget.Limit())
	r.loop.HeapInUse = func() uint64 { return gate + 1 }
	r.tick(t)
	if r.src.calls() != 0 || !r.logs.has("over the gate") {
		t.Fatalf("a leg started over the heap gate (calls %d)", r.src.calls())
	}
	r.wantCounts(t, 4, 0, 0, 0)
	r.loop.HeapInUse = func() uint64 { return gate }
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
}

func TestLegacyLoopScanDropsLegsNoLongerListedAndRereadsAChangedBundle(t *testing.T) {
	r := newRig(t)
	r.loop.RescanEvery = time.Hour
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
	pages := r.lister.pages
	if pages != 2 { // 4 legs at 2 per page: the scan pages until the cursor ends
		t.Fatalf("the scan took %d pages, want 2", pages)
	}
	r.clock.advance(time.Hour - time.Nanosecond)
	r.tick(t)
	if r.lister.pages != pages {
		t.Fatal("the list was scanned again before RescanEvery")
	}
	// one leg is gone from the list (finalized or its bundle gained a header); another has a new bundle
	changed := r.legs[1].cand
	changed.Leg.BundleID = "b-new"
	r.lister.set([]legacyhdr.Candidate{r.legs[0].cand, changed})
	r.clock.advance(time.Nanosecond)
	r.tick(t)
	r.wantCounts(t, 0, 2, 0, 0) // the changed leg was judged afresh (its row is in the store: no fetch) and two legs were dropped
	if r.loop.Counts()[LegacyReconstructed] != 2 {
		t.Fatal("legs no longer listed are still counted")
	}
}

func TestLegacyLoopListerFailureKeepsTheKnownLegsAndRetriesTheScan(t *testing.T) {
	r := newRig(t)
	r.tick(t)
	r.wantCounts(t, 0, 4, 0, 0)
	r.loop.RescanEvery = time.Minute
	r.clock.advance(time.Minute)
	r.lister.err = errors.New("dial tcp 10.0.0.9:5432: connection refused")
	if err := r.loop.Tick(context.Background()); err == nil {
		t.Fatal("a failed scan was not reported")
	}
	r.wantCounts(t, 0, 4, 0, 0)
	r.lister.err = nil
	r.tick(t) // the scan is retried at the next tick, not after RescanEvery
	if r.lister.pages < 4 {
		t.Fatalf("the failed scan was not retried: %d pages", r.lister.pages)
	}
}

// The gauge must be non-zero exactly when legs stand in a state, and the loop must be a registered finality.Capturer of its chain.
func TestLegacyLoopGaugeCountsLegsPerStateAndTheLoopIsACapturer(t *testing.T) {
	r := newRig(t)
	r.src.by[r.legs[3].cand.Leg.BlockHash] = nil
	var c finality.Capturer = r.loop
	if c.Chain() != arbChain || c.Name() != "legacy-header/421614" {
		t.Fatalf("capturer = %d %s", c.Chain(), c.Name())
	}
	r.tick(t)
	metrics.RegisterMetrics()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "certen_finality_legacy_headers" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var chain, state string
			for _, lp := range m.GetLabel() {
				switch lp.GetName() {
				case "chain":
					chain = lp.GetValue()
				case "state":
					state = lp.GetValue()
				}
			}
			if chain == "421614" {
				got[state] = m.GetGauge().GetValue()
			}
		}
	}
	if got[LegacyReconstructed] != 3 || got[LegacyUnserved] != 1 || got[LegacyPending] != 0 || got[LegacyInvalid] != 0 {
		t.Fatalf("gauge = %v; want reconstructed 3 unserved 1", got)
	}
	if !r.logs.has("1 unserved") {
		t.Fatal("the counts were not logged")
	}
}

func TestLegacyLoopRunTicksUntilItsContextEndsAndNeverReturnsEarly(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	script := &rtScript{stopAfter: 3, cancel: cancel}
	// only the wait between ticks counts toward the script; the gaps between legs and pages answer at once
	r.loop.Clock = loopClock{Now: r.clock.loop().Now, After: func(d time.Duration) <-chan time.Time {
		if d == r.loop.every() {
			return script.After(d)
		}
		ch := make(chan time.Time, 1)
		ch <- time.Time{}
		return ch
	}}
	if err := r.loop.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want nil when ctx ends", err)
	}
	r.wantCounts(t, 0, 4, 0, 0)
	if r.src.calls() != 4 {
		t.Fatalf("calls %d", r.src.calls())
	}
}

func TestRTWireRegistersALegacyHeaderLoopPerChainWithThatChainsProvidersAndTheSharedBudget(t *testing.T) {
	rtProviderEnv(t)
	t.Setenv(EnvArchiveURLs, "https://archive.example/rpc")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	reg := finality.NewRegistry()
	status := &rtStatus{}
	w, err := Wire(cfg, Deps{Registry: reg, Store: finality.NewMemCaptureStore(), Status: status, Logf: logs.Logf, Legacy: &lgLister{}})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.LegacyLoops) != 3 {
		t.Fatalf("%d legacy loops, want Sepolia, Base Sepolia and Arbitrum Sepolia", len(w.LegacyLoops))
	}
	want := map[uint64][]string{
		finality.ChainSepolia:         append(append([]string(nil), cfg.L1RPC...), cfg.Archive...),
		finality.ChainBaseSepolia:     cfg.BaseL2,
		finality.ChainArbitrumSepolia: cfg.ArbL2,
	}
	for _, l := range w.LegacyLoops {
		src, ok := l.Source.(*legacyhdr.RPCSource)
		if !ok {
			t.Fatalf("chain %d: source %T", l.ChainID, l.Source)
		}
		if fmt.Sprint(src.URLs[l.ChainID]) != fmt.Sprint(want[l.ChainID]) || len(want[l.ChainID]) == 0 {
			t.Fatalf("chain %d providers = %v, want %v", l.ChainID, src.URLs[l.ChainID], want[l.ChainID])
		}
		if l.Budget != w.Upgrader.Memory {
			t.Fatalf("chain %d: the loop does not share the upgrader's memory budget", l.ChainID)
		}
		if len(l.Targets) == 0 || l.Status != status {
			t.Fatalf("chain %d: targets %v status %v", l.ChainID, l.Targets, l.Status)
		}
		for _, lv := range l.Targets {
			if !lv.Stored() {
				t.Fatalf("chain %d: status target %s is not a stored level", l.ChainID, lv)
			}
		}
		found := false
		for _, c := range reg.Capturers() {
			if c.Chain() == l.ChainID && c.Name() == l.Name() {
				found = true
			}
		}
		if !found {
			t.Fatalf("chain %d: %s is not a registered capturer", l.ChainID, l.Name())
		}
	}
	if !strings.Contains(logs.String(), "legacy_headers=on") {
		t.Fatalf("the startup line does not report the legacy-header loops:\n%s", logs.String())
	}
}

func TestRTWireNamesAMissingLegLister(t *testing.T) {
	rtProviderEnv(t)
	w, reg, logs := rtWire(t)
	if len(w.LegacyLoops) != 0 {
		t.Fatalf("%d legacy loops without a leg lister", len(w.LegacyLoops))
	}
	for _, c := range reg.Capturers() {
		if strings.HasPrefix(c.Name(), "legacy-header/") {
			t.Fatalf("%s registered without a leg lister", c.Name())
		}
	}
	if !strings.Contains(logs.String(), "legacy_headers=off (no leg lister)") {
		t.Fatalf("the startup line does not say the legacy-header loops are off:\n%s", logs.String())
	}
}
