// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// settlementSource answers every LegSettlement with a fixed error (or, with a nil error, the fixture's settlement) and counts the
// calls per bundle.
type settlementSource struct {
	*memSource
	err   error
	mu    *sync.Mutex
	calls map[string]int // bundle id -> LegSettlement calls
}

func newSettlementSource(m *memSource, err error) *settlementSource {
	return &settlementSource{memSource: m, err: err, mu: &sync.Mutex{}, calls: map[string]int{}}
}

func (s *settlementSource) LegSettlement(ctx context.Context, ref LegRef) (Settlement, error) {
	s.mu.Lock()
	s.calls[ref.BundleID]++
	s.mu.Unlock()
	if s.err != nil {
		return Settlement{}, s.err
	}
	return s.memSource.LegSettlement(ctx, ref)
}

func (s *settlementSource) total() (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.calls {
		n += c
	}
	return n
}

// gapRec is a Recorder that also implements GapRecorder.
type gapRec struct {
	*recSink
	gmu              sync.Mutex
	quiet            map[uint64]int
	unrecorded       int
	unrecordedSeries []int // every value the gauge was set to, in order
	noProver         map[uint64]int
}

func (g *gapRec) LegsWithoutSettlement(c uint64, n int) {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	if g.quiet == nil {
		g.quiet = map[uint64]int{}
	}
	g.quiet[c] = n
}
func (g *gapRec) UnrecordedSettlements(n int) {
	g.gmu.Lock()
	g.unrecorded = n
	g.unrecordedSeries = append(g.unrecordedSeries, n)
	g.gmu.Unlock()
}
func (g *gapRec) LegsWithoutProver(c uint64, n int) {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	if g.noProver == nil {
		g.noProver = map[uint64]int{}
	}
	g.noProver[c] = n
}
func (g *gapRec) quietOn(c uint64) int { g.gmu.Lock(); defer g.gmu.Unlock(); return g.quiet[c] }

var errNoComponent = IncludedUnavailable(IncludedNoExecutionProof, "proof_id", legID)

// A leg whose bundle holds no execution proof has no settlement (yet): the named finality_included_unavailable state is neither
// a failure nor an unusable leg, writes no log line and no failure metric. A source that does not name bundles is asked again on
// the pending schedule.
func TestUpgraderStaysQuietForALegWithoutASettlementAndAsksAgainOnThePendingSchedule(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	src := newSettlementSource(f.src, errNoComponent)
	f.u.src = src

	rep := f.u.RunOnce(ctx)
	if rep.NoSettlement != 1 || rep.Attempts != 1 || rep.Unusable != 0 || rep.Failed != 0 || rep.Appended != 0 || rep.Broken != 0 {
		t.Fatalf("%+v", rep)
	}
	if len(f.rec.failures) != 0 {
		t.Fatalf("a failure was recorded for a leg that is only not settled yet: %v", f.rec.failures)
	}
	if out := f.logs.Joined(); out != "" {
		t.Fatalf("the upgrader logged for a leg that is only not settled yet:\n%s", out)
	}
	if got, want := f.nextAt(t), f.clock.Now().Add(2*time.Minute); !got.Equal(want) {
		t.Fatalf("next ask %v, want the pending retry %v", got, want)
	}
	// not asked before the schedule, asked again after it, never taken for complete
	f.clock.Advance(time.Minute)
	if rep := f.u.RunOnce(ctx); rep.NotDue != 1 || rep.Attempts != 0 {
		t.Fatalf("asked again before its schedule: %+v", rep)
	}
	f.clock.Advance(2 * time.Minute)
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Complete != 0 {
		t.Fatalf("not asked again after its schedule: %+v", rep)
	}
}

// A bundle that was read and holds no execution proof is read once: later passes do not fetch it again, however much time passes,
// and a NEWER bundle of the same proof (another bundle id) is examined at once. The legs held back are a gauge, not an absence.
func TestUpgraderReadsABundleWithoutAnExecutionProofOnceAndExaminesANewerOne(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	g := &gapRec{recSink: f.rec}
	f.u.cfg.Recorder = g
	src := newSettlementSource(f.src, errNoComponent)
	f.u.src = src
	f.src.legs[0].BundleID = "bundle-1"

	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Attempts != 1 || src.total() != 1 {
		t.Fatalf("first pass: %+v calls %d", rep, src.total())
	}
	if g.quietOn(ChainBaseSepolia) != 1 {
		t.Fatalf("the quiet leg is not in the gauge: %v", g.quiet)
	}
	for i := 0; i < 3; i++ {
		f.clock.Advance(3 * time.Hour)
		rep := f.u.RunOnce(ctx)
		if rep.NoSettlement != 1 || rep.Attempts != 0 || rep.Unusable != 0 || src.total() != 1 {
			t.Fatalf("pass %d read the examined bundle again: %+v calls %d", i+2, rep, src.total())
		}
		if g.quietOn(ChainBaseSepolia) != 1 {
			t.Fatalf("pass %d: the quiet leg dropped out of the gauge: %v", i+2, g.quiet)
		}
	}
	if len(f.rec.failures) != 0 || f.logs.Joined() != "" {
		t.Fatalf("quiet is not quiet: %v\n%s", f.rec.failures, f.logs.Joined())
	}

	// a newer bundle for the same proof is examined at once (and, still empty, remembered against its own id)
	f.src.legs[0].BundleID = "bundle-2"
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Attempts != 1 || src.calls["bundle-2"] != 1 || src.total() != 2 {
		t.Fatalf("the newer bundle was not examined: %+v calls %v", rep, src.calls)
	}
	f.clock.Advance(time.Hour)
	if rep := f.u.RunOnce(ctx); rep.Attempts != 0 || src.total() != 2 {
		t.Fatalf("the newer bundle was read again: %+v calls %v", rep, src.calls)
	}

	// and a bundle that now holds the execution proof upgrades the leg and takes it out of the quiet set
	src.err = nil
	f.src.legs[0].BundleID = "bundle-3"
	if rep := f.u.RunOnce(ctx); rep.Appended != 2 || rep.NoSettlement != 0 {
		t.Fatalf("a bundle with the execution proof was not upgraded: %+v\n%s", rep, f.logs.Joined())
	}
	if g.quietOn(ChainBaseSepolia) != 0 {
		t.Fatalf("an upgraded leg is still counted as quiet: %v", g.quiet)
	}
	f.u.mu.Lock()
	remembered := f.u.noComponent.has(legID, "bundle-2")
	f.u.mu.Unlock()
	if remembered {
		t.Fatal("the memo still holds the old bundle of an upgraded leg")
	}
}

// The memory of examined bundles is bounded: at its cap the oldest remembered proof is forgotten (and its bundle is read once more,
// which costs a read and never a leg). A newer bundle of a remembered proof replaces its entry and does not grow the memo.
func TestBundleMemoIsBoundedAndForgetsTheOldestFirst(t *testing.T) {
	if noComponentMemoCap != 16384 {
		t.Fatalf("the cap documented in the report is 16384, the code has %d", noComponentMemoCap)
	}
	m := newBundleMemo(3)
	m.put("p1", "b1")
	m.put("p2", "b2")
	m.put("p3", "b3")
	m.put("p2", "b2b") // a newer bundle of p2: replaces its entry
	if m.len() != 3 || m.has("p2", "b2") || !m.has("p2", "b2b") {
		t.Fatalf("replacing an entry: len %d", m.len())
	}
	m.put("p4", "b4") // full: the oldest (p1) goes
	if m.len() != 3 || m.has("p1", "b1") || !m.has("p2", "b2b") || !m.has("p3", "b3") || !m.has("p4", "b4") {
		t.Fatalf("the oldest was not evicted: len %d", m.len())
	}
	m.put("p5", "b5") // next oldest (p2)
	if m.len() != 3 || m.has("p2", "b2b") || !m.has("p3", "b3") {
		t.Fatalf("eviction order: len %d", m.len())
	}
	for i := 0; i < 100; i++ {
		m.put(strings.Repeat("x", i+1), "b")
		if m.len() > 3 {
			t.Fatalf("the memo grew past its cap: %d", m.len())
		}
	}
	m.forget("p3")
	if m.has("p3", "b3") {
		t.Fatal("forget did not forget")
	}
	if m.has("nobody", "") || newBundleMemo(1).has("p", "") {
		t.Fatal("an empty bundle id matched")
	}
}

// Evidence served before the proof row recorded its settlement is used, and counted: in the pass report, the gauge and a log line
// that appears when the count changes, not on every pass.
func TestUpgraderCountsLegsServedBeforeTheirSettlementWasRecorded(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	g := &gapRec{recSink: f.rec}
	f.u.cfg.Recorder = g
	st := f.src.settlements[legID]
	st.Unrecorded = true
	f.src.settlements[legID] = st

	rep := f.u.RunOnce(ctx)
	if rep.Unrecorded != 1 || rep.Appended != 2 || rep.Unusable != 0 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	g.gmu.Lock()
	got := g.unrecorded
	g.gmu.Unlock()
	if got != 1 {
		t.Fatalf("the gauge of unrecorded settlements is %d", got)
	}
	f.u.announceGaps(rep)
	f.u.announceGaps(rep)
	logs := f.logs.Joined()
	if strings.Count(logs, "settlement_block_number") != 1 || !strings.Contains(logs, "1 legs had settlement evidence served") {
		t.Fatalf("the unrecorded count must be logged once while it does not change:\n%s", logs)
	}
	f.u.announceGaps(PassReport{NoSettlement: 3})
	if !strings.Contains(f.logs.Joined(), "3 legs have no execution proof in their newest bundle") {
		t.Fatalf("a change of the quiet count is not logged:\n%s", f.logs.Joined())
	}
}

// Only the named unavailable state is quiet: a plain source error and a named invalid state are still counted, recorded and logged.
func TestUpgraderIsLoudForEveryOtherSettlementError(t *testing.T) {
	ctx := context.Background()
	for name, err := range map[string]error{
		"a plain error":         errors.New("db down"),
		"a named invalid state": NewState(CodeIncludedInvalid, "cause", "bundle is not gzip"),
	} {
		f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
		f.src.legs[0].BundleID = "bundle-1"
		src := newSettlementSource(f.src, err)
		f.u.src = src
		rep := f.u.RunOnce(ctx)
		if rep.Unusable != 1 || rep.NoSettlement != 0 {
			t.Fatalf("%s: %+v", name, rep)
		}
		if f.logs.Joined() == "" {
			t.Fatalf("%s: nothing was logged", name)
		}
		if got, want := f.nextAt(t), f.clock.Now().Add(time.Hour); !got.Equal(want) {
			t.Fatalf("%s: next ask %v, want %v", name, got, want)
		}
		// and it is not remembered as an examined empty bundle: after its retry it is read again
		f.clock.Advance(2 * time.Hour)
		if rep := f.u.RunOnce(ctx); rep.Attempts != 1 || src.total() != 2 {
			t.Fatalf("%s: the failing bundle was not read again: %+v calls %d", name, rep, src.total())
		}
	}
}

// The unrecorded count follows the legs, not the attempts: a leg waiting for a later level is skipped between attempts (60 s
// passes, a 2 m pending retry), yet it stays counted in every pass, the gauge is constant, and the line is logged once. When the
// proof row records its settlement the count goes to 0 (one more line), and a leg that is no longer listed is forgotten.
func TestUpgraderUnrecordedCountIsPerLegNotPerAttempt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, pendingProver(func(Level) time.Time { return time.Time{} }), UpgraderConfig{}, nil)
	g := &gapRec{recSink: f.rec}
	f.u.cfg.Recorder = g
	st := f.src.settlements[legID]
	st.Unrecorded = true
	f.src.settlements[legID] = st

	attempts := 0
	for i := 0; i < 8; i++ {
		rep := f.u.RunOnce(ctx)
		attempts += rep.Attempts
		if rep.Unrecorded != 1 {
			t.Fatalf("pass %d: Unrecorded %d, want 1 (attempts %d, not due %d)", i, rep.Unrecorded, rep.Attempts, rep.NotDue)
		}
		f.u.announceGaps(rep)
		f.clock.Advance(time.Minute)
	}
	if attempts >= 8 || attempts < 2 {
		t.Fatalf("the probe must skip the leg between attempts: %d attempts in 8 passes", attempts)
	}
	g.gmu.Lock()
	series := append([]int(nil), g.unrecordedSeries...)
	g.gmu.Unlock()
	for i, v := range series {
		if v != 1 {
			t.Fatalf("the gauge flapped: %v (index %d)", series, i)
		}
	}
	if n := strings.Count(f.logs.Joined(), "legs had settlement evidence served"); n != 1 {
		t.Fatalf("the unrecorded line was logged %d times over 8 passes:\n%s", n, f.logs.Joined())
	}

	// the proof row records its settlement: the next serve is recorded, the count goes to 0 and the change is logged once
	st.Unrecorded = false
	f.src.settlements[legID] = st
	f.clock.Advance(10 * time.Minute)
	rep := f.u.RunOnce(ctx)
	f.u.announceGaps(rep)
	if rep.Unrecorded != 0 || rep.Attempts != 1 || strings.Count(f.logs.Joined(), "legs had settlement evidence served") != 2 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}

	// a leg no longer listed (finalized elsewhere, or gone) does not hold the gauge up
	st.Unrecorded = true
	f.src.settlements[legID] = st
	f.clock.Advance(10 * time.Minute)
	if rep := f.u.RunOnce(ctx); rep.Unrecorded != 1 {
		t.Fatalf("%+v", rep)
	}
	f.src.legs = nil
	if rep := f.u.RunOnce(ctx); rep.Unrecorded != 0 {
		t.Fatalf("an unlisted leg still counts as unrecorded: %+v", rep)
	}
}

// A leg whose proof row names no usable chain (chain 0) is not silently counted as having no prover: its bundle is read. Without
// an execution proof it is the quiet state (read once); with one, the source's named state is loud.
func TestUpgraderReadsALegOfAnUnnamedChainInsteadOfCountingNoProver(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.src.legs = []LegRef{{ProofID: legID, Chain: 0, BundleID: "bundle-1"}}
	src := newSettlementSource(f.src, errNoComponent)
	f.u.src = src

	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.NoProver != 0 || rep.Unusable != 0 || src.total() != 1 {
		t.Fatalf("a chainless leg without a component 5: %+v calls %d", rep, src.total())
	}
	f.clock.Advance(3 * time.Hour)
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Attempts != 0 || src.total() != 1 {
		t.Fatalf("the examined chainless bundle was read again: %+v calls %d", rep, src.total())
	}

	// the source names a bundle that has an execution proof but a proof row without a chain
	src.err = NewState(CodeIncludedInvalid, "proof_id", legID, "cause", "the proof's summary names no usable chain_id, but its bundle's execution proof settled on chain 84532")
	f.src.legs[0].BundleID = "bundle-2"
	rep := f.u.RunOnce(ctx)
	if rep.Unusable != 1 || rep.NoSettlement != 0 || rep.NoProver != 0 || f.rec.failures[CodeIncludedInvalid] != 1 || !strings.Contains(f.logs.Joined(), "names no usable chain") {
		t.Fatalf("%+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}

	// a source that serves a settlement for a leg that names no chain is refused as well: nothing is upgraded on chain 0
	src.err = nil
	f.src.legs[0].BundleID = "bundle-3"
	f.clock.Advance(3 * time.Hour)
	if rep := f.u.RunOnce(ctx); rep.Unusable != 1 || rep.Appended != 0 {
		t.Fatalf("%+v", rep)
	}
}

// Legs of a chain with no registered prover are counted per chain (a gauge that resets when they are gone).
func TestUpgraderReportsNoProverLegsPerChain(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	g := &gapRec{recSink: f.rec}
	f.u.cfg.Recorder = g
	f.src.legs = []LegRef{{ProofID: "00000000-0000-0000-0000-000000000001", Chain: 99999}, {ProofID: "00000000-0000-0000-0000-000000000002", Chain: 99999}}
	if rep := f.u.RunOnce(ctx); rep.NoProver != 2 {
		t.Fatalf("%+v", rep)
	}
	g.gmu.Lock()
	got := g.noProver[99999]
	g.gmu.Unlock()
	if got != 2 {
		t.Fatalf("the no-prover gauge of chain 99999 is %d, want 2", got)
	}
	f.src.legs = f.src.legs[:1]
	f.u.RunOnce(ctx)
	g.gmu.Lock()
	got = g.noProver[99999]
	g.gmu.Unlock()
	if got != 1 {
		t.Fatalf("the gauge did not follow the legs: %d", got)
	}
	f.src.legs = nil
	f.u.RunOnce(ctx)
	g.gmu.Lock()
	got = g.noProver[99999]
	g.gmu.Unlock()
	if got != 0 {
		t.Fatalf("the gauge of a chain with no legs left was not reset: %d", got)
	}
}

// A bundle whose component 5 has no block header (the legacy bundles) is quiet like any other unavailable state: counted, not logged
// per leg. Since RB12-LEGACY-191 it is NOT remembered against its bundle id (the header is reconstructed in the background and
// appears in the capture store without the bundle changing): it is read again once HeaderRetry has passed and not before, however
// many passes run (the exact schedule is in upgrader_legacyheader_test.go).
func TestUpgraderStaysQuietForALegacyBundleWithoutABlockHeader(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.src.legs[0].BundleID = "legacy-1"
	src := newSettlementSource(f.src, IncludedUnavailable(IncludedNoBlockHeader, "proof_id", legID))
	f.u.src = src
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Unusable != 0 || rep.Failed != 0 || len(f.rec.failures) != 0 || f.logs.Joined() != "" {
		t.Fatalf("%+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}
	if rep := f.u.RunOnce(ctx); rep.NotDue != 1 || rep.Attempts != 0 || src.total() != 1 {
		t.Fatalf("read again in the same instant: %+v calls %d", rep, src.total())
	}
	f.clock.Advance(3 * time.Hour)
	if rep := f.u.RunOnce(ctx); rep.NoSettlement != 1 || rep.Attempts != 1 || rep.Unusable != 0 || src.total() != 2 || f.logs.Joined() != "" {
		t.Fatalf("%+v calls %d %s", rep, src.total(), f.logs.Joined())
	}
	if rep := f.u.RunOnce(ctx); rep.NotDue != 1 || rep.Attempts != 0 || src.total() != 2 {
		t.Fatalf("read on every pass: %+v calls %d", rep, src.total())
	}
}

// A proof forgotten and remembered again leaves its first ring slot behind; when that slot comes round it must not evict the live
// entry (an early eviction would read a bundle again for nothing).
func TestBundleMemoStaleSlotNeverEvictsALiveEntry(t *testing.T) {
	m := newBundleMemo(4)
	m.put("p1", "b1")
	m.put("p2", "b2")
	m.put("p3", "b3")
	m.forget("p1")
	m.put("p1", "b1b") // ring: p1(stale) p2 p3 p1
	m.put("p4", "b4")  // the ring is full at 4 slots: the stale p1 slot comes round and evicts nothing
	m.put("p5", "b5")  // the oldest live entry (p2) goes
	if !m.has("p1", "b1b") {
		t.Fatal("a stale ring slot evicted a live entry")
	}
	if m.len() > 4 {
		t.Fatalf("the memo grew past its cap: %d", m.len())
	}
	if !m.has("p5", "b5") || !m.has("p4", "b4") {
		t.Fatal("the newest entries are missing")
	}
	// bounded under churn of forgotten and remembered proofs
	for i := 0; i < 1000; i++ {
		id := strings.Repeat("q", i%50+1)
		m.put(id, "b")
		if i%3 == 0 {
			m.forget(id)
		}
		if m.len() > 4 {
			t.Fatalf("the memo grew past its cap under churn: %d", m.len())
		}
	}
}
