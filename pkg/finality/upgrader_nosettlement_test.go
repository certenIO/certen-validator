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
	gmu        sync.Mutex
	quiet      map[uint64]int
	unrecorded int
}

func (g *gapRec) LegsWithoutSettlement(c uint64, n int) {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	if g.quiet == nil {
		g.quiet = map[uint64]int{}
	}
	g.quiet[c] = n
}
func (g *gapRec) UnrecordedSettlements(n int) { g.gmu.Lock(); g.unrecorded = n; g.gmu.Unlock() }
func (g *gapRec) quietOn(c uint64) int        { g.gmu.Lock(); defer g.gmu.Unlock(); return g.quiet[c] }

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
