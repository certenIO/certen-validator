// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB11-GATE-A, upgrader: the schedule, the pass summary, the paging and every named failure of upgradeLeg, each asserted through
// the pass report, the recorder, the log and the next-attempt time, which are what an operator sees.

type legsRec struct {
	recSink
	mu2  sync.Mutex
	legs map[string]int
}

func (r *legsRec) LegsAt(c uint64, l Level, n int) {
	r.mu2.Lock()
	if r.legs == nil {
		r.legs = map[string]int{}
	}
	r.legs[l.String()+"@"+string(rune('0'+c%10))] = n
	r.mu2.Unlock()
}

type errStore struct {
	*memStore
	chainErr, appendErr error
}

func (s *errStore) Chain(ctx context.Context, id string) ([]Addendum, error) {
	if s.chainErr != nil {
		return nil, s.chainErr
	}
	return s.memStore.Chain(ctx, id)
}

func (s *errStore) Append(ctx context.Context, a Addendum) error {
	if s.appendErr != nil {
		return s.appendErr
	}
	return s.memStore.Append(ctx, a)
}

type errSource struct {
	*memSource
	err    error
	cancel context.CancelFunc
}

func (s *errSource) SettledLegs(context.Context, string, int) ([]LegRef, error) {
	if s.cancel != nil {
		s.cancel()
	}
	return nil, s.err
}

type panicSource struct{ *memSource }

func (panicSource) LegSettlement(context.Context, LegRef) (Settlement, error) {
	panic("source blew up")
}

type ceilProver struct {
	*finalProver
	ceil Level
}

func (p *ceilProver) Ceiling() Level { return p.ceil }

func pendingFor(target Level, eta time.Time) *PendingState {
	return &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelNone, NextLevel: target, Reason: "waiting", ETA: eta}
}

func pendingProver(eta func(Level) time.Time) *finalProver {
	return &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, _ *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		return nil, pendingFor(target, eta(target)), nil
	}}
}

func (f *upgraderFixture) nextAt(t *testing.T) time.Time {
	t.Helper()
	f.u.mu.Lock()
	defer f.u.mu.Unlock()
	at, ok := f.u.next[legID]
	if !ok {
		t.Fatal("the leg has no scheduled next attempt")
	}
	return at
}

func TestUpgraderConfigDefaultsAreTheDocumentedOnesAndSmallPositiveValuesAreKept(t *testing.T) {
	d := UpgraderConfig{}.withDefaults()
	if d.Concurrency != 4 || d.PageSize != 200 || d.Interval != 60*time.Second || d.BuildTimeout != 5*time.Minute ||
		d.PendingRetry != 2*time.Minute || d.FailureRetry != 5*time.Minute || d.BrokenRetry != time.Hour {
		t.Fatalf("%+v", d)
	}
	k := UpgraderConfig{Concurrency: 1, PageSize: 1, Interval: 1, BuildTimeout: 1, PendingRetry: 1, FailureRetry: 1, BrokenRetry: 1}.withDefaults()
	if k.Concurrency != 1 || k.PageSize != 1 || k.Interval != 1 || k.BuildTimeout != 1 || k.PendingRetry != 1 || k.FailureRetry != 1 || k.BrokenRetry != 1 {
		t.Fatalf("a configured value of 1 must be kept: %+v", k)
	}
	neg := UpgraderConfig{Concurrency: -3, PageSize: -3, Interval: -1}.withDefaults()
	if neg.Concurrency != 4 || neg.PageSize != 200 || neg.Interval != 60*time.Second {
		t.Fatalf("non-positive values take the defaults: %+v", neg)
	}
	if d.Now == nil || d.Logf == nil || d.Recorder == nil || d.Jitter == nil {
		t.Fatal("defaults for the hooks")
	}
	// the default jitter adds between 0 and 20 percent, never subtracts, and leaves a non-positive wait alone
	const base = 1000 * time.Second
	spread := false
	for i := 0; i < 400; i++ {
		j := d.Jitter(base)
		if j < base || j > base+base/5 {
			t.Fatalf("jitter %v of %v", j, base)
		}
		if j > base {
			spread = true
		}
	}
	if !spread {
		t.Fatal("the default jitter never added anything")
	}
	if d.Jitter(1) != 1 {
		t.Fatalf("jitter of 1ns: %v", d.Jitter(1))
	}
	if d.Jitter(0) != 0 || d.Jitter(-5) != -5 {
		t.Fatalf("non-positive waits are returned as they are: %v %v", d.Jitter(0), d.Jitter(-5))
	}
}

func TestNewUpgraderNeedsASourceAStoreAndARegistry(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	for name, args := range map[string][3]any{
		"no source":   {nil, f.store, f.reg},
		"no store":    {f.src, nil, f.reg},
		"no registry": {f.src, f.store, nil},
	} {
		var src LegSource
		var st AddendumStore
		var reg *Registry
		if args[0] != nil {
			src = args[0].(LegSource)
		}
		if args[1] != nil {
			st = args[1].(AddendumStore)
		}
		if args[2] != nil {
			reg = args[2].(*Registry)
		}
		if u, err := NewUpgrader(src, st, reg, nil, UpgraderConfig{}); err == nil || u != nil {
			t.Errorf("%s: an upgrader was built", name)
		}
		if u, err := Launch(context.Background(), true, src, st, reg, nil, UpgraderConfig{}); err == nil || u != nil {
			t.Errorf("%s: Launch started an upgrader", name)
		}
	}
}

func upgraderEnabledGauge(t *testing.T) float64 {
	t.Helper()
	metrics.RegisterMetrics()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "certen_finality_upgrader_enabled" {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("certen_finality_upgrader_enabled is not registered")
	return -1
}

func TestLaunchSetsTheEnabledGaugeToTheStateItAnnounced(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	u, err := Launch(ctx, true, f.src, f.store, f.reg, nil, UpgraderConfig{Interval: time.Hour, Logf: f.logs.Logf, Recorder: f.rec})
	if err != nil || u == nil {
		t.Fatal(err)
	}
	if v := upgraderEnabledGauge(t); v != 1 {
		t.Fatalf("enabled gauge %v after an enabled launch", v)
	}
	cancel()
	if u, err := Launch(context.Background(), false, f.src, f.store, f.reg, nil, UpgraderConfig{Logf: f.logs.Logf}); err != nil || u != nil {
		t.Fatalf("%v %v", u, err)
	}
	if v := upgraderEnabledGauge(t); v != 0 {
		t.Fatalf("enabled gauge %v after a disabled launch", v)
	}
}

// runOnePassAndStop runs the worker until its first pass has completed and its summary line is written, then stops it.
func runOnePassAndStop(t *testing.T, f *upgraderFixture) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.u.Run(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for {
		f.rec.mu.Lock()
		n := f.rec.passCount
		f.rec.mu.Unlock()
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("no pass completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestRunLogsThePassSummaryExactlyWhenSomethingWasAppendedFailedBrokenOrUnusable(t *testing.T) {
	const line = "[FINALITY] pass: "
	build1 := func(t *testing.T) *finalProver {
		return &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
			if target == LevelL1Posted {
				return built(t, s, target, "x"), nil, nil
			}
			return nil, pendingFor(target, time.Time{}), nil
		}}
	}
	cases := []struct {
		name string
		prep func(t *testing.T) *upgraderFixture
		want []string // fragments of the summary line, none = no summary line at all
	}{
		{"one appended", func(t *testing.T) *upgraderFixture { return newFixture(t, build1(t), UpgraderConfig{}, nil) }, []string{"appended=1", "failed=0", "pending=1"}},
		{"two appended", func(t *testing.T) *upgraderFixture { return newFixture(t, allLevels(t), UpgraderConfig{}, nil) }, []string{"appended=2"}},
		{"one failed", func(t *testing.T) *upgraderFixture {
			return newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
				return nil, nil, errors.New("provider down")
			}}, UpgraderConfig{}, nil)
		}, []string{"failed=1", "appended=0"}},
		{"one broken", func(t *testing.T) *upgraderFixture {
			f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
			chain := buildChain(t, f.src.settlements[legID].Block(), LevelL1Posted)
			chain[0].OwnHash[0] ^= 1
			f.store.chains[legID] = chain
			return f
		}, []string{"broken=1", "appended=0"}},
		{"one unusable", func(t *testing.T) *upgraderFixture {
			f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
			delete(f.src.settlements, legID)
			return f
		}, []string{"unusable=1", "appended=0"}},
		{"only pending is silent", func(t *testing.T) *upgraderFixture {
			return newFixture(t, pendingProver(func(Level) time.Time { return time.Time{} }), UpgraderConfig{}, nil)
		}, nil},
		{"nothing listed is silent", func(t *testing.T) *upgraderFixture {
			f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
			f.src.legs = nil
			return f
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := c.prep(t)
			runOnePassAndStop(t, f)
			logs := f.logs.Joined()
			if c.want == nil {
				if strings_count(logs, line) != 0 {
					t.Fatalf("a summary line for a quiet pass:\n%s", logs)
				}
				return
			}
			if strings_count(logs, line) != 1 {
				t.Fatalf("want one summary line:\n%s", logs)
			}
			for _, w := range c.want {
				if strings_count(logs, w) == 0 {
					t.Errorf("summary lacks %q:\n%s", w, logs)
				}
			}
		})
	}
}

func TestRunReportsASourceFailureUnlessItWasCausedByCancellation(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.u.src = &errSource{memSource: f.src, err: errors.New("db down")}
	runOnePassAndStop(t, f)
	if strings_count(f.logs.Joined(), "pass could not list settled legs") != 1 {
		t.Fatalf("a source failure is announced once:\n%s", f.logs.Joined())
	}
	g := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	g.u.src = &errSource{memSource: g.src, err: context.Canceled, cancel: cancel}
	done := make(chan struct{})
	go func() { g.u.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if strings_count(g.logs.Joined(), "pass could not list settled legs") != 0 {
		t.Fatalf("a failure caused by cancellation was announced:\n%s", g.logs.Joined())
	}
}

func TestRunOncePagesBySizeAndStopsOnAnEmptyOrShortPageAndReportsSourceErrors(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{PageSize: 1}, nil)
	rep := f.u.RunOnce(context.Background())
	if rep.Listed != 1 || rep.Attempts != 1 || f.src.listed.Load() != 2 {
		t.Fatalf("a full page is followed by one more call that finds the end: %+v listed calls %d", rep, f.src.listed.Load())
	}
	g := newFixture(t, allLevels(t), UpgraderConfig{PageSize: 2}, nil)
	rep = g.u.RunOnce(context.Background())
	if rep.Listed != 1 || g.src.listed.Load() != 1 {
		t.Fatalf("a short page ends the listing: %+v calls %d", rep, g.src.listed.Load())
	}
	h := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	h.u.src = &errSource{memSource: h.src, err: errors.New("db down")}
	if rep := h.u.RunOnce(context.Background()); rep.SourceErr == nil || rep.Listed != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestUpgradeLegNamesEachWayAPassCanFailAndSchedulesTheRetry(t *testing.T) {
	ctx := context.Background()
	// a panic anywhere in the leg is a failed leg with the panic code, scheduled at the failure retry
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.u.src = panicSource{f.src}
	if rep := f.u.RunOnce(ctx); rep.Failed != 1 || f.rec.failures[CodePanic] != 1 {
		t.Fatalf("%+v %v", rep, f.rec.failures)
	}
	if got, want := f.nextAt(t), f.clock.Now().Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("next %v want %v", got, want)
	}
	// a leg of a chain with a prover but no profile
	g := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	g.reg.RegisterProver(&finalProver{chain: 999, mode: allLevels(t).mode})
	g.src.legs = []LegRef{{ProofID: legID, Chain: 999}}
	if rep := g.u.RunOnce(ctx); rep.Failed != 1 || g.rec.failures[CodeChainUnsupported] != 1 {
		t.Fatalf("%+v %v", rep, g.rec.failures)
	}
	if got, want := g.nextAt(t), g.clock.Now().Add(time.Hour); !got.Equal(want) {
		t.Fatalf("an unprofiled chain retries at the broken retry: %v want %v", got, want)
	}
	// a leg whose proof id is not a uuid
	h := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	h.src.legs = []LegRef{{ProofID: "not-a-uuid", Chain: ChainBaseSepolia}}
	if rep := h.u.RunOnce(ctx); rep.Failed != 1 || h.rec.failures[CodeAddendumMalformed] != 1 {
		t.Fatalf("%+v %v", rep, h.rec.failures)
	}
	// the addendum store cannot be read
	s := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	s.u.store = &errStore{memStore: s.store, chainErr: errors.New("db down")}
	if rep := s.u.RunOnce(ctx); rep.Failed != 1 || s.rec.failures["store_read"] != 1 || rep.Appended != 0 {
		t.Fatalf("%+v %v", rep, s.rec.failures)
	}
	if got, want := s.nextAt(t), s.clock.Now().Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("%v want %v", got, want)
	}
}

func TestUpgradeLegUnusableL6EvidenceIsRetriedLaterNotMarkedComplete(t *testing.T) {
	ctx := context.Background()
	for name, prep := range map[string]func(f *upgraderFixture){
		"source cannot load": func(f *upgraderFixture) { delete(f.src.settlements, legID) },
		"no L6 block": func(f *upgraderFixture) {
			st := f.src.settlements[legID]
			st.Included = nil
			f.src.settlements[legID] = st
		},
	} {
		f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
		prep(f)
		if rep := f.u.RunOnce(ctx); rep.Unusable != 1 || rep.Appended != 0 {
			t.Fatalf("%s: %+v", name, rep)
		}
		if got, want := f.nextAt(t), f.clock.Now().Add(time.Hour); !got.Equal(want) {
			t.Fatalf("%s: %v want %v", name, got, want)
		}
		f.clock.Advance(2 * time.Hour)
		if rep := f.u.RunOnce(ctx); rep.Unusable != 1 || rep.Complete != 0 {
			t.Fatalf("%s: the leg must be attempted again after the retry, not skipped as complete: %+v", name, rep)
		}
	}
}

func TestUpgradeLegRefusesAStoredChainOfAnotherChainAndCompletesAFullyStoredOne(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	block := f.src.settlements[legID].Block()
	arb := BlockRef{Chain: ChainArbitrumSepolia, Number: block.Number, Hash: block.Hash}
	const kArb = "arb-sepolia/finalized/v1"
	other, err := NewAddendum(LegBindingOf(block), testProofID, nil, ChainArbitrumSepolia, LevelFinalized, kArb, containerFor(t, kArb, arb, LevelFinalized, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChain(LegBindingOf(block), []Addendum{other}); err != nil {
		t.Fatalf("the seeded chain must verify on its own so that only the chain mismatch refuses it: %v", err)
	}
	f.store.chains[legID] = []Addendum{other}
	if rep := f.u.RunOnce(ctx); rep.Broken != 1 || rep.Appended != 0 || f.rec.broken != 1 {
		t.Fatalf("%+v", rep)
	}
	if st := f.logs.Joined(); strings_count(st, "stored=") == 0 && strings_count(st, "does not verify") == 0 {
		t.Fatalf("the refusal is logged:\n%s", st)
	}

	g := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	g.store.chains[legID] = buildChain(t, g.src.settlements[legID].Block(), LevelL1Posted, LevelFinalized)
	rep := g.u.RunOnce(ctx)
	if rep.Attempts != 1 || rep.Appended != 0 || rep.Failed != 0 || g.u.reg.Provers(ChainBaseSepolia)[0].(*finalProver).calls.Load() != 0 {
		t.Fatalf("a chain that already holds every stored level builds nothing: %+v", rep)
	}
	if rep := g.u.RunOnce(ctx); rep.Complete != 1 || rep.Attempts != 0 {
		t.Fatalf("and is skipped as complete from then on: %+v", rep)
	}
	g.u.mu.Lock()
	_, scheduled := g.u.next[legID]
	g.u.mu.Unlock()
	if scheduled {
		t.Fatal("a complete leg has no next attempt")
	}
}

func TestUpgradeLegHonoursProverCeilingsNotApplicableAndCancellation(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var asked []Level
	mk := func(ceil Level) *ceilProver {
		return &ceilProver{ceil: ceil, finalProver: &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
			mu.Lock()
			asked = append(asked, target)
			mu.Unlock()
			return built(t, s, target, "x"), nil, nil
		}}}
	}
	// a prover whose ceiling is l1_posted is asked for l1_posted (equal is not below) and never for finalized
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	if err := f.reg.RegisterProver(mk(LevelL1Posted)); err != nil {
		t.Fatal(err)
	}
	if rep := f.u.RunOnce(ctx); rep.Appended != 1 {
		t.Fatalf("%+v", rep)
	}
	if len(asked) != 1 || asked[0] != LevelL1Posted {
		t.Fatalf("asked %v", asked)
	}
	// a prover whose ceiling is finalized is asked for both
	asked = nil
	g := newFixture(t, nil, UpgraderConfig{}, nil)
	if err := g.reg.RegisterProver(mk(LevelFinalized)); err != nil {
		t.Fatal(err)
	}
	if rep := g.u.RunOnce(ctx); rep.Appended != 2 || len(asked) != 2 {
		t.Fatalf("%+v asked %v", rep, asked)
	}
	// level_not_applicable from a prover is not a failure
	n := newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, NotApplicableState(ChainBaseSepolia, LevelL1Posted, ReasonChainIsL1)
	}}, UpgraderConfig{}, nil)
	if rep := n.u.RunOnce(ctx); rep.Failed != 0 || len(n.rec.failures) != 0 {
		t.Fatalf("a not-applicable answer is not a failure: %+v %v", rep, n.rec.failures)
	}
	// a prover that cancels the pass and then errs leaves the schedule and the failure counters alone
	cctx, cancel := context.WithCancel(ctx)
	c := newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		cancel()
		return nil, nil, errors.New("boom")
	}}, UpgraderConfig{}, nil)
	if rep := c.u.RunOnce(cctx); rep.Failed != 0 || len(c.rec.failures) != 0 {
		t.Fatalf("a cancelled pass judged nothing: %+v %v", rep, c.rec.failures)
	}
	c.u.mu.Lock()
	_, scheduled := c.u.next[legID]
	c.u.mu.Unlock()
	if scheduled {
		t.Fatal("a cancelled pass must not schedule the leg")
	}
}

func TestUpgradeLegAppendOutcomesAreNamedAndTheLevelReachedIsReported(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		err      error
		conflict int
		failed   int
		fail     string
	}{
		"conflict":        {NewState(CodeAppendConflict, "seq", 1), 1, 0, ""},
		"named other":     {NewState("some_other_state"), 0, 1, "store_write"},
		"plain store err": {errors.New("disk full"), 0, 1, "store_write"},
	} {
		f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
		f.u.store = &errStore{memStore: f.store, appendErr: c.err}
		rep := f.u.RunOnce(ctx)
		if rep.Conflict != c.conflict || rep.Failed != c.failed || rep.Appended != 0 {
			t.Errorf("%s: %+v", name, rep)
		}
		if c.fail != "" && f.rec.failures[c.fail] == 0 {
			t.Errorf("%s: recorded %v", name, f.rec.failures)
		}
	}
	// the gauges publish the highest level reached, not the first one appended
	g := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	lr := &legsRec{}
	lr.appended, lr.failures = map[string]int{}, map[string]int{}
	g.u.cfg.Recorder = lr
	if rep := g.u.RunOnce(ctx); rep.Appended != 2 {
		t.Fatalf("%+v", rep)
	}
	lr.mu2.Lock()
	defer lr.mu2.Unlock()
	if lr.legs["finalized@"+string(rune('0'+ChainBaseSepolia%10))] != 1 || lr.legs["l1_posted@"+string(rune('0'+ChainBaseSepolia%10))] != 0 {
		t.Fatalf("legs by level: %v", lr.legs)
	}
}

func TestUpgradeLegSchedulesTheEarliestETAAndTheRightRetryForEachOutcome(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	// two provers with different ETAs: the earliest wins whatever the registration order
	for _, order := range [][2]time.Duration{{300 * time.Second, 60 * time.Second}, {60 * time.Second, 300 * time.Second}} {
		f := newFixture(t, nil, UpgraderConfig{}, nil)
		for _, d := range order {
			d := d
			f.reg.RegisterProver(pendingProver(func(Level) time.Time { return now.Add(d) }))
		}
		rep := f.u.RunOnce(ctx)
		if rep.Pending != 1 {
			t.Fatalf("%+v", rep)
		}
		if got, want := f.nextAt(t), now.Add(60*time.Second); !got.Equal(want) {
			t.Fatalf("order %v: next %v want %v", order, got, want)
		}
	}
	// a pending without an ETA retries at PendingRetry; an ETA in the past is clamped to one second
	g := newFixture(t, pendingProver(func(Level) time.Time { return time.Time{} }), UpgraderConfig{}, nil)
	g.u.RunOnce(ctx)
	if got, want := g.nextAt(t), g.clock.Now().Add(2*time.Minute); !got.Equal(want) {
		t.Fatalf("no ETA: %v want %v", got, want)
	}
	h := newFixture(t, pendingProver(func(Level) time.Time { return time.Unix(1, 0) }), UpgraderConfig{}, nil)
	h.u.RunOnce(ctx)
	if got, want := h.nextAt(t), h.clock.Now().Add(time.Second); !got.Equal(want) {
		t.Fatalf("a stale ETA: %v want %v", got, want)
	}
	// a prover that builds nothing and says nothing: not a failure, PendingRetry
	q := newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		return nil, nil, nil
	}}, UpgraderConfig{}, nil)
	if rep := q.u.RunOnce(ctx); rep.Failed != 0 || rep.Pending != 0 || rep.Appended != 0 {
		t.Fatalf("%+v", rep)
	}
	if got, want := q.nextAt(t), q.clock.Now().Add(2*time.Minute); !got.Equal(want) {
		t.Fatalf("silent prover: %v want %v", got, want)
	}
	// evidence the offline kind refuses fails the leg and retries at FailureRetry, with nothing named by the prover
	r := newFixture(t, allLevels(t), UpgraderConfig{}, errors.New("not final"))
	rep := r.u.RunOnce(ctx)
	if rep.Failed != 1 || rep.Appended != 1 {
		t.Fatalf("%+v", rep)
	}
	if got, want := r.nextAt(t), r.clock.Now().Add(5*time.Minute); !got.Equal(want) {
		t.Fatalf("judge refusal: %v want %v", got, want)
	}
	// the pending is not stored while the leg completes; a completed pass leaves no schedule
	s := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	s.u.RunOnce(ctx)
	s.u.mu.Lock()
	_, scheduled := s.u.next[legID]
	s.u.mu.Unlock()
	if scheduled {
		t.Fatal("a leg that reached its top has no next attempt")
	}
}

func TestAProverThatIgnoresItsContextDoesNotLeakItsGoroutineOnceItReturns(t *testing.T) {
	release := make(chan struct{})
	p := &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		<-release
		return nil, nil, nil
	}}
	f := newFixture(t, p, UpgraderConfig{BuildTimeout: 30 * time.Millisecond}, nil)
	before := runtime.NumGoroutine()
	f.u.RunOnce(context.Background())
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		t.Fatalf("%d goroutines after the abandoned prover returned, %d before", n, before)
	}
}
