// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// ---- test doubles for the status store and the status recorder ----

type memStatus struct {
	mu   sync.Mutex
	rows map[string]BuilderStatus // proof id + level
	fail error
	hang chan struct{}
}

func newMemStatus() *memStatus { return &memStatus{rows: map[string]BuilderStatus{}} }

func (m *memStatus) UpsertStatus(_ context.Context, s BuilderStatus) error {
	if m.hang != nil {
		<-m.hang // ignores its context entirely
	}
	if m.fail != nil {
		return m.fail
	}
	if _, err := s.Document(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[s.ProofID+"/"+s.TargetLevel.String()] = s
	return nil
}

func (m *memStatus) GetStatus(_ context.Context, id string, target Level) (BuilderStatusView, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.rows[id+"/"+target.String()]
	return BuilderStatusView{Class: s.Class, LevelReached: s.LevelReached, NextLevel: s.NextLevel, ETA: s.ETA, Seq: s.Seq}, ok, nil
}

func (m *memStatus) row(id string, l Level) BuilderStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[id+"/"+l.String()]
}

func (r *recSink) Status(c uint64, l Level, state string) {
	r.mu.Lock()
	r.failures["status:"+state+"@"+l.String()]++
	r.mu.Unlock()
}
func (r *recSink) StatusWriteFailed(c uint64) {
	r.mu.Lock()
	r.failures["status_write_failed"]++
	r.mu.Unlock()
}

// perLevelProver answers each target with its own function and counts the asks per target.
type perLevelProver struct {
	chain uint64
	by    map[Level]func(s *ethproof.Settlement) (*Addendum, *PendingState, error)
	asked map[Level]*atomic.Int64
}

func newPerLevelProver(chain uint64, by map[Level]func(s *ethproof.Settlement) (*Addendum, *PendingState, error)) *perLevelProver {
	p := &perLevelProver{chain: chain, by: by, asked: map[Level]*atomic.Int64{LevelL1Posted: {}, LevelFinalized: {}}}
	return p
}

func (p *perLevelProver) Chain() uint64 { return p.chain }
func (p *perLevelProver) Build(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
	p.asked[target].Add(1)
	return p.by[target](s)
}

func pendingWith(reached, next Level, reason string, eta time.Time) func(*ethproof.Settlement) (*Addendum, *PendingState, error) {
	return func(*ethproof.Settlement) (*Addendum, *PendingState, error) {
		return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: reached, NextLevel: next, Reason: reason, ETA: eta}, nil
	}
}

// ---- V2_SPEC_S7 8.3: the eta rule, per (leg, level) ----

func TestUpgraderDoesNotAskALevelBeforeItsEtaEvenWhenAnotherLevelFallsDue(t *testing.T) {
	var f *upgraderFixture
	finETA := time.Unix(1_800_000_000, 0).Add(5 * 24 * time.Hour) // Base finalized: about five days
	prover := newPerLevelProver(ChainBaseSepolia, map[Level]func(*ethproof.Settlement) (*Addendum, *PendingState, error){
		LevelL1Posted:  pendingWith(LevelIncluded, LevelL1Posted, "awaiting_l1_finality_of_batch", time.Time{}), // no eta: bounded interval
		LevelFinalized: pendingWith(LevelIncluded, LevelFinalized, "within_finality_delay", finETA),
	})
	f = newFixture(t, nil, UpgraderConfig{PendingRetry: 2 * time.Minute}, nil)
	if err := f.reg.RegisterProver(prover); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.u.RunOnce(ctx)
	if prover.asked[LevelL1Posted].Load() != 1 || prover.asked[LevelFinalized].Load() != 1 {
		t.Fatalf("first pass asks each level once: %d %d", prover.asked[LevelL1Posted].Load(), prover.asked[LevelFinalized].Load())
	}
	// l1_posted falls due every 2 minutes; finalized must NOT be asked until its eta, whatever l1_posted does
	for i := 0; i < 50; i++ {
		f.clock.Advance(2*time.Minute + time.Second)
		f.u.RunOnce(ctx)
	}
	if got := prover.asked[LevelFinalized].Load(); got != 1 {
		t.Fatalf("finalized was asked %d times before its eta", got)
	}
	if got := prover.asked[LevelL1Posted].Load(); got != 51 {
		t.Fatalf("l1_posted (no eta) is polled at the bounded interval: %d asks", got)
	}
	f.clock.Advance(5 * 24 * time.Hour)
	f.u.RunOnce(ctx)
	if got := prover.asked[LevelFinalized].Load(); got != 2 {
		t.Fatalf("finalized is asked once its eta has passed: %d", got)
	}
}

func TestUpgraderPollsALevelWithNoEtaAtTheConfiguredBoundedIntervalNeverTighter(t *testing.T) {
	prover := newPerLevelProver(ChainBaseSepolia, map[Level]func(*ethproof.Settlement) (*Addendum, *PendingState, error){
		LevelL1Posted:  pendingWith(LevelIncluded, LevelL1Posted, "awaiting_batch_post", time.Time{}),
		LevelFinalized: pendingWith(LevelIncluded, LevelFinalized, "within_finality_delay", time.Time{}),
	})
	f := newFixture(t, nil, UpgraderConfig{PendingRetry: 30 * time.Second}, nil)
	_ = f.reg.RegisterProver(prover)
	ctx := context.Background()
	f.u.RunOnce(ctx)
	for _, step := range []struct {
		advance time.Duration
		asks    int64
	}{{time.Second, 1}, {28 * time.Second, 1}, {time.Second, 2}, {29 * time.Second, 2}, {time.Second, 3}} {
		f.clock.Advance(step.advance)
		f.u.RunOnce(ctx)
		if got := prover.asked[LevelL1Posted].Load(); got != step.asks {
			t.Fatalf("after +%s the level has been asked %d times, want %d", step.advance, got, step.asks)
		}
	}
	// no configuration makes the worker a tight loop: every polling interval is raised to MinPoll
	cfg := UpgraderConfig{Interval: time.Nanosecond, PendingRetry: time.Millisecond, FailureRetry: 5 * time.Millisecond, BrokenRetry: 1}.withDefaults()
	for name, d := range map[string]time.Duration{"Interval": cfg.Interval, "PendingRetry": cfg.PendingRetry, "FailureRetry": cfg.FailureRetry, "BrokenRetry": cfg.BrokenRetry} {
		if d < MinPoll {
			t.Fatalf("%s = %s is below the floor %s", name, d, MinPoll)
		}
	}
}

// ---- V2_SPEC_S7 2.7: a status row for every pending / unavailable / refused / not applicable state, and for a stored level ----

func TestUpgraderWritesAStatusRowForEveryJudgedState(t *testing.T) {
	eta := time.Unix(1_800_000_000, 0).Add(20 * time.Minute)
	var refuse atomic.Bool
	prover := newPerLevelProver(ChainBaseSepolia, nil)
	prover.by = map[Level]func(*ethproof.Settlement) (*Addendum, *PendingState, error){
		LevelL1Posted: func(s *ethproof.Settlement) (*Addendum, *PendingState, error) {
			return built(t, s, LevelL1Posted, "x"), nil, nil
		},
		LevelFinalized: func(s *ethproof.Settlement) (*Addendum, *PendingState, error) {
			if refuse.Load() {
				return built(t, s, LevelFinalized, "x"), nil, nil
			}
			return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, Reason: "game_unresolved", ETA: eta}, nil
		},
	}
	status := newMemStatus()
	f := newFixture(t, nil, UpgraderConfig{Status: status}, nil)
	_ = f.reg.RegisterProver(prover)
	ctx := context.Background()

	f.u.RunOnce(ctx)
	l1 := status.row(legID, LevelL1Posted)
	if l1.Class != BuilderVerified || l1.Seq != 1 || l1.State != nil || l1.TargetLevel != LevelL1Posted || l1.Chain != ChainBaseSepolia {
		t.Fatalf("a stored level has a verified row: %+v", l1)
	}
	fin := status.row(legID, LevelFinalized)
	if fin.Class != BuilderPending || fin.LevelReached != LevelL1Posted || fin.NextLevel != LevelFinalized || !fin.ETA.Equal(eta) ||
		fin.State == nil || fin.State.Fields["reason"] != "game_unresolved" {
		t.Fatalf("pending carries the level reached, the next level and the eta: %+v", fin)
	}
	doc, err := fin.Document()
	if err != nil {
		t.Fatal(err)
	}
	view, err := ParseBuilderStatusDocument(doc)
	if err != nil || view.Class != BuilderPending || view.LevelReached != LevelL1Posted || view.NextLevel != LevelFinalized || !view.ETA.Equal(eta) {
		t.Fatalf("the stored document reads back: %v %+v", err, view)
	}
	if f.rec.failures["status:finality_pending@finalized"] != 1 || f.rec.failures["status:verified@l1_posted"] != 1 {
		t.Fatalf("status rows are counted per level and state: %v", f.rec.failures)
	}

	// the registered Kind refuses what the prover built: nothing is stored, the row says refused with the Kind's state
	f.fin.err = NewState("game_challenger_wins")
	refuse.Store(true)
	f.clock.Advance(time.Hour)
	f.u.RunOnce(ctx)
	fin = status.row(legID, LevelFinalized)
	if fin.Class != BuilderRefused || fin.State == nil || fin.State.Code != "game_challenger_wins" || fin.LevelReached != LevelL1Posted {
		t.Fatalf("%+v", fin)
	}
	if chain, _ := f.store.Chain(ctx, legID); len(chain) != 1 {
		t.Fatalf("a refused build was stored: %+v", chain)
	}

	// a builder-side unavailability, then a not-applicable level
	prover.by[LevelFinalized] = func(*ethproof.Settlement) (*Addendum, *PendingState, error) {
		return nil, nil, NewState("l1_blob_unavailable", "l1_block", uint64(7))
	}
	f.clock.Advance(time.Hour)
	f.u.RunOnce(ctx)
	if fin = status.row(legID, LevelFinalized); fin.Class != BuilderUnavailable || fin.State.Code != "l1_blob_unavailable" {
		t.Fatalf("%+v", fin)
	}
	prover.by[LevelFinalized] = func(*ethproof.Settlement) (*Addendum, *PendingState, error) {
		return nil, nil, NotApplicableState(ChainBaseSepolia, LevelFinalized, ReasonChainIsL1)
	}
	f.clock.Advance(time.Hour)
	f.u.RunOnce(ctx)
	if fin = status.row(legID, LevelFinalized); fin.Class != BuilderNotApplicable || fin.State.Code != CodeNotApplicable {
		t.Fatalf("%+v", fin)
	}
}

func TestAStatusStoreThatFailsOrHangsNeverFailsOrStallsTheLeg(t *testing.T) {
	status := newMemStatus()
	status.fail = errors.New("connection reset")
	f := newFixture(t, allLevels(t), UpgraderConfig{Status: status}, nil)
	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 2 || rep.Failed != 0 || f.rec.failures["status_write_failed"] != 2 {
		t.Fatalf("%+v %v", rep, f.rec.failures)
	}
	hung := newMemStatus()
	hung.hang = make(chan struct{})
	defer close(hung.hang)
	g := newFixture(t, allLevels(t), UpgraderConfig{Status: hung, StoreTimeout: 200 * time.Millisecond}, nil)
	done := make(chan PassReport, 1)
	go func() { done <- g.u.RunOnce(context.Background()) }()
	select {
	case rep := <-done:
		if rep.Appended != 2 {
			t.Fatalf("%+v", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a status store that ignores its context stalled the pass")
	}
}

// ---- per-chain switch ----

func TestAChainSwitchedOffIsNamedAndLoggedOnceAndItsLegsAreNotTouched(t *testing.T) {
	prover := allLevels(t)
	f := newFixture(t, prover, UpgraderConfig{DisabledChains: map[uint64]bool{ChainBaseSepolia: true}}, nil)
	for i := 0; i < 3; i++ {
		rep := f.u.RunOnce(context.Background())
		if rep.Disabled != 1 || rep.Attempts != 0 || rep.Appended != 0 {
			t.Fatalf("%+v", rep)
		}
	}
	logs := f.logs.Joined()
	if strings.Count(logs, CodeUpgraderDisabled) != 1 || !strings.Contains(logs, "CERTEN_FINALITY_CHAIN_84532_ENABLED") {
		t.Fatalf("the off switch is a named state logged once per chain:\n%s", logs)
	}
	if prover.calls.Load() != 0 {
		t.Fatal("a prover of a switched-off chain was asked")
	}
	if chain, _ := f.store.Chain(context.Background(), legID); len(chain) != 0 {
		t.Fatal("an addendum was appended on a switched-off chain")
	}
}

func TestPerChainSwitchesDefaultOnAndRefuseAValueThatIsNotASwitch(t *testing.T) {
	off, err := DisabledChainsFromEnv([]uint64{ChainSepolia, ChainBaseSepolia})
	if err != nil || len(off) != 0 {
		t.Fatalf("default on: %v %v", off, err)
	}
	t.Setenv(ChainEnv(ChainBaseSepolia), "false")
	if off, err = DisabledChainsFromEnv([]uint64{ChainSepolia, ChainBaseSepolia}); err != nil || !off[ChainBaseSepolia] || off[ChainSepolia] {
		t.Fatalf("%v %v", off, err)
	}
	t.Setenv(ChainEnv(ChainSepolia), "maybe")
	if _, err = DisabledChainsFromEnv([]uint64{ChainSepolia}); err == nil || !strings.Contains(err.Error(), ChainEnv(ChainSepolia)) {
		t.Fatalf("a value that is not a switch must refuse by naming the variable: %v", err)
	}
	if st := ChainSwitchState(ChainAdiri); st.Code != CodeUpgraderDisabled || st.Fields["env"] != "CERTEN_FINALITY_CHAIN_2017_ENABLED" {
		t.Fatalf("%v", st)
	}
}

// ---- it never blocks settlement, attestation or write-back: a hung Kind, store or status store ----

type hungStore struct {
	*memStore
	release chan struct{}
	entered chan struct{} // closed when the first Append is inside the hang (nil: nobody waits for it)
	once    sync.Once
}

func (h *hungStore) Append(ctx context.Context, req AppendRequest) (Addendum, error) {
	if h.entered != nil {
		h.once.Do(func() { close(h.entered) })
	}
	<-h.release // a database that ignores the context entirely
	return h.memStore.Append(ctx, req)
}

func TestAHungKindOrDatabaseDoesNotStallASettlementWorkerOrShutdown(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	// RB12 OPS-A2 item 4: no clock decides this test. The hang lasts the whole test (the timeouts are far beyond it), the settlement worker is
	// started only once the upgrader is inside the hang, and it must finish all its jobs while the upgrader is still stuck: independence is
	// shown by order, not by a stopwatch that a loaded machine can overrun.
	f := newFixture(t, allLevels(t), UpgraderConfig{BuildTimeout: 10 * time.Minute, StoreTimeout: 10 * time.Minute, Interval: MinPoll}, nil)
	entered := make(chan struct{})
	f.u.store = &hungStore{memStore: f.store, release: release, entered: entered}

	// a stand-in for the settlement worker: it shares nothing with the upgrader and must finish its jobs on time
	var settled atomic.Int64
	jobs := make(chan int)
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		for range jobs {
			settled.Add(1)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { f.u.Run(ctx); close(runDone) }()
	select {
	case <-entered:
	case <-time.After(45 * time.Second): // a hang detector only: it never decides a passing run
		t.Fatal("the upgrader never reached its hung store")
	}
	for i := 0; i < 1000; i++ {
		jobs <- i
	}
	close(jobs)
	<-workerDone
	if settled.Load() != 1000 {
		t.Fatalf("the settlement worker settled %d of 1000 jobs", settled.Load())
	}
	if strings.Contains(f.logs.Joined(), CodeBuildTimeout) {
		t.Fatalf("the upgrader gave up its call before the worker was done: the worker was not shown to be independent of a stuck upgrader:\n%s", f.logs.Joined())
	}
	// shutdown: the upgrader is still inside its hung Append, which ignores its context; the cancel makes it abandon the call (a named state)
	cancel()
	select {
	case <-runDone:
	case <-time.After(45 * time.Second): // a hang detector only
		t.Fatal("shutdown is blocked by a database call that ignores its context")
	}
}

// The hung store is abandoned at the deadline as a named state in the log (a cancelled run leaves its schedule alone and logs nothing, so this
// is a pass of its own: it ends when the call is abandoned, whatever the machine's load).
func TestAHungStoreIsAbandonedAtTheDeadlineAsANamedStateInTheLog(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newFixture(t, allLevels(t), UpgraderConfig{BuildTimeout: 200 * time.Millisecond, StoreTimeout: 200 * time.Millisecond, Interval: MinPoll}, nil)
	f.u.store = &hungStore{memStore: f.store, release: release}
	done := make(chan PassReport, 1)
	go func() { done <- f.u.RunOnce(context.Background()) }()
	select {
	case <-done:
	case <-time.After(45 * time.Second): // a hang detector only
		t.Fatal("a store that ignores its context stalled the pass")
	}
	if !strings.Contains(f.logs.Joined(), CodeBuildTimeout) {
		t.Fatalf("the abandoned call is a named state in the log:\n%s", f.logs.Joined())
	}
}

func TestAKindThatHangsInsideAppendIsAbandonedAtTheDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	f := newFixture(t, allLevels(t), UpgraderConfig{BuildTimeout: 200 * time.Millisecond}, nil)
	f.reg.mu.Lock()
	f.reg.kinds[kBaseL1] = hangKind{&fakeKind{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted}, release}
	f.reg.mu.Unlock()
	done := make(chan PassReport, 1)
	go func() { done <- f.u.RunOnce(context.Background()) }()
	select {
	case rep := <-done:
		if rep.Appended != 1 || rep.Failed != 1 {
			t.Fatalf("only finalized is stored; the hung l1_posted Kind is a named failure: %+v\n%s", rep, f.logs.Joined())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a Kind that never returns stalled the pass")
	}
}

type hangKind struct {
	*fakeKind
	release chan struct{}
}

func (h hangKind) Verify(p *Pins, b BlockRef, ev []byte) (Verdict, error) {
	<-h.release
	return h.fakeKind.Verify(p, b, ev)
}

// ---- the capture supervisor: a separate loop, never delayed by an eta, restarted after a named failure ----

type fakeCapturer struct {
	chain   uint64
	name    string
	runs    atomic.Int64
	started chan struct{}
	failN   int64 // fail this many times, then run until cancelled
	panicOn int64
}

func (c *fakeCapturer) Chain() uint64 { return c.chain }
func (c *fakeCapturer) Name() string  { return c.name }
func (c *fakeCapturer) Run(ctx context.Context) error {
	n := c.runs.Add(1)
	if c.panicOn == n {
		panic("provider exploded")
	}
	if n <= c.failN {
		return NewState(CodeBuildTimeout, "chain", c.chain, "after", time.Second, "cause", "head poll")
	}
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil
}

func TestCapturersRunOnTheirOwnAreRestartedAfterFailuresAndSkipASwitchedOffChain(t *testing.T) {
	reg := NewRegistry()
	flaky := &fakeCapturer{chain: ChainBaseSepolia, name: "base-sepolia/inbox", started: make(chan struct{}, 1), failN: 1, panicOn: 2}
	steady := &fakeCapturer{chain: ChainArbitrumSepolia, name: "arb-sepolia/events", started: make(chan struct{}, 1)}
	off := &fakeCapturer{chain: ChainAdiri, name: "adiri/none", started: make(chan struct{}, 1)}
	for _, c := range []*fakeCapturer{flaky, steady, off} {
		if err := reg.RegisterCapturer(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.RegisterCapturer(flaky); err == nil {
		t.Fatal("a second capturer of the same name was accepted")
	}
	if err := reg.RegisterCapturer(&fakeCapturer{chain: 1, name: "x"}); err == nil {
		t.Fatal("a capturer of a chain with no profile was accepted")
	}
	var restarts atomic.Int64
	var causes sync.Map // capturer name -> []string
	var logs logSink
	ctx, cancel := context.WithCancel(context.Background())
	sup := StartCapturers(ctx, reg, SupervisorConfig{
		RestartMin: MinPoll, RestartMax: MinPoll, DisabledChains: map[uint64]bool{ChainAdiri: true}, Logf: logs.Logf,
		Restarted: func(c Capturer, err error, _ time.Duration) {
			restarts.Add(1)
			prev, _ := causes.LoadOrStore(c.Name(), []string{})
			causes.Store(c.Name(), append(prev.([]string), codeOf(err)))
		},
	})
	for _, c := range []*fakeCapturer{steady, flaky} {
		select {
		case <-c.started:
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not run", c.name)
		}
	}
	if restarts.Load() != 2 || flaky.runs.Load() != 3 {
		t.Fatalf("one named failure and one panic are restarted: restarts=%d runs=%d\n%s", restarts.Load(), flaky.runs.Load(), logs.Joined())
	}
	if off.runs.Load() != 0 || !strings.Contains(logs.Joined(), CodeUpgraderDisabled) {
		t.Fatalf("a switched-off chain's capturer must not run and must be named:\n%s", logs.Joined())
	}
	if got, _ := causes.Load("base-sepolia/inbox"); len(got.([]string)) != 2 || got.([]string)[0] != CodeBuildTimeout || got.([]string)[1] != CodePanic {
		t.Fatalf("the supervisor reports the loop's own named failure, then the recovered panic: %v", got)
	}
	cancel()
	waited := make(chan struct{})
	go func() { sup.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop")
	}
	if restarts.Load() != 2 {
		t.Fatalf("a loop that stops because its context ended is not a failure and is not restarted: %d", restarts.Load())
	}
}

// capture is NOT delayed by any eta: while the upgrader's leg waits five days for its eta the capture loop keeps running.
func TestCaptureIsNotDelayedByTheUpgradersEta(t *testing.T) {
	prover := newPerLevelProver(ChainBaseSepolia, map[Level]func(*ethproof.Settlement) (*Addendum, *PendingState, error){
		LevelL1Posted:  pendingWith(LevelIncluded, LevelL1Posted, "awaiting_batch_post", time.Unix(1_800_000_000, 0).Add(5*24*time.Hour)),
		LevelFinalized: pendingWith(LevelIncluded, LevelFinalized, "within_finality_delay", time.Unix(1_800_000_000, 0).Add(5*24*time.Hour)),
	})
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	_ = f.reg.RegisterProver(prover)
	c := &fakeCapturer{chain: ChainBaseSepolia, name: "base-sepolia/inbox", started: make(chan struct{}, 1)}
	_ = f.reg.RegisterCapturer(c)
	f.u.RunOnce(context.Background()) // the leg is now waiting for an eta five days away
	ctx, cancel := context.WithCancel(context.Background())
	sup := StartCapturers(ctx, f.reg, SupervisorConfig{})
	select {
	case <-c.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the capture loop waited for the upgrader's eta")
	}
	cancel()
	sup.Wait()
}
