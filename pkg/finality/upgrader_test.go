// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fakes ----

type memStore struct {
	mu     sync.Mutex
	chains map[string][]Addendum
	failOn int // Append calls to fail with a plain error, counting from 1; 0 = never
	calls  int
}

func newMemStore() *memStore { return &memStore{chains: map[string][]Addendum{}} }

func (m *memStore) Append(_ context.Context, a Addendum) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.failOn != 0 && m.calls == m.failOn {
		return fmt.Errorf("database unavailable")
	}
	c := m.chains[a.ProofID]
	if a.Seq != uint64(len(c))+1 {
		return NewState(CodeAppendConflict, "proof_id", a.ProofID, "seq", a.Seq)
	}
	m.chains[a.ProofID] = append(c, a)
	return nil
}

func (m *memStore) Chain(_ context.Context, id string) ([]Addendum, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Addendum(nil), m.chains[id]...), nil
}

type memSource struct {
	legs        []LegRef
	settlements map[string]Settlement
	listed      atomic.Int64
}

func (s *memSource) SettledLegs(_ context.Context, after string, limit int) ([]LegRef, error) {
	s.listed.Add(1)
	var out []LegRef
	for _, l := range s.legs {
		if l.ProofID > after && len(out) < limit {
			out = append(out, l)
		}
	}
	return out, nil
}

func (s *memSource) LegSettlement(_ context.Context, ref LegRef) (Settlement, error) {
	st, ok := s.settlements[ref.ProofID]
	if !ok {
		return Settlement{}, NewState(CodeIncludedInvalid, "proof_id", ref.ProofID)
	}
	return st, nil
}

// finalProver stands in for a chain package's prover: it returns finalized evidence, a Pending, a lie, a hang or a panic.
type finalProver struct {
	chain uint64
	mode  func(ctx context.Context, s Settlement) (Evidence, Level, error)
	calls atomic.Int64
}

func (p *finalProver) Chain() uint64 { return p.chain }
func (p *finalProver) Build(ctx context.Context, s Settlement) (Evidence, Level, error) {
	p.calls.Add(1)
	return p.mode(ctx, s)
}

func finalEvidence(s Settlement) Evidence { return NewEvidence("t.fin/v1", s, []byte("final")) }

type upgraderFixture struct {
	reg   *Registry
	store *memStore
	src   *memSource
	clock *fakeClock
	logs  *logSink
	rec   *recSink
	u     *Upgrader
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) Logf(f string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
	l.mu.Unlock()
}
func (l *logSink) Joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

type recSink struct {
	mu        sync.Mutex
	appended  map[string]int
	failures  map[string]int
	pending   int
	broken    int
	passCount int
}

func newRec() *recSink { return &recSink{appended: map[string]int{}, failures: map[string]int{}} }
func (r *recSink) Appended(c uint64, l Level) {
	r.mu.Lock()
	r.appended[fmt.Sprint(c, "/", l)]++
	r.mu.Unlock()
}
func (r *recSink) BuildFailed(c uint64, code string) {
	r.mu.Lock()
	r.failures[code]++
	r.mu.Unlock()
}
func (r *recSink) Pending(uint64, Level)         { r.mu.Lock(); r.pending++; r.mu.Unlock() }
func (r *recSink) ChainBroken(uint64)            { r.mu.Lock(); r.broken++; r.mu.Unlock() }
func (r *recSink) LegsAt(uint64, Level, int)     {}
func (r *recSink) Pass(time.Duration, time.Time) { r.mu.Lock(); r.passCount++; r.mu.Unlock() }

// newFixture registers a finalized-evidence verifier for chain 84532 (kind t.fin/v1) and one leg settled on it.
func newFixture(t *testing.T, prover *finalProver, cfg UpgraderConfig) *upgraderFixture {
	t.Helper()
	reg := NewRegistry()
	if err := reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.fin/v1", max: LevelFinalized, level: LevelFinalized}); err != nil {
		t.Fatal(err)
	}
	if prover != nil {
		if err := reg.RegisterProver(prover); err != nil {
			t.Fatal(err)
		}
	}
	settlement := realSettlement(t, "base_sepolia_47368146")
	f := &upgraderFixture{
		reg: reg, store: newMemStore(), clock: &fakeClock{t: time.Unix(1_800_000_000, 0)}, logs: &logSink{}, rec: newRec(),
		src: &memSource{
			legs:        []LegRef{{ProofID: "leg-1", Digest: [32]byte{7}, Chain: 84532}},
			settlements: map[string]Settlement{"leg-1": settlement},
		},
	}
	cfg.Logf, cfg.Now, cfg.Recorder = f.logs.Logf, f.clock.Now, f.rec
	cfg.Jitter = func(d time.Duration) time.Duration { return d }
	u, err := NewUpgrader(f.src, f.store, reg, NewPins(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.u = u
	return f
}

// ---- behaviour ----

func TestUpgraderAppendsEveryBuildableLevelInOrderAndStops(t *testing.T) {
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		return finalEvidence(s), LevelFinalized, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{})
	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 2 || rep.Failed != 0 {
		t.Fatalf("report %+v\n%s", rep, f.logs.Joined())
	}
	chain, _ := f.store.Chain(context.Background(), "leg-1")
	if len(chain) != 2 || chain[0].Level != LevelIncluded || chain[1].Level != LevelFinalized || chain[0].Kind != KindIncluded {
		t.Fatalf("chain %+v", chain)
	}
	if err := VerifyChain([32]byte{7}, chain); err != nil {
		t.Fatal(err)
	}
	// the leg is complete: later passes do not attempt it again
	before := prover.calls.Load()
	rep = f.u.RunOnce(context.Background())
	if rep.Attempts != 0 || rep.Complete != 1 || prover.calls.Load() != before {
		t.Fatalf("second pass %+v", rep)
	}
}

func TestUpgraderReschedulesFromThePendingETAUntilFinalized(t *testing.T) {
	ready := atomic.Bool{}
	eta := func(c *fakeClock) time.Time { return c.Now().Add(20 * time.Minute) }
	var f *upgraderFixture
	prover := &finalProver{chain: 84532}
	prover.mode = func(_ context.Context, s Settlement) (Evidence, Level, error) {
		if ready.Load() {
			return finalEvidence(s), LevelFinalized, nil
		}
		return Evidence{}, LevelNone, &Pending{Chain: 84532, LevelReached: LevelIncluded, NextLevel: LevelFinalized, ETA: eta(f.clock), Reason: "game_unresolved"}
	}
	f = newFixture(t, prover, UpgraderConfig{})

	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 1 || rep.Pending != 1 {
		t.Fatalf("first pass %+v\n%s", rep, f.logs.Joined())
	}
	if chain, _ := f.store.Chain(context.Background(), "leg-1"); len(chain) != 1 || chain[0].Level != LevelIncluded {
		t.Fatalf("chain after pending: %+v", chain)
	}
	// not due before the ETA: the prover is not called again
	calls := prover.calls.Load()
	f.clock.Advance(10 * time.Minute)
	if rep = f.u.RunOnce(context.Background()); rep.Attempts != 0 || rep.NotDue != 1 || prover.calls.Load() != calls {
		t.Fatalf("before ETA %+v", rep)
	}
	// at the ETA the next level is built and appended, and the leg completes
	ready.Store(true)
	f.clock.Advance(11 * time.Minute)
	if rep = f.u.RunOnce(context.Background()); rep.Appended != 1 {
		t.Fatalf("at ETA %+v\n%s", rep, f.logs.Joined())
	}
	if chain, _ := f.store.Chain(context.Background(), "leg-1"); len(chain) != 2 || chain[1].Level != LevelFinalized {
		t.Fatalf("final chain %+v", chain)
	}
	if rep = f.u.RunOnce(context.Background()); rep.Complete != 1 {
		t.Fatalf("not complete: %+v", rep)
	}
}

func TestUpgraderNeverAppendsEvidenceTheOfflineVerifierRefuses(t *testing.T) {
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		// claims finalized with a kind nobody can verify
		return NewEvidence("t.unverifiable/v1", s, nil), LevelFinalized, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{})
	rep := f.u.RunOnce(context.Background())
	chain, _ := f.store.Chain(context.Background(), "leg-1")
	if rep.Appended != 1 || len(chain) != 1 || chain[0].Level != LevelIncluded {
		t.Fatalf("only the included level may be appended: %+v chain %+v", rep, chain)
	}
	if rep.Failed != 1 || f.rec.failures[CodeKindUnknown] != 1 {
		t.Fatalf("the refusal is a counted named state: %+v %v", rep, f.rec.failures)
	}
	if !strings.Contains(f.logs.Joined(), CodeKindUnknown) {
		t.Fatalf("not logged by name:\n%s", f.logs.Joined())
	}
}

func TestUpgraderAppendsTheLevelTheVerifierReportsNotTheOneTheProverClaims(t *testing.T) {
	reg := NewRegistry()
	if err := reg.RegisterVerifier(fakeVerifier{chain: 84532, kind: "t.weak/v1", max: LevelFinalized, level: LevelIncluded}); err != nil {
		t.Fatal(err)
	}
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		return NewEvidence("t.weak/v1", s, nil), LevelFinalized, nil // claims finalized, evidence only proves included
	}}
	_ = reg.RegisterProver(prover)
	settlement := realSettlement(t, "base_sepolia_47368146")
	src := &memSource{legs: []LegRef{{ProofID: "leg-2", Chain: 84532}}, settlements: map[string]Settlement{"leg-2": settlement}}
	store := newMemStore()
	u, _ := NewUpgrader(src, store, reg, nil, UpgraderConfig{Logf: func(string, ...any) {}, Recorder: newRec()})
	u.RunOnce(context.Background())
	chain, _ := store.Chain(context.Background(), "leg-2")
	for _, a := range chain {
		if a.Level == LevelFinalized {
			t.Fatalf("a finalized addendum was stored over evidence that proves included: %+v", a)
		}
	}
}

func TestUpgraderRefusesToAppendToAChainThatDoesNotVerify(t *testing.T) {
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		return finalEvidence(s), LevelFinalized, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{})
	// a stored chain whose first addendum was tampered with after the fact
	settlement := f.src.settlements["leg-1"]
	ev, _, _ := (IncludedProver{ChainID: 84532}).Build(context.Background(), settlement)
	a, _ := NewAddendum([32]byte{7}, "leg-1", nil, 84532, LevelIncluded, ev)
	a.Evidence = append([]byte(nil), a.Evidence...)
	a.Evidence[len(a.Evidence)-1] ^= 1
	f.store.chains["leg-1"] = []Addendum{a}

	rep := f.u.RunOnce(context.Background())
	if rep.Broken != 1 || rep.Appended != 0 || f.rec.broken != 1 {
		t.Fatalf("report %+v", rep)
	}
	if got, _ := f.store.Chain(context.Background(), "leg-1"); len(got) != 1 {
		t.Fatalf("something was appended to a broken chain: %d", len(got))
	}
	if prover.calls.Load() != 0 {
		t.Fatal("a prover ran for a leg whose chain does not verify")
	}
}

func TestUpgraderReportsALegWithoutUsableL6EvidenceByName(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{})
	delete(f.src.settlements, "leg-1")
	rep := f.u.RunOnce(context.Background())
	if rep.Unusable != 1 || f.rec.failures[CodeIncludedInvalid] != 1 || !strings.Contains(f.logs.Joined(), "L6 evidence cannot be used") {
		t.Fatalf("%+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}
}

func TestUpgraderLoserOfAnAppendRaceReadsTheWinnersChainNextPass(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{})
	// another validator appends the included addendum between our read and our write
	settlement := f.src.settlements["leg-1"]
	ev, _, _ := (IncludedProver{ChainID: 84532}).Build(context.Background(), settlement)
	winner, _ := NewAddendum([32]byte{7}, "leg-1", nil, 84532, LevelIncluded, ev)
	racing := &racingStore{memStore: f.store, winner: winner}
	f.u.store = racing
	rep := f.u.RunOnce(context.Background())
	if rep.Conflict != 1 || rep.Appended != 0 {
		t.Fatalf("%+v", rep)
	}
	if chain, _ := f.store.Chain(context.Background(), "leg-1"); len(chain) != 1 || chain[0].OwnHash != winner.OwnHash {
		t.Fatalf("chain %+v", chain)
	}
}

type racingStore struct {
	*memStore
	winner Addendum
	raced  bool
}

func (r *racingStore) Append(ctx context.Context, a Addendum) error {
	if !r.raced {
		r.raced = true
		r.memStore.chains[a.ProofID] = []Addendum{r.winner}
	}
	return r.memStore.Append(ctx, a)
}

// ---- it never blocks settlement, attestation or write-back ----

func TestUpgraderHonoursCancellationAndAStuckProverCannotStallThePass(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := &finalProver{chain: 84532, mode: func(ctx context.Context, s Settlement) (Evidence, Level, error) {
		<-release // ignores its context entirely
		return Evidence{}, LevelNone, nil
	}}
	f := newFixture(t, stuck, UpgraderConfig{BuildTimeout: 150 * time.Millisecond})

	start := time.Now()
	rep := f.u.RunOnce(context.Background())
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a prover that ignores its context held the pass for %s", d)
	}
	if rep.Appended != 1 || rep.Failed != 1 || f.rec.failures[CodeBuildTimeout] != 1 {
		t.Fatalf("the included level is still appended and the timeout is named: %+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}

	// Run returns as soon as its context is cancelled, even with a prover hanging on every pass
	f2 := newFixture(t, stuck, UpgraderConfig{BuildTimeout: time.Hour, Interval: 10 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f2.u.Run(ctx); close(done) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestUpgraderRecoversAPanickingProverAndIsBoundedInConcurrency(t *testing.T) {
	var running, peak atomic.Int64
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		running.Add(-1)
		if s.TxHash[0] == 0xFF {
			panic("boom")
		}
		return finalEvidence(s), LevelFinalized, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{Concurrency: 2})
	base := f.src.settlements["leg-1"]
	f.src.legs, f.src.settlements = nil, map[string]Settlement{}
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("leg-%02d", i)
		f.src.legs = append(f.src.legs, LegRef{ProofID: id, Digest: [32]byte{7}, Chain: 84532})
		f.src.settlements[id] = base
	}
	rep := f.u.RunOnce(context.Background())
	if peak.Load() > 2 {
		t.Fatalf("concurrency peaked at %d with a bound of 2", peak.Load())
	}
	if rep.Attempts != 8 {
		t.Fatalf("%+v", rep)
	}

	// a panic is a named, counted state and does not take the worker down
	f3 := newFixture(t, &finalProver{chain: 84532, mode: func(context.Context, Settlement) (Evidence, Level, error) { panic("boom") }}, UpgraderConfig{})
	rep = f3.u.RunOnce(context.Background())
	if rep.Failed != 1 || f3.rec.failures[CodePanic] != 1 {
		t.Fatalf("%+v %v", rep, f3.rec.failures)
	}
}

// ---- the enable flag ----

func TestTheDisabledUpgraderIsAnnouncedByNameAndTouchesNothing(t *testing.T) {
	src := &memSource{}
	logs := &logSink{}
	u, err := Launch(context.Background(), false, src, newMemStore(), NewRegistry(), nil, UpgraderConfig{Logf: logs.Logf})
	if err != nil || u != nil {
		t.Fatalf("disabled launch returned %v %v", u, err)
	}
	out := logs.Joined()
	for _, want := range []string{CodeUpgraderDisabled, EnvEnabled, "DISABLED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the off switch is not logged with %q:\n%s", want, out)
		}
	}
	time.Sleep(20 * time.Millisecond)
	if src.listed.Load() != 0 {
		t.Fatal("a disabled upgrader listed legs")
	}
}

func TestTheEnableFlagDefaultsOnAndRefusesAValueThatIsNotASwitch(t *testing.T) {
	t.Setenv(EnvEnabled, "")
	if on, err := Enabled(); err != nil || !on {
		t.Fatalf("unset: %v %v", on, err)
	}
	for v, want := range map[string]bool{"false": false, "off": false, "0": false, "true": true, "on": true} {
		t.Setenv(EnvEnabled, v)
		if on, err := Enabled(); err != nil || on != want {
			t.Fatalf("%q: %v %v", v, on, err)
		}
	}
	t.Setenv(EnvEnabled, "flase")
	if _, err := Enabled(); err == nil || !strings.Contains(err.Error(), EnvEnabled) {
		t.Fatalf("a misspelt switch was accepted or unnamed: %v", err)
	}
}

func TestAnEnabledLaunchRunsInTheBackgroundAndStopsOnCancel(t *testing.T) {
	prover := &finalProver{chain: 84532, mode: func(_ context.Context, s Settlement) (Evidence, Level, error) {
		return finalEvidence(s), LevelFinalized, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u, err := Launch(ctx, true, f.src, f.store, f.reg, nil, UpgraderConfig{Interval: 20 * time.Millisecond, Logf: f.logs.Logf, Recorder: f.rec})
	if err != nil || u == nil {
		t.Fatalf("%v %v", u, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if chain, _ := f.store.Chain(context.Background(), "leg-1"); len(chain) == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the background worker did not upgrade the leg\n%s", f.logs.Joined())
}
