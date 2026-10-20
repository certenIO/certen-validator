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

	"github.com/certen/independant-validator/pkg/ethproof"
)

// ---- fakes ----

const legID = "00000000-0000-4000-8000-000000000001"

type memStore struct {
	mu     sync.Mutex
	chains map[string][]Addendum
	calls  int
}

func newMemStore() *memStore { return &memStore{chains: map[string][]Addendum{}} }

func (m *memStore) Append(_ context.Context, a Addendum) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	id := ProofIDString(a.ProofID)
	c := m.chains[id]
	if a.Seq != uint64(len(c))+1 {
		return NewState(CodeAppendConflict, "proof_id", id, "seq", a.Seq)
	}
	m.chains[id] = append(c, a)
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
		return Settlement{}, NewState(CodeIncludedInvalid, "cause", "no L6 evidence for "+ref.ProofID)
	}
	return st, nil
}

// finalProver stands in for a chain package's prover: it returns an addendum, a pending, a lie, a hang or a panic.
type finalProver struct {
	chain uint64
	mode  func(ctx context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error)
	calls atomic.Int64
}

func (p *finalProver) Chain() uint64 { return p.chain }
func (p *finalProver) Build(ctx context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error) {
	p.calls.Add(1)
	return p.mode(ctx, s, have, target)
}

var baseKinds = map[Level]string{LevelL1Posted: kBaseL1, LevelFinalized: kBaseFin}

// built is the addendum a prover returns for target about the settlement's own block.
func built(t testing.TB, s *ethproof.Settlement, target Level, body string) *Addendum {
	t.Helper()
	b, err := DeriveIncluded(ChainBaseSepolia, s)
	if err != nil {
		t.Fatal(err)
	}
	return &Addendum{Level: target, Chain: ChainBaseSepolia, Kind: baseKinds[target], Evidence: containerFor(t, baseKinds[target], b, target, body)}
}

type upgraderFixture struct {
	reg   *Registry
	store *memStore
	src   *memSource
	clock *fakeClock
	logs  *logSink
	rec   *recSink
	u     *Upgrader
	fin   *fakeKind
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

// newFixture registers fake kinds for Base's two stored levels and one leg settled on the real Base block.
func newFixture(t *testing.T, prover *finalProver, cfg UpgraderConfig, finErr error) *upgraderFixture {
	t.Helper()
	reg := NewRegistry()
	l1 := &fakeKind{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted}
	fin := &fakeKind{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized, err: finErr}
	for _, k := range []*fakeKind{l1, fin} {
		if err := reg.RegisterKind(k); err != nil {
			t.Fatal(err)
		}
	}
	if prover != nil {
		if err := reg.RegisterProver(prover); err != nil {
			t.Fatal(err)
		}
	}
	settlement := realSettlement(t, "base_sepolia_47368146")
	f := &upgraderFixture{
		reg: reg, store: newMemStore(), clock: &fakeClock{t: time.Unix(1_800_000_000, 0)}, logs: &logSink{}, rec: newRec(), fin: fin,
		src: &memSource{
			legs:        []LegRef{{ProofID: legID, Chain: ChainBaseSepolia}},
			settlements: map[string]Settlement{legID: settlement},
		},
	}
	cfg.Logf, cfg.Now, cfg.Recorder = f.logs.Logf, f.clock.Now, f.rec
	cfg.Jitter = func(d time.Duration) time.Duration { return d }
	u, err := NewUpgrader(f.src, f.store, reg, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.u = u
	return f
}

func allLevels(t *testing.T) *finalProver {
	return &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		return built(t, s, target, "evidence"), nil, nil
	}}
}

func (f *upgraderFixture) d0() [32]byte { return LegBindingOf(f.src.settlements[legID].Block()) }

// ---- behaviour ----

func TestUpgraderAppendsEveryBuildableStoredLevelAndNeverLevelOne(t *testing.T) {
	prover := allLevels(t)
	f := newFixture(t, prover, UpgraderConfig{}, nil)
	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 2 || rep.Failed != 0 {
		t.Fatalf("report %+v\n%s", rep, f.logs.Joined())
	}
	chain, _ := f.store.Chain(context.Background(), legID)
	if len(chain) != 2 || chain[0].Level != LevelL1Posted || chain[1].Level != LevelFinalized {
		t.Fatalf("chain %+v", chain)
	}
	for _, a := range chain {
		if a.Level == LevelIncluded {
			t.Fatal("level 1 was stored")
		}
	}
	if err := VerifyChain(f.d0(), chain); err != nil {
		t.Fatal(err)
	}
	before := prover.calls.Load()
	rep = f.u.RunOnce(context.Background())
	if rep.Attempts != 0 || rep.Complete != 1 || prover.calls.Load() != before {
		t.Fatalf("second pass %+v", rep)
	}
}

func TestUpgraderBuildsTheLevelsInWhateverOrderTheyBecomeBuildable(t *testing.T) {
	finalizedOnly := &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error) {
		if target == LevelFinalized {
			return built(t, s, target, "evidence"), nil, nil
		}
		return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelFinalized, NextLevel: LevelL1Posted, Reason: "l1_posted_unproven"}, nil
	}}
	f := newFixture(t, finalizedOnly, UpgraderConfig{}, nil)
	if rep := f.u.RunOnce(context.Background()); rep.Appended != 1 || rep.Pending != 1 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	chain, _ := f.store.Chain(context.Background(), legID)
	if len(chain) != 1 || chain[0].Level != LevelFinalized {
		t.Fatalf("finalized must be storable first: %+v", chain)
	}
	// l1_posted becomes buildable later and is appended AFTER finalized (seq orders the chain, not the levels)
	finalizedOnly.mode = func(_ context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error) {
		if have.Has(target) {
			t.Errorf("the prover was asked to rebuild a level the leg holds: %v", target)
		}
		return built(t, s, target, "later"), nil, nil
	}
	f.clock.Advance(time.Hour)
	if rep := f.u.RunOnce(context.Background()); rep.Appended != 1 {
		t.Fatalf("%+v\n%s", rep, f.logs.Joined())
	}
	chain, _ = f.store.Chain(context.Background(), legID)
	if len(chain) != 2 || chain[1].Level != LevelL1Posted || VerifyChain(f.d0(), chain) != nil {
		t.Fatalf("%+v", chain)
	}
}

func TestUpgraderReschedulesFromThePendingETAUntilFinalized(t *testing.T) {
	ready := atomic.Bool{}
	var f *upgraderFixture
	prover := &finalProver{chain: ChainBaseSepolia}
	prover.mode = func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		if target == LevelFinalized && !ready.Load() {
			return nil, &PendingState{Chain: ChainBaseSepolia, LevelReached: LevelL1Posted, NextLevel: LevelFinalized, ETA: f.clock.Now().Add(20 * time.Minute), Reason: "game_unresolved"}, nil
		}
		return built(t, s, target, "evidence"), nil, nil
	}
	f = newFixture(t, prover, UpgraderConfig{}, nil)

	rep := f.u.RunOnce(context.Background())
	if rep.Appended != 1 || rep.Pending != 1 {
		t.Fatalf("first pass %+v\n%s", rep, f.logs.Joined())
	}
	if chain, _ := f.store.Chain(context.Background(), legID); len(chain) != 1 || chain[0].Level != LevelL1Posted {
		t.Fatalf("chain after pending: %+v", chain)
	}
	calls := prover.calls.Load()
	f.clock.Advance(10 * time.Minute)
	if rep = f.u.RunOnce(context.Background()); rep.Attempts != 0 || rep.NotDue != 1 || prover.calls.Load() != calls {
		t.Fatalf("before ETA %+v", rep)
	}
	ready.Store(true)
	f.clock.Advance(11 * time.Minute)
	if rep = f.u.RunOnce(context.Background()); rep.Appended != 1 {
		t.Fatalf("at ETA %+v\n%s", rep, f.logs.Joined())
	}
	if chain, _ := f.store.Chain(context.Background(), legID); len(chain) != 2 || chain[1].Level != LevelFinalized {
		t.Fatalf("final chain %+v", chain)
	}
	if rep = f.u.RunOnce(context.Background()); rep.Complete != 1 {
		t.Fatalf("not complete: %+v", rep)
	}
}

func TestUpgraderNeverAppendsEvidenceTheOfflineKindRefuses(t *testing.T) {
	refusal := NewState("game_challenger_wins")
	f := newFixture(t, allLevels(t), UpgraderConfig{}, refusal)
	rep := f.u.RunOnce(context.Background())
	chain, _ := f.store.Chain(context.Background(), legID)
	if rep.Appended != 1 || len(chain) != 1 || chain[0].Level != LevelL1Posted {
		t.Fatalf("only l1_posted may be appended: %+v chain %+v", rep, chain)
	}
	if rep.Failed != 1 || f.rec.failures["game_challenger_wins"] != 1 || !strings.Contains(f.logs.Joined(), "game_challenger_wins") {
		t.Fatalf("the refusal is a counted, logged named state: %+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}
}

func TestUpgraderAppendsOnlyWhatIsBoundToTheRowLevelAndTheLegsBlock(t *testing.T) {
	var mode string
	prover := &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		if target != LevelFinalized {
			return nil, nil, nil
		}
		a := built(t, s, target, "x")
		switch mode {
		case "container says l1_posted":
			a.Evidence = built(t, s, LevelL1Posted, "x").Evidence
		case "another block":
			b, _ := DeriveIncluded(ChainBaseSepolia, s)
			b.Number++
			a.Evidence = containerFor(t, kBaseFin, b, LevelFinalized, "x")
		case "claims l1_posted":
			a.Level = LevelL1Posted
		}
		return a, nil, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{}, nil)
	for _, mode = range []string{"container says l1_posted", "another block", "claims l1_posted"} {
		f.clock.Advance(24 * time.Hour)
		f.u.RunOnce(context.Background())
		if chain, _ := f.store.Chain(context.Background(), legID); len(chain) != 0 {
			t.Fatalf("%s: a finalized addendum was stored: %+v", mode, chain)
		}
	}
	if f.rec.failures[CodeEvidenceMalformed] < 1 || f.rec.failures[CodeBlockMismatch] < 1 {
		t.Fatalf("the refusals are counted by name: %v", f.rec.failures)
	}
}

func TestUpgraderRefusesToAppendToAChainThatDoesNotVerify(t *testing.T) {
	prover := allLevels(t)
	f := newFixture(t, prover, UpgraderConfig{}, nil)
	settlement := f.src.settlements[legID]
	pid, _ := ParseProofID(legID)
	a, err := NewAddendum(f.d0(), pid, nil, ChainBaseSepolia, LevelL1Posted, kBaseL1, built(t, settlement.Included, LevelL1Posted, "x").Evidence)
	if err != nil {
		t.Fatal(err)
	}
	a.Evidence = append([]byte(nil), a.Evidence...)
	a.Evidence[len(a.Evidence)-1] ^= 1 // tampered after the fact
	f.store.chains[legID] = []Addendum{a}

	rep := f.u.RunOnce(context.Background())
	if rep.Broken != 1 || rep.Appended != 0 || f.rec.broken != 1 {
		t.Fatalf("report %+v", rep)
	}
	if got, _ := f.store.Chain(context.Background(), legID); len(got) != 1 {
		t.Fatalf("something was appended to a broken chain: %d", len(got))
	}
	if prover.calls.Load() != 0 {
		t.Fatal("a prover ran for a leg whose chain does not verify")
	}
}

func TestUpgraderRefusesAChainChainedUnderAnotherLegsBinding(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	settlement := f.src.settlements[legID]
	other := settlement.Block()
	other.Number++
	pid, _ := ParseProofID(legID)
	a, _ := NewAddendum(LegBindingOf(other), pid, nil, ChainBaseSepolia, LevelL1Posted, kBaseL1, built(t, settlement.Included, LevelL1Posted, "x").Evidence)
	f.store.chains[legID] = []Addendum{a}
	if rep := f.u.RunOnce(context.Background()); rep.Broken != 1 || rep.Appended != 0 {
		t.Fatalf("a chain bound to another block was extended: %+v", rep)
	}
}

func TestUpgraderReportsALegWithoutUsableL6EvidenceByName(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	delete(f.src.settlements, legID)
	rep := f.u.RunOnce(context.Background())
	if rep.Unusable != 1 || f.rec.failures[CodeIncludedInvalid] != 1 || !strings.Contains(f.logs.Joined(), "L6 evidence cannot be used") {
		t.Fatalf("%+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}
}

func TestUpgraderLoserOfAnAppendRaceReadsTheWinnersChainNextPass(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	settlement := f.src.settlements[legID]
	pid, _ := ParseProofID(legID)
	winner, _ := NewAddendum(f.d0(), pid, nil, ChainBaseSepolia, LevelL1Posted, kBaseL1, built(t, settlement.Included, LevelL1Posted, "winner").Evidence)
	racing := &racingStore{memStore: f.store, winner: winner}
	f.u.store = racing
	rep := f.u.RunOnce(context.Background())
	if rep.Conflict != 1 || rep.Appended != 0 {
		t.Fatalf("%+v", rep)
	}
	if chain, _ := f.store.Chain(context.Background(), legID); len(chain) != 1 || chain[0].OwnHash != winner.OwnHash {
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
		r.memStore.chains[ProofIDString(a.ProofID)] = []Addendum{r.winner}
	}
	return r.memStore.Append(ctx, a)
}

// ---- it never blocks settlement, attestation or write-back ----

func TestUpgraderHonoursCancellationAndAStuckProverCannotStallThePass(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := &finalProver{chain: ChainBaseSepolia, mode: func(ctx context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		<-release // ignores its context entirely
		return nil, nil, nil
	}}
	f := newFixture(t, stuck, UpgraderConfig{BuildTimeout: 150 * time.Millisecond}, nil)

	start := time.Now()
	rep := f.u.RunOnce(context.Background())
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a prover that ignores its context held the pass for %s", d)
	}
	if rep.Failed != 1 || f.rec.failures[CodeBuildTimeout] < 1 {
		t.Fatalf("the timeout is named: %+v %v\n%s", rep, f.rec.failures, f.logs.Joined())
	}

	f2 := newFixture(t, stuck, UpgraderConfig{BuildTimeout: time.Hour, Interval: 10 * time.Millisecond}, nil)
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
	prover := &finalProver{chain: ChainBaseSepolia, mode: func(_ context.Context, s *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		running.Add(-1)
		return built(t, s, target, "evidence"), nil, nil
	}}
	f := newFixture(t, prover, UpgraderConfig{Concurrency: 2}, nil)
	base := f.src.settlements[legID]
	f.src.legs, f.src.settlements = nil, map[string]Settlement{}
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10)
		f.src.legs = append(f.src.legs, LegRef{ProofID: id, Chain: ChainBaseSepolia})
		f.src.settlements[id] = base
	}
	rep := f.u.RunOnce(context.Background())
	if peak.Load() > 2 {
		t.Fatalf("concurrency peaked at %d with a bound of 2", peak.Load())
	}
	if rep.Attempts != 8 {
		t.Fatalf("%+v", rep)
	}

	f3 := newFixture(t, &finalProver{chain: ChainBaseSepolia, mode: func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
		panic("boom")
	}}, UpgraderConfig{}, nil)
	rep = f3.u.RunOnce(context.Background())
	if rep.Failed != 1 || f3.rec.failures[CodePanic] < 1 {
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
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u, err := Launch(ctx, true, f.src, f.store, f.reg, nil, UpgraderConfig{Interval: 20 * time.Millisecond, Logf: f.logs.Logf, Recorder: f.rec})
	if err != nil || u == nil {
		t.Fatalf("%v %v", u, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if chain, _ := f.store.Chain(context.Background(), legID); len(chain) == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the background worker did not upgrade the leg\n%s", f.logs.Joined())
}
