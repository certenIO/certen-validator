// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- PlanAppend: the chain checks that precede the Kind ----

func TestPlanAppendRefusesAChainOfAnotherChainAndNumbersTheSeqOfItsRefusals(t *testing.T) {
	f := newFixture(t, nil, UpgraderConfig{}, nil)
	pid, _ := ParseProofID(legID)
	block := f.src.settlements[legID].Block()
	arbKind, err := KindFor(ChainArbitrumSepolia, LevelL1Posted)
	if err != nil {
		t.Fatal(err)
	}
	// a chain whose first addendum is about Arbitrum, hash-linked correctly under THIS leg's D0
	arb, err := NewAddendum(LegBindingOf(block), pid, nil, ChainArbitrumSepolia, LevelL1Posted, arbKind,
		containerFor(t, arbKind, BlockRef{Chain: ChainArbitrumSepolia, Number: block.Number, Hash: block.Hash}, LevelL1Posted, "x"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = PlanAppend(planRequest(t, f, LevelFinalized, "y"), []Addendum{arb})
	st, ok := AsNamed(err)
	if !ok || st.Code != CodeChainBroken || st.Fields["check"] != CheckKind || st.Fields["stored"] != ChainArbitrumSepolia || st.Fields["seq"] != uint64(1) {
		t.Fatalf("%v", err)
	}

	// the refusal of level 1 and of a non-row names the seq it would have had: 1 on an empty chain, 2 after one addendum
	one, _, err := PlanAppend(planRequest(t, f, LevelL1Posted, "x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	inc := planRequest(t, f, LevelFinalized, "y")
	inc.Level = LevelIncluded
	for stored, want := range map[int]uint64{0: 1, 1: 2} {
		chain := []Addendum{}
		if stored == 1 {
			chain = append(chain, one)
		}
		_, _, err := PlanAppend(inc, chain)
		if st, ok := AsNamed(err); !ok || st.Code != CodeChainBroken || st.Fields["seq"] != want {
			t.Fatalf("stored=%d: %v", stored, err)
		}
	}

	// the cheap level check runs BEFORE the Kind: a Kind that must not be asked is not asked
	l1 := f.reg.kinds[kBaseL1].(*fakeKind)
	before := l1.calls
	if _, _, err := PlanAppend(planRequest(t, f, LevelL1Posted, "again"), []Addendum{one}); stateCodeOf(err) != CodeLevelAlreadyPresent || l1.calls != before {
		t.Fatalf("the Kind ran for a level the chain already holds (%d -> %d): %v", before, l1.calls, err)
	}
}

// ---- status documents ----

func TestStatusDocumentOmitsAnAbsentEtaAndReadsOnlyKnownLevelsAndTimes(t *testing.T) {
	noETA := BuilderStatusOf(legID, ChainBaseSepolia, LevelFinalized, LevelIncluded, nil, NewState(CodeBuildTimeout, "chain", uint64(1), "after", time.Second, "cause", "x"), false, time.Now())
	doc, err := noETA.Document()
	if err != nil || strings.Contains(string(doc), `"eta"`) {
		t.Fatalf("a status with no eta must not carry one: %s %v", doc, err)
	}
	for name, raw := range map[string]string{
		"levelReached": `{"format":"` + BuilderStatusFormat + `","class":"pending","levelReached":"bogus","nextLevel":"finalized"}`,
		"nextLevel":    `{"format":"` + BuilderStatusFormat + `","class":"pending","levelReached":"included","nextLevel":"bogus"}`,
		"eta":          `{"format":"` + BuilderStatusFormat + `","class":"pending","levelReached":"included","nextLevel":"finalized","eta":"tomorrow"}`,
	} {
		if _, err := ParseBuilderStatusDocument([]byte(raw)); err == nil {
			t.Errorf("a document with a bad %s was read", name)
		}
	}
	if l, err := ParseLevelOrNone("none"); err != nil || l != LevelNone {
		t.Fatalf("none: %v %v", l, err)
	}
	if l, err := ParseLevelOrNone("l1_posted"); err != nil || l != LevelL1Posted {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := ParseLevelOrNone("nonsense"); err == nil {
		t.Fatal("nonsense was read as a level")
	}
	// classification: a pending is pending; an unnamed error becomes a named verifier_failed unavailability; N and R are told apart
	pd := &PendingState{Chain: 1, LevelReached: LevelIncluded, NextLevel: LevelL1Posted, Reason: "awaiting_batch_post"}
	if s := BuilderStatusOf(legID, 1, LevelL1Posted, LevelIncluded, pd, errors.New("ignored"), true, time.Now()); s.Class != BuilderPending || s.State.Code != CodePending {
		t.Fatalf("%+v", s)
	}
	if s := BuilderStatusOf(legID, 1, LevelL1Posted, LevelIncluded, nil, errors.New("plain failure"), false, time.Now()); s.Class != BuilderUnavailable || s.State.Code != CodeVerifierFailed {
		t.Fatalf("%+v", s)
	}
	na := NotApplicableState(1, LevelL1Posted, ReasonChainIsL1)
	if s := BuilderStatusOf(legID, 1, LevelL1Posted, LevelIncluded, nil, na, true, time.Now()); s.Class != BuilderNotApplicable {
		t.Fatalf("level_not_applicable is not applicable even when flagged refused: %+v", s)
	}
	if s := BuilderStatusOf(legID, 1, LevelL1Posted, LevelIncluded, nil, NewState("game_challenger_wins"), true, time.Now()); s.Class != BuilderRefused {
		t.Fatalf("%+v", s)
	}
	// provider text in a field is redacted before it is stored
	leaky := NewState(CodeBuildTimeout, "chain", uint64(1), "after", time.Second, "cause", "GET https://sepolia.example.org/v2/SECRETKEY123456789 failed")
	s := BuilderStatusOf(legID, 1, LevelL1Posted, LevelIncluded, nil, leaky, false, time.Now())
	if d, _ := s.Document(); strings.Contains(string(d), "SECRETKEY123456789") {
		t.Fatalf("a credential reached the status row: %s", d)
	}
}

// ---- composition: every read failure is returned, none is swallowed into an empty section ----

type failingSource struct {
	fakeSectionSource
	chainErr, refErr, settleErr error
}

func (f failingSource) Chain(ctx context.Context, id string) ([]Addendum, error) {
	if f.chainErr != nil {
		return nil, f.chainErr
	}
	return f.fakeSectionSource.Chain(ctx, id)
}

func (f failingSource) LegRef(ctx context.Context, id string) (LegRef, error) {
	if f.refErr != nil {
		return LegRef{}, f.refErr
	}
	return f.fakeSectionSource.LegRef(ctx, id)
}

func (f failingSource) LegSettlement(ctx context.Context, ref LegRef) (Settlement, error) {
	if f.settleErr != nil {
		return Settlement{}, f.settleErr
	}
	return f.fakeSectionSource.LegSettlement(ctx, ref)
}

func TestComposeSectionReturnsEveryReadFailureAndANonVerifyingSettlement(t *testing.T) {
	f := newFixture(t, allLevels(t), UpgraderConfig{}, nil)
	f.u.RunOnce(context.Background())
	base := fakeSectionSource{memStore: f.store, src: f.src}
	boom := errors.New("connection reset")
	for name, src := range map[string]failingSource{
		"chain read": {fakeSectionSource: base, chainErr: boom},
		"leg ref":    {fakeSectionSource: base, refErr: boom},
		"settlement": {fakeSectionSource: base, settleErr: boom},
	} {
		if s, err := ComposeSection(context.Background(), src, legID); !errors.Is(err, boom) || s != nil {
			t.Errorf("%s: %v %v", name, s, err)
		}
	}
	// a settlement that does not verify is not a leg
	s := f.src.settlements[legID]
	bad := *s.Included
	bad.Header = append([]byte(nil), bad.Header...)
	bad.Header[len(bad.Header)-1] ^= 1
	f.src.settlements[legID] = Settlement{Chain: s.Chain, Subject: s.Subject, Included: &bad}
	if sec, err := ComposeSection(context.Background(), base, legID); stateCodeOf(err) != CodeIncludedInvalid || sec != nil {
		t.Fatalf("%v %v", sec, err)
	}
}

// ---- supervisor configuration and lifecycle ----

func TestSupervisorConfigDefaultsAndClamps(t *testing.T) {
	d := SupervisorConfig{}.withDefaults()
	if d.RestartMin != 5*time.Second || d.RestartMax != 5*time.Minute {
		t.Fatalf("%+v", d)
	}
	low := SupervisorConfig{RestartMin: time.Nanosecond, RestartMax: time.Nanosecond}.withDefaults()
	if low.RestartMin != 5*time.Second || low.RestartMax != 5*time.Minute {
		t.Fatalf("a restart wait below the floor is replaced by the defaults: %+v", low)
	}
	eq := SupervisorConfig{RestartMin: 3 * time.Second, RestartMax: 3 * time.Second}.withDefaults()
	if eq.RestartMin != 3*time.Second || eq.RestartMax != 3*time.Second {
		t.Fatalf("equal bounds are kept: %+v", eq)
	}
	inverted := SupervisorConfig{RestartMin: 10 * time.Second, RestartMax: 2 * time.Second}.withDefaults()
	if inverted.RestartMax != 5*time.Minute {
		t.Fatalf("a maximum below the minimum is replaced by the default: %+v", inverted)
	}
	huge := SupervisorConfig{RestartMin: 10 * time.Minute, RestartMax: time.Minute}.withDefaults()
	if huge.RestartMax != huge.RestartMin {
		t.Fatalf("with a minimum above the default maximum the maximum is the minimum: %+v", huge)
	}
}

type onceCapturer struct {
	fakeCapturer
	returnNil bool
}

func (c *onceCapturer) Run(ctx context.Context) error {
	c.runs.Add(1)
	if c.returnNil {
		return nil // returned without an error before the context ended: a defect the supervisor names and restarts
	}
	<-ctx.Done()
	return nil
}

func TestACapturerThatReturnsWithoutAnErrorIsRestartedAndAStoppedContextEndsTheLoop(t *testing.T) {
	reg := NewRegistry()
	c := &onceCapturer{fakeCapturer: fakeCapturer{chain: ChainBaseSepolia, name: "base-sepolia/early-return"}, returnNil: true}
	if err := reg.RegisterCapturer(c); err != nil {
		t.Fatal(err)
	}
	var restarts atomic.Int64
	var gotErr atomic.Value
	var logs logSink
	ctx, cancel := context.WithCancel(context.Background())
	sup := StartCapturers(ctx, reg, SupervisorConfig{RestartMin: MinPoll, RestartMax: MinPoll, Logf: logs.Logf,
		Restarted: func(_ Capturer, err error, _ time.Duration) { restarts.Add(1); gotErr.Store(err.Error()) }})
	deadline := time.Now().Add(5 * time.Second)
	for restarts.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if restarts.Load() < 1 || !strings.Contains(gotErr.Load().(string), "without an error") {
		t.Fatalf("an early nil return must be restarted with a named cause: %v\n%s", gotErr.Load(), logs.Joined())
	}
	cancel()
	done := make(chan struct{})
	go func() { sup.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor did not stop on cancel")
	}
	// a capture loop whose context is already cancelled never starts
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	idle := &onceCapturer{fakeCapturer: fakeCapturer{chain: ChainBaseSepolia, name: "base-sepolia/never"}}
	reg2 := NewRegistry()
	_ = reg2.RegisterCapturer(idle)
	StartCapturers(cancelled, reg2, SupervisorConfig{}).Wait()
	if idle.runs.Load() != 0 {
		t.Fatalf("a loop ran under a cancelled context: %d", idle.runs.Load())
	}
}

// scriptedCapturer fails every run after advancing the shared clock by ran.
type scriptedCapturer struct {
	fakeCapturer
	clock *fakeClock
	ran   []time.Duration
}

func (c *scriptedCapturer) Run(ctx context.Context) error {
	n := c.runs.Add(1)
	if int(n) > len(c.ran) {
		<-ctx.Done()
		return nil
	}
	c.clock.Advance(c.ran[n-1])
	return NewState(CodeBuildTimeout, "chain", c.chain, "after", time.Second, "cause", "head poll")
}

// The restart backoff doubles from RestartMin to RestartMax, is clamped at RestartMax, and starts again from RestartMin only
// after a run that lasted MORE than twice RestartMax. Time is scripted: nothing here sleeps.
func TestCapturerRestartBackoffDoublesIsClampedAndResetsAfterALongRun(t *testing.T) {
	min, max := time.Second, 8*time.Second
	run := func(ran ...time.Duration) []time.Duration {
		clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
		c := &scriptedCapturer{fakeCapturer: fakeCapturer{chain: ChainBaseSepolia, name: "base-sepolia/scripted", started: make(chan struct{}, 1)}, clock: clock, ran: ran}
		reg := NewRegistry()
		if err := reg.RegisterCapturer(c); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var waits []time.Duration
		done := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		sup := StartCapturers(ctx, reg, SupervisorConfig{RestartMin: min, RestartMax: max, Now: clock.Now,
			After: func(d time.Duration) <-chan time.Time { ch := make(chan time.Time, 1); ch <- clock.Now(); return ch },
			Restarted: func(_ Capturer, _ error, wait time.Duration) {
				mu.Lock()
				waits = append(waits, wait)
				n := len(waits)
				mu.Unlock()
				if n == len(ran) {
					close(done)
				}
			}})
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("restarts did not happen: %v", waits)
		}
		cancel()
		sup.Wait()
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), waits...)
	}
	s := time.Second
	if got := run(0, 0, 0, 0, 0); fmt.Sprint(got) != fmt.Sprint([]time.Duration{1 * s, 2 * s, 4 * s, 8 * s, 8 * s}) {
		t.Fatalf("short runs: doubled from the minimum and clamped at the maximum: %v", got)
	}
	// a run of exactly 2*max is not 'long' (the comparison is strict); one nanosecond more is, and restarts from the minimum
	if got := run(0, 0, 2*max, 0); fmt.Sprint(got) != fmt.Sprint([]time.Duration{1 * s, 2 * s, 4 * s, 8 * s}) {
		t.Fatalf("a run of exactly twice the maximum does not reset: %v", got)
	}
	if got := run(0, 0, 2*max+1, 0); fmt.Sprint(got) != fmt.Sprint([]time.Duration{1 * s, 2 * s, 1 * s, 2 * s}) {
		t.Fatalf("a run longer than twice the maximum restarts the backoff: %v", got)
	}
}
