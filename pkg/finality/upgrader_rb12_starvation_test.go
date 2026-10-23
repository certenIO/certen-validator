// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// RB12-F1 (live, 2026-10-23): legs whose evidence cannot be built inside BuildTimeout (Base l1_posted for legs that pre-date the capture,
// a Sepolia spine too long for a public RPC) held the 4 upgrader slots for BuildTimeout per attempt and, with 575 settled legs in the
// backlog, made every pass as long as the slowest leg, so a new leg was not even listed until the pass ended.
//
// These tests use production-shaped legs (the field names and types of the live listing: proof id, chain, newest bundle id) with the
// existing configuration surface only, so they run unchanged against the base commit.

// rb12Source lists legs newest first, as the database source does, and serves one settlement per leg (a distinct pointer per leg, so a
// prover can tell the legs apart).
type rb12Source struct {
	mu          sync.Mutex
	legs        []LegRef // newest first
	settlements map[string]Settlement
	byPtr       map[*ethproof.Settlement]string
	proto       Settlement
}

func newRB12Source(base Settlement) *rb12Source {
	s := &rb12Source{settlements: map[string]Settlement{}, byPtr: map[*ethproof.Settlement]string{}}
	s.proto = base
	return s
}

func (s *rb12Source) add(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.proto.Included
	st := s.proto
	st.Included = &cp
	s.settlements[id] = st
	s.byPtr[&cp] = id
	s.legs = append([]LegRef{{ProofID: id, Chain: ChainBaseSepolia, BundleID: "bundle-" + id}}, s.legs...)
}

func (s *rb12Source) legOf(p *ethproof.Settlement) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byPtr[p]
}

func (s *rb12Source) SettledLegs(_ context.Context, after string, limit int) ([]LegRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	start := 0
	if after != "" {
		start = len(s.legs)
		for i, l := range s.legs {
			if l.ProofID == after {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(s.legs) {
		end = len(s.legs)
	}
	return append([]LegRef(nil), s.legs[start:end]...), nil
}

func (s *rb12Source) LegSettlement(_ context.Context, ref LegRef) (Settlement, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.settlements[ref.ProofID]
	if !ok {
		return Settlement{}, NewState(CodeIncludedInvalid, "cause", "no L6 evidence for "+ref.ProofID)
	}
	return st, nil
}

// rb12Status is a BuilderStatusStore that keeps the newest row per (proof, level).
type rb12Status struct {
	mu   sync.Mutex
	rows map[string]BuilderStatus
	log  []BuilderStatus
}

func newRB12Status() *rb12Status { return &rb12Status{rows: map[string]BuilderStatus{}} }

func (r *rb12Status) UpsertStatus(_ context.Context, s BuilderStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[s.ProofID+"/"+s.TargetLevel.String()] = s
	r.log = append(r.log, s)
	return nil
}

func (r *rb12Status) GetStatus(context.Context, string, Level) (BuilderStatusView, bool, error) {
	return BuilderStatusView{}, false, nil
}

func (r *rb12Status) row(id string, l Level) (BuilderStatus, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.rows[id+"/"+l.String()]
	return s, ok
}

func rb12Fixture(t *testing.T, cfg UpgraderConfig, prover func(src *rb12Source) func(ctx context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error)) (*Upgrader, *rb12Source, *fakeClock, *recSink, *logSink) {
	t.Helper()
	reg := NewRegistry()
	for _, k := range []*fakeKind{
		{chain: ChainBaseSepolia, name: kBaseL1, level: LevelL1Posted},
		{chain: ChainBaseSepolia, name: kBaseFin, level: LevelFinalized},
	} {
		if err := reg.RegisterKind(k); err != nil {
			t.Fatal(err)
		}
	}
	src := newRB12Source(realSettlement(t, "base_sepolia_47368146"))
	p := &finalProver{chain: ChainBaseSepolia, mode: prover(src)}
	if err := reg.RegisterProver(p); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	logs, rec := &logSink{}, newRec()
	cfg.Logf, cfg.Now, cfg.Recorder = logs.Logf, clock.Now, rec
	cfg.Jitter = func(d time.Duration) time.Duration { return d }
	u, err := NewUpgrader(src, newMemStore(), reg, nil, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return u, src, clock, rec, logs
}

func leg(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }

// A leg that timed out is a suspect: it may hold at most half of the slots, and the pass does not wait for it, so a leg that appears
// while the suspects run is built at once (before the suspects' own timeout ends).
func TestRB12SuspectLegsHoldAtMostHalfTheSlotsAndANewLegIsServedWhileTheyRun(t *testing.T) {
	const buildTimeout = 2500 * time.Millisecond // MinPoll (1s) is the floor of the pass interval
	var stuckRunning, stuckPeak atomic.Int64
	var learning atomic.Bool
	learning.Store(true)
	var freshBuiltAt sync.Map // leg id -> time of its build
	u, src0, clock, _, logs := rb12Fixture(t, UpgraderConfig{Concurrency: 4, BuildTimeout: buildTimeout, Interval: MinPoll},
		func(s *rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, st *ethproof.Settlement, _ LevelSet, target Level) (*Addendum, *PendingState, error) {
				id := s.legOf(st)
				if id >= leg(100) { // fresh legs are built at once
					freshBuiltAt.Store(id, time.Now())
					return built(t, st, target, "evidence"), nil, nil
				}
				n := stuckRunning.Add(1)
				for {
					p := stuckPeak.Load()
					if n <= p || stuckPeak.CompareAndSwap(p, n) {
						break
					}
				}
				defer stuckRunning.Add(-1)
				if learning.Load() { // pass 1: the provider reports its own timeout at once, so the legs become suspects
					return nil, nil, NewState(CodeBuildTimeout, "chain", ChainBaseSepolia, "after", buildTimeout, "cause", "building the evidence: context deadline exceeded")
				}
				<-ctx.Done() // the evidence never arrives inside the window: only the timeout ends it
				return nil, nil, ctx.Err()
			}
		})
	for i := 0; i < 8; i++ { // the backlog: 8 legs that cannot be built (older than every fresh leg)
		src0.add(leg(i))
	}

	// pass 1 learns which legs are stuck: they time out
	if rep := u.RunOnce(context.Background()); rep.Failed != 8 {
		t.Fatalf("pass 1 should time out all 8 stuck legs: %+v\n%s", rep, logs.Joined())
	}
	stuckPeak.Store(0)
	learning.Store(false)

	// every stuck leg is due again; a fresh leg exists
	clock.Advance(40 * time.Minute)
	src0.add(leg(100))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := freshBuiltAt.Load(leg(100)); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fresh leg was never built")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// the suspects are now running; a second fresh leg appears and must not wait for them
	time.Sleep(100 * time.Millisecond)
	if stuckRunning.Load() == 0 {
		t.Fatalf("the suspect legs were expected to be running")
	}
	added := time.Now()
	src0.add(leg(101))
	for {
		if at, ok := freshBuiltAt.Load(leg(101)); ok {
			if d := at.(time.Time).Sub(added); d > 1700*time.Millisecond {
				t.Fatalf("a leg that appeared while the suspects ran waited %s (the suspects' timeout is %s): the pass blocked on them", d, buildTimeout)
			}
			break
		}
		if time.Now().After(added.Add(2400 * time.Millisecond)) {
			t.Fatalf("a leg that appeared while the suspects ran was not built within 2.4s (the suspects' timeout is %s): the pass blocked on them\n%s", buildTimeout, logs.Joined())
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done
	if p := stuckPeak.Load(); p > 2 {
		t.Fatalf("suspect legs held %d of the 4 slots at once; at most half may be held", p)
	}
}

// Each failure of the same (leg, level) doubles the wait, and the status row says when the leg is asked next.
func TestRB12ATimedOutLegBacksOffAndTheStatusRowNamesItsNextAttempt(t *testing.T) {
	u, src, clock, _, logs := rb12Fixture(t, UpgraderConfig{BuildTimeout: 30 * time.Millisecond, Status: nil},
		func(*rb12Source) func(context.Context, *ethproof.Settlement, LevelSet, Level) (*Addendum, *PendingState, error) {
			return func(ctx context.Context, _ *ethproof.Settlement, _ LevelSet, _ Level) (*Addendum, *PendingState, error) {
				<-ctx.Done()
				return nil, nil, ctx.Err()
			}
		})
	status := newRB12Status()
	u.cfg.Status = status
	src.add(leg(1))

	wait := 5 * time.Minute // the default FailureRetry
	for attempt := 1; attempt <= 4; attempt++ {
		at := clock.Now()
		if rep := u.RunOnce(context.Background()); rep.Failed != 1 {
			t.Fatalf("attempt %d: %+v\n%s", attempt, rep, logs.Joined())
		}
		row, ok := status.row(leg(1), LevelL1Posted)
		if !ok || row.Class != BuilderUnavailable || row.State == nil || row.State.Code != CodeBuildTimeout {
			t.Fatalf("attempt %d: the status row names the timeout: %+v", attempt, row)
		}
		if got := fmt.Sprint(row.State.Fields["attempt"]); got != fmt.Sprint(attempt) {
			t.Fatalf("attempt %d: the status row counts the attempts: attempt=%q fields=%v", attempt, got, row.State.Fields)
		}
		want := at.Add(wait).UTC().Format(time.RFC3339)
		if got := fmt.Sprint(row.State.Fields["next_attempt_at"]); got != want {
			t.Fatalf("attempt %d: next_attempt_at=%q want %q (the wait doubles on every failure)", attempt, got, want)
		}
		// not asked again before the recorded time
		clock.Advance(wait - time.Second)
		if rep := u.RunOnce(context.Background()); rep.Attempts != 0 {
			t.Fatalf("attempt %d: asked again before next_attempt_at: %+v", attempt, rep)
		}
		clock.Advance(2 * time.Second)
		wait *= 2
	}
}
