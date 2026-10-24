// Copyright 2026 Certen Protocol

package capture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// longEdit lays the blocks of a hops world out with the given gaps: gaps[0] is B_v -> tick 1, ..., gaps[last] is tick k -> N.
func longEdit(gaps []uint64) func(*world.Spec) {
	return func(sp *world.Spec) {
		var total uint64
		for _, g := range gaps {
			total += g
		}
		// B_v stays where the generated world has it (the owner pin rows are valid from there); the settlement block moves later
		bv := sp.Blocks.Attest.Number
		sp.Blocks.Settle.Number = bv + total
		sp.Blocks.Attest.Number, sp.Blocks.AttestParent.Number = bv, bv-1
		sp.Blocks.Between = nil
		cur := bv
		for i, g := range gaps[:len(gaps)-1] {
			cur += g
			sp.Blocks.Between = append(sp.Blocks.Between, world.BlockSpec{Number: cur})
			if sp.Stations[world.HopStation(i+1)] == nil {
				sp.Stations[world.HopStation(i+1)] = &world.Station{Accounts: map[string]*world.AcctSpec{}}
			}
		}
	}
}

// headSource is a chain whose head the test moves; every other read is the fake chain's.
type headSource struct {
	*fakeSource
	head      uint64
	headPanic bool
}

func (s *headSource) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	if n != nil && n.Sign() < 0 {
		if s.headPanic {
			panic("hostile head reader")
		}
		if h, ok := s.fc.headers[s.head]; ok {
			return h, nil
		}
		return nil, errors.New("no head")
	}
	return s.fakeSource.HeaderByNumber(ctx, n)
}

func newHeadSource(fc *fakeChain, modes ...hostile) *headSource {
	if len(modes) == 0 {
		modes = []hostile{honest}
	}
	src, _ := fc.source(modes...)
	return &headSource{fakeSource: src}
}

// spyStore records every successful Put and can crash at the N-th operation (before or after the operation took effect).
type spyStore struct {
	capture.Store
	mu     sync.Mutex
	rows   map[capture.Key][]byte
	ops    int
	crash  int // 0: never; N: the N-th operation of store and source fails
	after  bool
	puts   []capture.Key
	panics bool
}

func newSpy() *spyStore {
	return &spyStore{Store: capture.NewMemStore(), rows: map[capture.Key][]byte{}}
}

var errCrash = errors.New("simulated crash")

func (s *spyStore) tick() (crashNow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops++
	return s.crash != 0 && s.ops == s.crash
}

func (s *spyStore) fail() error {
	if s.panics {
		panic(errCrash)
	}
	return errCrash
}

func (s *spyStore) Put(ctx context.Context, k capture.Key, data []byte) error {
	c := s.tick()
	if c && !s.after {
		return s.fail()
	}
	if err := s.Store.Put(ctx, k, data); err != nil {
		return err
	}
	s.mu.Lock()
	s.rows[k] = append([]byte(nil), data...)
	s.puts = append(s.puts, k)
	s.mu.Unlock()
	if c {
		return s.fail()
	}
	return nil
}

func (s *spyStore) Get(ctx context.Context, k capture.Key) ([]byte, bool, error) {
	if s.tick() {
		return nil, false, s.fail()
	}
	return s.Store.Get(ctx, k)
}

func (s *spyStore) ListByAnchor(ctx context.Context, chain uint64, a [32]byte) ([]capture.Key, error) {
	if s.tick() {
		return nil, s.fail()
	}
	return s.Store.ListByAnchor(ctx, chain, a)
}

// crashSource counts the source's head and header reads and its providers' calls into the same operation counter.
type crashSource struct {
	*headSource
	spy *spyStore
}

func (s *crashSource) HeaderByNumber(ctx context.Context, n *big.Int) (*types.Header, error) {
	if s.spy.tick() {
		return nil, s.spy.fail()
	}
	return s.headSource.HeaderByNumber(ctx, n)
}

func (s *crashSource) Providers() []capture.Provider {
	ps := s.headSource.Providers()
	out := make([]capture.Provider, len(ps))
	for i, p := range ps {
		out[i] = crashProvider{p, s.spy}
	}
	return out
}

type crashProvider struct {
	capture.Provider
	spy *spyStore
}

func (p crashProvider) GetProof(ctx context.Context, a common.Address, keys []string, block string) (json.RawMessage, error) {
	if p.spy.tick() {
		return nil, p.spy.fail()
	}
	return p.Provider.GetProof(ctx, a, keys, block)
}

func (fc *fakeChain) bvRef() ci.BlockRef {
	return ci.BlockRef{Number: fc.w.Spec.Blocks.Attest.Number, Hash: [32]byte(fc.w.BlockHashes[world.BlockAttest])}
}

func (fc *fakeChain) tickHeads() []uint64 {
	var hs []uint64
	for _, b := range fc.w.Spec.Blocks.Between {
		hs = append(hs, b.Number)
	}
	return hs
}

func newTicker(t testing.TB, fc *fakeChain, src capture.Source, st capture.Store) *capture.Ticker {
	t.Helper()
	cfg := fc.config(src)
	tk, err := capture.NewTicker(capture.TickConfig{Config: cfg, Store: st, Poll: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Track(capture.TrackedAnchor{AnchorID: fc.facts(t).AnchorID, Bv: fc.bvRef()}); err != nil {
		t.Fatal(err)
	}
	return tk
}

// drive moves the head over the ticks. A step that fails (a crash) is followed by a RESTART: a new ticker over the same store.
func drive(t testing.TB, fc *fakeChain, src *headSource, spy *spyStore, mk func() *capture.Ticker, heads []uint64) {
	t.Helper()
	tk := mk()
	for _, h := range heads {
		src.head = h
		for attempt := 0; attempt < 4; attempt++ {
			res, err := tk.Step(context.Background())
			if err != nil {
				spy.crash = 0
				tk = mk()
				continue
			}
			if res.Kind != capture.StepTicked {
				break
			}
		}
	}
}

// legReport builds the whole leg over the store (E1, E2, the stored hop chain) and verifies it with the REAL verifier.
func legReport(t testing.TB, fc *fakeChain, src *headSource, st capture.Store) (ci.Report, capture.LinkPlan, error) {
	t.Helper()
	ctx := context.Background()
	cfg := fc.config(src)
	att, err := capture.CaptureAttest(ctx, cfg, capture.AttestRequest{TxHash: fc.attTx})
	if err != nil || att.Stated != nil {
		t.Fatalf("CaptureAttest: %v %+v", err, att)
	}
	plan, hc, perr := capture.PlanLink(ctx, st, fc.w.Manifest, fc.w.Spec.Chain, fc.facts(t).AnchorID, att.Block, fc.w.Spec.Blocks.Settle.Number)
	req := fc.request()
	facts := fc.facts(t)
	var part *capture.AttestPart
	if perr != nil {
		var oor *capture.OutOfReachError
		if !errors.As(perr, &oor) {
			return ci.Report{}, plan, perr
		}
		req.Link, req.HopNumbers = ci.LinkSpine, nil
		var derr error
		if facts, derr = capture.DeriveFacts(fc.w.Manifest, fc.w.Spec.Chain, fc.tx, fc.rc, req); derr != nil {
			t.Fatal(derr)
		}
		part = &capture.AttestPart{Stated: capture.OutOfReachStated(oor, att.Block)}
	} else {
		if len(plan.HopNumbers) != len(req.HopNumbers) {
			return ci.Report{}, plan, fmt.Errorf("plan hops %v, world hops %v", plan.HopNumbers, req.HopNumbers)
		}
		var berr error
		if part, berr = capture.BuildAttestPartHops(ctx, src, att, fc.headers[fc.w.Spec.Blocks.Settle.Number], plan, hc); berr != nil {
			t.Fatalf("BuildAttestPartHops: %v", berr)
		}
	}
	set, err := capture.CaptureSettle(ctx, cfg, req)
	if err != nil || set.Stated != nil {
		t.Fatalf("CaptureSettle: %v %+v", err, set)
	}
	_, container, err := capture.Assemble(capture.Parts{Chain: fc.w.Spec.Chain, Leg: set.Block, Facts: facts, Settle: set, Attest: part})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if perr == nil && !bytes.Equal(container, fc.w.ContainerBytes) {
		t.Fatalf("the container built from stored ticks (%d B) differs from the world's (%d B)", len(container), len(fc.w.ContainerBytes))
	}
	v, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := v.Verify(fc.w.Ctx, container, fc.w.Manifest)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep, plan, perr
}

func partOf(rep ci.Report, name string) *ci.PartResult {
	for i := range rep.Parts {
		if rep.Parts[i].Part == name {
			return &rep.Parts[i]
		}
	}
	return nil
}

func requireAttestVerified(t testing.TB, rep ci.Report) {
	t.Helper()
	for _, p := range rep.Parts {
		if p.Status == ci.StatusRefused {
			t.Fatalf("part %s refused: %+v", p.Part, p.State)
		}
	}
	for _, name := range []string{ci.JudgedAuthorizationAttest, ci.JudgedIntraBlockWindow} {
		if p := partOf(rep, name); p == nil || p.Status != ci.StatusVerified {
			t.Fatalf("part %s: %+v", name, p)
		}
	}
}

func halfWindow(t testing.TB, chain uint64) (h, w uint64) {
	t.Helper()
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	h, w, err = capture.TickSpacing(m, chain)
	if err != nil {
		t.Fatal(err)
	}
	return h, w
}

func ladder(g uint64, n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = g
	}
	return out
}

// TestLongGapTicksVerifyWithTheRealVerifier: a world with a gap of 5 x W/2 blocks between the attestation and the settlement, ticks at the
// exact boundary W/2 and at W/2+1, a tick spacing of exactly W, all built from the stored ticks by the loop and judged by NewDefaultVerifier.
func TestLongGapTicksVerifyWithTheRealVerifier(t *testing.T) {
	for _, chain := range chains {
		h, w := halfWindow(t, chain)
		cases := []struct {
			name string
			gaps []uint64
		}{
			{"W/2", []uint64{h, h, h, h, h + 2}},
			{"W/2+1", ladder(h+1, 5)},
			{"W between two ticks and W to N", []uint64{h, w, h, h, w}},
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%d/%s", chain, tc.name), func(t *testing.T) {
				fc := newFakeChainWith(t, chain, "hops", longEdit(tc.gaps))
				src := newHeadSource(fc)
				st := newSpy()
				drive(t, fc, src, st, func() *capture.Ticker { return newTicker(t, fc, src, st) }, fc.tickHeads())
				rep, plan, err := legReport(t, fc, src, st)
				if err != nil {
					t.Fatal(err)
				}
				if plan.Link != ci.LinkHops || len(plan.HopNumbers) != 5 {
					t.Fatalf("plan %+v, want link 1 with B_v and 4 ticks", plan)
				}
				requireAttestVerified(t, rep)
			})
		}
	}
}

// TestATickMissedForMoreThanWIsTheNamedOutOfReach: ticks W blocks apart still chain; W+1 apart break the chain, and the leg carries
// attest_block_out_of_reach{gap,window,hops_carried,last_hop} with the ticks it did carry, judged by the real verifier.
func TestATickMissedForMoreThanWIsTheNamedOutOfReach(t *testing.T) {
	chain := uint64(11155111)
	h, w := halfWindow(t, chain)
	gaps := []uint64{h, w + 1, h, h, h}
	fc := newFakeChainWith(t, chain, "hops", longEdit(gaps))
	src := newHeadSource(fc)
	st := newSpy()
	drive(t, fc, src, st, func() *capture.Ticker { return newTicker(t, fc, src, st) }, fc.tickHeads())
	rep, _, perr := legReport(t, fc, src, st)
	var oor *capture.OutOfReachError
	if !errors.As(perr, &oor) {
		t.Fatalf("want OutOfReachError, got %v", perr)
	}
	bv := fc.bvRef().Number
	n := fc.w.Spec.Blocks.Settle.Number
	if oor.Gap != n-bv || oor.Window != w || oor.HopsCarried != 1 || oor.LastHop != bv+h {
		t.Fatalf("out of reach %+v: want gap %d window %d hops_carried 1 last_hop %d", oor, n-bv, w, bv+h)
	}
	p := partOf(rep, ci.JudgedAuthorizationAttest)
	if p == nil || p.Status != ci.StatusUnproven || p.State == nil || p.State.Reason != ci.StatedAttestBlockOutOfReach {
		t.Fatalf("authorization_attest: %+v", p)
	}
	for k, want := range map[string]uint64{"gap": n - bv, "window": w, "hops_carried": 1, "last_hop": bv + h} {
		if fmt.Sprint(p.State.Fields[k]) != fmt.Sprint(want) {
			t.Fatalf("state field %s = %v, want %d", k, p.State.Fields[k], want)
		}
	}
	// the chain of the world is also refused by the real verifier when the SAME numbers are forced into one hop chain: the builder never
	// stores a tick it could not link, so the refusal lives in the unlinked ticks, not in a container
	if !strings.Contains(capture.OutOfReachStated(oor, fc.bvRef()).Detail, fmt.Sprintf("hops_carried=1;last_hop=%d", bv+h)) {
		t.Fatalf("the Stated detail does not carry the fields")
	}
}

// TestTickLoopSurvivesACrashAtEveryOperation: a crash (error or panic, before or after the operation took effect) at every store, header and
// provider operation of the loop; the restart derives everything from the store and ends with exactly the rows of an uninterrupted run.
func TestTickLoopSurvivesACrashAtEveryOperation(t *testing.T) {
	chain := uint64(11155111)
	h, _ := halfWindow(t, chain)
	fc := newFakeChainWith(t, chain, "hops", longEdit(ladder(h, 5)))
	run := func(crash int, after, panics bool) *spyStore {
		spy := newSpy()
		spy.crash, spy.after, spy.panics = crash, after, panics
		hs := newHeadSource(fc)
		src := &crashSource{hs, spy}
		drive(t, fc, hs, spy, func() *capture.Ticker { return newTicker(t, fc, src, spy) }, fc.tickHeads())
		return spy
	}
	base := run(0, false, false)
	if len(base.rows) != 4+1 { // 4 ticks and the first link
		t.Fatalf("an uninterrupted run stores %d rows, want 5", len(base.rows))
	}
	total := base.ops
	if total < 20 {
		t.Fatalf("only %d operations counted", total)
	}
	for _, mode := range []struct{ after, panics bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		for at := 1; at <= total; at++ {
			got := run(at, mode.after, mode.panics)
			if len(got.rows) != len(base.rows) {
				t.Fatalf("crash at op %d (after=%v panic=%v): %d rows, want %d", at, mode.after, mode.panics, len(got.rows), len(base.rows))
			}
			for k, v := range base.rows {
				if !bytes.Equal(got.rows[k], v) {
					t.Fatalf("crash at op %d (after=%v panic=%v): row %s differs", at, mode.after, mode.panics, k)
				}
			}
		}
	}
}

// TestTickerOnlyWritesTickRowsAndNeverTouchesTheStations: non-interference with attestation and settlement - the loop's writes are the tick
// and first-link keys, nothing under the attest or settle items; a hostile head reader (panic) is a failed step and the next step works.
func TestTickerOnlyWritesTickRowsAndNeverTouchesTheStations(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	src := newHeadSource(fc)
	st := newSpy()
	tk := newTicker(t, fc, src, st)
	src.headPanic = true
	if _, err := tk.Step(context.Background()); err == nil {
		t.Fatal("a panic in the head reader must be a step error")
	} else {
		var pe *capture.PanicError
		if !errors.As(err, &pe) {
			t.Fatalf("want PanicError, got %v", err)
		}
	}
	src.headPanic = false
	drive(t, fc, src, st, func() *capture.Ticker { return tk }, fc.tickHeads())
	if len(st.puts) == 0 {
		t.Fatal("nothing stored")
	}
	for _, k := range st.puts {
		if !strings.HasPrefix(k.Item, capture.ItemTickPrefix) && !strings.HasPrefix(k.Item, capture.ItemFirstPrefix) {
			t.Fatalf("the ticker wrote %s", k)
		}
	}
}

func TestTickerHostileProviders(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	heads := fc.tickHeads()
	for _, mode := range []hostile{lieSlot, lieValue, lieBlock, down, pruned, padNodes, hugeReply, leakyText} {
		// a lone hostile provider stores nothing; the honest one next to it yields the honest rows
		src := newHeadSource(fc, mode)
		st := newSpy()
		tk := newTicker(t, fc, src, st)
		src.head = heads[0]
		res, err := tk.Step(context.Background())
		if mode == padNodes {
			if err != nil || res.Kind != capture.StepTicked {
				t.Fatalf("padNodes: %v %+v", err, res)
			}
			continue
		}
		if len(st.puts) != 0 {
			t.Fatalf("mode %d: a hostile provider got %d rows stored (%v %+v)", mode, len(st.puts), err, res)
		}
		mixed := newHeadSource(fc, mode, honest)
		st2 := newSpy()
		tk2 := newTicker(t, fc, mixed, st2)
		mixed.head = heads[0]
		if res, err := tk2.Step(context.Background()); err != nil || res.Kind != capture.StepTicked || len(st2.puts) != 2 {
			t.Fatalf("mode %d with an honest provider: %v %+v puts %d", mode, err, res, len(st2.puts))
		}
	}
}

func TestTickerWrongBlockHashIsASkippedLinkNotAStoredLie(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	src := newHeadSource(fc)
	st := newSpy()
	cfg := fc.config(src)
	tk, _ := capture.NewTicker(capture.TickConfig{Config: cfg, Store: st})
	bad := fc.bvRef()
	bad.Hash[0] ^= 1 // an attestation block that was reorged away: the slot holds the hash of the block that stayed
	_ = tk.Track(capture.TrackedAnchor{AnchorID: fc.facts(t).AnchorID, Bv: bad})
	src.head = fc.tickHeads()[0]
	res, err := tk.Step(context.Background())
	if err != nil || res.Kind != capture.StepTicked || res.Mismatches != 1 || len(res.Firsts) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	for _, k := range st.puts {
		if strings.HasPrefix(k.Item, capture.ItemFirstPrefix) {
			t.Fatal("a first link was stored for a block whose slot holds another hash")
		}
	}
}

func TestTickerStopsAtTheDeadlineAndAtTheReach(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	h, w := halfWindow(t, 11155111)
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name   string
		a      capture.TrackedAnchor
		hook   func([32]byte) (time.Time, bool)
		reason string
	}{
		{"own deadline", capture.TrackedAnchor{Bv: fc.bvRef(), Deadline: now}, nil, "deadline"},
		{"deadline one second ahead", capture.TrackedAnchor{Bv: fc.bvRef(), Deadline: now.Add(time.Second)}, nil, ""},
		{"memberChainDeadline hook", capture.TrackedAnchor{Bv: fc.bvRef()}, func([32]byte) (time.Time, bool) { return now.Add(-time.Second), true }, "deadline"},
		{"reach: 16 ticks and one window past B_v", capture.TrackedAnchor{Bv: ci.BlockRef{Number: fc.tickHeads()[0] - 16*h - w - 1, Hash: [32]byte{1}}}, nil, "reach"},
		{"reach: exactly at the bound", capture.TrackedAnchor{Bv: ci.BlockRef{Number: fc.tickHeads()[0] - 16*h - w, Hash: [32]byte{1}}}, nil, ""},
	} {
		src := newHeadSource(fc)
		src.head = fc.tickHeads()[0]
		cfg := fc.config(src)
		tk, _ := capture.NewTicker(capture.TickConfig{Config: cfg, Store: newSpy(), Deadline: tc.hook})
		tc.a.AnchorID = [32]byte{9}
		_ = tk.Track(tc.a)
		res, err := tk.Step(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.reason != "" && (res.Dropped[tc.reason] != 1 || res.Kind != capture.StepIdle || tk.Tracked() != 0) {
			t.Fatalf("%s: %+v tracked %d", tc.name, res, tk.Tracked())
		}
		if tc.reason == "" && (len(res.Dropped) != 0 || tk.Tracked() != 1) {
			t.Fatalf("%s: dropped %+v tracked %d", tc.name, res.Dropped, tk.Tracked())
		}
	}
}

func TestTickerBoundsMemoryConcurrencyAndTracking(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	src := newHeadSource(fc)
	src.head = fc.tickHeads()[0]
	var held, released int32
	full := true
	st := newSpy()
	cfg := fc.config(src)
	cfg.Gate = capture.NewGate(1)
	tk, _ := capture.NewTicker(capture.TickConfig{Config: cfg, Store: st, Reserve: func() (func(), bool) {
		if full {
			return nil, false
		}
		atomic.AddInt32(&held, 1)
		return func() { atomic.AddInt32(&released, 1) }, true
	}})
	_ = tk.Track(capture.TrackedAnchor{AnchorID: fc.facts(t).AnchorID, Bv: fc.bvRef()})
	if res, _ := tk.Step(context.Background()); res.Kind != capture.StepNoBudget || len(st.puts) != 0 {
		t.Fatalf("a full budget must read nothing: %+v", res)
	}
	full = false
	release, _ := cfg.Gate.Acquire(context.Background())
	gctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, err := tk.Step(gctx); !errors.Is(err, context.DeadlineExceeded) || len(st.puts) != 0 {
		t.Fatalf("a full gate holds the step until its context ends and reads nothing: %v", err)
	}
	stop()
	release()
	held, released = 0, 0
	if res, err := tk.Step(context.Background()); err != nil || res.Kind != capture.StepTicked {
		t.Fatalf("%v %+v", err, res)
	}
	if atomic.LoadInt32(&held) != atomic.LoadInt32(&released) || held != 1 || cfg.Gate.InUse() != 0 {
		t.Fatalf("reservations held %d released %d, gate in use %d", held, released, cfg.Gate.InUse())
	}
	for i := 0; i < capture.MaxTracked+1; i++ {
		var id [32]byte
		id[0], id[1], id[2] = byte(i), byte(i>>8), 1
		err := tk.Track(capture.TrackedAnchor{AnchorID: id, Bv: fc.bvRef()})
		if i < capture.MaxTracked-1 && err != nil {
			t.Fatalf("anchor %d: %v", i, err)
		}
		if i >= capture.MaxTracked-1 && !errors.Is(err, capture.ErrTooManyTracked) {
			t.Fatalf("anchor %d: want ErrTooManyTracked, got %v", i, err)
		}
	}
}

func TestBuildHopChainHostileStore(t *testing.T) {
	fc := newFakeChainWith(t, 11155111, "hops", longEdit(ladder(4095, 5)))
	src := newHeadSource(fc)
	st := newSpy()
	drive(t, fc, src, st, func() *capture.Ticker { return newTicker(t, fc, src, st) }, fc.tickHeads())
	anchor := fc.facts(t).AnchorID
	n := fc.w.Spec.Blocks.Settle.Number
	// every stored row corrupted in turn (truncated, a flipped byte, trailing bytes): a named error or a shorter chain, never a panic and never a chain
	var keys []capture.Key
	for k := range st.rows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Item < keys[j].Item })
	for _, k := range keys {
		orig := st.rows[k]
		for _, mut := range []func([]byte) []byte{
			func(b []byte) []byte { return b[:len(b)-1] },
			func(b []byte) []byte { c := append([]byte(nil), b...); c[len(c)/2] ^= 0x55; return c },
			func(b []byte) []byte { return append(append([]byte(nil), b...), 0) },
			func(b []byte) []byte { return nil },
		} {
			bad := capture.NewMemStore()
			for kk, v := range st.rows {
				data := v
				if kk == k {
					data = mut(orig)
				}
				if len(data) > 0 {
					_ = bad.Put(context.Background(), kk, data)
				}
			}
			hc, err := capture.BuildHopChain(context.Background(), bad, fc.w.Manifest, 11155111, anchor, fc.bvRef(), n)
			if err == nil && hc != nil {
				// a flipped byte inside a trie node is invisible to the row decode; the chain it yields is judged by Assemble and the verifier
				continue
			}
			if err == nil {
				t.Fatalf("row %s: neither a chain nor an error", k)
			}
		}
	}
	// a listing past its bound is a named error
	big := &bigStore{Store: st.Store}
	if _, err := capture.BuildHopChain(context.Background(), big, fc.w.Manifest, 11155111, anchor, fc.bvRef(), n); !errors.Is(err, capture.ErrTickListTooLarge) {
		t.Fatalf("want ErrTickListTooLarge, got %v", err)
	}
	// a settlement block not after B_v is refused, and an unknown chain has no tick chain
	if _, err := capture.BuildHopChain(context.Background(), st.Store, fc.w.Manifest, 11155111, anchor, fc.bvRef(), fc.bvRef().Number); err == nil {
		t.Fatal("n == B_v must be refused")
	}
	if _, err := capture.BuildHopChain(context.Background(), st.Store, fc.w.Manifest, 1, anchor, fc.bvRef(), n); !errors.Is(err, capture.ErrNoTickWindow) {
		t.Fatalf("want ErrNoTickWindow, got %v", err)
	}
}

type bigStore struct{ capture.Store }

func (b *bigStore) ListByAnchor(_ context.Context, _ uint64, _ [32]byte) ([]capture.Key, error) {
	out := make([]capture.Key, 4097)
	for i := range out {
		out[i] = capture.Key{Chain: 1, AnchorID: [32]byte{1}, BlockHash: [32]byte{2}, Item: fmt.Sprintf("x/%d", i)}
	}
	return out, nil
}
