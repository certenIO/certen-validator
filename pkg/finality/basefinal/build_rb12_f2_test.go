// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-F2 (live, 2026-10-23): every Base `finalized` build of a leg created before the Denim fork (2026-10-21T18:00Z) logged
//   finality_verifier_failed{cause="the factory scan did not reach the covering game within its bound"}
// although the covering game exists and is simply not resolved yet. The factory scan estimated the covering index by dividing by the
// NEWEST game's range, which after Denim is 6000 L2 blocks (200 ms blocks) while every game before it spans 600: the estimate lands
// about 160 games from the truth, past the 64-step walk. The world below is the live factory (measured 2026-10-23T10:10Z over
// ethereum-sepolia-rpc.publicnode.com: gameCount 28734, games <= 28633 span 600 L2 blocks, games >= 28634 span 6000, newest
// l2SequenceNumber 49025063, one game every 20 minutes). Only key names and numbers of the live listing are used.

const (
	prodGameCount   = 28734
	prodBoundary    = 28633    // the last game of the 2 s era
	prodBoundarySeq = 48425063 // its l2SequenceNumber
	prodNewestIdx   = prodGameCount - 1
)

// prodFactory is a scripted DisputeGameFactory with the live shape. Codes are the recorded game's code (a real aggregate_v1 clone)
// with the l2 sequence number patched; games of the fast era point at the 0.3.0 implementation, which carries the 6000/300 pair.
type prodFactory struct {
	w          *liveWorld
	newestAt   uint64 // createdAt of the newest game
	mu         sync.Mutex
	calls      map[string]int
	countErr   error
	gap        bool // a hole between two games (no game covers the blocks in it)
	gapAfter   uint64
	fastImpl   [20]byte
	proxyIndex map[[20]byte]uint64
}

func newProdFactory(t *testing.T) *prodFactory {
	w := loadLive(t)
	f := &prodFactory{w: w, newestAt: uint64(time.Date(2026, 10, 23, 4, 6, 0, 0, time.UTC).Unix()), calls: map[string]int{}, proxyIndex: map[[20]byte]uint64{}}
	for _, r := range w.bp.Impl {
		if r.Role == RoleGameImpl && len(r.IntervalPairs) == 2 {
			f.fastImpl = r.Impl
		}
	}
	if f.fastImpl == ([20]byte{}) {
		t.Fatal("the pins carry no 0.3.0 game implementation row")
	}
	return f
}

func (f *prodFactory) seq(i uint64) uint64 {
	s := uint64(0)
	if i <= prodBoundary {
		s = prodBoundarySeq - 600*(prodBoundary-i)
	} else {
		s = prodBoundarySeq + 6000*(i-prodBoundary)
	}
	if f.gap && i > f.gapAfter {
		s += 3000 // the games after the hole start 3000 blocks later, so (start, l2seq] of game gapAfter+1 skips them
	}
	return s
}

func (f *prodFactory) start(i uint64) uint64 {
	if i <= prodBoundary {
		return f.seq(i) - 600
	}
	return f.seq(i) - 6000
}

func (f *prodFactory) created(i uint64) uint64 { return f.newestAt - 1200*(prodNewestIdx-i) }

func (f *prodFactory) count(k string) {
	f.mu.Lock()
	f.calls[k]++
	f.mu.Unlock()
}

func (f *prodFactory) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.calls {
		n += v
	}
	return n
}

func (f *prodFactory) proxy(i uint64) [20]byte {
	var p [20]byte
	p[0] = 0xfa
	binary.BigEndian.PutUint64(p[12:], i)
	f.proxyIndex[p] = i
	return p
}

func (f *prodFactory) GameCount(context.Context) (uint64, error) {
	f.count("count")
	if f.countErr != nil {
		return 0, f.countErr
	}
	return prodGameCount, nil
}

func (f *prodFactory) GameAt(_ context.Context, i uint64) (GameInfo, error) {
	f.count("at")
	if i >= prodGameCount {
		return GameInfo{}, fmt.Errorf("gameAtIndex(%d): no answer", i)
	}
	return GameInfo{Type: 621, CreatedAt: f.created(i), Proxy: f.proxy(i)}, nil
}

func (f *prodFactory) Code(_ context.Context, p [20]byte) ([]byte, error) {
	f.count("code")
	i := f.proxyIndex[p]
	code := append([]byte(nil), f.w.body.GameCode...)
	lay := f.w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	binary.BigEndian.PutUint64(code[tl+84+24:tl+84+32], f.seq(i))
	if i > prodBoundary {
		copy(code[len(lay.CloneHead)+2+len(lay.CloneMid):], f.fastImpl[:])
	}
	return code, nil
}

func (f *prodFactory) Slot(_ context.Context, p [20]byte, slot [32]byte) ([32]byte, error) {
	f.count("slot")
	i := f.proxyIndex[p]
	var out [32]byte
	switch slot {
	case be32(slotGameStartL2Seq):
		return be32(f.start(i)), nil
	case be32(slotGameMain): // IN_PROGRESS
		put64(&out, 0, f.created(i))
	case be32(slotGameExpectedRes):
		put64(&out, 0, f.created(i)+432000)
		put64(&out, 8, 1)
	}
	return out, nil
}

func (f *prodFactory) builder(w *liveWorld, now time.Time) *Builder {
	return &Builder{Pins: w.pins, Games: f, Now: func() time.Time { return now }, MaxScan: 64}
}

// legAt is a Base leg with the given number and header time (the header is the only part of a leg the game search reads).
func legAt(number, ts uint64) finality.BlockRef {
	raw, err := rlp.EncodeToBytes(&types.Header{Number: new(big.Int).SetUint64(number), Time: ts, Difficulty: big.NewInt(0), BaseFee: big.NewInt(1)})
	if err != nil {
		panic(err)
	}
	h, err := finality.ReadHeader(raw)
	if err != nil {
		panic(err)
	}
	return finality.BlockRef{Chain: uint64(Chain), Number: number, Hash: h.Hash, HeaderRLP: raw}
}

// firstIndexAtOrAbove is the index of the covering game by the definition: the first game whose l2 sequence number reaches the block.
func (f *prodFactory) firstIndexAtOrAbove(n uint64) uint64 {
	for i := uint64(0); i < prodGameCount; i++ {
		if f.seq(i) >= n {
			return i
		}
	}
	return prodGameCount
}

func TestRB12CoveringGameIsFoundForLegsOnBothSidesOfTheDenimFork(t *testing.T) {
	f := newProdFactory(t)
	now := time.Unix(int64(f.newestAt)+6*3600, 0)
	b := f.builder(f.w, now)
	ctx := context.Background()
	startOf := func(proxy [20]byte) (uint64, error) {
		w, err := f.Slot(ctx, proxy, be32(slotGameStartL2Seq))
		return binary.BigEndian.Uint64(w[24:]), err
	}
	for _, leg := range []uint64{48278400, 48330263, 48333021, 48333406, 48400000, prodBoundarySeq, prodBoundarySeq + 1, 48431063, 48725063, 49025063} {
		f.mu.Lock()
		f.calls = map[string]int{}
		f.mu.Unlock()
		g, pend, err := b.covering(ctx, b.mustPins(t), leg, startOf, finality.LevelSet(0))
		if err != nil || pend != nil {
			t.Fatalf("leg %d: the covering game exists (index %d) but the search returned pend=%v err=%v", leg, f.firstIndexAtOrAbove(leg), pend, err)
		}
		if want := f.firstIndexAtOrAbove(leg); g.Index != want {
			t.Fatalf("leg %d: covering game index %d, want %d", leg, g.Index, want)
		}
		if !(g.Start < leg && leg <= g.L2Seq) {
			t.Fatalf("leg %d: game range (%d, %d] does not hold the block", leg, g.Start, g.L2Seq)
		}
		if n := f.total(); n > 120 {
			t.Fatalf("leg %d: %d provider calls to find one game in a factory of %d", leg, n, prodGameCount)
		}
	}
}

func (b *Builder) mustPins(t *testing.T) *Pins {
	t.Helper()
	bp, err := ParsePins(b.Pins)
	if err != nil {
		t.Fatal(err)
	}
	return bp
}

// The measured leg of RB12-F2: created 2026-10-19, 4 d 21 h before the check. Its game exists and is in progress, so the state is the
// pending game_unresolved with the chain's own expectedResolution as its eta, never a verifier failure.
func TestRB12AnOldLegWhoseGameIsStillInProgressIsPendingWithTheChainsExpectedResolution(t *testing.T) {
	f := newProdFactory(t)
	now := time.Unix(int64(f.newestAt)+6*3600, 0)
	leg := legAt(48333406, uint64(time.Date(2026, 10, 19, 17, 5, 0, 0, time.UTC).Unix()))
	_, pend, err := f.builder(f.w, now).build(context.Background(), leg, finality.LevelSet(0).With(finality.LevelIncluded))
	if err != nil {
		t.Fatalf("an honest leg whose game is not resolved yet must not fail: %v", err)
	}
	if pend == nil || pend.Reason != "game_unresolved" {
		t.Fatalf("want finality_pending{game_unresolved}, got %+v", pend)
	}
	idx := f.firstIndexAtOrAbove(48333406)
	if want := time.Unix(int64(f.created(idx)+432000), 0); !pend.ETA.Equal(want) {
		t.Fatalf("eta %s, want the game's expectedResolution %s", pend.ETA, want)
	}
	if pend.LevelReached != finality.LevelIncluded || pend.NextLevel != finality.LevelFinalized {
		t.Fatalf("the pending names the level reached and the next level: %+v", pend)
	}
}

// A leg newer than the newest game: pending no_covering_game with the spec's expected game time (annex R11-base-sepolia Q8 / the
// named-states table: the covering game is created about 30-70 minutes after the block; 70 minutes is the late end).
func TestRB12ALegBeyondTheNewestGameIsPendingWithTheSpecETA(t *testing.T) {
	f := newProdFactory(t)
	legTime := f.newestAt + 3600
	leg := legAt(f.seq(prodNewestIdx)+1000, legTime)
	now := time.Unix(int64(legTime)+10*60, 0)
	_, pend, err := f.builder(f.w, now).build(context.Background(), leg, finality.LevelSet(0).With(finality.LevelIncluded))
	if err != nil {
		t.Fatal(err)
	}
	if pend == nil || pend.Reason != "no_covering_game" {
		t.Fatalf("want finality_pending{no_covering_game}, got %+v", pend)
	}
	if want := time.Unix(int64(legTime)+70*60, 0); !pend.ETA.Equal(want) {
		t.Fatalf("eta %s, want block time + 70 min = %s", pend.ETA, want)
	}
	if pend.Judged["eta_basis"] != "annex_base_sepolia_game_lag_70min" {
		t.Fatalf("the eta says where it comes from: %v", pend.Judged)
	}
	// once the spec's window has passed the eta is the next game slot, still in the future
	_, pend, _ = f.builder(f.w, time.Unix(int64(legTime)+3*3600, 0)).build(context.Background(), leg, finality.LevelSet(0).With(finality.LevelIncluded))
	if pend == nil || !pend.ETA.After(time.Unix(int64(legTime)+3*3600, 0)) {
		t.Fatalf("a pending state past its window still states a future eta: %+v", pend)
	}
}

// A hole in the factory's ranges and a provider that fails are each a NAMED unavailable state with the
// values they were judged at. finality_verifier_failed is for evidence that was built and failed verification, and none was built.
func TestRB12FactoryTroublesAreNamedUnavailableStatesNeverVerifierFailed(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		mutate func(f *prodFactory)
		leg    uint64
		code   string
		reason string
	}{
		{"hole between two games", func(f *prodFactory) { f.gap, f.gapAfter = true, 28700 }, 0, "finality_covering_game_unavailable", "gap_between_games"},
		{"provider fails", func(f *prodFactory) { f.countErr = fmt.Errorf("gameCount(): HTTP 429") }, 48333406, "finality_game_source_unavailable", ""},
	}
	for _, c := range cases {
		f := newProdFactory(t)
		c.mutate(f)
		leg := c.leg
		if leg == 0 { // a block inside the hole
			leg = f.seq(28700) + 1500
		}
		now := time.Unix(int64(f.newestAt)+6*3600, 0)
		_, pend, err := f.builder(f.w, now).build(ctx, legAt(leg, uint64(time.Date(2026, 10, 19, 17, 5, 0, 0, time.UTC).Unix())), finality.LevelSet(0).With(finality.LevelIncluded))
		st, named := finality.AsNamed(err)
		if pend != nil || !named {
			t.Fatalf("%s: want a named unavailable state, got pend=%v err=%v", c.name, pend, err)
		}
		if st.Code == finality.CodeVerifierFailed {
			t.Fatalf("%s: finality_verifier_failed claims built evidence failed verification, and none was built: %v", c.name, st)
		}
		if st.Code != c.code {
			t.Fatalf("%s: code %q, want %q (%v)", c.name, st.Code, c.code, st)
		}
		if c.reason != "" && st.Fields["reason"] != c.reason {
			t.Fatalf("%s: reason %v, want %q (%v)", c.name, st.Fields["reason"], c.reason, st)
		}
	}
}
