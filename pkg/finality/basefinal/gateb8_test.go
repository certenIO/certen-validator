// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

var haveIncluded = finality.LevelSet(0).With(finality.LevelIncluded)

// scriptGames is a factory with scripted games and failures, over the live world for the values no script changes.
type scriptGames struct {
	base     fakeGames
	count    uint64
	countErr error
	atErr    error
	failAt   map[uint64]error // GameAt fails for these indexes only
	codeErr  error
	slotErr  error
	l2seq    map[[20]byte]uint64 // per proxy: the end of its range (its code carries it); the live game when absent
	codes    map[[20]byte][]byte
	slots    map[[20]byte]map[[32]byte][32]byte
	nSlot    int
}

func (g *scriptGames) GameCount(context.Context) (uint64, error) { return g.count, g.countErr }
func (g *scriptGames) GameAt(ctx context.Context, i uint64) (GameInfo, error) {
	if g.atErr != nil {
		return GameInfo{}, g.atErr
	}
	if err := g.failAt[i]; err != nil {
		return GameInfo{}, err
	}
	info, _ := g.base.GameAt(ctx, i)
	if i != g.liveIndex() {
		info.Proxy = [20]byte{byte(i + 1), 0xaa}
	}
	return info, nil
}
func (g *scriptGames) liveIndex() uint64 { return g.base.w.liveIdx }
func (g *scriptGames) Code(_ context.Context, proxy [20]byte) ([]byte, error) {
	if g.codeErr != nil {
		return nil, g.codeErr
	}
	if c, ok := g.codes[proxy]; ok {
		return c, nil
	}
	if e, ok := g.l2seq[proxy]; ok {
		w := g.base.w
		lay := w.bp.Layouts[LayoutAggregateV1]
		tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
		code := append([]byte(nil), w.body.GameCode...)
		binary.BigEndian.PutUint64(code[tl+84+24:], e)
		return code, nil
	}
	return g.base.Code(context.Background(), proxy)
}
func (g *scriptGames) Slot(ctx context.Context, proxy [20]byte, slot [32]byte) ([32]byte, error) {
	g.nSlot++
	if g.slotErr != nil {
		return [32]byte{}, g.slotErr
	}
	if m, ok := g.slots[proxy]; ok {
		if v, ok := m[slot]; ok {
			return v, nil
		}
	}
	if e, ok := g.l2seq[proxy]; ok && slot == be32(slotGameStartL2Seq) {
		return be32(e - 600), nil
	}
	return g.base.Slot(ctx, proxy, slot)
}

func (w *liveWorld) scripted() *scriptGames { return &scriptGames{base: fakeGames{w}, count: 1} }

// factory is a factory of n games of which game t is the live one; the others end 600 blocks apart below it and `after` blocks apart
// above it, each with its own proxy and code.
func (w *liveWorld) factory(n, t int, after uint64) *scriptGames {
	w.liveIdx = uint64(t)
	g := w.scripted()
	g.count = uint64(n)
	lay := w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(w.body.GameCode[tl+84+24 : tl+84+32])
	g.l2seq = map[[20]byte]uint64{}
	for i := 0; i < n; i++ {
		if i == t {
			continue
		}
		var e uint64
		if i > t {
			e = x + after*uint64(i-t)
		} else {
			e = x - 600*uint64(t-i)
		}
		g.l2seq[[20]byte{byte(i + 1), 0xaa}] = e
	}
	return g
}

func (w *liveWorld) store(t *testing.T) *MemStore {
	t.Helper()
	st := &MemStore{}
	w.capture(t, st, w.body.StateBlock, aOf(w).Hash)
	return st
}

func (w *liveWorld) built(t *testing.T, b *Builder) (*finality.Addendum, *finality.PendingState, error) {
	t.Helper()
	return b.buildLeg(context.Background(), w.leg, haveIncluded)
}

func wantAddendum(t *testing.T, w *liveWorld, ad *finality.Addendum, p *finality.PendingState, err error) {
	t.Helper()
	if err != nil || p != nil || ad == nil || !bytes.Equal(ad.Evidence, w.evidence) {
		t.Fatalf("want the published evidence, got ad=%v pend=%v err=%v", ad != nil, p, err)
	}
}

func wantPendingReason(t *testing.T, p *finality.PendingState, err error, reason string) *finality.PendingState {
	t.Helper()
	if err != nil || p == nil || p.Reason != reason || p.Chain != uint64(Chain) || p.NextLevel != finality.LevelFinalized {
		t.Fatalf("want pending %s, got %+v %v", reason, p, err)
	}
	return p
}

func TestTheBuilderFindsTheCoveringGameByEstimateThenWalkAndNamesTheEnds(t *testing.T) {
	for _, c := range []struct {
		name         string
		n, t         int
		after        uint64
		maxScan      int
		wantFound    bool
		wantScanFail bool
	}{
		{"the live game is the only one", 1, 0, 600, 0, true, false},
		{"the live game is the newest of many", 30, 29, 600, 0, true, false},
		{"the estimate is exact: the live game is in the middle of regular games", 30, 12, 600, 1, true, false},
		{"games above are wider apart: the estimate lands below and the walk goes up", 30, 12, 700, 0, true, false},
		{"games above are closer: the estimate lands above and the walk goes down", 30, 12, 500, 0, true, false},
		{"the walk needs exactly two loads and may take two", 30, 12, 650, 2, true, false},
		{"the walk needs two loads and may take one", 30, 12, 650, 1, false, true},
	} {
		w := loadLive(t)
		g := w.factory(c.n, c.t, c.after)
		b := w.builder(t, w.store(t))
		b.Games = g
		b.MaxScan = c.maxScan
		ad, p, err := w.built(t, b)
		switch {
		case c.wantFound:
			wantAddendum(t, w, ad, p, err)
		case c.wantScanFail:
			if err == nil || !strings.Contains(err.Error(), "did not reach the covering game") || ad != nil || p != nil {
				t.Errorf("%s: %v %v %v", c.name, ad != nil, p, err)
			}
		}
	}
	// a leg above the newest game, and a leg below the oldest, wait for a game rather than guess
	w := loadLive(t)
	g := w.factory(30, 12, 600)
	b := w.builder(t, w.store(t))
	b.Games = g
	above := w.leg
	above.Number += 600*20 + 5
	_, p, err := b.buildLeg(context.Background(), above, haveIncluded)
	p = wantPendingReason(t, p, err, "no_covering_game")
	if p.Judged["leg_block"] != above.Number || p.Judged["newest_l2_sequence_number"] == nil {
		t.Errorf("%+v", p.Judged)
	}
	below := w.leg
	below.Number -= 600*20 + 5
	_, p, err = b.buildLeg(context.Background(), below, haveIncluded)
	p = wantPendingReason(t, p, err, "no_covering_game")
	if p.Judged["leg_block"] != below.Number {
		t.Errorf("%+v", p.Judged)
	}
	// the end of the newest game belongs to it; the start of a game belongs to the game before
	lay := w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(w.body.GameCode[tl+84+24 : tl+84+32])
	w2 := loadLive(t)
	g2 := w2.factory(13, 12, 600) // the live game is the newest
	b2 := w2.builder(t, w2.store(t))
	b2.Games = g2
	end := w2.leg
	end.Number = x
	_, p, err = b2.buildLeg(context.Background(), end, haveIncluded)
	if p != nil && p.Reason == "no_covering_game" {
		t.Errorf("the last block of the newest game is covered: %+v", p)
	}
	b2.L2 = anyL2{}
	startLeg := w2.leg
	startLeg.Number = x - 600 // the first block of the range is the end of the game before
	_, p, err = b2.buildLeg(context.Background(), startLeg, haveIncluded)
	p = wantPendingReason(t, p, err, "l1_proof_window_unavailable") // the game before has no capture
	_ = err
	// a factory that is empty or unreadable is a builder-side refusal that names the cause
	for name, mod := range map[string]func(g *scriptGames){
		"no games":         func(g *scriptGames) { g.count = 0 },
		"count unreadable": func(g *scriptGames) { g.countErr = errors.New("rpc down") },
		"game unreadable":  func(g *scriptGames) { g.atErr = errors.New("rpc down") },
		"code unreadable":  func(g *scriptGames) { g.codeErr = errors.New("rpc down") },
		"start unreadable": func(g *scriptGames) { g.slotErr = errors.New("rpc down") },
	} {
		ww := loadLive(t)
		gg := ww.scripted()
		mod(gg)
		bb := ww.builder(t, ww.store(t))
		bb.Games = gg
		_, _, err := ww.built(t, bb)
		se, ok := finality.AsNamed(err)
		if !ok || se.Code != finality.CodeVerifierFailed || fmt.Sprint(se.Fields["kind"]) != KindName || se.Fields["cause"] == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTheBuilderRefusesAGameWhoseCodeOrSizeItCannotPlace(t *testing.T) {
	w := loadLive(t)
	lay := w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	build := func(mod func(g *scriptGames), pins func(p *Pins)) error {
		ww := loadLive(t)
		g := ww.scripted()
		mod(g)
		b := ww.builder(t, ww.store(t))
		b.Games = g
		if pins != nil {
			// a pins copy for the builder: ParsePins reads the framework pins, so edit the parsed copy through a wrapper is not possible;
			// the tests that need other pins use the code instead
			pins(ww.bp)
		}
		_, _, err := ww.built(t, b)
		return err
	}
	code := func(f func(c []byte) []byte) func(g *scriptGames) {
		return func(g *scriptGames) {
			g.codes = map[[20]byte][]byte{g.base.w.body.GameProxy: f(append([]byte(nil), g.base.w.body.GameCode...))}
		}
	}
	// code too short to hold the fixed args: one byte short is refused, exactly enough is read
	err := build(code(func(c []byte) []byte { return c[:tl+2+lay.ArgsBaseLen-1] }), nil)
	if got := canonOf(t, err); got != unrecCanon(ReasonArgsLen) {
		t.Errorf("one byte short: %s", got)
	}
	err = build(code(func(c []byte) []byte { return append(append([]byte(nil), c[:tl+lay.ArgsBaseLen]...), c[len(c)-2:]...) }), nil)
	if se, ok := finality.AsNamed(err); ok && se.Code == CodeGameUnrecognised && fmt.Sprint(se.Fields["reason"]) == ReasonArgsLen {
		t.Errorf("code of exactly the fixed args is long enough: %v", err)
	}
	// an implementation address no pinned complete game row has
	err = build(code(func(c []byte) []byte {
		c[len(lay.CloneHead)+2+len(lay.CloneMid)] ^= 0xff
		return c
	}), nil)
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("unpinned implementation: %v", err)
	}
	// a range that no pinned interval pair explains
	err = build(func(g *scriptGames) {
		g.slots = map[[20]byte]map[[32]byte][32]byte{g.base.w.body.GameProxy: {be32(slotGameStartL2Seq): be32(1)}}
	}, nil)
	se, ok := finality.AsNamed(err)
	if !ok || se.Code != CodeGameUnrecognised || fmt.Sprint(se.Fields["reason"]) != ReasonIntervalPair {
		t.Errorf("no interval pair: %v", err)
	}
	// a start that is the end plus the pair total less one is not that pair (the total is the difference exactly)
	x := binary.BigEndian.Uint64(w.body.GameCode[tl+84+24 : tl+84+32])
	err = build(func(g *scriptGames) {
		g.slots = map[[20]byte]map[[32]byte][32]byte{g.base.w.body.GameProxy: {be32(slotGameStartL2Seq): be32(x - 599)}}
	}, nil)
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeGameUnrecognised {
		t.Errorf("total 599: %v", err)
	}
}

func TestTheBuilderPicksTheOutputRootAnchorAtOrAboveTheLeg(t *testing.T) {
	w := loadLive(t)
	lay := w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(w.body.GameCode[tl+84+24 : tl+84+32])
	start := x - 600
	interval := w.expect["output_root_block"]
	_ = interval
	// the anchor is the first intermediate root at or above the leg: the vector has index 17 and the leg right below it
	if w.body.OutputRootIndex == 0 || w.expect["output_root_index"] != fmt.Sprint(w.body.OutputRootIndex) {
		t.Fatalf("test assumption: the vector anchors at an intermediate root (%d)", w.body.OutputRootIndex)
	}
	k := uint64(w.body.OutputRootIndex)
	step := (uint64(47604773) - start) / k
	if start+step*k != 47604773 || start+step*(k-1) >= w.leg.Number || w.leg.Number > 47604773 {
		t.Fatalf("test assumption: start %d step %d k %d leg %d", start, step, k, w.leg.Number)
	}
	// the headers the builder asked for are exactly those from the anchor down to the leg
	asked := map[uint64]bool{}
	b := w.builder(t, w.store(t))
	b.L2 = recordL2{fakeL2{w}, asked}
	ad, p, err := w.built(t, b)
	wantAddendum(t, w, ad, p, err)
	if !asked[47604773] || !asked[w.leg.Number] || len(asked) != int(47604773-w.leg.Number)+1 {
		t.Errorf("headers asked %d, anchor %d..leg %d", len(asked), 47604773, w.leg.Number)
	}
	// a leg exactly at an interval boundary anchors at that root, not the next
	w2 := loadLive(t)
	w2.l2 = map[uint64]HeaderInfo{}
	for n, h := range w.l2 {
		w2.l2[n] = h
	}
	b2 := w2.builder(t, w2.store(t))
	boundary := w2.leg
	boundary.Number = start + step*(k-1)
	asked2 := map[uint64]bool{}
	b2.L2 = recordL2{fakeL2{w2}, asked2}
	_, _, _ = b2.buildLeg(context.Background(), boundary, haveIncluded)
	if len(asked2) == 0 || !asked2[start+step*(k-1)] {
		t.Errorf("a leg at a boundary: %v", asked2)
	}
	for n := range asked2 {
		if n > start+step*(k-1)+step {
			t.Errorf("asked %d above the next boundary", n)
		}
	}
}

// anyL2 serves a header for every block number.
type anyL2 struct{}

func (anyL2) L2HeaderByNumber(_ context.Context, n uint64) (HeaderInfo, error) {
	return HeaderInfo{Number: n, Raw: []byte{byte(n)}}, nil
}

type recordL2 struct {
	fakeL2
	asked map[uint64]bool
}

func (r recordL2) L2HeaderByNumber(ctx context.Context, n uint64) (HeaderInfo, error) {
	r.asked[n] = true
	return r.fakeL2.L2HeaderByNumber(ctx, n)
}

func TestAnUnresolvedGameIsReportedWithItsFactsAndTheTimeItCanResolveAt(t *testing.T) {
	lay := loadLive(t).bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	parent := [20]byte{0x77, 0x01}
	run := func(now int64, exp uint64, tee, zk bool, parentStatus byte, parentErr, expErr error) *finality.PendingState {
		w := loadLive(t)
		w.status = StatusInProgress
		g := w.scripted()
		prover := [32]byte{31: 1}
		var e [32]byte
		put64(&e, 0, exp)
		put64(&e, 8, 2)
		var pw [32]byte
		pw[15] = parentStatus
		g.slots = map[[20]byte]map[[32]byte][32]byte{w.body.GameProxy: {be32(slotGameExpectedRes): e}, parent: {be32(slotGameMain): pw}}
		if !tee {
			g.slots[w.body.GameProxy][mapSlot(be32(0), mapGameProver)] = [32]byte{}
		} else {
			g.slots[w.body.GameProxy][mapSlot(be32(0), mapGameProver)] = prover
		}
		if zk {
			g.slots[w.body.GameProxy][mapSlot(be32(1), mapGameProver)] = prover
		}
		code := append([]byte(nil), w.body.GameCode...)
		copy(code[tl+116:tl+136], parent[:])
		g.codes = map[[20]byte][]byte{w.body.GameProxy: code}
		wrapped := &errGames{scriptGames: g, parent: parent, parentErr: parentErr, expErr: expErr}
		b := w.builder(t, &MemStore{})
		b.Games = wrapped
		b.Now = func() time.Time { return time.Unix(now, 0) }
		_, p, err := w.built(t, b)
		return wantPendingReason(t, p, err, "game_unresolved")
	}
	p := run(1000, 1500, true, false, 3, nil, nil)
	if p.Judged["seconds_remaining"] != uint64(500) || p.Judged["parent_status"] != "3" || p.Judged["proof_system"] != "tee" || p.Judged["expectedResolution"] != uint64(1500) ||
		p.Judged["proofCount"] != uint64(2) || !p.ETA.Equal(time.Unix(1500, 0)) || p.Judged["createdAt"] == nil {
		t.Errorf("%+v %v", p.Judged, p.ETA)
	}
	for _, c := range []struct {
		now       int64
		remaining uint64
	}{{1500, 0}, {1501, 0}, {1499, 1}, {5000, 0}} {
		if p := run(c.now, 1500, true, false, 3, nil, nil); p.Judged["seconds_remaining"] != c.remaining {
			t.Errorf("now %d: %v", c.now, p.Judged["seconds_remaining"])
		}
	}
	for _, c := range []struct {
		tee, zk bool
		want    string
	}{{true, true, "tee+zk"}, {true, false, "tee"}, {false, true, "zk"}, {false, false, "none"}} {
		if p := run(1000, 1500, c.tee, c.zk, 3, nil, nil); p.Judged["proof_system"] != c.want {
			t.Errorf("tee=%v zk=%v: %v", c.tee, c.zk, p.Judged["proof_system"])
		}
	}
	if p := run(1000, 1500, true, false, 3, errors.New("down"), nil); p.Judged["parent_status"] != "unknown" {
		t.Errorf("parent unreadable: %v", p.Judged["parent_status"])
	}
	if p := run(1000, 1500, true, false, 0, nil, nil); p.Judged["parent_status"] != "0" {
		t.Errorf("parent in progress: %v", p.Judged["parent_status"])
	}
	// the expected resolution unreadable: zero, and no seconds remaining
	if p := run(1000, 1500, true, false, 3, nil, errors.New("down")); p.Judged["expectedResolution"] != uint64(0) || p.Judged["seconds_remaining"] != uint64(0) {
		t.Errorf("%+v", p.Judged)
	}
}

type errGames struct {
	*scriptGames
	parent    [20]byte
	parentErr error
	expErr    error
}

func (e *errGames) Slot(ctx context.Context, proxy [20]byte, slot [32]byte) ([32]byte, error) {
	if proxy == e.parent && e.parentErr != nil {
		return [32]byte{}, e.parentErr
	}
	if slot == be32(slotGameExpectedRes) && e.expErr != nil {
		return [32]byte{}, e.expErr
	}
	return e.scriptGames.Slot(ctx, proxy, slot)
}

func TestTheBuilderUsesACaptureOnlyWhileItIsGoodAndRecapturesOtherwise(t *testing.T) {
	ctx := context.Background()
	have := haveIncluded
	// a capture that is not a capture row is passed over, and a capture whose block the provider does not know
	w := loadLive(t)
	st := &MemStore{}
	_ = st.Put(ctx, uint64(Chain), 5, [32]byte{9}, ItemGame(w.body.GameProxy), []byte{1, 2, 3})
	w.capture(t, st, w.body.StateBlock, [32]byte{0xde, 0xad}) // a hash no header has
	_, p, err := w.builder(t, st).buildLeg(ctx, w.leg, have)
	wantPendingReason(t, p, err, "l1_proof_window_unavailable")
	// within the finality delay: the wait ends at resolution plus the delay
	w3 := loadLive(t)
	st3 := w3.store(t)
	b3 := w3.builder(t, st3)
	// make A's timestamp land inside the delay: the headers report A at the resolution time
	resolved := uint64(0)
	fmt.Sscan(w3.expect["resolved_at"], &resolved)
	var delay uint64
	for _, r := range w3.bp.Impl {
		if r.Role == RoleASRImpl && r.FinalityDelaySeconds != nil {
			delay = *r.FinalityDelaySeconds
		}
	}
	a := aOf(w3)
	a.Timestamp = resolved + delay // exactly the end of the delay is still inside it
	w3.headers[a.Hash] = a
	_, p, err = b3.buildLeg(ctx, w3.leg, have)
	p = wantPendingReason(t, p, err, "within_finality_delay")
	if !p.ETA.Equal(time.Unix(int64(resolved+delay), 0)) {
		t.Errorf("eta %v, want %d", p.ETA, resolved+delay)
	}
	// a capture the judge refuses on its own terms is that refusal, not a wait
	w4 := loadLive(t)
	st4 := &MemStore{}
	c := GameCapture{L1Block: w4.body.StateBlock, L1Hash: aOf(w4).Hash, Game: w4.body.GameProxy, GameCode: w4.body.GameCode, Nodes: nil}
	_ = st4.Put(ctx, uint64(Chain), c.L1Block, c.L1Hash, ItemGame(c.Game), c.Encode())
	_, _, err = w4.builder(t, st4).buildLeg(ctx, w4.leg, have)
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity && se.Code != CodeL1StateProofInvalid {
		t.Errorf("a capture without proofs: %v", err)
	}
	// nothing captured and the provider still has the state: the capture is taken and the wait is for A to be final
	w5 := loadLive(t)
	b5 := w5.builder(t, &MemStore{})
	b5.L1 = capturingL1{fakeL1{w: w5}, w5}
	_, p, err = w5.built(t, b5)
	p = wantPendingReason(t, p, err, "block_not_yet_covered")
	if !p.ETA.Equal(time.Unix(1792485500, 0).Add(19 * time.Minute)) {
		t.Errorf("eta %v", p.ETA)
	}
	for _, k := range []string{"latest_finalized_exec_number", "latest_finalized_slot", "observed_head_slot", "captured_l1_block"} {
		if _, ok := p.Judged[k]; !ok {
			t.Errorf("lacks %s: %+v", k, p.Judged)
		}
	}
	// the wait also carries what the builder has reached
	b5.Back = 7
	if back := b5.back(); back != 7 {
		t.Errorf("back %d", back)
	}
}

// capturingL1 serves proofs of the live world so that CaptureGame succeeds.
type capturingL1 struct {
	fakeL1
	w *liveWorld
}

func (c capturingL1) L1HeaderByNumber(_ context.Context, n uint64) (HeaderInfo, error) {
	return HeaderInfo{Number: n, Hash: [32]byte{byte(n), 7}}, nil
}

func (c capturingL1) Code(context.Context, [20]byte, uint64) ([]byte, error) {
	return c.w.body.GameCode, nil
}
func (c capturingL1) Proof(_ context.Context, a [20]byte, _ [][32]byte, _ uint64) (StateProof, error) {
	return StateProof{Nodes: [][]byte{a[:]}, Values: map[[32]byte][32]byte{}}, nil
}

func TestTheBuilderAttestsOnlyWhenTheLightClientSpineAndVerifierAgree(t *testing.T) {
	ctx := context.Background()
	have := haveIncluded
	mk := func() (*liveWorld, *Builder) {
		w := loadLive(t)
		return w, w.builder(t, w.store(t))
	}
	// the light client is unavailable
	w, b := mk()
	b.LC = errLC{err: errors.New("lodestar down")}
	_, p, err := b.buildLeg(ctx, w.leg, have)
	p = wantPendingReason(t, p, err, "finality_lc_unavailable")
	if p.Judged["endpoints"] == nil {
		t.Errorf("%+v", p.Judged)
	}
	// the pins have no Sepolia section
	w, b = mk()
	b.Pins = pinsWithoutSepolia(t, w)
	_, _, err = b.buildLeg(ctx, w.leg, have)
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodePinUnknown {
		t.Errorf("no sepolia pins: %v", err)
	}
	// the light client evidence is refused, with the code of the fault
	w, b = mk()
	bad := w.body.LC
	bad.FinalUpdate.SSZ = append([]byte(nil), bad.FinalUpdate.SSZ...)
	bad.FinalUpdate.SSZ[40] ^= 1
	_, ferr := ethl1.VerifyFinalizedHead(EthL1Pins(w.pins), bad)
	if faultCode(ferr) == "" {
		t.Fatalf("test assumption: a fault, got %v", ferr)
	}
	b.LC = fakeLC{lc: bad, slot: 1}
	_, _, err = b.buildLeg(ctx, w.leg, have)
	if got := canonOf(t, err); got != string(finality.NewState(CodeL1FinalityUnproven, "reason", LCRefused, "inner", faultCode(ferr)).Canonical()) {
		t.Errorf("%s", got)
	}
	if faultCode(errors.New("x")) != "" {
		t.Error("a plain error has no fault code")
	}
	// the execution header of the finalized head is not served, and a spine header below it is not served
	w, b = mk()
	b.L1 = &onceL1{fakeL1: fakeL1{w: w}, calls: map[[32]byte]int{}}
	_, p, err = b.buildLeg(ctx, w.leg, have)
	p = wantPendingReason(t, p, err, "l1_state_unavailable")
	if p.Judged["providers"] == nil || p.Judged["block"] == nil {
		t.Errorf("%+v", p.Judged)
	}
	// the finalized head exactly at A is covered; one below is not, and the wait is seven minutes
	w, b = mk()
	b.L1 = lowHeadL1{fakeL1{w: w}, aOf(w)} // reports the head one below A
	_, p, err = b.buildLeg(ctx, w.leg, have)
	p = wantPendingReason(t, p, err, "block_not_yet_covered")
	if !p.ETA.Equal(time.Unix(1792485500, 0).Add(7*time.Minute)) || p.Judged["observed_head_slot"] != uint64(11400000) || p.Judged["latest_finalized_slot"] == nil {
		t.Errorf("%+v %v", p.Judged, p.ETA)
	}
	// a leg without its header passes the judge (which binds number and hash) and cannot be put in a container; a leg the judge refuses
	// is not built
	w, b = mk()
	badLeg := w.leg
	badLeg.HeaderRLP = nil
	_, _, err = b.buildLeg(ctx, badLeg, have)
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodeEvidenceMalformed {
		t.Errorf("bad leg header: %v", err)
	}
	w, b = mk()
	wrongLeg := w.leg
	wrongLeg.Hash[0] ^= 1
	ad, p, err := b.buildLeg(ctx, wrongLeg, have)
	if ad != nil || p != nil || err == nil {
		t.Errorf("a leg the verifier refuses: %v %v %v", ad != nil, p, err)
	}
}

type errLC struct{ err error }

func (e errLC) Finalized(context.Context) (ethl1.LC, uint64, error) { return ethl1.LC{}, 0, e.err }

// onceL1 serves each header by hash once and refuses it the second time: the capture lookup of A succeeds, the lookup of the
// finalized execution header (which is A itself in the vector) does not.
type onceL1 struct {
	fakeL1
	calls map[[32]byte]int
}

func (n *onceL1) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	n.calls[h]++
	if n.calls[h] > 1 {
		return HeaderInfo{}, errors.New("unknown block")
	}
	return n.fakeL1.L1HeaderByHash(ctx, h)
}

func pinsWithoutSepolia(t *testing.T, w *liveWorld) *finality.Pins {
	t.Helper()
	raw, _ := ReadFile(setDir, "pins/main.json")
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "eth_sepolia")
	nb, _ := json.MarshalIndent(m, "", "  ")
	p, err := finality.ParsePinsOverride(append(nb, '\n'))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTheBuilderEntryRefusesTheWrongLevelAndAWrongLegAndReportsWhatItHasReached(t *testing.T) {
	ctx := context.Background()
	w := loadLive(t)
	b := w.builder(t, &MemStore{})
	// l1_posted belongs to the sibling prover: nothing, no error
	ad, p, err := b.Build(ctx, &ethproof.Settlement{}, 0, finality.LevelL1Posted)
	if ad != nil || p != nil || err != nil {
		t.Errorf("%v %v %v", ad, p, err)
	}
	// the finalized level of a settlement the framework cannot derive a leg from
	_, _, err = b.Build(ctx, &ethproof.Settlement{}, 0, finality.LevelFinalized)
	if err == nil {
		t.Error("a settlement without a header has no leg")
	}
	// pins without the base section
	b2 := w.builder(t, &MemStore{})
	b2.Pins = &finality.Pins{}
	_, _, err = b2.buildLeg(ctx, w.leg, haveIncluded)
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodePinUnknown {
		t.Errorf("%v", err)
	}
	// what has been reached: l1_posted when the set has it, included otherwise
	pend := b.pending(0, "x", time.Time{})
	if pend.LevelReached != finality.LevelIncluded {
		t.Errorf("%v", pend.LevelReached)
	}
	if pend = b.pending(finality.LevelSet(0).With(finality.LevelL1Posted), "x", time.Time{}); pend.LevelReached != finality.LevelL1Posted {
		t.Errorf("%v", pend.LevelReached)
	}
	// key/value pairs: a trailing key without a value is dropped, never read past the end
	pend = b.pending(0, "x", time.Time{}, "a", 1, "b", 2, "dangling")
	if len(pend.Judged) != 2 || pend.Judged["a"] != 1 || pend.Judged["b"] != 2 {
		t.Errorf("%+v", pend.Judged)
	}
	if pend = b.pending(0, "x", time.Time{}, "only"); len(pend.Judged) != 0 {
		t.Errorf("%+v", pend.Judged)
	}
	// the clock: the injected one when set, the real one otherwise; the capture offset: 12 by default
	if got := b.now(); !got.Equal(time.Unix(1792485500, 0)) {
		t.Errorf("%v", got)
	}
	b.Now = nil
	if d := time.Since(b.now()); d < 0 || d > time.Minute {
		t.Errorf("%v", d)
	}
	if b.back() != 12 {
		t.Errorf("%d", b.back())
	}
	// a builder whose pins do not parse has no layout
	if lay := (&Builder{Pins: &finality.Pins{}}).pinsLayout(); lay.ArgsBaseLen != 0 {
		t.Errorf("%+v", lay)
	}
	if lay := b.pinsLayout(); lay.ArgsBaseLen != w.bp.Layouts[LayoutAggregateV1].ArgsBaseLen {
		t.Errorf("%+v", lay)
	}
}
