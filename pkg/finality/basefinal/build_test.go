// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// liveWorld is the published live vector turned into fake providers: the L1 spine, the L2 headers, the game and the light-client
// evidence are the recorded bytes, so the builder is exercised on the real objects without a network.
type liveWorld struct {
	pins     *finality.Pins
	bp       *Pins
	leg      finality.BlockRef
	body     Body
	evidence []byte
	expect   map[string]string
	headers  map[[32]byte]HeaderInfo
	l2       map[uint64]HeaderInfo
	status   uint8
	finalNum uint64 // the finalized execution number the LC source reports (the spine top by default)
}

func loadLive(t *testing.T) *liveWorld {
	t.Helper()
	raw, err := ReadFile(setDir, "cases/valid_leg_47604755.json")
	if err != nil {
		t.Fatal(err)
	}
	var c Case
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	pinsRaw, _ := ReadFile(setDir, c.Pins)
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	bp, err := ParsePins(pins)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(setDir, c.Leg)
	var leg Leg
	_ = json.Unmarshal(legRaw, &leg)
	ev, _ := ReadFile(setDir, c.Base)
	cont, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	es, _ := pins.Sepolia()
	body, err := DecodeBody(cont.Body, finality.DefaultLimits(), l1adapt.Pins(es), bp.MaxL2Headers)
	if err != nil {
		t.Fatal(err)
	}
	w := &liveWorld{pins: pins, bp: bp, leg: leg.BlockRef(t), body: body, evidence: ev, status: StatusDefenderWins, headers: map[[32]byte]HeaderInfo{}, l2: map[uint64]HeaderInfo{}}
	var e Expect
	_ = json.Unmarshal(c.Expect, &e)
	_ = json.Unmarshal(e.Fields, &w.expect)
	for _, raw := range body.L1Spine {
		h, _ := finality.ReadHeader(raw)
		w.headers[h.Hash] = HeaderInfo{Raw: raw, Hash: h.Hash, Parent: h.ParentHash, Number: h.Number, Timestamp: h.Timestamp, StateRoot: h.StateRoot}
		if w.finalNum == 0 {
			w.finalNum = h.Number
		}
	}
	for _, raw := range body.L2Spine {
		h, _ := finality.ReadHeader(raw)
		w.l2[h.Number] = HeaderInfo{Raw: raw, Hash: h.Hash, Parent: h.ParentHash, Number: h.Number, Timestamp: h.Timestamp, StateRoot: h.StateRoot}
	}
	return w
}

// fakes
type fakeGames struct{ w *liveWorld }

func (f fakeGames) GameCount(context.Context) (uint64, error) { return 1, nil }
func (f fakeGames) GameAt(_ context.Context, i uint64) (GameInfo, error) {
	c, _ := strconv.ParseUint(f.w.expect["created_at"], 10, 64)
	return GameInfo{Type: 621, CreatedAt: c, Proxy: f.w.body.GameProxy}, nil
}
func (f fakeGames) Code(context.Context, [20]byte) ([]byte, error) { return f.w.body.GameCode, nil }
func (f fakeGames) Slot(_ context.Context, _ [20]byte, slot [32]byte) ([32]byte, error) {
	var out [32]byte
	lay := f.w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	l2seq := binary.BigEndian.Uint64(f.w.body.GameCode[tl+84+24 : tl+84+32])
	switch slot {
	case be32(slotGameStartL2Seq):
		return be32(l2seq - 600), nil
	case be32(slotGameMain):
		c, _ := strconv.ParseUint(f.w.expect["created_at"], 10, 64)
		r, _ := strconv.ParseUint(f.w.expect["resolved_at"], 10, 64)
		put64(&out, 0, c)
		put64(&out, 8, r)
		out[15] = f.w.status
	case be32(slotGameExpectedRes):
		e, _ := strconv.ParseUint(f.w.expect["expected_resolution"], 10, 64)
		put64(&out, 0, e)
		put64(&out, 8, 1)
	case mapSlot(be32(0), mapGameProver):
		out[31] = 1
	}
	return out, nil
}

type fakeL1 struct {
	w       *liveWorld
	failing bool
}

func (f fakeL1) ProofHead(context.Context) (uint64, error) { return f.w.finalNum + 100, nil }
func (f fakeL1) L1HeaderByNumber(_ context.Context, n uint64) (HeaderInfo, error) {
	for _, h := range f.w.headers {
		if h.Number == n {
			return h, nil
		}
	}
	return HeaderInfo{}, fmt.Errorf("no such block")
}
func (f fakeL1) L1HeaderByHash(_ context.Context, h [32]byte) (HeaderInfo, error) {
	if x, ok := f.w.headers[h]; ok {
		return x, nil
	}
	return HeaderInfo{}, fmt.Errorf("no such block")
}
func (f fakeL1) Code(context.Context, [20]byte, uint64) ([]byte, error) {
	return nil, fmt.Errorf("historical state is not available")
}
func (f fakeL1) Proof(context.Context, [20]byte, [][32]byte, uint64) (StateProof, error) {
	return StateProof{}, fmt.Errorf("historical state is not available")
}

type fakeL2 struct{ w *liveWorld }

func (f fakeL2) L2HeaderByNumber(_ context.Context, n uint64) (HeaderInfo, error) {
	if h, ok := f.w.l2[n]; ok {
		return h, nil
	}
	return HeaderInfo{}, fmt.Errorf("no such block")
}

type fakeLC struct {
	lc   ethl1.LC
	slot uint64
}

func (f fakeLC) Finalized(context.Context) (ethl1.LC, uint64, error) { return f.lc, f.slot, nil }

func (w *liveWorld) builder(t *testing.T, store CaptureStore) *Builder {
	t.Helper()
	return &Builder{Pins: w.pins, Store: store, Games: fakeGames{w}, L1: fakeL1{w: w}, L2: fakeL2{w}, LC: fakeLC{lc: w.body.LC, slot: 11400000},
		Now: func() time.Time { return time.Unix(1792485500, 0) }, Providers: []string{"fake-l1"}}
}

func (w *liveWorld) capture(t *testing.T, store CaptureStore, block uint64, hash [32]byte) {
	t.Helper()
	c := GameCapture{L1Block: block, L1Hash: hash, Game: w.body.GameProxy, GameCode: w.body.GameCode, Nodes: w.body.Nodes}
	if err := store.Put(context.Background(), finality.CaptureKey{Chain: uint64(Chain), L1Block: block, L1Hash: hash, Item: ItemGame(w.body.GameProxy)}, c.Encode()); err != nil {
		t.Fatal(err)
	}
}

// buildLeg runs Build with the leg given directly (the vector carries no transaction proofs, so no ethproof.Settlement exists).
func (b *Builder) buildLeg(ctx context.Context, leg finality.BlockRef, have finality.LevelSet) (*finality.Addendum, *finality.PendingState, error) {
	return b.build(ctx, leg, have)
}

func aOf(w *liveWorld) HeaderInfo {
	for _, h := range w.headers {
		if h.Number == w.body.StateBlock {
			return h
		}
	}
	return HeaderInfo{}
}

func TestTheBuilderAttestsACapturedGameOnceTheFinalizedHeadCoversA(t *testing.T) {
	w := loadLive(t)
	store := &MemStore{}
	w.capture(t, store, w.body.StateBlock, aOf(w).Hash)
	add, pend, err := w.builder(t, store).buildLeg(context.Background(), w.leg, finality.LevelSet(0).With(finality.LevelIncluded))
	if err != nil || pend != nil || add == nil {
		t.Fatalf("add %v pend %v err %v", add != nil, pend, err)
	}
	if add.Level != finality.LevelFinalized || add.Kind != KindName || add.Chain != uint64(Chain) {
		t.Fatalf("%+v", add)
	}
	// the built evidence verifies offline and is the published evidence byte for byte (same LC, same spine down to A)
	if _, err := (Kind{}).Verify(w.pins, w.leg, add.Evidence); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(add.Evidence, w.evidence) {
		t.Errorf("built %d bytes, the vector holds %d", len(add.Evidence), len(w.evidence))
	}
}

func TestTheBuilderNamesWhyALevelIsNotReachedYet(t *testing.T) {
	ctx := context.Background()
	have := finality.LevelSet(0).With(finality.LevelIncluded)
	canon := func(p *finality.PendingState) string { return string(p.State().Canonical()) }

	// the finalized head is below A: block_not_yet_covered with the numbers it was judged at
	w := loadLive(t)
	store := &MemStore{}
	w.capture(t, store, w.body.StateBlock, aOf(w).Hash)
	b := w.builder(t, store)
	// an LC whose finalized head is older than A: use the A header as the "finalized" execution header
	b.L1 = lowHeadL1{fakeL1{w: w}, aOf(w)}
	_, pend, err := b.buildLeg(ctx, w.leg, have)
	if err != nil || pend == nil {
		t.Fatalf("pend %v err %v", pend, err)
	}
	if pend.Reason != "block_not_yet_covered" || pend.NextLevel != finality.LevelFinalized || pend.LevelReached != finality.LevelIncluded {
		t.Fatalf("%s", canon(pend))
	}

	// an unresolved game: the facts of the game and an upper bound
	w2 := loadLive(t)
	w2.status = StatusInProgress
	_, pend, err = w2.builder(t, &MemStore{}).buildLeg(ctx, w2.leg, have)
	if err != nil || pend == nil || pend.Reason != "game_unresolved" {
		t.Fatalf("%v %v", pend, err)
	}
	for _, k := range []string{"createdAt", "expectedResolution", "proofCount", "proof_system", "parent_status", "seconds_remaining"} {
		if _, ok := pend.Judged[k]; !ok {
			t.Errorf("game_unresolved lacks %s: %s", k, canon(pend))
		}
	}
	if pend.Judged["proof_system"] != "tee" || pend.Judged["seconds_remaining"] != uint64(0) {
		t.Errorf("%s", canon(pend))
	}

	// a challenger win is a refusal, not a wait
	w3 := loadLive(t)
	w3.status = StatusChallengerWins
	_, _, err = w3.builder(t, &MemStore{}).buildLeg(ctx, w3.leg, have)
	if s, _ := finality.AsNamed(err); s == nil || s.Code != CodeGameChallengerWins {
		t.Fatalf("%v", err)
	}

	// a leg above the newest game: no covering game yet
	w4 := loadLive(t)
	far := w4.leg
	far.Number += 100000
	_, pend, err = w4.builder(t, &MemStore{}).buildLeg(ctx, far, have)
	if err != nil || pend == nil || pend.Reason != "no_covering_game" {
		t.Fatalf("%v %v", pend, err)
	}

	// resolved, nothing captured, and the proof providers have dropped the state: a named pending, never a weaker answer
	w5 := loadLive(t)
	_, pend, err = w5.builder(t, &MemStore{}).buildLeg(ctx, w5.leg, have)
	if err != nil || pend == nil || pend.Reason != "l1_proof_window_unavailable" {
		t.Fatalf("%v %v", pend, err)
	}
	if pend.Judged["providers"] == nil {
		t.Errorf("%s", canon(pend))
	}

	// the L2 headers are not served: the named builder-side state
	w6 := loadLive(t)
	w6.l2 = map[uint64]HeaderInfo{}
	_, _, err = w6.builder(t, &MemStore{}).buildLeg(ctx, w6.leg, have)
	if s, _ := finality.AsNamed(err); s == nil || s.Code != "l2_header_unavailable" {
		t.Fatalf("%v", err)
	}
}

// lowHeadL1 serves a world whose finalized execution header is the given block (below A is not needed: A itself is not yet
// covered when the LC's execution head is older than A, so the test points the execution hash at A's parent).
type lowHeadL1 struct {
	fakeL1
	a HeaderInfo
}

func (l lowHeadL1) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	x, err := l.fakeL1.L1HeaderByHash(ctx, h)
	if err == nil && x.Number > l.a.Number {
		x.Number = l.a.Number - 1 // the finalized execution header is reported older than A
	}
	return x, err
}
