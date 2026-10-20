// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/certen/independant-validator/pkg/finality"
)

// A game owns the blocks after its start up to and including its end: the end of a game that is not the newest belongs to it, the
// start belongs to the game before, wherever the walk arrives from.
func TestTheEndOfAGameBelongsToItAndItsStartToTheGameBeforeFromEitherSide(t *testing.T) {
	ctx := context.Background()
	lay := loadLive(t).bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(loadLive(t).body.GameCode[tl+84+24 : tl+84+32])
	// the end of the live game, which has newer games above it: the walk keeps it
	w := loadLive(t)
	b := w.builder(t, w.store(t))
	b.Games = w.factory(30, 12, 600)
	b.L2 = anyL2{}
	end := w.leg
	end.Number = x
	_, p, err := b.buildLeg(ctx, end, haveIncluded)
	if p != nil && p.Reason == "l1_proof_window_unavailable" {
		t.Errorf("the end of the live game was given to another game: %+v", p)
	}
	_ = err
	// the start of the live game, arriving from above (games above it are closer together than the estimate assumes): it goes to
	// the game before, which has no capture
	w2 := loadLive(t)
	b2 := w2.builder(t, w2.store(t))
	b2.Games = w2.factory(30, 12, 500)
	b2.L2 = anyL2{}
	start := w2.leg
	start.Number = x - 600
	_, p, err = b2.buildLeg(ctx, start, haveIncluded)
	wantPendingReason(t, p, err, "l1_proof_window_unavailable")
}

func TestTheParentStatusOfAnUnresolvedGameIsReadFromTheParentAddressInTheArgs(t *testing.T) {
	w := loadLive(t)
	lay := w.bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	w.status = StatusInProgress
	var parent [20]byte
	for i := range parent {
		parent[i] = byte(0x30 + i)
	}
	g := w.scripted()
	var pw [32]byte
	pw[15] = 5
	g.slots = map[[20]byte]map[[32]byte][32]byte{parent: {be32(slotGameMain): pw}}
	code := append([]byte(nil), w.body.GameCode...)
	copy(code[tl+116:tl+136], parent[:])
	code[tl+136] = 0xdd // the byte after it (the args are longer than the fixed part)
	g.codes = map[[20]byte][]byte{w.body.GameProxy: code}
	b := w.builder(t, &MemStore{})
	b.Games = g
	b.Now = func() time.Time { return time.Unix(0, 0) }
	_, p, err := w.built(t, b)
	p = wantPendingReason(t, p, err, "game_unresolved")
	if p.Judged["parent_status"] != "5" {
		t.Errorf("parent_status %v", p.Judged["parent_status"])
	}
	_ = finality.LevelFinalized
}
