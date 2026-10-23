// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// failHashL1 refuses the headers of the given hashes.
type failHashL1 struct {
	fakeL1
	fail map[[32]byte]bool
}

func (f failHashL1) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	if f.fail[h] {
		return HeaderInfo{}, errors.New("unknown block")
	}
	return f.fakeL1.L1HeaderByHash(ctx, h)
}

// rawL1 serves every header with a raw encoding that is not the header (the numbers, hashes and roots are right).
type rawL1 struct{ fakeL1 }

func (r rawL1) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	x, err := r.fakeL1.L1HeaderByHash(ctx, h)
	x.Raw = []byte{1, 2, 3}
	return x, err
}

// sameNumberL1 reports the finalized execution header at the number of A.
type sameNumberL1 struct {
	fakeL1
	a HeaderInfo
}

func (s sameNumberL1) L1HeaderByHash(ctx context.Context, h [32]byte) (HeaderInfo, error) {
	x, err := s.fakeL1.L1HeaderByHash(ctx, h)
	if err == nil && x.Number > s.a.Number {
		x.Number = s.a.Number
	}
	return x, err
}

func TestTheAttestStepNamesTheHeaderItCouldNotReadAndNeverReturnsEvidenceTheVerifierRefuses(t *testing.T) {
	ctx := context.Background()
	mk := func() (*liveWorld, *Builder, HeaderInfo) {
		w := loadLive(t)
		return w, w.builder(t, w.store(t)), aOf(w)
	}
	head, err := ethl1.VerifyFinalizedHead(EthL1Pins(loadLive(t).pins), loadLive(t).body.LC)
	if err != nil {
		t.Fatal(err)
	}
	hashOfNumber := func(w *liveWorld, n uint64) [32]byte {
		for h, x := range w.headers {
			if x.Number == n {
				return h
			}
		}
		t.Fatalf("no header %d", n)
		return [32]byte{}
	}
	// the finalized execution header is not served: the wait names the slot of the finalized head
	w, b, a := mk()
	b.L1 = failHashL1{fakeL1{w: w}, map[[32]byte]bool{hashOfNumber(w, w.finalNum): true}}
	_, p, err := b.buildLeg(ctx, w.leg, haveIncluded)
	p = wantPendingReason(t, p, err, "l1_state_unavailable")
	if fmt.Sprint(p.Judged["block"]) != fmt.Sprint(head.Slot) || p.Judged["providers"] == nil {
		t.Errorf("%+v", p.Judged)
	}
	// a header between the finalized head and A is not served: the wait names A
	w, b, a = mk()
	b.L1 = failHashL1{fakeL1{w: w}, map[[32]byte]bool{hashOfNumber(w, a.Number+3): true}}
	_, p, err = b.buildLeg(ctx, w.leg, haveIncluded)
	p = wantPendingReason(t, p, err, "l1_state_unavailable")
	if fmt.Sprint(p.Judged["block"]) != fmt.Sprint(a.Number) {
		t.Errorf("%+v", p.Judged)
	}
	// an execution header that is at A is covered (not a wait for A): the build goes on and the verifier refuses what the source served
	w, b, a = mk()
	b.L1 = sameNumberL1{fakeL1{w: w}, a}
	ad, p, err := b.buildLeg(ctx, w.leg, haveIncluded)
	if p != nil && p.Reason == "block_not_yet_covered" {
		t.Errorf("a finalized head at A was reported as not yet covering A: %+v", p)
	}
	if ad != nil {
		t.Error("evidence built from a head the verifier cannot accept")
	}
	// headers whose raw bytes are not the headers: the evidence is assembled, the verifier refuses it, and it is not returned
	w, b, _ = mk()
	b.L1 = rawL1{fakeL1{w: w}}
	ad, p, err = b.buildLeg(ctx, w.leg, haveIncluded)
	if ad != nil || p != nil || err == nil {
		t.Errorf("evidence the verifier refuses was returned: %v %v %v", ad != nil, p, err)
	}
}

func TestTheFactoryScanNamesAGameItCannotReadAndTheEdgesItStoppedAt(t *testing.T) {
	ctx := context.Background()
	lay := loadLive(t).bp.Layouts[LayoutAggregateV1]
	tl := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	x := binary.BigEndian.Uint64(loadLive(t).body.GameCode[tl+84+24 : tl+84+32])
	// a game of the search that cannot be read (the bisection probes index 10)
	w := loadLive(t)
	g := w.factory(30, 12, 700)
	g.failAt = map[uint64]error{10: errors.New("rpc down")}
	b := w.builder(t, w.store(t))
	b.Games = g
	_, _, err := w.built(t, b)
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeGameSourceUnavailable || se.Fields["step"] != StepGameAt || se.Fields["cause"] == nil {
		t.Errorf("a game that cannot be read is a named source failure, not a verifier failure: %v", err)
	}
	// the pending states carry the end of the game they stopped at
	w2 := loadLive(t)
	b2 := w2.builder(t, w2.store(t))
	b2.Games = w2.factory(30, 12, 600)
	above := w2.leg
	above.Number = x + 600*17 + 1
	_, p, err := b2.buildLeg(ctx, above, haveIncluded)
	p = wantPendingReason(t, p, err, "no_covering_game")
	if p.Judged["newest_l2_sequence_number"] != x+600*17 {
		t.Errorf("above: %+v", p.Judged)
	}
	below := w2.leg
	below.Number = x - 600*13 // the first block of the oldest game is the end of no game, and none will ever cover it
	_, p, err = b2.buildLeg(ctx, below, haveIncluded)
	if se, ok := finality.AsNamed(err); !ok || p != nil || se.Code != CodeCoveringGameUnavailable || se.Fields["reason"] != ReasonBeforeFirstGame || se.Fields["game_l2_sequence_number"] != x-600*12 {
		t.Errorf("below: %v %v", p, err)
	}
}
