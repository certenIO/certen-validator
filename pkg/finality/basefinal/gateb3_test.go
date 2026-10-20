// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

func unrecCanon(reason string, kv ...any) string {
	return string(finality.NewState(CodeGameUnrecognised, append([]any{"reason", reason}, kv...)...).Canonical())
}

func clonePinsAll(p *Pins) *Pins {
	q := clonePins(p)
	q.Layouts = map[string]GameLayout{}
	for k, v := range p.Layouts {
		q.Layouts[k] = v
	}
	return q
}

// The game proxy code is a clone template, its immutable args and a trailer: each length that cannot hold them is its own refusal.
func TestTheGameCodeLengthsAreRefusedByTheirOwnCheck(t *testing.T) {
	p := loadPins(t)
	lay := p.Layouts[LayoutAggregateV1]
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	cut := func(f func(code []byte) []byte) SynthSpec {
		return SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, code *[]byte) { *code = f(*code) }}
	}
	for _, c := range []struct {
		name string
		f    func(code []byte) []byte
		want string
	}{
		{"one byte past the template", func(c []byte) []byte { return c[:tmplLen+1] }, unrecCanon(ReasonPrefix)},
		{"the template and its trailer only", func(c []byte) []byte { return c[:tmplLen+2] }, unrecCanon(ReasonArgsLen)},
		{"the template, three bytes", func(c []byte) []byte { return c[:tmplLen+3] }, unrecCanon(ReasonArgsLen)},
		{"one byte short of the fixed args", func(c []byte) []byte {
			return append(append([]byte(nil), c[:tmplLen+lay.ArgsBaseLen-1]...), c[len(c)-2:]...)
		}, unrecCanon(ReasonArgsLen)},
		{"exactly the fixed args and no root", func(c []byte) []byte {
			return append(append([]byte(nil), c[:tmplLen+lay.ArgsBaseLen]...), c[len(c)-2:]...)
		}, unrecCanon(ReasonNMismatch)},
		{"a root and one byte more", func(c []byte) []byte {
			return append(append([]byte(nil), c[:tmplLen+lay.ArgsBaseLen+lay.ArgsPerRoot+1]...), c[len(c)-2:]...)
		}, unrecCanon(ReasonArgsLen)},
	} {
		_, err := judgeSpec(t, p, cut(c.f))
		if got := canonOf(t, err); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// The L2 sequence numbers of a game are uint256 words that must fit 64 bits, and a game cannot end before it starts.
func TestAGameWhoseSequenceWordsDoNotFitOrEndBeforeTheyStartIsAnIntervalPairRefusal(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{})
	if err != nil {
		t.Fatal(err)
	}
	n := o.Row.NIntermediate
	want := unrecCanon(ReasonIntervalPair, "total", uint64(0), "n", uint64(n))
	lay := p.Layouts[LayoutAggregateV1]
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	// the start word with a bit above 64, at its first and at its last high byte
	for _, idx := range []int{0, 23} {
		idx := idx
		hi := be32(47604773 - 600)
		hi[idx] = 1
		_, err = judgeSpec(t, p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) { w.Set(SynthAddrs.Game, be32(slotGameStartL2Seq), hi) }})
		if got := canonOf(t, err); got != want {
			t.Errorf("start word, byte %d: %s", idx, got)
		}
	}
	// the sequence word of the immutable args, with the game registered again under the uuid of the changed args
	for _, idx := range []int{0, 23} {
		idx := idx
		_, err = judgeSpec(t, p, SynthSpec{CreatedAt: 1790980536, Tweak: func(w *SynthWorld, _ *Pins, code *[]byte) {
			(*code)[tmplLen+84+idx] = 1
			args := (*code)[tmplLen : len(*code)-2]
			var root [32]byte
			copy(root[:], args[20:52])
			var reg [32]byte
			binary.BigEndian.PutUint32(reg[0:4], o.Row.GameType)
			binary.BigEndian.PutUint64(reg[4:12], 1790980536)
			copy(reg[12:], SynthAddrs.Game[:])
			w.Set(SynthAddrs.DGF, mapSlot(gameUUID(o.Row.GameType, root, args[84:]), mapDGFGames), reg)
		}})
		if got := canonOf(t, err); got != want {
			t.Errorf("sequence word, byte %d: %s", idx, got)
		}
	}
	// a start after the end: total is reported as 0, not as the wrapped difference
	_, err = judgeSpec(t, p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) {
		w.Set(SynthAddrs.Game, be32(slotGameStartL2Seq), be32(47604773+5))
	}})
	if got := canonOf(t, err); got != want {
		t.Errorf("start after end: %s", got)
	}
}

// A resolution time of zero is an unresolved game even when the status says otherwise.
func TestAResolutionTimeOfZeroIsAnUnresolvedGameWhateverTheStatus(t *testing.T) {
	p := loadPins(t)
	_, err := judgeSpec(t, p, SynthSpec{CreatedAt: 1790980536, Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) {
		var g0 [32]byte
		put64(&g0, 0, 1790980536)
		g0[15], g0[14], g0[13] = StatusDefenderWins, 1, 1
		w.Set(SynthAddrs.Game, be32(slotGameMain), g0)
	}})
	if got := canonOf(t, err); got != `{"code":"game_not_resolved","fields":{"status":"2"}}` {
		t.Errorf("%s", got)
	}
}

// The pins decide what a contract is: a row of another role, an implementation row without its delay, and a missing game layout are
// each refused by their own check.
func TestThePinsDecideWhatEachContractIsAndWhatAGameLooksLike(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{K: 1, Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	// k = 1 is the first intermediate root: an accepted, intermediate anchor
	f, err := Judge(p, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
	if err != nil || f["root_kind"] != "intermediate" || f["output_root_index"] != uint32(1) {
		t.Fatalf("%v %v", f, err)
	}
	var gameHash, asrHash [32]byte
	for h, r := range p.Impl {
		switch r.Role {
		case RoleGameImpl:
			if r.Version == "0.2.0" {
				gameHash = h
			}
		case RoleASRImpl:
			asrHash = h
		}
	}
	judgeWith := func(q *Pins) error {
		_, err := Judge(q, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
		return err
	}
	// the game implementation code hash is pinned, but as another role
	q := clonePinsAll(p)
	r := q.Impl[gameHash]
	r.Role = RolePortalImpl
	q.Impl[gameHash] = r
	if se, ok := finality.AsNamed(judgeWith(q)); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("another role: %v", se)
	}
	// the ASR implementation row carries no finality delay
	q = clonePinsAll(p)
	r = q.Impl[asrHash]
	r.FinalityDelaySeconds = nil
	q.Impl[asrHash] = r
	if se, ok := finality.AsNamed(judgeWith(q)); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleASRImpl {
		t.Errorf("no delay: %v", se)
	}
	// no game layout in the pins
	q = clonePinsAll(p)
	delete(q.Layouts, LayoutAggregateV1)
	wantCanon := string(finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia.game_layout").Canonical())
	if got := canonOf(t, judgeWith(q)); got != wantCanon {
		t.Errorf("no layout: %s", got)
	}
	// an output-root index above the number of intermediate roots
	b := o.Body
	b.OutputRootIndex = uint32(o.Row.NIntermediate) + 1
	_, err = Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodeEvidenceTooLarge || fmt.Sprint(se.Fields["part"]) != "outputRootIndex" {
		t.Errorf("index above N: %v", err)
	}
}

// The L2 spine: a first header that is no header, and a later one that is none, are named; the later one with the number it should have had.
func TestTheL2SpineRefusesAHeaderThatIsNoHeaderAndNamesTheNumberItExpected(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	b := o.Body
	b.L2Spine = append([][]byte{{1, 2, 3}}, o.Body.L2Spine[1:]...)
	_, err = Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
	if se, ok := finality.AsNamed(err); !ok || se.Code != finality.CodeEvidenceMalformed || fmt.Sprint(se.Fields["part"]) != "header" {
		t.Errorf("first header: %v", err)
	}
	h0, _ := finality.ReadHeader(o.Body.L2Spine[0])
	junk := []byte{9, 9, 9}
	b = o.Body
	b.L2Spine = [][]byte{o.Body.L2Spine[0], junk, o.Body.L2Spine[2]}
	_, err = Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
	want := string(stateOf(ethl1.HeaderChainBroken("l2", h0.Number-1, h0.ParentHash, [32]byte(crypto.Keccak256Hash(junk)), "rlp")).(*finality.StateError).Canonical())
	if got := canonOf(t, err); got != want {
		t.Errorf("later header:\n got %s\nwant %s", got, want)
	}
}
