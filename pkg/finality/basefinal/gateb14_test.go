// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// ---- defects found by the independent review V-D1 (checks that were absent) ----

func gameRow(p *Pins) ImplRow {
	for _, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Version == "0.2.0" {
			return r
		}
	}
	panic("no 0.2.0 game row")
}

func layTmplLen(p *Pins) int {
	lay := p.Layouts[LayoutAggregateV1]
	return len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
}

// registerAs re-registers the game of the (changed) code under its uuid, as the factory would have stored it.
func registerAs(w *SynthWorld, code []byte, tl int, created uint64, row ImplRow) {
	args := code[tl : len(code)-2]
	var rc [32]byte
	copy(rc[:], args[20:52])
	var reg [32]byte
	binary.BigEndian.PutUint32(reg[0:4], row.GameType)
	binary.BigEndian.PutUint64(reg[4:12], created)
	copy(reg[12:], synthGame[:])
	w.Set(synthDGF, mapSlot(gameUUID(row.GameType, rc, args[84:]), mapDGFGames), reg)
}

// dropLastItem re-encodes an RLP list without its last item.
func dropLastItem(t *testing.T, raw []byte) []byte {
	t.Helper()
	content, _, err := rlp.SplitList(raw)
	if err != nil {
		t.Fatal(err)
	}
	var items []rlp.RawValue
	for len(content) > 0 {
		_, _, rest, err := rlp.Split(content)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, rlp.RawValue(content[:len(content)-len(rest)]))
		content = rest
	}
	out, err := rlp.EncodeToBytes(items[:len(items)-1])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func outputRootMismatch(t *testing.T, err error) {
	t.Helper()
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeOutputRootMismatch {
		t.Fatalf("want output_root_mismatch, got %v", err)
	}
}

// A header without a withdrawals root has no output root: a claimed root of all zeros must not match the zero that stands for absent.
func TestAZeroClaimIsNotMatchedByAHeaderWithoutAWithdrawalsRoot(t *testing.T) {
	p := loadPins(t)
	row, tl := gameRow(p), layTmplLen(p)
	o, err := BuildSynth(p, SynthSpec{K: 0, Depth: 2, CreatedAt: 1790980536, Tweak: func(w *SynthWorld, _ *Pins, code *[]byte) {
		c := *code
		for i := tl + 20; i < tl+52; i++ {
			c[i] = 0 // the rootClaim
		}
		registerAs(w, c, tl, 1790980536, row)
	}})
	if err != nil {
		t.Fatal(err)
	}
	b := o.Body
	b.L2Spine = append([][]byte{dropLastItem(t, o.Body.L2Spine[0])}, o.Body.L2Spine[1:]...)
	if h, err := finality.ReadHeader(b.L2Spine[0]); err != nil || h.WithdrawalsRoot != nil {
		t.Fatalf("test assumption: a header without a withdrawals root, got %v %v", h.WithdrawalsRoot, err)
	}
	_, err = Judge(p, o.A, b, o.Leg, ethl1.FinalizedHead{})
	outputRootMismatch(t, err)
	// and with a claim that is not zero, as before
	o2, _ := BuildSynth(p, SynthSpec{K: 0, Depth: 2})
	b2 := o2.Body
	b2.L2Spine = append([][]byte{dropLastItem(t, o2.Body.L2Spine[0])}, o2.Body.L2Spine[1:]...)
	_, err = Judge(p, o2.A, b2, o2.Leg, ethl1.FinalizedHead{})
	outputRootMismatch(t, err)
}

// The header the output root is computed from must be the block the game implies (spec 5.5 O5).
func TestTheOutputRootHeaderMustBeTheBlockTheGameImplies(t *testing.T) {
	p := loadPins(t)
	row, tl := gameRow(p), layTmplLen(p)
	const shift = 1000
	for _, k := range []uint32{0, 3} {
		o, err := BuildSynth(p, SynthSpec{K: k, Depth: 2, CreatedAt: 1790980536, Tweak: func(w *SynthWorld, _ *Pins, code *[]byte) {
			c := *code
			args := c[tl : len(c)-2]
			l2 := binary.BigEndian.Uint64(args[84+24 : 84+32])
			binary.BigEndian.PutUint64(args[84+24:84+32], l2+shift)
			w.Set(synthGame, be32(slotGameStartL2Seq), be32(l2-600+shift))
			registerAs(w, c, tl, 1790980536, row)
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Judge(p, o.A, o.Body, o.Leg, ethl1.FinalizedHead{})
		outputRootMismatch(t, err)
	}
}

// The pinned build of the game implementation is made for one AnchorStateRegistry (and, when pinned, one factory).
func TestAPortalThatNamesAnotherASRThanTheOneTheGameImplementationIsBuiltForIsRefused(t *testing.T) {
	p := loadPins(t)
	// the Portal names another ASR proxy (a copy of the real one: same code, same state)
	asr2 := [20]byte{0x77, 0x01}
	_, err := run(t, p, SynthSpec{Tweak: func(w *SynthWorld, p *Pins, _ *[]byte) {
		old := w.Accts[synthASR]
		x := w.acct(asr2)
		x.CodeHash = old.CodeHash
		for s, v := range old.Slots {
			x.Slots[s] = v
		}
		x.Prove = append(x.Prove, old.Prove...)
		w.Set(p.Portal, be32(slotPortalASR), addrToWord(asr2))
	}}, nil)
	if se, ok := finality.AsNamed(err); !ok || se.Code != CodeContractIdentity || fmt.Sprint(se.Fields["role"]) != RoleGameImpl {
		t.Errorf("another ASR: %v", err)
	}
}

// R11 Q5: a game is respected by its own flag; a later switch of the ASR respected type does not unrespect it.
func TestAnOldGameStaysValidWhenTheRespectedTypeIsSwitched(t *testing.T) {
	p := loadPins(t)
	_, err := run(t, p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) {
		var rr [32]byte
		binary.BigEndian.PutUint32(rr[28:], 8)
		put64(&rr, 4, 1776392808)
		w.Set(synthASR, be32(slotASRRespectedRetire), rr)
	}}, nil)
	if err != nil {
		t.Errorf("%v", err)
	}
}

// A provider answer with a storage key or value longer than a word is an error, never a slice panic.
func TestAProofAnswerWithAKeyOrValueLongerThanAWordIsRefusedNotAPanic(t *testing.T) {
	for _, c := range []struct{ name, key, val string }{
		{"key of 33 bytes", "0x" + strings.Repeat("11", 33), "0x01"},
		{"value of 33 bytes", "0x" + strings.Repeat("11", 32), "0x" + strings.Repeat("01", 33)},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"codeHash":"0x%s","accountProof":["0x00"],"storageProof":[{"key":%q,"value":%q,"proof":["0x00"]}]}}`,
				strings.Repeat("00", 32), c.key, c.val)
		}))
		rpc := &RPC{ProofURLs: []string{srv.URL}}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic %v", c.name, r)
				}
			}()
			sp, err := rpc.Proof(context.Background(), [20]byte{1}, [][32]byte{{1}}, 5)
			if err == nil || len(sp.Values) != 0 || strings.Contains(err.Error(), srv.URL) {
				t.Errorf("%s: %v %v", c.name, sp.Values, err)
			}
		}()
		srv.Close()
	}
	// a word-sized key and value are read
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"codeHash":"0x%s","accountProof":["0x00"],"storageProof":[{"key":"0x01","value":"0x02","proof":["0x00"]}]}}`, strings.Repeat("00", 32))
	}))
	defer srv.Close()
	sp, err := (&RPC{ProofURLs: []string{srv.URL}}).Proof(context.Background(), [20]byte{1}, [][32]byte{{31: 1}}, 5)
	if err != nil || sp.Values[be32(1)] != be32(2) {
		t.Errorf("%v %v", sp.Values, err)
	}
}

// No deployed code hashes to zero: a pins file that keys a row by the zero hash would make an absent account look pinned.
func TestAPinsFileThatKeysARowByTheZeroCodeHashIsCorrupt(t *testing.T) {
	zero := "0x" + strings.Repeat("00", 32)
	for _, section := range []string{"impl_pins", "proxy_pins"} {
		m := baseSection(t)
		m[section].(map[string]any)[zero] = map[string]any{"role": "portal_impl"}
		_, err := ParsePins(pinsWith(t, m))
		wantPinsCorrupt(t, section, err, section)
	}
}

// ---- killers of the survivors the equivalents file wrongly excused (V-D1) ----

type slotFailGames struct {
	fakeGames
	slot [32]byte
}

func (g slotFailGames) Slot(ctx context.Context, p [20]byte, s [32]byte) ([32]byte, error) {
	if s == g.slot {
		return [32]byte{}, errors.New("provider down")
	}
	return g.fakeGames.Slot(ctx, p, s)
}

type rowsFailStore struct{ CaptureStore }

func (rowsFailStore) ListByRange(context.Context, uint64, uint64, uint64, string) ([]finality.CaptureKey, error) {
	return nil, errors.New("store down")
}

func TestTheBuilderNamesAnUnreadableLiveViewAndAnUnreadableStoreInsteadOfWaitingOrRecapturing(t *testing.T) {
	w := loadLive(t)
	b := w.builder(t, w.store(t))
	b.Games = slotFailGames{fakeGames{w}, be32(slotGameMain)}
	if ad, pend, err := b.buildLeg(context.Background(), w.leg, haveIncluded); err == nil || pend != nil || ad != nil {
		t.Errorf("live view: ad=%v pend=%+v err=%v", ad != nil, pend, err)
	}
	w2 := loadLive(t)
	b2 := w2.builder(t, rowsFailStore{w2.store(t)})
	if ad, pend, err := b2.buildLeg(context.Background(), w2.leg, haveIncluded); err == nil || pend != nil || ad != nil {
		t.Errorf("store: ad=%v pend=%+v err=%v", ad != nil, pend, err)
	}
}

// A stored row whose prefix decodes but whose end does not (a trailing byte) is passed over, not used.
func TestAStoredCaptureWithATrailingByteIsPassedOver(t *testing.T) {
	w := loadLive(t)
	st := &MemStore{}
	c := GameCapture{L1Block: w.body.StateBlock, L1Hash: aOf(w).Hash, Game: w.body.GameProxy, GameCode: w.body.GameCode, Nodes: w.body.Nodes}
	if err := st.Put(context.Background(), finality.CaptureKey{Chain: uint64(Chain), L1Block: c.L1Block, L1Hash: c.L1Hash, Item: ItemGame(c.Game)}, append(c.Encode(), 0x00)); err != nil {
		t.Fatal(err)
	}
	ad, pend, err := w.builder(t, st).buildLeg(context.Background(), w.leg, haveIncluded)
	if err != nil || ad != nil || pend == nil || pend.Reason != "l1_proof_window_unavailable" {
		t.Errorf("ad=%v pend=%+v err=%v", ad != nil, pend, err)
	}
}

// An unreadable proof of the expected-resolution slot is the error, before the rules that would refuse the game for another reason.
func TestAnUnreadableExpectedResolutionProofOutranksTheLaterRules(t *testing.T) {
	p := loadPins(t)
	_, err := run(t, p, SynthSpec{Blacklisted: true, Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) {
		w.SetRaw(synthGame, be32(slotGameExpectedRes), []byte{0x80})
	}}, nil)
	if got := canonOf(t, err); got != `{"code":"l1_state_proof_invalid","fields":{"which":"slot"}}` {
		t.Errorf("%s", got)
	}
}

// A zero code-hash key (not accepted from a pins file, but possible in a parsed one) must not make an absent account look pinned.
func TestAnAbsentImplementationAccountIsNeverPinnedByAZeroHashKey(t *testing.T) {
	p := clonePins(loadPins(t))
	p.Impl[[32]byte{}] = ImplRow{Role: RolePortalImpl}
	_, err := run(t, p, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetAbsent(synthPImpl) }}, nil)
	if s, ok := finality.AsNamed(err); !ok || s.Code != CodeContractIdentity || s.Fields["role"] != RolePortalImpl {
		t.Errorf("an absent implementation account was accepted: %v", err)
	}
	p2 := clonePins(loadPins(t))
	row := gameRow(p2)
	p2.Impl[[32]byte{}] = row
	_, err = run(t, p2, SynthSpec{Tweak: func(w *SynthWorld, _ *Pins, _ *[]byte) { w.SetAbsent(row.Impl) }}, nil)
	if s, ok := finality.AsNamed(err); !ok || s.Code != CodeContractIdentity || s.Fields["role"] != RoleGameImpl {
		t.Errorf("an absent game implementation account was accepted: %v", err)
	}
	_ = json.Marshal
}
