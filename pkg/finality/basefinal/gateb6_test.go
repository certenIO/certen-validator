// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
)

// scriptProof serves the values of a synthetic world and records every proof it is asked for.
type scriptProof struct {
	world    *SynthWorld
	head     uint64
	headErr  error
	hdrErr   error
	codeErr  error
	code     []byte
	failAt   int // the n-th Proof call fails (1-based); 0: none
	calls    []proofCall
	hdrAsked []uint64
}

type proofCall struct {
	addr  [20]byte
	slots [][32]byte
	block uint64
}

func (s *scriptProof) ProofHead(context.Context) (uint64, error) { return s.head, s.headErr }
func (s *scriptProof) L1HeaderByNumber(_ context.Context, n uint64) (HeaderInfo, error) {
	s.hdrAsked = append(s.hdrAsked, n)
	if s.hdrErr != nil {
		return HeaderInfo{}, s.hdrErr
	}
	return HeaderInfo{Number: n, Hash: [32]byte(crypto.Keccak256Hash([]byte(fmt.Sprint("header ", n))))}, nil
}
func (s *scriptProof) Code(context.Context, [20]byte, uint64) ([]byte, error) {
	return s.code, s.codeErr
}
func (s *scriptProof) Proof(_ context.Context, addr [20]byte, slots [][32]byte, block uint64) (StateProof, error) {
	s.calls = append(s.calls, proofCall{addr, slots, block})
	if len(s.calls) == s.failAt {
		return StateProof{}, errors.New("historical state is not available")
	}
	sp := StateProof{Nodes: [][]byte{[]byte(fmt.Sprintf("node %d %x", len(s.calls), addr[:3]))}, Values: map[[32]byte][32]byte{}}
	if a, ok := s.world.Accts[addr]; ok {
		for _, sl := range slots {
			sp.Values[sl] = a.Slots[sl]
		}
	}
	return sp, nil
}

func TestCaptureGameProvesTheWholeContractGraphAndTheGameAtABlockBehindTheHeadAndStoresItInsertOnly(t *testing.T) {
	p := loadPins(t)
	o, err := BuildSynth(p, SynthSpec{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	code := o.Body.GameCode
	lay := p.Layouts[LayoutAggregateV1]
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	args := code[tmplLen : len(code)-2]
	var rootClaim [32]byte
	copy(rootClaim[:], args[20:52])
	uuid := gameUUID(o.Row.GameType, rootClaim, args[84:])
	src := func() *scriptProof { return &scriptProof{world: o.World, head: 1000, code: code} }

	s := src()
	st := &MemStore{}
	c, err := CaptureGame(ctx, s, st, p, SynthAddrs.Game, 12)
	if err != nil {
		t.Fatal(err)
	}
	if c.L1Block != 988 || c.Game != SynthAddrs.Game || !bytes.Equal(c.GameCode, code) || c.L1Hash == ([32]byte{}) || len(s.hdrAsked) != 1 || s.hdrAsked[0] != 988 {
		t.Fatalf("%+v asked %v", c, s.hdrAsked)
	}
	// the proofs, in the order and with the slots the verifier reads (spec 2.8): Portal, SystemConfig, ASR, DGF, Superchain, the game,
	// the five implementations and the game implementation
	impl := [32]byte(eip1967ImplSlot)
	want := []proofCall{
		{p.Portal, [][32]byte{be32(slotPortalSystemConfig), be32(slotPortalASR), impl}, 988},
		{p.SystemConfig, [][32]byte{be32(slotSysCfgSuperchain), [32]byte(optimismPortalSlot), impl}, 988},
		{SynthAddrs.ASR, [][32]byte{be32(slotASRSystemConfig), be32(slotASRDGF), be32(slotASRRespectedRetire), mapSlot(pad32Addr(SynthAddrs.Game), mapASRBlacklist), impl}, 988},
		{SynthAddrs.DGF, [][32]byte{mapSlot(uuid, mapDGFGames), impl}, 988},
		{SynthAddrs.SUP, [][32]byte{mapSlot(be32(0), 0), mapSlot(pad32Addr(p.Portal), 0), impl}, 988},
		{SynthAddrs.Game, [][32]byte{be32(slotGameMain), be32(slotGameStartL2Seq), be32(slotGameCountered), mapSlot(be32(0), mapGameProver), mapSlot(be32(1), mapGameProver), be32(slotGameExpectedRes)}, 988},
		{SynthAddrs.PortalImpl, nil, 988}, {SynthAddrs.SysCfgImpl, nil, 988}, {SynthAddrs.ASRImpl, nil, 988}, {SynthAddrs.DGFImpl, nil, 988}, {SynthAddrs.SupImpl, nil, 988},
		{o.Row.Impl, nil, 988},
	}
	if len(s.calls) != len(want) {
		t.Fatalf("%d proof calls, want %d: %+v", len(s.calls), len(want), s.calls)
	}
	for i, w := range want {
		g := s.calls[i]
		if g.addr != w.addr || g.block != w.block || len(g.slots) != len(w.slots) {
			t.Fatalf("call %d: %x %v @%d, want %x %v", i, g.addr, g.slots, g.block, w.addr, w.slots)
		}
		for j := range w.slots {
			if g.slots[j] != w.slots[j] {
				t.Fatalf("call %d slot %d: %x, want %x", i, j, g.slots[j], w.slots[j])
			}
		}
	}
	// the stored row is the capture, and every node of every proof is in it
	rows, err := st.Rows(ctx, uint64(Chain), ItemGame(SynthAddrs.Game))
	if err != nil || len(rows) != 1 || rows[0].L1Block != 988 || rows[0].L1Hash != c.L1Hash {
		t.Fatalf("%v %v", rows, err)
	}
	back, err := DecodeGameCapture(rows[0].Data)
	if err != nil || back.L1Block != 988 || back.Game != SynthAddrs.Game || !bytes.Equal(back.GameCode, code) || len(back.Nodes) != len(want) {
		t.Fatalf("%+v %v", back, err)
	}
	// the same capture again is a no-op, a different one for the same key is refused
	if _, err := CaptureGame(ctx, src(), st, p, SynthAddrs.Game, 12); err != nil {
		t.Fatal(err)
	}
	s2 := src()
	s2.code = append(append([]byte(nil), code...), 0)
	if _, err := CaptureGame(ctx, s2, st, p, SynthAddrs.Game, 12); err == nil {
		t.Fatal("a second capture of the same block with other bytes must be refused")
	}

	// a game whose code is too short to hold its immutable args has no implementation to prove: five implementations only
	short := src()
	short.code = code[:tmplLen+2+83]
	cs, err := CaptureGame(ctx, short, &MemStore{}, p, SynthAddrs.Game, 12)
	if err != nil || len(short.calls) != 11 || len(cs.GameCode) != tmplLen+2+83 {
		t.Fatalf("%d calls, %v", len(short.calls), err)
	}
	// code of exactly the minimum length is read
	min := src()
	min.code = append(append([]byte(nil), code[:tmplLen+2+84-2]...), code[len(code)-2:]...)
	if _, err := CaptureGame(ctx, min, &MemStore{}, p, SynthAddrs.Game, 12); err != nil || len(min.calls) != 12 {
		t.Fatalf("%d calls, %v", len(min.calls), err)
	}

	// every failure is an error and stores nothing
	fails := []struct {
		name string
		s    *scriptProof
		pins *Pins
		back uint64
		want string
	}{
		{"head unreadable", &scriptProof{world: o.World, headErr: errors.New("rpc down"), code: code}, p, 12, "rpc down"},
		{"head below the offset", &scriptProof{world: o.World, head: 5, code: code}, p, 12, "below the capture offset"},
		{"header unreadable", &scriptProof{world: o.World, head: 1000, hdrErr: errors.New("no header"), code: code}, p, 12, "no header"},
		{"code unreadable", &scriptProof{world: o.World, head: 1000, codeErr: errors.New("no code")}, p, 12, "no code"},
	}
	for i := 1; i <= len(want); i++ {
		fails = append(fails, struct {
			name string
			s    *scriptProof
			pins *Pins
			back uint64
			want string
		}{fmt.Sprintf("proof %d unavailable", i), &scriptProof{world: o.World, head: 1000, code: code, failAt: i}, p, 12, "historical state"})
	}
	noLayout := clonePinsAll(p)
	delete(noLayout.Layouts, LayoutAggregateV1)
	fails = append(fails, struct {
		name string
		s    *scriptProof
		pins *Pins
		back uint64
		want string
	}{"no layout", src(), noLayout, 12, "game_layout"})
	for _, f := range fails {
		store := &MemStore{}
		_, err := CaptureGame(ctx, f.s, store, f.pins, SynthAddrs.Game, f.back)
		if err == nil || !strings.Contains(err.Error(), f.want) && !strings.Contains(fmt.Sprint(errString(err)), f.want) {
			t.Errorf("%s: %v", f.name, err)
		}
		if rows, _ := store.Rows(ctx, uint64(Chain), ItemGame(SynthAddrs.Game)); len(rows) != 0 {
			t.Errorf("%s: a failed capture stored a row", f.name)
		}
	}
	// the head may equal the offset: block 0
	z := src()
	z.head = 12
	if c, err := CaptureGame(ctx, z, &MemStore{}, p, SynthAddrs.Game, 12); err != nil || c.L1Block != 0 {
		t.Fatalf("%+v %v", c, err)
	}
}

func errString(err error) string {
	if se, ok := finality.AsNamed(err); ok {
		return string(se.Canonical())
	}
	return err.Error()
}

func TestTheCaptureStoresAreInsertOnlyAndListNewestFirst(t *testing.T) {
	ctx := context.Background()
	for name, mk := range map[string]func(t *testing.T) CaptureStore{
		"mem": func(t *testing.T) CaptureStore { return &MemStore{} },
		"dir": func(t *testing.T) CaptureStore {
			return DirStore{Dir: filepath.Join(t.TempDir(), "not", "yet", "there")}
		},
	} {
		st := mk(t)
		h := func(b byte) [32]byte { return [32]byte{b, 2, 3, 4, 5, 6, 7, 8, 9} }
		put := func(chain, block uint64, hash byte, item string, data string) error {
			return st.Put(ctx, chain, block, h(hash), item, []byte(data))
		}
		for _, r := range []struct {
			chain, block uint64
			hash         byte
			item, data   string
		}{{84532, 10, 1, "a", "ten"}, {84532, 30, 1, "a", "thirty"}, {84532, 20, 1, "a", "twenty"}, {84532, 20, 2, "b", "other item"}, {1, 40, 1, "a", "other chain"}, {84532, 20, 3, "a", "twenty again"}} {
			if err := put(r.chain, r.block, r.hash, r.item, r.data); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		rows, err := st.Rows(ctx, 84532, "a")
		if err != nil || len(rows) != 4 {
			t.Fatalf("%s: %d rows, %v", name, len(rows), err)
		}
		if rows[0].L1Block != 30 || rows[3].L1Block != 10 || rows[1].L1Block != 20 || rows[2].L1Block != 20 {
			t.Errorf("%s: order %d %d %d %d", name, rows[0].L1Block, rows[1].L1Block, rows[2].L1Block, rows[3].L1Block)
		}
		for _, r := range rows {
			if r.Chain != 84532 || r.Item != "a" {
				t.Errorf("%s: %+v", name, r)
			}
		}
		if string(rows[0].Data) != "thirty" || string(rows[3].Data) != "ten" || rows[0].L1Hash != h(1) {
			t.Errorf("%s: %+v", name, rows)
		}
		// the same bytes again are a no-op, other bytes under the same key are refused, and the row is unchanged
		if err := put(84532, 30, 1, "a", "thirty"); err != nil {
			t.Errorf("%s: a repeat must be a no-op: %v", name, err)
		}
		if err := put(84532, 30, 1, "a", "THIRTY"); err == nil || !strings.Contains(err.Error(), "insert-only") {
			t.Errorf("%s: a rewrite must be refused: %v", name, err)
		}
		if err := put(84532, 30, 1, "a", ""); err == nil {
			t.Errorf("%s: an emptied row must be refused", name)
		}
		if rows, _ = st.Rows(ctx, 84532, "a"); string(rows[0].Data) != "thirty" || len(rows) != 4 {
			t.Errorf("%s: %+v", name, rows)
		}
		if none, err := st.Rows(ctx, 84532, "missing"); err != nil || len(none) != 0 {
			t.Errorf("%s: %v %v", name, none, err)
		}
	}
}

func TestTheDirStoreWritesOneNamedFilePerRowAndRefusesAFileThatIsNotARow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := DirStore{Dir: dir}
	hash := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	if err := st.Put(ctx, 84532, 12345, hash, "item", []byte("data")); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("84532-000000012345-0102030405060708-%s.cap", hex.EncodeToString(crypto.Keccak256([]byte("item"))[:6]))
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		t.Fatalf("the row is not at %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "junk.cap"), []byte{1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Rows(ctx, 84532, "item"); err == nil {
		t.Fatal("a file that is not a row must be refused, not skipped")
	}
	// a store whose directory cannot be created reports it
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (DirStore{Dir: filepath.Join(file, "sub")}).Put(ctx, 1, 1, hash, "i", []byte("d")); err == nil {
		t.Fatal("a directory under a file cannot be created")
	}
}

func TestADecodedCaptureIsExactlyWhatWasEncodedAndAnythingElseIsRefused(t *testing.T) {
	c := GameCapture{L1Block: 77, L1Hash: [32]byte{5}, Game: [20]byte{6}, GameCode: []byte{1, 2, 3}, Nodes: [][]byte{{9, 9}, {1}, {4, 4, 4}}}
	enc := c.Encode()
	got, err := DecodeGameCapture(enc)
	if err != nil || got.L1Block != 77 || got.L1Hash != c.L1Hash || got.Game != c.Game || !bytes.Equal(got.GameCode, c.GameCode) || len(got.Nodes) != 3 {
		t.Fatalf("%+v %v", got, err)
	}
	// every cut and every extra byte is a named refusal, in the order of the fields
	for cut := 0; cut < len(enc); cut++ {
		if _, err := DecodeGameCapture(enc[:cut]); err == nil {
			t.Fatalf("cut %d accepted", cut)
		} else if _, ok := finality.AsNamed(err); !ok {
			t.Fatalf("cut %d: not a named state: %v", cut, err)
		}
	}
	if _, err := DecodeGameCapture(append(append([]byte(nil), enc...), 0)); err == nil {
		t.Fatal("a trailing byte must be refused")
	}
	// nodes out of order are refused
	var w finality.Writer
	w.U64(1)
	w.B32([32]byte{})
	w.Fixed(make([]byte, 20))
	w.LP(nil)
	n1, n2 := []byte{1}, []byte{2}
	if string(crypto.Keccak256(n1)) > string(crypto.Keccak256(n2)) {
		n1, n2 = n2, n1
	}
	w.Nodes([][]byte{n2, n1})
	if _, err := DecodeGameCapture(w.Bytes()); err == nil {
		t.Fatal("nodes not ascending by hash must be refused")
	}
	// the field names of the first refusals
	for cut, part := range map[int]string{0: "capture.l1Block", 8: "capture.l1Hash", 40: "capture.game"} {
		_, err := DecodeGameCapture(enc[:cut])
		if se, ok := finality.AsNamed(err); !ok || fmt.Sprint(se.Fields["part"]) != part {
			t.Errorf("cut %d: %v, want %s", cut, err, part)
		}
	}
}
