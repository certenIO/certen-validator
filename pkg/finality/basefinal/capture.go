// Copyright 2026 Certen Protocol

package basefinal

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/certen/independant-validator/pkg/finality"
)

// CaptureStore is the insert-only capture table of V2_SPEC_S7 2.8, keyed (chain, l1_block, l1_hash, item): the framework's store
// (pkg/database.FinalityCaptureStore in production; MemStore and DirStore here). Rows are never updated or deleted, and a
// verifier never reads them.
type CaptureStore = finality.CaptureStore

// CaptureRow is one stored capture.
type CaptureRow struct {
	Chain   uint64
	L1Block uint64
	L1Hash  [32]byte
	Item    string
	Data    []byte
}

// Rows returns every row of an item for a chain, newest L1 block first: the question the builder and the recorder commands ask
// of the store.
func Rows(ctx context.Context, s CaptureStore, chain uint64, item string) ([]CaptureRow, error) {
	rs, err := finality.CaptureRowsOfItem(ctx, s, chain, item)
	if err != nil {
		return nil, err
	}
	out := make([]CaptureRow, 0, len(rs))
	for i := len(rs) - 1; i >= 0; i-- {
		r := rs[i]
		out = append(out, CaptureRow{Chain: r.Chain, L1Block: r.L1Block, L1Hash: r.L1Hash, Item: r.Item, Data: r.Bytes})
	}
	return out, nil
}

// ItemGame is the item name of the state capture of one game proxy.
func ItemGame(game [20]byte) string { return "basefinal/game/" + hex.EncodeToString(game[:]) }

// MemStore is the in-memory CaptureStore used by the tests (the zero value is an empty store).
type MemStore = finality.MemCaptureStore

// DirStore is the CaptureStore over a directory (the recorder's store): the framework's finality.DirCaptureStore.
type DirStore = finality.DirCaptureStore

// GameCapture is what is captured near the L1 head for one game: the proofs of the whole contract graph, the game proxy and
// its slots under the state root of L1 block A, and the proxy's code. Nothing in it is trusted: the attest step verifies it
// under the state root of the covered header numbered A.
type GameCapture struct {
	L1Block  uint64
	L1Hash   [32]byte
	Game     [20]byte
	GameCode []byte
	Nodes    [][]byte
}

// Encode is the stored form: u64 l1Block || B32 l1Hash || B20 game || LP code || NODES.
func (c GameCapture) Encode() []byte {
	var w finality.Writer
	w.U64(c.L1Block)
	w.B32(c.L1Hash)
	w.Fixed(c.Game[:])
	w.LP(c.GameCode)
	w.Nodes(finality.EncodeNodes(c.Nodes))
	return w.Bytes()
}

// DecodeGameCapture is the strict inverse of Encode.
func DecodeGameCapture(b []byte) (GameCapture, error) {
	var c GameCapture
	lim := finality.DefaultLimits()
	r := finality.NewReader(b, lim)
	var err error
	if c.L1Block, err = r.U64("capture.l1Block"); err != nil {
		return c, err
	}
	if c.L1Hash, err = r.B32("capture.l1Hash"); err != nil {
		return c, err
	}
	g, err := r.Fixed("capture.game", 20)
	if err != nil {
		return c, err
	}
	copy(c.Game[:], g)
	if c.GameCode, err = r.LP("capture.code", lim.MaxCodeBytes); err != nil {
		return c, err
	}
	if c.Nodes, err = r.Nodes("capture.nodes", lim.MaxNodeBytes); err != nil {
		return c, err
	}
	return c, r.End("capture")
}

// ProofSource is the near-head proof side of the builder.
type ProofSource interface {
	ProofHead(ctx context.Context) (uint64, error)
	L1HeaderByNumber(ctx context.Context, n uint64) (HeaderInfo, error)
	Code(ctx context.Context, addr [20]byte, block uint64) ([]byte, error)
	Proof(ctx context.Context, addr [20]byte, slots [][32]byte, block uint64) (StateProof, error)
}

// CaptureGame captures, at L1 block A = proofHead - back, the proofs the 5.5 verifier needs for one game (spec 2.8 phase 1):
// Portal {55, 62, impl}, SystemConfig {108, OPTIMISM_PORTAL_SLOT, impl}, ASR {0, 1, 6, blacklist[game], impl}, DGF {uuid, impl},
// SuperchainConfig {pause[0], pause[portal], impl}, the game {0, 2, 5, 6/TEE, 6/ZK, 7} and the five implementation accounts and
// the game implementation. A provider that has dropped the state answers with an error, which is returned redacted: a missed
// window is a named state of the caller (l1_proof_window_unavailable), never a weaker capture.
func CaptureGame(ctx context.Context, src ProofSource, store CaptureStore, p *Pins, game [20]byte, back uint64) (GameCapture, error) {
	head, err := src.ProofHead(ctx)
	if err != nil {
		return GameCapture{}, err
	}
	if head < back {
		return GameCapture{}, fmt.Errorf("proof provider head %d below the capture offset", head)
	}
	a := head - back
	hdr, err := src.L1HeaderByNumber(ctx, a)
	if err != nil {
		return GameCapture{}, err
	}
	code, err := src.Code(ctx, game, a)
	if err != nil {
		return GameCapture{}, err
	}
	lay, ok := p.Layouts[LayoutAggregateV1]
	if !ok {
		return GameCapture{}, finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia.game_layout")
	}
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	var gameType uint32 = 621
	var gimpl [20]byte
	if len(code) >= tmplLen+2+84 {
		copy(gimpl[:], code[len(lay.CloneHead)+2+len(lay.CloneMid):])
		for _, r := range p.Impl {
			if r.Role == RoleGameImpl && r.Impl == gimpl {
				gameType = r.GameType
			}
		}
	}
	var rootClaim [32]byte
	var extra []byte
	if len(code) >= tmplLen+2+84 {
		args := code[tmplLen : len(code)-2]
		copy(rootClaim[:], args[20:52])
		extra = args[84:]
	}
	uuid := gameUUID(gameType, rootClaim, extra)
	var nodes [][]byte
	proveAt := func(addr [20]byte, slots ...[32]byte) (StateProof, error) {
		sp, err := src.Proof(ctx, addr, slots, a)
		if err != nil {
			return sp, err
		}
		nodes = append(nodes, sp.Nodes...)
		return sp, nil
	}
	val := func(sp StateProof, slot [32]byte) [32]byte { return sp.Values[slot] }

	portalImplSlot := [32]byte(eip1967ImplSlot)
	spPortal, err := proveAt(p.Portal, be32(slotPortalSystemConfig), be32(slotPortalASR), portalImplSlot)
	if err != nil {
		return GameCapture{}, err
	}
	spSys, err := proveAt(p.SystemConfig, be32(slotSysCfgSuperchain), [32]byte(optimismPortalSlot), portalImplSlot)
	if err != nil {
		return GameCapture{}, err
	}
	asr := addrWord(val(spPortal, be32(slotPortalASR)))
	sup := addrWord(val(spSys, be32(slotSysCfgSuperchain)))
	spASR, err := proveAt(asr, be32(slotASRSystemConfig), be32(slotASRDGF), be32(slotASRRespectedRetire),
		mapSlot(pad32Addr(game), mapASRBlacklist), portalImplSlot)
	if err != nil {
		return GameCapture{}, err
	}
	dgf := addrWord(val(spASR, be32(slotASRDGF)))
	spDGF, err := proveAt(dgf, mapSlot(uuid, mapDGFGames), portalImplSlot)
	if err != nil {
		return GameCapture{}, err
	}
	spSup, err := proveAt(sup, mapSlot(be32(0), 0), mapSlot(pad32Addr(p.Portal), 0), portalImplSlot)
	if err != nil {
		return GameCapture{}, err
	}
	if _, err = proveAt(game, be32(slotGameMain), be32(slotGameStartL2Seq), be32(slotGameCountered), mapSlot(be32(0), mapGameProver),
		mapSlot(be32(1), mapGameProver), be32(slotGameExpectedRes)); err != nil {
		return GameCapture{}, err
	}
	// the implementation accounts (code hashes against impl_pins) and the game's embedded implementation
	impls := [][20]byte{
		addrWord(val(spPortal, portalImplSlot)), addrWord(val(spSys, portalImplSlot)), addrWord(val(spASR, portalImplSlot)),
		addrWord(val(spDGF, portalImplSlot)), addrWord(val(spSup, portalImplSlot)),
	}
	if gimpl != ([20]byte{}) {
		impls = append(impls, gimpl)
	}
	for _, ia := range impls {
		if _, err := proveAt(ia); err != nil {
			return GameCapture{}, err
		}
	}
	c := GameCapture{L1Block: a, L1Hash: hdr.Hash, Game: game, GameCode: code, Nodes: finality.EncodeNodes(nodes)}
	if err := store.Put(ctx, finality.CaptureKey{Chain: uint64(Chain), L1Block: a, L1Hash: hdr.Hash, Item: ItemGame(game)}, c.Encode()); err != nil {
		return GameCapture{}, err
	}
	return c, nil
}
