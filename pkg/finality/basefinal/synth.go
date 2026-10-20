// Copyright 2026 Certen Protocol

package basefinal

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// This file builds SYNTHETIC L1 worlds: a state trie holding the contract graph and one game in exactly the layout the 5.5
// verifier reads, with every value a knob. The synthetic cases cover what no live game can reach today (a blacklisted game, a
// paused system, a fast-path or ZK-only game, a nullified proof, a challenger win, a non-pinned implementation ...). They are
// built from the same pins as the live cases (the implementation accounts carry the real pinned code hashes), so a verdict of a
// synthetic world exercises the real rules; only the state root they commit to is not an Ethereum block's.

type synthAcct struct {
	CodeHash [32]byte
	Slots    map[[32]byte][32]byte
	Prove    [][32]byte // extra slots to prove (absent ones included)
	// Raw holds slot values stored exactly as given (the RLP of the leaf, not of the trimmed word): malformed values for the tests.
	Raw map[[32]byte][]byte
	// RawAcct, when set, is the account leaf stored as given instead of the encoded StateAccount.
	RawAcct []byte
	// Absent leaves the account out of the state trie (its absence is still proven).
	Absent bool
}

// SynthWorld is a set of accounts.
type SynthWorld struct {
	Accts map[[20]byte]*synthAcct
}

func newSynthWorld() *SynthWorld { return &SynthWorld{Accts: map[[20]byte]*synthAcct{}} }

func (w *SynthWorld) acct(a [20]byte) *synthAcct {
	if x, ok := w.Accts[a]; ok {
		return x
	}
	x := &synthAcct{Slots: map[[32]byte][32]byte{}}
	w.Accts[a] = x
	return x
}

// Set stores a slot value (a zero value is an absent slot that is still proven).
func (w *SynthWorld) Set(a [20]byte, slot, val [32]byte) {
	x := w.acct(a)
	if val == ([32]byte{}) {
		delete(x.Slots, slot)
		x.Prove = append(x.Prove, slot)
		return
	}
	x.Slots[slot] = val
}

// SetRaw stores a slot value as the given leaf bytes (a malformed value for the tests); it replaces any value set before.
func (w *SynthWorld) SetRaw(a [20]byte, slot [32]byte, leaf []byte) {
	x := w.acct(a)
	delete(x.Slots, slot)
	if x.Raw == nil {
		x.Raw = map[[32]byte][]byte{}
	}
	x.Raw[slot] = leaf
}

// SetRawAccount stores the account leaf as the given bytes (a malformed account for the tests).
func (w *SynthWorld) SetRawAccount(a [20]byte, leaf []byte) { w.acct(a).RawAcct = leaf }

// SetAbsent removes the account from the state trie; the proof of its absence is still given.
func (w *SynthWorld) SetAbsent(a [20]byte) { w.acct(a).Absent = true }

// SetCodeHash sets the account's code hash.
func (w *SynthWorld) SetCodeHash(a [20]byte, h [32]byte) { w.acct(a).CodeHash = h }

type proofSet struct{ nodes [][]byte }

func (s *proofSet) Put(_ []byte, v []byte) error {
	s.nodes = append(s.nodes, common.CopyBytes(v))
	return nil
}
func (s *proofSet) Delete([]byte) error { return fmt.Errorf("a proof is never deleted from") }

// Build commits the world: it returns the state root and the deduplicated proof nodes of every account and every present or
// explicitly proven slot.
func (w *SynthWorld) Build() (root [32]byte, nodes [][]byte, err error) {
	st := trie.NewEmpty(nil)
	type built struct {
		tr *trie.Trie
		a  *synthAcct
	}
	stor := map[[20]byte]built{}
	for addr, a := range w.Accts {
		tr := trie.NewEmpty(nil)
		for s, v := range a.Slots {
			enc, _ := rlp.EncodeToBytes(trimLeadingZeros(v[:]))
			if err := tr.Update(crypto.Keccak256(s[:]), enc); err != nil {
				return root, nil, err
			}
		}
		for s, leaf := range a.Raw {
			if err := tr.Update(crypto.Keccak256(s[:]), leaf); err != nil {
				return root, nil, err
			}
		}
		stor[addr] = built{tr, a}
		if a.Absent {
			continue
		}
		acc := types.NewEmptyStateAccount()
		acc.Nonce, acc.Root, acc.CodeHash = 1, tr.Hash(), a.CodeHash[:]
		enc, err := rlp.EncodeToBytes(acc)
		if err != nil {
			return root, nil, err
		}
		if a.RawAcct != nil {
			enc = a.RawAcct
		}
		if err := st.Update(crypto.Keccak256(addr[:]), enc); err != nil {
			return root, nil, err
		}
	}
	root = [32]byte(st.Hash())
	var set proofSet
	for addr, b := range stor {
		if err := st.Prove(crypto.Keccak256(addr[:]), &set); err != nil {
			return root, nil, err
		}
		if b.a.Absent || b.a.RawAcct != nil {
			continue // nothing is proven under an account that is absent or malformed
		}
		slots := map[[32]byte]bool{}
		for s := range b.a.Slots {
			slots[s] = true
		}
		for s := range b.a.Raw {
			slots[s] = true
		}
		for _, s := range b.a.Prove {
			slots[s] = true
		}
		for s := range slots {
			if err := b.tr.Prove(crypto.Keccak256(s[:]), &set); err != nil {
				return root, nil, err
			}
		}
	}
	return root, finality.EncodeNodes(set.nodes), nil
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b) && b[i] == 0 {
		i++
	}
	return b[i:]
}

// ---- synthetic L2 headers ----

// SynthL2Header is a Base-like L2 header of 17 items (withdrawalsRoot at item 16) for the given number, parent, state root and
// withdrawals root.
func SynthL2Header(number uint64, parent, stateRoot, withdrawals [32]byte) []byte {
	items := []any{
		parent[:], make([]byte, 32), make([]byte, 20), stateRoot[:], make([]byte, 32), make([]byte, 32), make([]byte, 256),
		new(big.Int), new(big.Int).SetUint64(number), new(big.Int).SetUint64(60000000), new(big.Int).SetUint64(21000),
		new(big.Int).SetUint64(1790000000 + 2*number), []byte("synthetic"), make([]byte, 32), make([]byte, 8),
		new(big.Int).SetUint64(7), withdrawals[:],
	}
	b, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return b
}

func outputRoot(h finality.HeaderFields) [32]byte {
	var w [32]byte
	if h.WithdrawalsRoot != nil {
		w = *h.WithdrawalsRoot
	}
	return [32]byte(crypto.Keccak256Hash(make([]byte, 32), h.StateRoot[:], w[:], h.Hash[:]))
}

// ---- the scenario ----

// SynthSpec is every knob of a synthetic game world. The zero value of a knob is "as a healthy resolved DEFENDER_WINS game
// of the 0.2.0 implementation".
type SynthSpec struct {
	Version string // "0.2.0" (default) or "0.3.0"
	K       uint32 // outputRootIndex
	Depth   int    // number of L2 headers below the output-root block (0: the leg IS the output-root block)
	// L2 block of the output-root header (default 47604773)
	OutBlock uint64
	// game state
	CreatedAt, ResolvedAt uint64
	Status                *uint8
	Respected             *uint8
	Countered             uint64
	TEE, ZK               *bool
	ExpectedRes           *uint64
	ProofCount            *uint64
	Blacklisted           bool
	PauseZero, PausePort  uint64
	Retirement            *uint64
	Pair                  *[2]uint64 // {total, interval}; default the first interval pair of the pinned row
	StartDelta            int64      // added to the game's starting block (slot 2) to break the interval pair
	// L1 header
	ATimestamp uint64
	// Tweak runs on the finished world and code before the proofs are built
	Tweak func(w *SynthWorld, p *Pins, code *[]byte)
	// RegTweak edits the DGF registration word of the game before it is stored
	RegTweak func(reg *[32]byte)
	// L2NumberSkipAt (> 0) makes the L2 spine skip a block number at that depth while every hash link stays valid
	L2NumberSkipAt int
}

// SynthOut is a built synthetic world and the inputs of Judge.
type SynthOut struct {
	A        ethl1.L1Block
	Body     Body
	Leg      finality.BlockRef
	Root     [32]byte
	World    *SynthWorld
	GameAddr [20]byte
	Row      ImplRow
}

var (
	synthASR   = [20]byte(common.HexToAddress("0x2fF5cC82dBf333Ea30D8ee462178ab1707315355"))
	synthDGF   = [20]byte(common.HexToAddress("0xd6E6dBf4F7EA0ac412fD8b65ED297e64BB7a06E1"))
	synthSUP   = [20]byte(common.HexToAddress("0xE4401EB53AE90a5335a51fe1828d7BeCf7a63508"))
	synthGame  = [20]byte(common.HexToAddress("0x3b91948AAFcc00CF76aEcd837169e4cEe0389815"))
	synthPImpl = [20]byte(common.HexToAddress("0xa53f56711a2f65c19c1542c98116b98fc07a9bb1"))
	synthSImpl = [20]byte(common.HexToAddress("0xaeb75e200b9bcf9343ff1a2d2b1b3976e7339ca4"))
	synthAImpl = [20]byte(common.HexToAddress("0xb1cc9f8422042eda9eb36a408002517d7c772ac7"))
	synthDImpl = [20]byte(common.HexToAddress("0x9cacf701ef24b8339cd1fdecadde7c080373fb29"))
	synthUImpl = [20]byte(common.HexToAddress("0x99fcf11772af0a9cc411af3cb4311a387dd55b15"))
)

func hashOfRole(p *Pins, role string) [32]byte {
	for _, h := range sortedImplHashes(p.Impl) {
		if p.Impl[h].Role == role {
			return h
		}
	}
	panic("no pinned implementation with role " + role)
}

func proxyHash(p *Pins, role string) [32]byte {
	for h, r := range p.Proxy {
		if r == role {
			return h
		}
	}
	panic("no pinned proxy with role " + role)
}

func put64(w *[32]byte, offFromRight int, v uint64) {
	binary.BigEndian.PutUint64(w[32-offFromRight-8:32-offFromRight], v)
}

func addrToWord(a [20]byte) (w [32]byte) {
	copy(w[12:], a[:])
	return w
}

// BuildSynth builds the world of a spec over the given pins.
func BuildSynth(p *Pins, s SynthSpec) (*SynthOut, error) {
	version := s.Version
	if version == "" {
		version = "0.2.0"
	}
	var rowHash [32]byte
	var row ImplRow
	for h, r := range p.Impl {
		if r.Role == RoleGameImpl && r.Version == version {
			rowHash, row = h, r
		}
	}
	if row.Role == "" {
		return nil, fmt.Errorf("no pinned game_impl of version %s", version)
	}
	lay := p.Layouts[LayoutAggregateV1]
	pair := row.IntervalPairs[0]
	if s.Pair != nil {
		pair = *s.Pair
	}
	n := uint64(row.NIntermediate)
	total, interval := pair[0], pair[1]
	outBlock := s.OutBlock
	if outBlock == 0 {
		outBlock = 47604773
	}
	// the L2 headers: the leg at the bottom, the output-root header on top
	nums := make([]uint64, s.Depth+1)
	for i := range nums {
		nums[i] = outBlock - uint64(i)
		if s.L2NumberSkipAt > 0 && i >= s.L2NumberSkipAt {
			nums[i]--
		}
	}
	var l2 [][]byte
	var parent [32]byte
	stateRoot := [32]byte(crypto.Keccak256Hash([]byte("synthetic l2 state root")))
	wroot := [32]byte(crypto.Keccak256Hash([]byte("synthetic l2 withdrawals root")))
	for i := len(nums) - 1; i >= 0; i-- {
		raw := SynthL2Header(nums[i], parent, stateRoot, wroot)
		h, err := finality.ReadHeader(raw)
		if err != nil {
			return nil, err
		}
		parent = h.Hash
		l2 = append([][]byte{raw}, l2...)
	}
	top, _ := finality.ReadHeader(l2[0])
	leg, _ := finality.ReadHeader(l2[len(l2)-1])
	// the game
	var start, l2seq uint64
	if s.K == 0 {
		l2seq = outBlock
		start = l2seq - total
	} else {
		start = outBlock - interval*uint64(s.K)
		l2seq = start + total
	}
	roots := make([][32]byte, n)
	for i := range roots {
		roots[i] = [32]byte(crypto.Keccak256Hash([]byte("synthetic intermediate root"), []byte{byte(i)}))
	}
	claim := outputRoot(top)
	if s.K == 0 {
		roots[n-1] = claim
	} else {
		roots[s.K-1] = claim
	}
	rootClaim := roots[n-1]
	var args []byte
	args = append(args, make([]byte, 20)...)
	args = append(args, rootClaim[:]...)
	args = append(args, make([]byte, 32)...)
	l2w := be32(l2seq)
	args = append(args, l2w[:]...)
	args = append(args, make([]byte, 20)...)
	for _, r := range roots {
		args = append(args, r[:]...)
	}
	if len(args) != row.ArgsLen {
		return nil, fmt.Errorf("synthetic args are %d bytes, the pin says %d", len(args), row.ArgsLen)
	}
	var code []byte
	code = append(code, lay.CloneHead...)
	code = binary.BigEndian.AppendUint16(code, uint16(row.ArgsLen+2))
	code = append(code, lay.CloneMid...)
	code = append(code, row.Impl[:]...)
	code = append(code, lay.CloneTail...)
	code = append(code, args...)
	code = binary.BigEndian.AppendUint16(code, uint16(row.ArgsLen+2))

	// the world
	w := newSynthWorld()
	prx, sprx := proxyHash(p, RoleOPProxy), proxyHash(p, RoleSuperchainPrx)
	implSlot := [32]byte(eip1967ImplSlot)
	for _, a := range []struct {
		addr  [20]byte
		impl  [20]byte
		role  string
		proxy [32]byte
	}{
		{p.Portal, synthPImpl, RolePortalImpl, prx}, {p.SystemConfig, synthSImpl, RoleSysCfgImpl, prx}, {synthASR, synthAImpl, RoleASRImpl, prx},
		{synthDGF, synthDImpl, RoleDGFImpl, prx}, {synthSUP, synthUImpl, RoleSuperchainImpl, sprx},
	} {
		w.SetCodeHash(a.addr, a.proxy)
		w.Set(a.addr, implSlot, addrToWord(a.impl))
		w.SetCodeHash(a.impl, hashOfRole(p, a.role))
	}
	w.SetCodeHash(row.Impl, rowHash)
	w.Set(p.Portal, be32(slotPortalSystemConfig), addrToWord(p.SystemConfig))
	w.Set(p.Portal, be32(slotPortalASR), addrToWord(synthASR))
	w.Set(p.SystemConfig, optimismPortalSlot, addrToWord(p.Portal))
	w.Set(p.SystemConfig, be32(slotSysCfgSuperchain), addrToWord(synthSUP))
	var asr0 [32]byte
	copy(asr0[10:30], p.SystemConfig[:])
	asr0[31] = 1
	w.Set(synthASR, be32(slotASRSystemConfig), asr0)
	w.Set(synthASR, be32(slotASRDGF), addrToWord(synthDGF))
	retire := uint64(1776392808)
	if s.Retirement != nil {
		retire = *s.Retirement
	}
	var rr [32]byte
	binary.BigEndian.PutUint32(rr[28:], 621)
	put64(&rr, 4, retire)
	w.Set(synthASR, be32(slotASRRespectedRetire), rr)
	blKey := mapSlot(addrToWord(synthGame), mapASRBlacklist)
	if s.Blacklisted {
		var one [32]byte
		one[31] = 1
		w.Set(synthASR, blKey, one)
	} else {
		w.Set(synthASR, blKey, [32]byte{})
	}
	var pz, pp [32]byte
	put64(&pz, 0, s.PauseZero)
	put64(&pp, 0, s.PausePort)
	w.Set(synthSUP, mapSlot(be32(0), 0), pz)
	w.Set(synthSUP, mapSlot(addrToWord(p.Portal), 0), pp)

	created := s.CreatedAt
	if created == 0 {
		created = 1790980536
	}
	resolved := s.ResolvedAt
	if resolved == 0 {
		resolved = created + 432288
	}
	status := StatusDefenderWins
	if s.Status != nil {
		status = *s.Status
	}
	respected := uint8(1)
	if s.Respected != nil {
		respected = *s.Respected
	}
	var g0 [32]byte
	put64(&g0, 0, created)
	put64(&g0, 8, resolved)
	g0[15], g0[14], g0[13] = status, 1, respected
	w.Set(synthGame, be32(slotGameMain), g0)
	w.Set(synthGame, be32(slotGameStartL2Seq), be32(uint64(int64(start)+s.StartDelta)))
	var c5 [32]byte
	put64(&c5, 0, s.Countered)
	w.Set(synthGame, be32(slotGameCountered), c5)
	prover := addrToWord([20]byte(common.HexToAddress("0xdb84125F2F4229c81c579F41BC129C71B174Eb58")))
	tee, zk := true, false
	if s.TEE != nil {
		tee = *s.TEE
	}
	if s.ZK != nil {
		zk = *s.ZK
	}
	if tee {
		w.Set(synthGame, mapSlot(be32(0), mapGameProver), prover)
	} else {
		w.Set(synthGame, mapSlot(be32(0), mapGameProver), [32]byte{})
	}
	if zk {
		w.Set(synthGame, mapSlot(be32(1), mapGameProver), prover)
	} else {
		w.Set(synthGame, mapSlot(be32(1), mapGameProver), [32]byte{})
	}
	exp := created + row.SlowDelay
	if s.ExpectedRes != nil {
		exp = *s.ExpectedRes
	}
	pc := uint64(1)
	if s.ProofCount != nil {
		pc = *s.ProofCount
	}
	var g7 [32]byte
	put64(&g7, 0, exp)
	put64(&g7, 8, pc)
	w.Set(synthGame, be32(slotGameExpectedRes), g7)

	if s.Tweak != nil {
		s.Tweak(w, p, &code)
	}
	w.SetCodeHash(synthGame, [32]byte(crypto.Keccak256Hash(code)))
	// the DGF registration of the game that is actually in the code
	uuid := gameUUID(row.GameType, rootClaim, args[84:])
	var reg [32]byte
	binary.BigEndian.PutUint32(reg[0:4], row.GameType)
	binary.BigEndian.PutUint64(reg[4:12], created)
	copy(reg[12:], synthGame[:])
	if s.RegTweak != nil {
		s.RegTweak(&reg)
	}
	w.Set(synthDGF, mapSlot(uuid, mapDGFGames), reg)

	root, nodes, err := w.Build()
	if err != nil {
		return nil, err
	}
	at := s.ATimestamp
	if at == 0 {
		at = resolved + 1000
	}
	a := ethl1.L1Block{Hash: [32]byte(crypto.Keccak256Hash([]byte("synthetic A"))), Number: 11954148, StateRoot: root, Timestamp: at}
	out := &SynthOut{A: a, Root: root, World: w, GameAddr: synthGame, Row: row}
	out.Body = Body{StateBlock: a.Number, GameProxy: synthGame, GameCode: code, OutputRootIndex: s.K, L2Spine: l2, Nodes: nodes}
	out.Leg = finality.BlockRef{Chain: uint64(Chain), Number: leg.Number, Hash: leg.Hash, HeaderRLP: l2[len(l2)-1]}
	return out, nil
}

// SynthAddrs are the addresses of the synthetic world's contracts, for the generator and the tests.
var SynthAddrs = struct {
	ASR, DGF, SUP, Game, PortalImpl, SysCfgImpl, ASRImpl, DGFImpl, SupImpl [20]byte
}{synthASR, synthDGF, synthSUP, synthGame, synthPImpl, synthSImpl, synthAImpl, synthDImpl, synthUImpl}

// SynthBadHash is a code hash no pin holds.
var SynthBadHash = [32]byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
