// Copyright 2026 Certen Protocol

package basefinal

import (
	"bytes"
	"encoding/binary"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The Base R and L1 codes this kind raises (V2_SPEC_S7 section 7); all are registered in testdata/finality/states.json.
const (
	CodeL1FinalityUnproven  = "l1_finality_unproven"
	CodeContractIdentity    = "contract_identity_unproven"
	CodeGameUnrecognised    = "game_unrecognised"
	CodeGameTypeUnsupported = "game_type_unsupported"
	CodeGameNotRegistered   = "game_not_registered"
	CodeGameBlacklisted     = "game_blacklisted"
	CodeGameRetired         = "game_retired"
	CodeL1SystemPaused      = "l1_system_paused"
	CodeGameNotRespected    = "game_not_respected"
	CodeGameNotResolved     = "game_not_resolved"
	CodeGameWithinDelay     = "game_within_finality_delay"
	CodeGameChallengerWins  = "game_challenger_wins"
	CodeOutputRootMismatch  = "output_root_mismatch"
	CodeL2NotCanonical      = "l2_block_not_canonical"
	CodeL1StateProofInvalid = "l1_state_proof_invalid"
)

// LCRefused is the reason of l1_finality_unproven when the LC part of the container is refused; the inner fault code rides in
// the `inner` field.
const LCRefused = "lc_refused"

// The reasons of game_unrecognised (closed set, states.json).
const (
	ReasonPrefix       = "prefix"
	ReasonTrailer      = "trailer"
	ReasonArgsLen      = "args_len"
	ReasonNMismatch    = "n_mismatch"
	ReasonIntervalPair = "interval_pair"
)

// GameStatus values (OP Types.GameStatus).
const (
	StatusInProgress     uint8 = 0
	StatusChallengerWins uint8 = 1
	StatusDefenderWins   uint8 = 2
)

var (
	// eip1967ImplSlot is keccak256("eip1967.proxy.implementation") - 1.
	eip1967ImplSlot = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	// optimismPortalSlot is SystemConfig's OPTIMISM_PORTAL_SLOT = keccak256("systemconfig.optimismportal") - 1 ([BASE Q9]).
	optimismPortalSlot = common.HexToHash("0x4b6c74f9e688cb39801f2112c14a8c57232a3fc5202e1444126d4bce86eb19ac")
)

// The storage slots read (V2_SPEC_S7 5.5, [BASE Q9], [B30 Q4(g)]).
const (
	slotPortalSystemConfig = 55
	slotPortalASR          = 62
	slotSysCfgSuperchain   = 108
	slotASRSystemConfig    = 0 // systemConfig at byte offset 2 of the word (bytes [10,30))
	slotASRDGF             = 1
	slotASRRespectedRetire = 6 // respectedGameType u32 @0, retirementTimestamp u64 @4
	mapASRBlacklist        = 5
	mapDGFGames            = 103
	slotGameMain           = 0
	slotGameStartL2Seq     = 2
	slotGameCountered      = 5
	mapGameProver          = 6
	slotGameExpectedRes    = 7
)

func st(code string, kv ...any) *finality.StateError { return finality.NewState(code, kv...) }

// Kind is the verifier of base-sepolia/finalized/v1 (spec 5.5). It is pure: no I/O, no clock.
type Kind struct{}

func (Kind) Name() string          { return KindName }
func (Kind) Chain() uint64         { return uint64(Chain) }
func (Kind) Level() finality.Level { return finality.LevelFinalized }

// Register adds the kind to a registry; there is no init().
func Register(reg *finality.Registry) error { return reg.RegisterKind(Kind{}) }

// ---- the MPT reader ----

type nodeDB struct{ db *memorydb.Database }

func newNodeDB(nodes [][]byte) nodeDB {
	db := memorydb.New()
	for _, n := range nodes {
		_ = db.Put(crypto.Keccak256(n), n)
	}
	return nodeDB{db}
}

// stateReader reads accounts and slots from the proof node set under one state root (spec 5.5 O2). Every read is an MPT proof
// from NODES: account key keccak256(address), slot key keccak256(slot), an absent key reads zero.
type stateReader struct {
	db    nodeDB
	root  [32]byte
	accts map[[20]byte]acctRead
}

type acctRead struct {
	acct   types.StateAccount
	exists bool
}

func newStateReader(nodes [][]byte, root [32]byte) *stateReader {
	return &stateReader{db: newNodeDB(nodes), root: root, accts: map[[20]byte]acctRead{}}
}

// account proves an account under the state root: exists=false is a proven absence. A missing or inconsistent node is
// l1_state_proof_invalid{which:"account"}.
func (r *stateReader) account(addr [20]byte) (acctRead, error) {
	if a, ok := r.accts[addr]; ok {
		return a, nil
	}
	v, err := trie.VerifyProof(common.Hash(r.root), crypto.Keccak256(addr[:]), r.db.db)
	if err != nil {
		return acctRead{}, st(CodeL1StateProofInvalid, "which", "account")
	}
	var out acctRead
	if len(v) != 0 {
		if err := rlp.DecodeBytes(v, &out.acct); err != nil {
			return acctRead{}, st(CodeL1StateProofInvalid, "which", "account")
		}
		out.exists = true
	}
	r.accts[addr] = out
	return out, nil
}

// slot proves a storage slot of an existing account; an absent slot reads zero. The account must exist: a slot of an absent
// account is l1_state_proof_invalid{which:"account"}.
func (r *stateReader) slot(addr [20]byte, slot [32]byte) ([32]byte, error) {
	var out [32]byte
	a, err := r.account(addr)
	if err != nil {
		return out, err
	}
	if !a.exists {
		return out, st(CodeL1StateProofInvalid, "which", "account")
	}
	v, err := trie.VerifyProof(common.Hash(a.acct.Root), crypto.Keccak256(slot[:]), r.db.db)
	if err != nil {
		return out, st(CodeL1StateProofInvalid, "which", "slot")
	}
	if len(v) == 0 {
		return out, nil
	}
	var raw []byte
	if err := rlp.DecodeBytes(v, &raw); err != nil || len(raw) > 32 || len(raw) == 0 {
		return out, st(CodeL1StateProofInvalid, "which", "slot")
	}
	copy(out[32-len(raw):], raw)
	return out, nil
}

func codeHashOf(a acctRead) (h [32]byte) {
	if a.exists {
		copy(h[:], a.acct.CodeHash)
	}
	return h
}

func addrWord(w [32]byte) [20]byte { return [20]byte(w[12:]) }

func pad32Addr(a [20]byte) (out [32]byte) {
	copy(out[12:], a[:])
	return out
}

func be32(v uint64) (out [32]byte) {
	binary.BigEndian.PutUint64(out[24:], v)
	return out
}

func mapSlot(key [32]byte, slot uint64) [32]byte {
	s := be32(slot)
	return [32]byte(crypto.Keccak256Hash(key[:], s[:]))
}

// ---- the judgement ----

// judgeInput is everything the L1-state part needs once the L1 finalized head has been proven and A located on its spine.
type judgeInput struct {
	A    ethl1.L1Block
	Body Body
	Leg  finality.BlockRef
	Pins *Pins
	Head ethl1.FinalizedHead
}

// GameState is what the proven L1 state says about the game, decoded before any predicate is applied. It is the verifier's
// result and the builder's view of an unresolved game.
type GameState struct {
	CreatedAt, ResolvedAt  uint64
	Status                 uint8
	Initialized, Respected uint8
	StartL2Seq             uint64
	Countered              [32]byte
	TEEProver, ZKProver    [32]byte
	ExpectedResolution     uint64
	ProofCount             uint64
	Blacklisted            bool
	RetirementTimestamp    uint64
	RespectedGameType      uint32
	Pause0, PauseOnPortal  [32]byte
}

func (g GameState) proofSystem() string {
	tee, zk := g.TEEProver != [32]byte{}, g.ZKProver != [32]byte{}
	switch {
	case tee && zk:
		return "tee+zk"
	case tee:
		return "tee"
	case zk:
		return "zk"
	}
	return "none"
}

func (g GameState) finalizationPath(slow uint64) (string, bool) {
	if g.ExpectedResolution < g.CreatedAt {
		return "", false
	}
	d := g.ExpectedResolution - g.CreatedAt
	switch {
	case d == slow:
		return "slow", true
	case d > slow:
		return "extended", true
	case g.ProofCount == 2 && g.Countered == [32]byte{}:
		return "fast", true
	}
	return "", false
}

func u64Of(w [32]byte, offFromRight int) uint64 {
	return binary.BigEndian.Uint64(w[32-offFromRight-8 : 32-offFromRight])
}

// judge is the L1-state half of 5.5 (O2-O6) over a proven A. It is pure.
func judge(in judgeInput) (map[string]any, error) {
	p, A, body := in.Pins, in.A, in.Body
	rd := newStateReader(body.Nodes, A.StateRoot)
	identity := func(role string, addr [20]byte, ch [32]byte) error {
		return st(CodeContractIdentity, "role", role, "address", addr, "code_hash", ch, "judged_at", A.Number)
	}
	// proxy proves the account of a pinned-by-graph proxy and its runtime code against proxy_pins.
	proxy := func(name string, addr [20]byte, want string) (acctRead, error) {
		a, err := rd.account(addr)
		if err != nil {
			return a, err
		}
		if !a.exists || p.Proxy[codeHashOf(a)] != want {
			return a, identity(name+"_proxy", addr, codeHashOf(a))
		}
		return a, nil
	}
	// impl proves the EIP-1967 implementation behind a proxy and its role in impl_pins.
	impl := func(role string, prx [20]byte) (ImplRow, error) {
		w, err := rd.slot(prx, eip1967ImplSlot)
		if err != nil {
			return ImplRow{}, err
		}
		ia := addrWord(w)
		a, err := rd.account(ia)
		if err != nil {
			return ImplRow{}, err
		}
		row, ok := p.Impl[codeHashOf(a)]
		if !a.exists || !ok || row.Role != role {
			return ImplRow{}, identity(role, ia, codeHashOf(a))
		}
		return row, nil
	}

	// -- identity: the contract graph from the two address pins (5.5 O3) --
	pa, err := proxy("portal", p.Portal, RoleOPProxy)
	if err != nil {
		return nil, err
	}
	w, err := rd.slot(p.Portal, be32(slotPortalSystemConfig))
	if err != nil {
		return nil, err
	}
	if addrWord(w) != p.SystemConfig {
		return nil, identity("portal.systemConfig", addrWord(w), codeHashOf(pa))
	}
	if _, err = impl(RolePortalImpl, p.Portal); err != nil {
		return nil, err
	}
	sa, err := proxy("system_config", p.SystemConfig, RoleOPProxy)
	if err != nil {
		return nil, err
	}
	if w, err = rd.slot(p.SystemConfig, optimismPortalSlot); err != nil {
		return nil, err
	}
	if addrWord(w) != p.Portal {
		return nil, identity("systemconfig.portal", addrWord(w), codeHashOf(sa))
	}
	if _, err = impl(RoleSysCfgImpl, p.SystemConfig); err != nil {
		return nil, err
	}
	if w, err = rd.slot(p.Portal, be32(slotPortalASR)); err != nil {
		return nil, err
	}
	asr := addrWord(w)
	aa, err := proxy("asr", asr, RoleOPProxy)
	if err != nil {
		return nil, err
	}
	if w, err = rd.slot(asr, be32(slotASRSystemConfig)); err != nil {
		return nil, err
	}
	if [20]byte(w[10:30]) != p.SystemConfig {
		return nil, identity("asr.systemConfig", [20]byte(w[10:30]), codeHashOf(aa))
	}
	asrRow, err := impl(RoleASRImpl, asr)
	if err != nil {
		return nil, err
	}
	if asrRow.FinalityDelaySeconds == nil {
		return nil, identity(RoleASRImpl, asr, codeHashOf(aa))
	}
	delay := *asrRow.FinalityDelaySeconds
	if w, err = rd.slot(asr, be32(slotASRDGF)); err != nil {
		return nil, err
	}
	dgf := addrWord(w)
	if _, err = proxy("dgf", dgf, RoleOPProxy); err != nil {
		return nil, err
	}
	if _, err = impl(RoleDGFImpl, dgf); err != nil {
		return nil, err
	}
	if w, err = rd.slot(p.SystemConfig, be32(slotSysCfgSuperchain)); err != nil {
		return nil, err
	}
	sup := addrWord(w)
	if _, err = proxy("superchain", sup, RoleSuperchainPrx); err != nil {
		return nil, err
	}
	if _, err = impl(RoleSuperchainImpl, sup); err != nil {
		return nil, err
	}

	// -- the game proxy: code, clone template, decoded args (5.5 O3) --
	ga, err := rd.account(body.GameProxy)
	if err != nil {
		return nil, err
	}
	code := body.GameCode
	if !ga.exists || crypto.Keccak256Hash(code) != common.BytesToHash(ga.acct.CodeHash) {
		return nil, st(CodeL1StateProofInvalid, "which", "account")
	}
	lay, ok := p.Layouts[LayoutAggregateV1]
	if !ok {
		return nil, finality.PinsCorrupt(finality.PinsBadValue, "key", "base_sepolia.game_layout")
	}
	tmplLen := len(lay.CloneHead) + 2 + len(lay.CloneMid) + 20 + len(lay.CloneTail)
	implOff := len(lay.CloneHead) + 2 + len(lay.CloneMid)
	unrec := func(reason string, kv ...any) error {
		return st(CodeGameUnrecognised, append([]any{"reason", reason}, kv...)...)
	}
	if len(code) < tmplLen+2 {
		return nil, unrec(ReasonPrefix)
	}
	var gimpl [20]byte
	copy(gimpl[:], code[implOff:implOff+20])
	gia, err := rd.account(gimpl)
	if err != nil {
		return nil, err
	}
	row, pinned := p.Impl[codeHashOf(gia)]
	if !gia.exists || !pinned || row.Role != RoleGameImpl || !row.Complete(p.Layouts) || row.Impl != gimpl || row.CWIA != LayoutAggregateV1 {
		return nil, identity(RoleGameImpl, gimpl, codeHashOf(gia))
	}
	rest := len(code) - tmplLen - 2
	if rest < lay.ArgsBaseLen || (rest-lay.ArgsBaseLen)%lay.ArgsPerRoot != 0 {
		return nil, unrec(ReasonArgsLen)
	}
	if n := (rest - lay.ArgsBaseLen) / lay.ArgsPerRoot; n != row.NIntermediate {
		return nil, unrec(ReasonNMismatch)
	}
	var want []byte
	want = append(want, lay.CloneHead...)
	want = binary.BigEndian.AppendUint16(want, uint16(row.ArgsLen+2))
	want = append(want, lay.CloneMid...)
	want = append(want, gimpl[:]...)
	want = append(want, lay.CloneTail...)
	if !bytes.Equal(code[:tmplLen], want) {
		return nil, unrec(ReasonPrefix)
	}
	if binary.BigEndian.Uint16(code[len(code)-2:]) != uint16(row.ArgsLen+2) {
		return nil, unrec(ReasonTrailer)
	}
	args := code[tmplLen : len(code)-2]
	rootClaim := [32]byte(args[20:52])
	extraData := args[84:]
	var l2seqW [32]byte
	copy(l2seqW[:], args[84:116])
	roots := make([][32]byte, row.NIntermediate)
	for i := range roots {
		copy(roots[i][:], args[lay.ArgsBaseLen+32*i:])
	}

	// -- registration: DGF._disputeGames[uuid] = gameType || createdAt || proxy (5.5 O4) --
	uuid := gameUUID(row.GameType, rootClaim, extraData)
	reg, err := rd.slot(dgf, mapSlot(uuid, mapDGFGames))
	if err != nil {
		return nil, err
	}
	if reg == ([32]byte{}) {
		return nil, st(CodeGameNotRegistered)
	}
	if gt := binary.BigEndian.Uint32(reg[0:4]); gt != row.GameType {
		return nil, st(CodeGameTypeUnsupported, "type", gt)
	}

	// -- the proven game state: slots 0, 2, 5, 6 (TEE and ZK keys), 7 --
	var g GameState
	slot := func(s [32]byte) ([32]byte, error) { return rd.slot(body.GameProxy, s) }
	w0, err := slot(be32(slotGameMain))
	if err != nil {
		return nil, err
	}
	g.CreatedAt, g.ResolvedAt = u64Of(w0, 0), u64Of(w0, 8)
	g.Status, g.Initialized, g.Respected = w0[15], w0[14], w0[13]
	w2, err := slot(be32(slotGameStartL2Seq))
	if err != nil {
		return nil, err
	}
	if g.Countered, err = slot(be32(slotGameCountered)); err != nil {
		return nil, err
	}
	if g.TEEProver, err = slot(mapSlot(be32(0), mapGameProver)); err != nil {
		return nil, err
	}
	if g.ZKProver, err = slot(mapSlot(be32(1), mapGameProver)); err != nil {
		return nil, err
	}
	w7, err := slot(be32(slotGameExpectedRes))
	if err != nil {
		return nil, err
	}
	g.ExpectedResolution, g.ProofCount = u64Of(w7, 0), u64Of(w7, 8)
	if [20]byte(reg[12:32]) != body.GameProxy || binary.BigEndian.Uint64(reg[4:12]) != g.CreatedAt {
		return nil, st(CodeGameNotRegistered)
	}

	// -- isGameClaimValid as of A (5.5 O4) --
	bl, err := rd.slot(asr, mapSlot(pad32Addr(body.GameProxy), mapASRBlacklist))
	if err != nil {
		return nil, err
	}
	rr, err := rd.slot(asr, be32(slotASRRespectedRetire))
	if err != nil {
		return nil, err
	}
	g.RespectedGameType, g.RetirementTimestamp = binary.BigEndian.Uint32(rr[28:32]), u64Of(rr, 4)
	supAddr := sup
	if g.Pause0, err = rd.slot(supAddr, mapSlot(be32(0), 0)); err != nil {
		return nil, err
	}
	if g.PauseOnPortal, err = rd.slot(supAddr, mapSlot(pad32Addr(p.Portal), 0)); err != nil {
		return nil, err
	}
	if bl != ([32]byte{}) {
		return nil, st(CodeGameBlacklisted)
	}
	if g.CreatedAt <= g.RetirementTimestamp {
		return nil, st(CodeGameRetired, "createdAt", g.CreatedAt, "retirementTimestamp", g.RetirementTimestamp)
	}
	if g.Pause0 != ([32]byte{}) {
		return nil, st(CodeL1SystemPaused, "identifier", [20]byte{}, "pauseTimestamp", new(big.Int).SetBytes(g.Pause0[:]).String())
	}
	if g.PauseOnPortal != ([32]byte{}) {
		return nil, st(CodeL1SystemPaused, "identifier", p.Portal, "pauseTimestamp", new(big.Int).SetBytes(g.PauseOnPortal[:]).String())
	}
	if g.Respected != 1 {
		return nil, st(CodeGameNotRespected)
	}
	if g.ResolvedAt == 0 || (g.Status != StatusChallengerWins && g.Status != StatusDefenderWins) {
		return nil, st(CodeGameNotResolved, "status", g.Status)
	}
	if A.Timestamp <= g.ResolvedAt+delay {
		return nil, st(CodeGameWithinDelay, "resolvedAt", g.ResolvedAt, "delay", delay, "T", A.Timestamp)
	}
	if g.Status != StatusDefenderWins {
		return nil, st(CodeGameChallengerWins)
	}
	// consistency of the proven slots (5.5 O4, [r2:E4]): a DEFENDER_WINS game has slot 5 = 0, at least one prover key, an
	// expectedResolution it was resolved after, and a finalization path its proof count explains.
	ps := g.proofSystem()
	path, pathOK := g.finalizationPath(row.SlowDelay)
	if g.Countered != ([32]byte{}) || ps == "none" || g.ResolvedAt < g.ExpectedResolution || !pathOK {
		return nil, st(CodeL1StateProofInvalid, "which", "slot")
	}

	// -- output root (5.5 O5) --
	// the l2 sequence numbers are uint256 words that must fit 64 bits
	pairErr := func(total uint64, n int) error {
		return unrec(ReasonIntervalPair, "total", total, "n", uint64(n))
	}
	if !bytes.Equal(l2seqW[:24], make([]byte, 24)) || !bytes.Equal(w2[:24], make([]byte, 24)) {
		return nil, pairErr(0, row.NIntermediate)
	}
	l2seq, start := binary.BigEndian.Uint64(l2seqW[24:]), binary.BigEndian.Uint64(w2[24:])
	if l2seq < start {
		return nil, pairErr(0, row.NIntermediate)
	}
	total := l2seq - start
	var interval uint64
	matched := false
	for _, pr := range row.IntervalPairs {
		if pr[0] == total {
			n := int(total / pr[1])
			if n != row.NIntermediate {
				return nil, pairErr(total, n)
			}
			interval, matched = pr[1], true
			break
		}
	}
	if !matched {
		return nil, pairErr(total, row.NIntermediate)
	}
	k := body.OutputRootIndex
	if uint64(k) > uint64(row.NIntermediate) {
		return nil, finality.EvidenceTooLarge("outputRootIndex", uint64(k), uint64(row.NIntermediate))
	}
	outBlock, claimed, kind := l2seq, rootClaim, "root_claim"
	if k > 0 {
		outBlock, claimed, kind = start+interval*uint64(k), roots[k-1], "intermediate"
	}
	if len(body.L2Spine) == 0 {
		return nil, st(CodeL2NotCanonical)
	}
	h0, err := finality.ReadHeader(body.L2Spine[0])
	if err != nil {
		return nil, err
	}
	var computed [32]byte
	if h0.WithdrawalsRoot != nil {
		computed = [32]byte(crypto.Keccak256Hash(make([]byte, 32), h0.StateRoot[:], h0.WithdrawalsRoot[:], h0.Hash[:]))
	}
	if computed != claimed {
		return nil, st(CodeOutputRootMismatch, "computed", computed, "claimed", claimed)
	}

	// -- the L2 spine from the output-root block down to the leg's block (5.5 O6) --
	prev := h0
	for _, raw := range body.L2Spine[1:] {
		cur, err := finality.ReadHeader(raw)
		if err != nil {
			return nil, stateOf(ethl1.HeaderChainBroken("l2", prev.Number-1, prev.ParentHash, [32]byte(crypto.Keccak256Hash(raw)), "rlp"))
		}
		if cur.Hash != prev.ParentHash {
			return nil, stateOf(ethl1.HeaderChainBroken("l2", prev.Number-1, prev.ParentHash, cur.Hash, "hash"))
		}
		if prev.Number == 0 || cur.Number != prev.Number-1 {
			return nil, stateOf(ethl1.HeaderChainBroken("l2", prev.Number-1, prev.ParentHash, cur.Hash, "number"))
		}
		prev = cur
	}
	last := body.L2Spine[len(body.L2Spine)-1]
	if prev.Number != in.Leg.Number || prev.Hash != in.Leg.Hash || (in.Leg.HeaderRLP != nil && !bytes.Equal(last, in.Leg.HeaderRLP)) {
		return nil, st(CodeL2NotCanonical)
	}

	return map[string]any{
		"a_number": A.Number, "a_hash": A.Hash, "a_timestamp": A.Timestamp,
		"game": body.GameProxy, "game_type": row.GameType, "game_version": row.Version,
		"created_at": g.CreatedAt, "resolved_at": g.ResolvedAt, "status": g.Status,
		"output_root_block": outBlock, "output_root_index": k, "root_kind": kind,
		"proof_system": ps, "proof_count": g.ProofCount, "expected_resolution": g.ExpectedResolution, "finalization_path": path,
		"l1_finalized_slot": in.Head.Slot, "l1_participants": uint64(in.Head.Participants),
	}, nil
}

// gameUUID is DGF's keccak256(abi.encode(gameType, rootClaim, extraData)) for a uint32 type, bytes32 root and bytes extraData.
func gameUUID(gameType uint32, rootClaim [32]byte, extra []byte) [32]byte {
	var b []byte
	t := be32(uint64(gameType))
	b = append(b, t[:]...)
	b = append(b, rootClaim[:]...)
	off := be32(0x60)
	b = append(b, off[:]...)
	ln := be32(uint64(len(extra)))
	b = append(b, ln[:]...)
	b = append(b, extra...)
	if pad := (32 - len(extra)%32) % 32; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return [32]byte(crypto.Keccak256Hash(b))
}

// Verify judges the whole CFE1 container `evidence` about the leg block b (spec 5.5). The LC part is proven first (a refusal is
// l1_finality_unproven{reason:lc_refused, inner}), the L1 spine must cover `stateBlock`, and A's state root and timestamp are
// read from the covered header, never from the evidence.
func (Kind) Verify(pins *finality.Pins, b finality.BlockRef, evidence []byte) (finality.Verdict, error) {
	lim := finality.DefaultLimits()
	c, err := finality.DecodeContainer(evidence, lim)
	if err != nil {
		return finality.Verdict{}, err
	}
	if c.Header.Kind != KindName {
		return finality.Verdict{}, finality.EvidenceUnrecognised(c.Header.Kind, "")
	}
	if c.Header.Chain != uint64(Chain) || c.Header.Level != finality.LevelFinalized {
		return finality.Verdict{}, finality.Malformed("header", finality.ReasonDiffersFromAddendum, 0, 0)
	}
	if c.Header.BlockNumber != b.Number || c.Header.BlockHash != b.Hash || b.Chain != uint64(Chain) {
		return finality.Verdict{}, finality.BlockMismatch("blockHash", b.Hash, c.Header.BlockHash)
	}
	bp, err := ParsePins(pins)
	if err != nil {
		return finality.Verdict{}, err
	}
	es, err := pins.Sepolia()
	if err != nil {
		return finality.Verdict{}, err
	}
	ep := ethl1Pins(es)
	body, err := DecodeBody(c.Body, lim, ep, bp.MaxL2Headers)
	if err != nil {
		return finality.Verdict{}, err
	}
	head, err := ethl1.VerifyFinalizedHead(ep, body.LC)
	if err != nil {
		inner := ""
		if f, ok := err.(*ethl1.Fault); ok {
			inner = f.Code
		}
		return finality.Verdict{}, st(CodeL1FinalityUnproven, "reason", LCRefused, "inner", inner)
	}
	covered, err := head.Covers(body.L1Spine, ep.MaxSpineHeaders)
	if err != nil {
		return finality.Verdict{}, stateOf(err)
	}
	a, err := ethl1.BlockAt(covered, body.StateBlock)
	if err != nil {
		return finality.Verdict{}, stateOf(err)
	}
	fields, err := judge(judgeInput{A: a, Body: body, Leg: b, Pins: bp, Head: head})
	if err != nil {
		return finality.Verdict{}, err
	}
	return finality.Verdict{Level: finality.LevelFinalized, Kind: KindName, Fields: fields}, nil
}

// Judge is the L1-state, output-root and L2-spine half of 5.5 (O2-O6) over an L1 block A that the caller has already located on a
// covered spine. Verify calls it after the LC and the spine; the builder calls it on captured material to learn the state a
// game is in (an unresolved game is game_not_resolved{status}) before it waits for A to be final. It is pure.
func Judge(p *Pins, a ethl1.L1Block, body Body, leg finality.BlockRef, head ethl1.FinalizedHead) (map[string]any, error) {
	return judge(judgeInput{A: a, Body: body, Leg: leg, Pins: p, Head: head})
}
