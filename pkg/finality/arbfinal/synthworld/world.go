// Copyright 2026 Certen Protocol

// Package synthworld builds complete, internally consistent evidence for arb-sepolia/finalized/v1 out of nothing but
// deterministic labels: an L2 header chain, a Rollup state trie with the BoLD assertion node, a confirmation transaction and
// receipt at a synthetic L1 block, an L1 spine, and a Sepolia light-client head signed by a test committee whose secret scalars
// are derived from labels and never stored (the vectors carry only public keys, roots and signatures, as the ethl1 synthetic
// cases do). It is test and vector-generator support; no production path imports it.
//
// Every adversarial vector is made by editing the Parts before Assemble (state-dependent cases) or the Evidence after it
// (field-level cases); the valid world verifies, which the package tests assert.
package synthworld

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Fixed real values the world reuses (the pinned contracts, so the pins file needs no change).
var (
	Rollup        = common.HexToAddress("0x042B2E6C5E99d4c521bd49beeD5E99651D9B0Cf4")
	AdminLogic    = common.HexToAddress("0x3b7aea898c7f51551daaff4dae8ab0f553f2aef8")
	UserLogic     = common.HexToAddress("0xdc2f809bba33cbb96a5ea8e9ee2dd4cb104e0ba5")
	AdminCode     = common.HexToHash("0xdd93a7606e6067aaae8ad5afa28b943a8272809eb72face4e2bb3bf4d0609445")
	UserCode      = common.HexToHash("0xeadf786edd4819d0262d9679d43b878d7005408a822aa0c43cf79bd0043c09a3")
	AdminSlot     = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	UserSlot      = common.HexToHash("0x2b1dbce74324248c222f0ec2d5ed7bd323cfc425b336f0253c5ccfda7265546d")
	TopicConfirm  = common.HexToHash("0xfc42829b29c259a7370ab56c8f69fce23b5f351a9ce151da453281993ec0090c")
	TopicForce    = common.HexToHash("0x0ef6ac64bd6b0fa95ed37aa19a1b16613fb89e2269c92639a9d516a64fea4938")
	ValidatorW    = common.HexToAddress("0x00000000000000000000000000000000000a11e7")
	Executor      = common.HexToAddress("0x5FEe78FE9AD96c1d8557C6D6BB22Eb5A61eeD315")
	SelConfirm    = [4]byte{0x10, 0xb9, 0x8a, 0x35}
	SelForce      = [4]byte{0x5b, 0xf0, 0x38, 0x33}
	SelFast       = [4]byte{0x60, 0x96, 0x68, 0x6d}
	SelFastNew    = [4]byte{0x64, 0x20, 0xfb, 0x9f}
	SelWalletTx   = [4]byte{0xce, 0x1d, 0x57, 0x1f}
	SelWalletTxs  = [4]byte{0x72, 0xf4, 0x58, 0x66}
	SelWalletTxR  = [4]byte{0x09, 0x7d, 0xa1, 0xf8}
	SelWalletTxsR = [4]byte{0xc1, 0x79, 0xf1, 0xd9}
)

// Log is one receipt log of the confirmation transaction.
type Log struct {
	Address common.Address
	Topics  []common.Hash
}

// Parts is everything an Assemble needs. NewParts returns the valid configuration; a vector changes fields.
type Parts struct {
	Label   string
	Leg     uint64 // the L2 leg block number
	L2Above int    // L2 headers above the leg (the assertion's block is Leg+L2Above)

	Parent    [32]byte
	SendRoot  [32]byte
	SeqAcc    [32]byte
	ParentCfg arbfinal.ParentConfig
	Machine   uint8

	// L1 geometry: the finalized head is F; S = F - SBack; K = S - KBack; the spine reaches down to min(K, S) - SpineExtra.
	F          uint64
	SBack      uint64
	KBack      uint64
	SpineExtra uint64

	// Rollup state words (valid defaults).
	Status       uint64 // the node's status byte
	ConfigWord   *common.Hash
	FastConfirm  common.Address
	AdminCodeS   common.Hash
	UserCodeS    common.Hash
	AdminCodeK   common.Hash
	UserCodeK    common.Hash
	AdminWordS   *common.Hash // overrides the EIP-1967 admin word at S
	UserWordS    *common.Hash
	AdminWordK   *common.Hash
	UserWordK    *common.Hash
	RollupAbsent bool // the Rollup account does not exist at S (an exclusion proof)

	// The confirmation transaction.
	TxTo      *common.Address // nil: the Rollup
	TxInput   []byte          // nil: SelConfirm || 160 bytes
	Logs      []Log           // nil: the AssertionConfirmed log of the Rollup for the assertion
	NoLogs    bool
	RcStatus  uint64 // 1
	TxIndex   int    // position in K's block (default 1 of 3)
	TxPadding int    // transactions before and after (default 1 each)
}

// NewParts is the valid world named by label.
func NewParts(label string) Parts {
	return Parts{
		Label: label, Leg: 400_000_000, L2Above: 3, Machine: 1, Status: 2, RcStatus: 1, TxPadding: 1,
		F: 12_000_000, SBack: 2, KBack: 3, SpineExtra: 1,
		AdminCodeS: AdminCode, UserCodeS: UserCode, AdminCodeK: AdminCode, UserCodeK: UserCode,
		ParentCfg: arbfinal.ParentConfig{ConfirmPeriodBlocks: 20, NextInboxPosition: 881475},
	}
}

func sum(label string) [32]byte { return sha256.Sum256([]byte("certen/arbfinal/synth/" + label)) }

// World is an assembled evidence container with the pins and leg it is judged against.
type World struct {
	Parts     Parts
	Pins      []byte // a full pins file (embedded pins with the synthetic ledger)
	Leg       finality.BlockRef
	Evidence  arbfinal.Evidence
	Container []byte
	Assertion [32]byte
	S, K      ethl1.L1Block
	TxHash    [32]byte
}

// Judge runs the verifier over the container.
func (w *World) Judge() (finality.Verdict, error) {
	p, err := finality.ParsePinsOverride(w.Pins)
	if err != nil {
		return finality.Verdict{}, err
	}
	return arbfinal.New().Verify(p, w.Leg, w.Container)
}

// Rebuild re-encodes the container from (a possibly edited) Evidence.
func (w *World) Rebuild() error {
	c, err := arbfinal.BuildContainer(w.Leg, w.Evidence)
	if err != nil {
		return err
	}
	w.Container = c
	return nil
}

func header(parent common.Hash, state, txRoot, rcRoot common.Hash, number, ts uint64, salt string) []byte {
	items := []any{parent.Bytes(), bytes.Repeat([]byte{0x1d}, 32), make([]byte, 20), state.Bytes(), txRoot.Bytes(), rcRoot.Bytes(),
		make([]byte, 256), uint64(0), number, uint64(30_000_000), uint64(1), ts, []byte(salt), bytes.Repeat([]byte{0x05}, 32), make([]byte, 8)}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return raw
}

func trimmed(w common.Hash) []byte {
	i := 0
	for i < 32 && w[i] == 0 {
		i++
	}
	b, _ := rlp.EncodeToBytes(w[i:])
	return b
}

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

type acct struct {
	addr    common.Address
	storage map[common.Hash]common.Hash
	code    common.Hash
}

// stateOf builds a state trie over the accounts and returns its root and the proofs of every account and every storage slot.
func stateOf(accts []acct, absent []common.Address) (common.Hash, [][]byte) {
	st := trie.NewEmpty(nil)
	var nodes [][]byte
	for _, a := range accts {
		sto := trie.NewEmpty(nil)
		for s, v := range a.storage {
			if err := sto.Update(crypto.Keccak256(s[:]), trimmed(v)); err != nil {
				panic(err)
			}
		}
		for s := range a.storage {
			var c collector
			if err := sto.Prove(crypto.Keccak256(s[:]), &c); err != nil {
				panic(err)
			}
			nodes = append(nodes, c.nodes...)
		}
		enc, _ := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), sto.Hash(), a.code.Bytes()})
		if err := st.Update(crypto.Keccak256(a.addr[:]), enc); err != nil {
			panic(err)
		}
	}
	for _, a := range append(accountsOf(accts), absent...) {
		var c collector
		if err := st.Prove(crypto.Keccak256(a[:]), &c); err != nil {
			panic(err)
		}
		nodes = append(nodes, c.nodes...)
	}
	return st.Hash(), nodes
}

func accountsOf(a []acct) []common.Address {
	out := make([]common.Address, len(a))
	for i := range a {
		out[i] = a[i].addr
	}
	return out
}

func word(a common.Address) common.Hash { var h common.Hash; copy(h[12:], a[:]); return h }

func u64w(v uint64) common.Hash { var h common.Hash; binary.BigEndian.PutUint64(h[24:], v); return h }

func (p Parts) rollupState(admin, user common.Hash, adminWord, userWord *common.Hash, assertion [32]byte, absentRollup bool) (common.Hash, [][]byte) {
	aw, uw := word(AdminLogic), word(UserLogic)
	if adminWord != nil {
		aw = *adminWord
	}
	if userWord != nil {
		uw = *userWord
	}
	node := common.Hash{}
	node = common.BigToHash(new(big.Int).Lsh(new(big.Int).SetUint64(p.Status), 200))
	cfg := common.Hash(arbfinal.ConfigHash(p.ParentCfg))
	if p.ConfigWord != nil {
		cfg = *p.ConfigWord
	}
	fast := word(p.FastConfirm)
	fastWord := common.BigToHash(new(big.Int).Lsh(new(big.Int).SetBytes(fast[:]), 8))
	rollup := acct{addr: Rollup, code: crypto.Keccak256Hash([]byte("rollup proxy")), storage: map[common.Hash]common.Hash{
		AdminSlot: aw, UserSlot: uw,
		arbfinal.NodeSlot(assertion, 117):             node,
		arbfinal.ConfigSlot(p.Parent, 117, 1):         cfg,
		common.BigToHash(new(big.Int).SetUint64(123)): fastWord,
	}}
	accts := []acct{
		{addr: AdminLogic, code: admin},
		{addr: UserLogic, code: user},
	}
	var absent []common.Address
	if absentRollup {
		absent = append(absent, Rollup)
	} else {
		accts = append(accts, rollup)
	}
	// the logic accounts named by overridden words must be provable too (as absent accounts when they are not built).
	for _, w := range []*common.Hash{adminWord, userWord} {
		if w != nil {
			a := common.BytesToAddress(w[12:])
			if a != AdminLogic && a != UserLogic {
				absent = append(absent, a)
			}
		}
	}
	return stateOf(accts, absent)
}

// ---- the synthetic Sepolia head ----

type keys struct {
	sk [4]*big.Int
	pk [4][48]byte
}

func newKeys() keys {
	var k keys
	for i := range k.sk {
		h := sha256.Sum256([]byte("certen/arbfinal/synth/key/" + string(rune('0'+i))))
		var e fr.Element
		e.SetBytes(h[:])
		k.sk[i] = e.BigInt(new(big.Int))
		var p bls12381.G1Affine
		p.ScalarMultiplicationBase(k.sk[i])
		k.pk[i] = p.Bytes()
	}
	return k
}

func (k keys) committee() []byte {
	b := make([]byte, 0, 24624)
	total := new(big.Int)
	for i := 0; i < 512; i++ {
		b = append(b, k.pk[i%4][:]...)
		total.Add(total, k.sk[i%4])
	}
	var agg bls12381.G1Affine
	agg.ScalarMultiplicationBase(total)
	a := agg.Bytes()
	return append(b, a[:]...)
}

func (k keys) sign(msg [32]byte, n int) [96]byte {
	total := new(big.Int)
	for i := 0; i < n; i++ {
		total.Add(total, k.sk[i%4])
	}
	h, err := bls12381.HashToG2(msg[:], []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	if err != nil {
		panic(err)
	}
	var s bls12381.G2Affine
	s.ScalarMultiplication(&h, total)
	return s.Bytes()
}

func beacon(slot uint64, parent, state, body [32]byte) []byte {
	b := make([]byte, 112)
	binary.LittleEndian.PutUint64(b[0:8], slot)
	binary.LittleEndian.PutUint64(b[8:16], 7)
	copy(b[16:48], parent[:])
	copy(b[48:80], state[:])
	copy(b[80:112], body[:])
	return b
}

func lcHeader(bc []byte, exec [32]byte, branch [][32]byte) []byte {
	b := append([]byte(nil), bc...)
	b = append(b, exec[:]...)
	for _, n := range branch {
		b = append(b, n[:]...)
	}
	return b
}

func nodesOf(label string, n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sum(label + "/" + string(rune('a'+i)))
	}
	return out
}

// L1Head builds the synthetic LC whose finalized execution head is exec, and the pins file that anchors its committee: the
// embedded pins with eth_sepolia.anchors replaced by one synthetic entry. The slots lie in the Gloas era of the embedded fork
// table (period 1379), so no part of the verification is bypassed: the real fork versions, genesis root and 342 floor apply.
func L1Head(exec [32]byte) (ethl1.LC, []byte) {
	emb, err := finality.EmbeddedPins()
	if err != nil {
		panic(err)
	}
	gvr, _ := hexTo32(emb.EthSepolia.GenesisValidatorsRoot)
	var version [4]byte
	for _, f := range emb.EthSepolia.Forks {
		if f.Name == "gloas" {
			b := common.FromHex(f.Version)
			copy(version[:], b)
		}
	}
	k := newKeys()
	committee := k.committee()
	root, err := ethl1.HashTreeRootSyncCommittee(committee)
	if err != nil {
		panic(err)
	}
	const gloasEpoch = 353024
	slot := func(epoch, i uint64) uint64 { return epoch*32 + i }
	finSlot, attSlot, sigSlot := slot(gloasEpoch+9, 0), slot(gloasEpoch+10, 5), slot(gloasEpoch+10, 6)
	fbranch := nodesOf("fbranch", 11)
	fbody := ethl1.RootFromNormalizedBranch(exec, fbranch, 2856)
	fbeacon := beacon(finSlot, sum("fparent"), sum("fstate"), fbody)
	froot, _ := ethl1.HashTreeRootBeaconBlockHeader(fbeacon)
	finBranch := nodesOf("finbranch", 9)
	state := ethl1.RootFromNormalizedBranch(froot, finBranch, 735)
	aexec := sum("attested-exec")
	abranch := nodesOf("abranch", 11)
	abody := ethl1.RootFromNormalizedBranch(aexec, abranch, 2856)
	abeacon := beacon(attSlot, sum("aparent"), state, abody)
	msg, err := ethl1.SyncCommitteeSigningRoot(abeacon, version, gvr)
	if err != nil {
		panic(err)
	}
	sig := k.sign(msg, 512)
	out := lcHeader(abeacon, aexec, abranch)
	out = append(out, lcHeader(fbeacon, exec, fbranch)...)
	for _, n := range finBranch {
		out = append(out, n[:]...)
	}
	bits := bytes.Repeat([]byte{0xff}, 64)
	out = append(out, bits...)
	out = append(out, sig[:]...)
	out = binary.LittleEndian.AppendUint64(out, sigSlot)
	lc := ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: gloasEpoch / 256, AnchorRoot: root,
		AnchorBody: ethl1.LB{Layout: ethl1.LayoutNone, SSZ: committee}, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: out}}

	var pf map[string]json.RawMessage
	if err := json.Unmarshal(finality.EmbeddedPinsBytes(), &pf); err != nil {
		panic(err)
	}
	var es map[string]json.RawMessage
	if err := json.Unmarshal(pf["eth_sepolia"], &es); err != nil {
		panic(err)
	}
	anchor := []map[string]any{{"period": gloasEpoch / 256, "committee_root": "0x" + common.Bytes2Hex(root[:]), "wsp_epochs": 279,
		"link_sha256": linkSum(), "derived_by": []string{"synthworld"}}}
	es["anchors"], _ = json.Marshal(anchor)
	pf["eth_sepolia"], _ = json.Marshal(es)
	raw, _ := json.Marshal(pf)
	return lc, raw
}

func hexTo32(s string) ([32]byte, bool) {
	b := common.FromHex(s)
	var out [32]byte
	if len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// ---- assembly ----

func (p Parts) txKey() *ecdsaKey { return newTxKey(p.Label) }

// Assemble builds the world.
func Assemble(p Parts) *World {
	w := &World{Parts: p}
	// L2 chain.
	l2 := make([][]byte, p.L2Above+1)
	var prev common.Hash = sum(p.Label + "/l2-parent")
	for i := range l2 {
		l2[i] = header(prev, sum(p.Label+"/l2state"), common.Hash{}, common.Hash{}, p.Leg+uint64(i), 1_700_000_000+uint64(i), "l2")
		prev = crypto.Keccak256Hash(l2[i])
	}
	legHash := crypto.Keccak256Hash(l2[0])
	w.Leg = finality.BlockRef{Chain: finality.ChainArbitrumSepolia, Number: p.Leg, Hash: legHash, HeaderRLP: l2[0]}
	spine := make([][]byte, len(l2))
	for i := range l2 {
		spine[i] = l2[len(l2)-1-i]
	}
	after := arbfinal.AfterState{BlockHash: crypto.Keccak256Hash(spine[0]), SendRoot: sum(p.Label + "/sendroot"), InboxPosition: 881475, MachineStatus: p.Machine, EndHistoryRoot: sum(p.Label + "/ehr")}
	if p.Parent == ([32]byte{}) {
		p.Parent = sum(p.Label + "/parent")
	}
	if p.SeqAcc == ([32]byte{}) {
		p.SeqAcc = sum(p.Label + "/seqacc")
	}
	assertion := arbfinal.AssertionHash(p.Parent, after, p.SeqAcc)
	w.Assertion = assertion

	// States at S and K.
	S, K := p.F-p.SBack, p.F-p.SBack-p.KBack
	rootS, nodesS := p.rollupState(p.AdminCodeS, p.UserCodeS, p.AdminWordS, p.UserWordS, assertion, p.RollupAbsent)
	rootK, nodesK := p.rollupState(p.AdminCodeK, p.UserCodeK, p.AdminWordK, p.UserWordK, assertion, false)
	if S == K {
		rootK, nodesK = rootS, nodesS
	}

	// The confirmation transaction and receipt in K's block.
	to := Rollup
	if p.TxTo != nil {
		to = *p.TxTo
	}
	input := p.TxInput
	if input == nil {
		input = append(append([]byte(nil), SelConfirm[:]...), bytes.Repeat([]byte{0x11}, 160)...)
	}
	signer := types.LatestSignerForChainID(big.NewInt(11155111))
	mk := func(nonce uint64, to common.Address, data []byte) *types.Transaction {
		tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(11155111), Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: 500000, To: &to, Value: big.NewInt(0), Data: data})
		st, err := types.SignTx(tx, signer, p.txKey().k)
		if err != nil {
			panic(err)
		}
		return st
	}
	var txs, rcs [][]byte
	var logs []*types.Log
	switch {
	case p.NoLogs:
	case p.Logs != nil:
		for _, l := range p.Logs {
			logs = append(logs, &types.Log{Address: l.Address, Topics: l.Topics})
		}
	default:
		logs = []*types.Log{{Address: Rollup, Topics: []common.Hash{TopicConfirm, common.Hash(assertion)}, Data: bytes.Repeat([]byte{0x22}, 64)}}
	}
	idx := p.TxPadding
	if p.TxIndex != 0 {
		idx = p.TxIndex
	}
	for i := 0; i < p.TxPadding*2+1; i++ {
		var tx *types.Transaction
		var rc *types.Receipt
		if i == idx {
			tx = mk(uint64(i), to, input)
			rc = &types.Receipt{Type: tx.Type(), Status: p.RcStatus, CumulativeGasUsed: uint64(100000 * (i + 1)), Logs: logs}
			w.TxHash = [32]byte(tx.Hash())
		} else {
			tx = mk(uint64(i), common.HexToAddress("0x00000000000000000000000000000000000000aa"), []byte{byte(i)})
			rc = &types.Receipt{Type: tx.Type(), Status: 1, CumulativeGasUsed: uint64(100000 * (i + 1))}
		}
		tb, err := tx.MarshalBinary()
		if err != nil {
			panic(err)
		}
		rb, err := rc.MarshalBinary()
		if err != nil {
			panic(err)
		}
		txs, rcs = append(txs, tb), append(rcs, rb)
	}
	txTrie, rcTrie := trie.NewEmpty(nil), trie.NewEmpty(nil)
	for i := range txs {
		key, _ := rlp.EncodeToBytes(uint64(i))
		_ = txTrie.Update(key, txs[i])
		_ = rcTrie.Update(key, rcs[i])
	}
	var proofNodes [][]byte
	key, _ := rlp.EncodeToBytes(uint64(idx))
	for _, t := range []*trie.Trie{txTrie, rcTrie} {
		var c collector
		if err := t.Prove(key, &c); err != nil {
			panic(err)
		}
		proofNodes = append(proofNodes, c.nodes...)
	}

	// L1 spine, built ascending so parent hashes link, then reversed.
	low := K
	if S < low {
		low = S
	}
	low -= p.SpineExtra
	emptyRoot := types.EmptyRootHash
	var l1 [][]byte
	var parent common.Hash = sum(p.Label + "/l1-parent")
	for n := low; n <= p.F; n++ {
		st, tr, rr := common.Hash(sum(p.Label+"/l1state/"+u(n))), emptyRoot, emptyRoot
		switch n {
		case S:
			st = rootS
		}
		if n == K {
			st, tr, rr = rootK, txTrie.Hash(), rcTrie.Hash()
		}
		raw := header(parent, st, tr, rr, n, 1_790_000_000+n*12, "l1")
		l1 = append([][]byte{raw}, l1...)
		parent = crypto.Keccak256Hash(raw)
	}
	hs := func(n uint64) ethl1.L1Block {
		raw := l1[p.F-n]
		h, _ := finality.ReadHeader(raw)
		return ethl1.L1Block{Hash: h.Hash, Number: h.Number, StateRoot: h.StateRoot, Timestamp: h.Timestamp}
	}
	w.S, w.K = hs(S), hs(K)

	lc, pins := L1Head(crypto.Keccak256Hash(l1[0]))
	w.Pins = pins
	w.Evidence = arbfinal.Evidence{
		LC: lc, L1Spine: l1, StateBlock: S, ConfBlock: K, ParentAssertionHash: p.Parent, After: after, SequencerBatchAcc: p.SeqAcc, Parent: p.ParentCfg,
		L2Spine: spine, ConfTxIndex: uint32(idx), ConfTxRaw: txs[idx], ConfReceiptRaw: rcs[idx],
		Nodes: finality.EncodeNodes(append(append(append([][]byte(nil), nodesS...), nodesK...), proofNodes...)),
	}
	if err := w.Rebuild(); err != nil {
		panic(err)
	}
	w.Parts = p
	return w
}

func u(n uint64) string { return string(binary.BigEndian.AppendUint64(nil, n)) }

// WalletCall packs the calldata of a ValidatorWallet entry point: executeTransaction (selector SelWalletTx), the gas-refunder
// variant, executeTransactions and its gas-refunder variant.
func WalletInput(sel [4]byte, datas [][]byte, dests []common.Address) []byte {
	bytesT, _ := abi.NewType("bytes", "", nil)
	addrT, _ := abi.NewType("address", "", nil)
	uintT, _ := abi.NewType("uint256", "", nil)
	bytesArr, _ := abi.NewType("bytes[]", "", nil)
	addrArr, _ := abi.NewType("address[]", "", nil)
	uintArr, _ := abi.NewType("uint256[]", "", nil)
	zeros := make([]*big.Int, len(datas))
	for i := range zeros {
		zeros[i] = new(big.Int)
	}
	var args abi.Arguments
	var vals []any
	switch sel {
	case SelWalletTx:
		args, vals = abi.Arguments{{Type: bytesT}, {Type: addrT}, {Type: uintT}}, []any{datas[0], dests[0], new(big.Int)}
	case SelWalletTxR:
		args, vals = abi.Arguments{{Type: addrT}, {Type: bytesT}, {Type: addrT}, {Type: uintT}}, []any{common.Address{}, datas[0], dests[0], new(big.Int)}
	case SelWalletTxs:
		args, vals = abi.Arguments{{Type: bytesArr}, {Type: addrArr}, {Type: uintArr}}, []any{datas, dests, zeros}
	case SelWalletTxsR:
		args, vals = abi.Arguments{{Type: addrT}, {Type: bytesArr}, {Type: addrArr}, {Type: uintArr}}, []any{common.Address{}, datas, dests, zeros}
	default:
		panic("not a wallet selector")
	}
	b, err := args.Pack(vals...)
	if err != nil {
		panic(err)
	}
	return append(append([]byte(nil), sel[:]...), b...)
}

// ConfirmCall is a calldata for the Rollup: the selector and 160 bytes of arguments.
func ConfirmCall(sel [4]byte) []byte {
	return append(append([]byte(nil), sel[:]...), bytes.Repeat([]byte{0x11}, 160)...)
}

func linkSum() string { s := sum("link"); return common.Bytes2Hex(s[:]) }
