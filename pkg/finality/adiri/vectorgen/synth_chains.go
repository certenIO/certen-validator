// Copyright 2026 Certen Protocol

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// The synthetic vectors cover the paths the live chain never took (annex OQ7): a rotation, a tolerated 4-of-5 ejection, a
// cumulative shrink to 4, a larger-than-expected committee, a committee below min_committee_size, and linkKind 2 with a
// synthetic EIP-2935 state proof. Keys are generated from a random seed kept only in the gitignored keys/ directory; the
// vectors contain public keys and signatures only.

const eip2935Runtime = "3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500"

type tb struct{}

func (tb) Helper()                {}
func (tb) Fatal(a ...interface{}) { panic(fmt.Sprint(a...)) }

type keyPool struct {
	sk []*bls.PrivateKey
	pk [][]byte
}

func loadKeys(dir string, n int) *keyPool {
	must(os.MkdirAll(dir, 0o700))
	p := filepath.Join(dir, "adiri-synthetic-seed.hex")
	raw, err := os.ReadFile(p)
	var seed []byte
	if err == nil {
		seed, _ = hex.DecodeString(string(raw[:min(len(raw), 64)]))
	}
	if len(seed) != 32 {
		seed = make([]byte, 32)
		_, err := rand.Read(seed)
		must(err)
		must(os.WriteFile(p, []byte(hex.EncodeToString(seed)), 0o600))
	}
	kp := &keyPool{}
	for i := 0; i < n; i++ {
		h := sha256.Sum256(append(append([]byte(nil), seed...), byte(i)))
		sk, pk, err := bls.GenerateKeyPairFromSeed(h[:])
		must(err)
		kp.sk = append(kp.sk, sk)
		kp.pk = append(kp.pk, pk.Bytes())
	}
	return kp
}

// epochSpec describes one synthetic epoch: committee and next_committee as key-pool indices, signer positions in the committee.
type epochSpec struct {
	committee, next []int
	signers         []int
}

type kind2 struct {
	slotValue  *common.Hash // the hash stored in the EIP-2935 slot (nil = the leg block's hash)
	code       []byte       // account code (nil = the real runtime)
	flipNode   bool         // flip a bit in a proof node
	legIsFinal bool         // the leg is the seal block (N = F)
}

type synthOut struct {
	pins     map[string]any
	evidence []byte
	leg      legJSON
	epoch    int
	size     int
	signers  int
}

func (kp *keyPool) keysOf(idx []int) [][]byte {
	out := make([][]byte, len(idx))
	for i, k := range idx {
		out[i] = kp.pk[k]
	}
	return out
}

// buildSynth assembles a signed chain of the given epochs, a 4-header execution chain 1000..1003 and the evidence for leg 1000
// (or 1003) under linkKind 1, or linkKind 2 when k2 is non-nil.
func buildSynth(kp *keyPool, epochs []epochSpec, k2 *kind2, salt byte) synthOut {
	const N, F = uint64(1000), uint64(1003)
	nLeg := N
	if k2 != nil && k2.legIsFinal {
		nLeg = F
	}
	var fc [32]byte
	for i := range fc {
		fc[i] = salt ^ 0x5a
	}
	// state for linkKind 2
	var stateRoot common.Hash
	var st *replayworld.State
	slotHash := common.Hash{}
	headers := make([]*types.Header, 0, 4)
	build := func(root common.Hash) {
		headers = headers[:0]
		parent := common.Hash{}
		for n := N; n <= F; n++ {
			h := &types.Header{
				ParentHash: parent, UncleHash: types.EmptyUncleHash, Root: types.EmptyRootHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
				Difficulty: big.NewInt(0), Number: new(big.Int).SetUint64(n), GasLimit: 30_000_000, Time: 1_790_000_000 + n, Extra: []byte("certen-synthetic-adiri"),
				BaseFee: big.NewInt(7), WithdrawalsHash: &types.EmptyWithdrawalsHash, BlobGasUsed: new(uint64), ExcessBlobGas: new(uint64),
				ParentBeaconRoot: (*common.Hash)(&fc), RequestsHash: &types.EmptyRequestsHash,
			}
			if n == F {
				h.Root = root
			}
			parent = h.Hash()
			headers = append(headers, h)
		}
	}
	build(common.Hash{})
	if k2 != nil {
		legHash := headers[nLeg-N].Hash()
		slotHash = legHash
		if k2.legIsFinal {
			slotHash = sha256.Sum256([]byte("placeholder: the seal block hash depends on the state root"))
		}
		if k2.slotValue != nil {
			slotHash = *k2.slotValue
		}
		code := common.FromHex(eip2935Runtime)
		if k2.code != nil {
			code = k2.code
		}
		addr := common.HexToAddress("0x0000F90827F1C53a10cb7A02335B175320002935")
		slot := common.BigToHash(new(big.Int).SetUint64(nLeg % adiri.EIP2935Window))
		st = replayworld.BuildState(tb{}, replayworld.Account{Addr: addr, Code: code, Storage: map[common.Hash]*big.Int{slot: new(big.Int).SetBytes(slotHash[:])}})
		stateRoot = st.Root
		build(stateRoot)
	}
	fHash := [32]byte(headers[len(headers)-1].Hash())

	// records
	var tables [][][]byte
	idx := map[string]uint8{}
	tableOf := func(keys []int) uint8 {
		k := fmt.Sprint(keys)
		if i, ok := idx[k]; ok {
			return i
		}
		idx[k] = uint8(len(tables))
		tables = append(tables, kp.keysOf(keys))
		return idx[k]
	}
	cf := &adiri.CFA1{}
	for e, sp := range epochs {
		r := adiri.Record{CommitteeIdx: tableOf(sp.committee), NextIdx: tableOf(sp.next)}
		for _, s := range sp.signers {
			r.Signers = append(r.Signers, uint8(s))
		}
		if e == len(epochs)-1 {
			r.FinalState = adiri.NumHash{Number: F, Hash: fHash}
			r.FinalConsensus = adiri.NumHash{Number: 9000 + uint64(e), Hash: fc}
		} else {
			r.FinalState = adiri.NumHash{Number: 100 * uint64(e+1), Hash: sha256.Sum256([]byte(fmt.Sprintf("synthetic-final-%d-%d", salt, e)))}
			r.FinalConsensus = adiri.NumHash{Number: 1000 + uint64(e), Hash: sha256.Sum256([]byte(fmt.Sprintf("synthetic-consensus-%d-%d", salt, e)))}
		}
		cf.Records = append(cf.Records, r)
	}
	cf.Tables = tables
	digests := cf.RecordDigests()
	for e, sp := range epochs {
		var sigs []*bls.Signature
		for _, s := range sp.signers {
			sigs = append(sigs, kp.sk[sp.committee[s]].Sign(adiri.SignedMessage(digests[e])))
		}
		agg, err := bls.AggregateSignatures(sigs)
		must(err)
		copy(cf.Records[e].Signature[:], agg.Bytes())
	}
	cfa1, err := cf.Encode()
	must(err)

	leg := finality.BlockRef{Chain: finality.ChainAdiri, Number: nLeg, Hash: [32]byte(headers[nLeg-N].Hash())}
	body := adiri.Body{CFA1: cfa1}
	rawHeader := func(h *types.Header) []byte {
		b, err := rlp.EncodeToBytes(h)
		must(err)
		return b
	}
	if k2 == nil {
		body.LinkKind = adiri.LinkSpine
		for i := len(headers) - 1; i >= int(nLeg-N); i-- {
			body.Spine = append(body.Spine, rawHeader(headers[i]))
		}
		_ = st
	} else {
		body.LinkKind = adiri.LinkSlot
		body.FinalHeader = rawHeader(headers[len(headers)-1])
		addr := common.HexToAddress("0x0000F90827F1C53a10cb7A02335B175320002935")
		sp := st.Prove(addr, common.BigToHash(new(big.Int).SetUint64(nLeg%adiri.EIP2935Window)))
		var nodes [][]byte
		for _, n := range sp.AccountProof {
			nodes = append(nodes, append([]byte(nil), n...))
		}
		for _, n := range sp.StorageProof {
			nodes = append(nodes, append([]byte(nil), n...))
		}
		if k2.flipNode {
			nodes[len(nodes)-1][len(nodes[len(nodes)-1])/2] ^= 1
		}
		body.Nodes = finality.EncodeNodes(nodes)
	}
	ev, err := adiri.BuildContainer(leg, body)
	must(err)

	// pins: this synthetic incarnation
	g0 := kp.keysOf(epochs[0].committee)
	gc := make([]any, len(g0))
	for i, k := range g0 {
		gc[i] = hex.EncodeToString(k)
	}
	emb := embeddedAdiriSection()
	pins := cloneSection(emb)
	pins["genesis_committee"] = gc
	pins["epoch0_final_state"] = map[string]any{"hash": "0x" + hex.EncodeToString(cf.Records[0].FinalState.Hash[:]), "number": float64(cf.Records[0].FinalState.Number)}
	gh := sha256.Sum256([]byte("synthetic-genesis"))
	pins["genesis_hash"] = "0x" + hex.EncodeToString(gh[:])
	last := epochs[len(epochs)-1]
	return synthOut{pins: pins, evidence: ev, leg: legJSON{finality.ChainAdiri, nLeg, "0x" + hex.EncodeToString(leg.Hash[:]), hex.EncodeToString(rawHeader(headers[nLeg-N]))},
		epoch: len(epochs) - 1, size: len(last.committee), signers: len(last.signers)}
}

func seq(from, to int) []int {
	var out []int
	for i := from; i < to; i++ {
		out = append(out, i)
	}
	return out
}

func syntheticChains(keysDir string) (map[string][]byte, []vec) {
	kp := loadKeys(keysDir, 8)
	ev := map[string][]byte{}
	var vs []vec
	add := func(name, note string, o synthOut, expect string) {
		ev[name] = o.evidence
		vs = append(vs, vec{Name: name, Group: "synthetic", Note: note, Leg: o.leg, Pins: o.pins, Evidence: name + ".bin", Expect: expect})
	}
	shr := func(epoch, size, exp int) string {
		return canon("committee_shrunk", "epoch", uint64(epoch), "size", uint64(size), "expected", uint64(exp))
	}
	g5 := seq(0, 5)
	rot := []int{0, 1, 2, 3, 5}

	// rotation: committee(1) = next_committee(0) with K5 replacing K4
	o := buildSynth(kp, []epochSpec{
		{committee: g5, next: rot, signers: seq(0, 5)},
		{committee: rot, next: rot, signers: []int{0, 1, 3, 4}},
		{committee: rot, next: rot, signers: seq(0, 5)},
	}, nil, 1)
	add("syn-rotation", "committee rotation: next_committee(0) replaces K4 by K5; epochs 1 and 2 are signed by the new set (4 of 5 signers at epoch 1)", o, "")
	vs[len(vs)-1].Expect = canon("finalized", "epoch", uint64(2), "chain_len", uint64(3), "committee_size", uint64(5), "signers", uint64(5),
		"final_number", uint64(1003), "final_hash", fHashOf(o), "distance", uint64(3), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{})

	// tolerated 4-of-5 ejection
	o = buildSynth(kp, []epochSpec{
		{committee: g5, next: g5, signers: seq(0, 5)},
		{committee: seq(0, 4), next: seq(0, 4), signers: []int{0, 1, 3}},
	}, nil, 2)
	add("syn-ejection-4-of-5", "K4 is ejected after epoch 0's record: committee(1) holds 4 of the expected 5 (tolerated, reported committee_shrunk); 3 of 4 signers is the quorum", o,
		canon("finalized", "epoch", uint64(1), "chain_len", uint64(2), "committee_size", uint64(4), "signers", uint64(3), "final_number", uint64(1003), "final_hash", fHashOf(o),
			"distance", uint64(3), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{shr(1, 4, 5)}))

	// cumulative shrink 7 -> 5 -> 4
	g7 := seq(0, 7)
	o = buildSynth(kp, []epochSpec{
		{committee: g7, next: g7, signers: seq(0, 7)},
		{committee: seq(0, 5), next: seq(0, 5), signers: seq(0, 5)},
		{committee: seq(0, 4), next: seq(0, 4), signers: []int{1, 2, 3}},
	}, nil, 3)
	add("syn-cumulative-shrink-to-4", "7 -> 5 -> 4: each step is tolerated (>= 2/3 of the expected set) but 4 of the original 7 is below 2/3 (the documented cumulative caveat); both steps are reported", o,
		canon("finalized", "epoch", uint64(2), "chain_len", uint64(3), "committee_size", uint64(4), "signers", uint64(3), "final_number", uint64(1003), "final_hash", fHashOf(o),
			"distance", uint64(3), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{shr(1, 5, 7), shr(2, 4, 5)}))

	// refusals
	inc := func(epoch int, reason string, size, exp int) string {
		return canon("committee_chain_broken", "epoch", uint64(epoch), "check", "committee_incompatible", "reason", reason, "size", uint64(size), "expected", uint64(exp), "min_committee_size", uint64(4))
	}
	o = buildSynth(kp, []epochSpec{
		{committee: g5, next: g5, signers: seq(0, 5)},
		{committee: seq(0, 6), next: seq(0, 6), signers: seq(0, 6)},
	}, nil, 4)
	add("syn-larger-than-expected", "committee(1) has 6 members, next_committee(0) listed 5: never larger", o, inc(1, "larger_than_expected", 6, 5))
	o = buildSynth(kp, []epochSpec{
		{committee: g5, next: g5, signers: seq(0, 5)},
		{committee: seq(0, 4), next: seq(0, 4), signers: seq(0, 4)},
		{committee: seq(0, 3), next: seq(0, 3), signers: seq(0, 3)},
	}, nil, 5)
	add("syn-below-min-committee-size", "5 -> 4 -> 3: the second step is within 2/3 (9 >= 8) but below min_committee_size 4", o, inc(2, "below_min_committee_size", 3, 4))
	o = buildSynth(kp, []epochSpec{
		{committee: g7, next: g7, signers: seq(0, 7)},
		{committee: seq(0, 4), next: seq(0, 4), signers: seq(0, 4)},
	}, nil, 6)
	add("syn-below-two-thirds", "7 -> 4: 4 members is under 2/3 of the expected 7 (12 < 14)", o, inc(1, "below_two_thirds", 4, 7))
	o = buildSynth(kp, []epochSpec{
		{committee: g5, next: g5, signers: seq(0, 5)},
		{committee: []int{0, 1, 2, 5}, next: []int{0, 1, 2, 5}, signers: seq(0, 4)},
	}, nil, 7)
	add("syn-shrink-not-a-subset", "committee(1) has 4 members, one of which (K5) is not in the expected set", o, inc(1, "not_subset", 4, 5))

	// linkKind 2
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{}, 8)
	add("syn-kind2", "linkKind 2: the seal header and the EIP-2935 account and slot 1000 proofs under its state root (synthetic state, the real runtime code hash)", o,
		canon("finalized", "epoch", uint64(0), "chain_len", uint64(1), "committee_size", uint64(5), "signers", uint64(5), "final_number", uint64(1003), "final_hash", fHashOf(o),
			"distance", uint64(3), "link_kind", uint64(2), "consensus_root_matches", true, "committee_shrunk", []string{}))
	wrong := common.HexToHash("0x" + "ab" + hex.EncodeToString(make([]byte, 31)))
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{slotValue: &wrong}, 9)
	add("syn-kind2-slot-value-mismatch", "linkKind 2 whose slot 1000 holds another block's hash", o,
		canon("finality_link_broken", "from", uint64(1003), "to", uint64(1000), "at", uint64(1000), "check", "slot_value_mismatch", "want", hash32(o.leg.Hash), "got", [32]byte(wrong)))
	otherCode := []byte{0x60, 0x00, 0x60, 0x00, 0xfd}
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{code: otherCode}, 10)
	add("syn-kind2-account-codehash-mismatch", "linkKind 2 whose account at the EIP-2935 address has other code than the pinned runtime", o,
		canon("finality_link_broken", "from", uint64(1003), "to", uint64(1000), "at", uint64(1000), "check", "account_codehash_mismatch", "want", hash32("0x6e49e66782037c0555897870e29fa5e552daf4719552131a0abce779daec0a5d"), "got", [32]byte(crypto.Keccak256Hash(otherCode))))
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{flipNode: true}, 11)
	add("syn-kind2-proof-invalid", "linkKind 2 with one bit of a storage proof node flipped", o,
		canon("finality_link_broken", "from", uint64(1003), "to", uint64(1000), "at", uint64(1000), "check", "proof_invalid"))
	o = buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, &kind2{legIsFinal: true}, 12)
	add("syn-kind2-leg-is-seal", "linkKind 2 for the seal block itself: the single-header spine is the only form", o,
		canon("finality_evidence_malformed", "part", "linkKind", "reason", "linkKind 2 is used only when the leg block is below the seal; the seal itself is a single-header spine", "got_len", uint64(2), "want_len", uint64(1)))
	// the single-header spine: the evidence for leg = F
	o = singleHeader(kp, g5)
	add("syn-spine-single-header", "N = F: linkKind 1 with the one-header spine [F]", o,
		canon("finalized", "epoch", uint64(0), "chain_len", uint64(1), "committee_size", uint64(5), "signers", uint64(5), "final_number", uint64(1003), "final_hash", hash32(o.leg.Hash),
			"distance", uint64(0), "link_kind", uint64(1), "consensus_root_matches", true, "committee_shrunk", []string{}))
	return ev, vs
}

func fHashOf(o synthOut) [32]byte {
	c, err := finality.DecodeContainer(o.evidence, finality.DefaultLimits())
	must(err)
	b, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
	must(err)
	if b.LinkKind == adiri.LinkSlot {
		return [32]byte(crypto.Keccak256Hash(b.FinalHeader))
	}
	return [32]byte(crypto.Keccak256Hash(b.Spine[0]))
}

// singleHeader builds the N = F evidence with linkKind 1.
func singleHeader(kp *keyPool, g5 []int) synthOut {
	o := buildSynth(kp, []epochSpec{{committee: g5, next: g5, signers: seq(0, 5)}}, nil, 14)
	c, err := finality.DecodeContainer(o.evidence, finality.DefaultLimits())
	must(err)
	b, err := adiri.DecodeBody(c.Body, finality.DefaultLimits(), 0)
	must(err)
	b.Spine = b.Spine[:1]
	hf, err := finality.ReadHeader(b.Spine[0])
	must(err)
	ev, err := adiri.BuildContainer(finality.BlockRef{Chain: finality.ChainAdiri, Number: hf.Number, Hash: hf.Hash}, *b)
	must(err)
	o.evidence = ev
	o.leg = legJSON{finality.ChainAdiri, hf.Number, "0x" + hex.EncodeToString(hf.Hash[:]), hex.EncodeToString(b.Spine[0])}
	return o
}
