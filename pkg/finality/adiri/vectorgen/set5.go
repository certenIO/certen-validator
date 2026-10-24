// Copyright 2026 Certen Protocol

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/adiri"
)

// finality_adiri5 (RB11-F1-FIX): the link-kind-2 leg binding (window, non-zero hash, the caller's header) and the pins floor
// min_committee_size >= 4. New evidence, new set: finality_adiri1..4 are untouched. Every expectation is a literal composed here
// by canon(); the verifier under test is never called. The slot vectors are hand-built single-epoch chains (five synthetic
// committee keys, all five sign) whose seal header F commits to a synthetic EIP-2935 account (the real runtime code) holding
// exactly the slots a vector lists; the pins vectors re-use finality_adiri3's syn-rotation evidence under one changed pin.

const (
	eip2935Addr = "0x0000F90827F1C53a10cb7A02335B175320002935"
	// maxSlotDistance is the greatest F - N a link-kind-2 proof may bind (V2_SPEC_S7 3.3: the prover emits linkKind 2 only when
	// F.number - N <= 8190). The EIP-2935 ring holds 8191 hashes; the one-block margin is the spec's.
	maxSlotDistance = uint64(8190)
)

// synthHeader is a synthetic execution header of the given number (root is the state root, fc the parentBeaconBlockRoot).
func synthHeader(n uint64, root common.Hash, fc [32]byte) *types.Header {
	return &types.Header{
		ParentHash: common.BigToHash(new(big.Int).SetUint64(n - 1)), UncleHash: types.EmptyUncleHash, Root: root, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash,
		Difficulty: big.NewInt(0), Number: new(big.Int).SetUint64(n), GasLimit: 30_000_000, Time: 1_790_000_000 + n, Extra: []byte("certen-synthetic-adiri5"),
		BaseFee: big.NewInt(7), WithdrawalsHash: &types.EmptyWithdrawalsHash, BlobGasUsed: new(uint64), ExcessBlobGas: new(uint64),
		ParentBeaconRoot: (*common.Hash)(&fc), RequestsHash: &types.EmptyRequestsHash,
	}
}

func rawRLP(h *types.Header) []byte {
	b, err := rlp.EncodeToBytes(h)
	must(err)
	return b
}

// slot5 is one link-kind-2 vector.
type slot5 struct {
	name, note string
	f          uint64              // the seal block F
	claimed    uint64              // the leg number N the evidence and the leg claim
	legHash    [32]byte            // the leg hash the evidence and the leg claim
	stored     map[uint64][32]byte // EIP-2935 storage: slot index -> value (an absent slot is the zero value)
	legHeader  []byte              // the leg's own header (leg.header_hex), when the caller holds it
	salt       byte
	expect     func(fHash [32]byte) string
}

func (kp *keyPool) slotVector(c slot5) (vec, []byte) {
	var fc [32]byte
	for i := range fc {
		fc[i] = c.salt ^ 0x5a
	}
	addr := common.HexToAddress(eip2935Addr)
	storage := map[common.Hash]*big.Int{}
	for s, v := range c.stored {
		storage[common.BigToHash(new(big.Int).SetUint64(s))] = new(big.Int).SetBytes(v[:])
	}
	st := replayworld.BuildState(tb{}, replayworld.Account{Addr: addr, Code: common.FromHex(eip2935Runtime), Storage: storage})
	fh := synthHeader(c.f, st.Root, fc)
	fHash := [32]byte(fh.Hash())

	g5 := seq(0, 5)
	cf := &adiri.CFA1{Tables: [][][]byte{kp.keysOf(g5)}, Records: []adiri.Record{{
		FinalState: adiri.NumHash{Number: c.f, Hash: fHash}, FinalConsensus: adiri.NumHash{Number: 9000, Hash: fc}, Signers: []uint8{0, 1, 2, 3, 4},
	}}}
	digests, derr := cf.RecordDigests()
	must(derr)
	var sigs []*bls.Signature
	for _, s := range cf.Records[0].Signers {
		sigs = append(sigs, kp.sk[s].Sign(adiri.SignedMessage(digests[0])))
	}
	agg, err := bls.AggregateSignatures(sigs)
	must(err)
	copy(cf.Records[0].Signature[:], agg.Bytes())
	cfa1, err := cf.Encode()
	must(err)

	sp := st.Prove(addr, common.BigToHash(new(big.Int).SetUint64(c.claimed%adiri.EIP2935Window)))
	var nodes [][]byte
	for _, n := range sp.AccountProof {
		nodes = append(nodes, append([]byte(nil), n...))
	}
	for _, n := range sp.StorageProof {
		nodes = append(nodes, append([]byte(nil), n...))
	}
	leg := finality.BlockRef{Chain: finality.ChainAdiri, Number: c.claimed, Hash: c.legHash}
	ev, err := adiri.BuildContainer(leg, adiri.Body{CFA1: cfa1, LinkKind: adiri.LinkSlot, FinalHeader: rawRLP(fh), Nodes: finality.EncodeNodes(nodes)})
	must(err)

	gc := make([]any, 5)
	for i, k := range kp.keysOf(g5) {
		gc[i] = hex.EncodeToString(k)
	}
	pins := cloneSection(embeddedAdiriSection())
	pins["genesis_committee"] = gc
	pins["epoch0_final_state"] = map[string]any{"hash": "0x" + hex.EncodeToString(fHash[:]), "number": float64(c.f)}
	gh := sha256.Sum256([]byte("synthetic-genesis"))
	pins["genesis_hash"] = "0x" + hex.EncodeToString(gh[:])

	lj := legJSON{Chain: finality.ChainAdiri, Number: c.claimed, Hash: "0x" + hex.EncodeToString(c.legHash[:])}
	if c.legHeader != nil {
		lj.HeaderHex = hex.EncodeToString(c.legHeader)
	}
	return vec{Name: c.name, Group: "slot", Note: c.note, Leg: lj, Pins: pins, Evidence: c.name + ".bin", Expect: c.expect(fHash)}, ev
}

func verdict2(f, n uint64, fHash [32]byte) string {
	return canon("finalized", "epoch", uint64(0), "chain_len", uint64(1), "committee_size", uint64(5), "signers", uint64(5), "final_number", f, "final_hash", fHash,
		"distance", f-n, "link_kind", uint64(2), "consensus_root_matches", true, "committee_shrunk", []string{})
}

func slotCases() []slot5 {
	var zero [32]byte
	hashOf := func(n uint64) [32]byte { return [32]byte(synthHeader(n, common.Hash{}, [32]byte{}).Hash()) }
	slotOf := func(n uint64) uint64 { return n % adiri.EIP2935Window }
	window := func(f, n uint64) func([32]byte) string {
		return func([32]byte) string {
			return canon("finality_block_mismatch", "field", "slotDistance", "want", maxSlotDistance, "got", f-n)
		}
	}
	link := func(check string, f, n, at uint64, kv ...any) func([32]byte) string {
		return func([32]byte) string {
			return canon("finality_link_broken", append([]any{"from", f, "to", n, "at", at, "check", check}, kv...)...)
		}
	}
	var cs []slot5

	// the window: F - N <= 8190 is served, 8191 and beyond are refused
	{
		const f = uint64(20000)
		const edge = f - maxSlotDistance
		const past = f - maxSlotDistance - 1
		cs = append(cs, slot5{name: "slot5-window-edge-8190-accepted", salt: 1, f: f, claimed: edge, legHash: hashOf(edge), stored: map[uint64][32]byte{slotOf(edge): hashOf(edge), slotOf(edge + 1): hashOf(edge + 1)},
			note:   "F = 20000, N = F - 8190: the greatest distance a link-kind-2 proof may bind; the slot holds the leg hash",
			expect: func(fh [32]byte) string { return verdict2(f, edge, fh) }})
		cs = append(cs, slot5{name: "slot5-window-8191-refused", salt: 2, f: f, claimed: past, legHash: hashOf(past), stored: map[uint64][32]byte{slotOf(past): hashOf(past), slotOf(past + 1): hashOf(past + 1)},
			note:   "F = 20000, N = F - 8191: one block past the served distance; the slot holds the leg hash but the distance is refused",
			expect: window(f, past)})
	}
	// the alias: a block really numbered 9000 claimed as 809 (the same ring slot, 9000 mod 8191 = 809)
	{
		const f, real, claimed = uint64(12000), uint64(9000), uint64(809)
		realHash := hashOf(real)
		stored := map[uint64][32]byte{slotOf(claimed): realHash, slotOf(claimed + 1): hashOf(real + 1)}
		cs = append(cs, slot5{name: "slot5-alias-9000-claimed-809", salt: 3, f: f, claimed: claimed, legHash: realHash, stored: stored, legHeader: rawRLP(synthHeader(real, common.Hash{}, [32]byte{})),
			note:   "the block really numbered 9000 (its header is the leg's) claimed as block 809: both map to ring slot 809 and the slot holds its hash at F = 12000, but F - 809 = 11191 is outside the window",
			expect: window(f, claimed)})
		cs = append(cs, slot5{name: "slot5-alias-9000-claimed-809-no-leg-header", salt: 3, f: f, claimed: claimed, legHash: realHash, stored: stored,
			note:   "the same claim by a caller that holds no leg header: refused by the window alone",
			expect: window(f, claimed)})
	}
	// the zero hash
	{
		const f, n = uint64(5000), uint64(4000)
		cs = append(cs, slot5{name: "slot5-zero-leg-hash-absent-slot", salt: 4, f: f, claimed: n, legHash: zero, stored: map[uint64][32]byte{slotOf(n + 1): hashOf(n + 1)},
			note: "the all-zero leg hash against a slot the account proves absent (a proven-absent slot reads as zero): never a finalized block",
			expect: func([32]byte) string {
				return canon("finality_block_mismatch", "field", "legHash", "want", "nonzero", "got", zero)
			}})
		cs = append(cs, slot5{name: "slot5-leg-hash-absent-slot", salt: 5, f: f, claimed: n, legHash: hashOf(n), stored: map[uint64][32]byte{slotOf(n + 1): hashOf(n + 1)},
			note:   "a real leg hash against a slot the account proves absent: the proven zero value is not the leg hash",
			expect: link("slot_value_mismatch", f, n, n, "want", hashOf(n), "got", zero)})
	}
	// the caller's own header
	{
		const f = uint64(12000)
		ok, other, wrongNo := uint64(11900), uint64(11500), uint64(11000)
		cs = append(cs, slot5{name: "slot5-leg-header-ok", salt: 6, f: f, claimed: ok, legHash: hashOf(ok), stored: map[uint64][32]byte{slotOf(ok): hashOf(ok), slotOf(ok + 1): hashOf(ok + 1)}, legHeader: rawRLP(synthHeader(ok, common.Hash{}, [32]byte{})),
			note:   "control: the caller's header hashes to the leg hash and carries the leg number",
			expect: func(fh [32]byte) string { return verdict2(f, ok, fh) }})
		cs = append(cs, slot5{name: "slot5-leg-header-number-mismatch", salt: 7, f: f, claimed: other, legHash: hashOf(wrongNo), stored: map[uint64][32]byte{slotOf(other): hashOf(wrongNo), slotOf(other + 1): hashOf(other + 1)},
			legHeader: rawRLP(synthHeader(wrongNo, common.Hash{}, [32]byte{})),
			note:      "inside the window: the leg is numbered 11500 but its header (the one that hashes to the leg hash, held in the ring slot of 11500) is block 11000's; a state no real chain produces, isolating the leg-header number check",
			expect: func([32]byte) string {
				return canon("finality_block_mismatch", "field", "legHeaderNumber", "want", other, "got", wrongNo)
			}})
		cs = append(cs, slot5{name: "slot5-leg-header-hash-mismatch", salt: 8, f: f, claimed: other, legHash: hashOf(wrongNo), stored: map[uint64][32]byte{slotOf(other): hashOf(wrongNo), slotOf(other + 1): hashOf(other + 1)},
			legHeader: rawRLP(synthHeader(other, common.Hash{}, [32]byte{})),
			note:      "inside the window: the caller's header (block 11500) does not hash to the leg hash the evidence and the ring slot carry",
			expect: func([32]byte) string {
				return canon("finality_block_mismatch", "field", "legHeaderHash", "want", hashOf(wrongNo), "got", hashOf(other))
			}})
		cs = append(cs, slot5{name: "slot5-leg-header-undecodable", salt: 9, f: f, claimed: ok, legHash: hashOf(ok), stored: map[uint64][32]byte{slotOf(ok): hashOf(ok), slotOf(ok + 1): hashOf(ok + 1)}, legHeader: []byte{0xc0},
			note:   "the caller's header is an empty RLP list: it cannot be read",
			expect: link("header_decode", f, ok, ok)})
	}
	return cs
}

// pinsVectors are the min_committee_size floor vectors: the SAME evidence and pins as finality_adiri3's syn-rotation with exactly
// the one pin changed.
func pinsVectors(baseDir string) ([]vec, []byte) {
	raw, err := os.ReadFile(filepath.Join(baseDir, "vectors.json"))
	must(err)
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	must(json.Unmarshal(raw, &f))
	var rot *vec
	for i := range f.Vectors {
		if f.Vectors[i].Name == "syn-rotation" {
			rot = &f.Vectors[i]
		}
	}
	if rot == nil {
		panic("syn-rotation not found in " + baseDir)
	}
	ev, err := os.ReadFile(filepath.Join(baseDir, "evidence", rot.Evidence))
	must(err)
	pinsOf := rot.Pins.(map[string]any)
	var out []vec
	add := func(name, note string, size float64, expect string) {
		p := cloneSection(pinsOf)
		p["min_committee_size"] = size
		out = append(out, vec{Name: name, Group: "pins", Note: note, Leg: rot.Leg, Pins: p, Evidence: "syn-rotation.bin", Expect: expect})
	}
	bad := canon("finality_pins_corrupt", "key", "adiri.min_committee_size", "reason", "bad_value")
	add("pins5-min-committee-size-4-control", "control: the floor itself (Telcoin's own shrink rule, annex A4: len >= 4) gives syn-rotation's verdict", 4, rot.Expect)
	add("pins5-min-committee-size-3", "a pin below Telcoin's own floor of 4 would accept committees Telcoin refuses", 3, bad)
	add("pins5-min-committee-size-2", "min_committee_size 2", 2, bad)
	add("pins5-min-committee-size-1", "min_committee_size 1", 1, bad)
	return out, ev
}

func writeAdiri5(out, keysDir, baseDir string) error {
	if out == "" || keysDir == "" || baseDir == "" {
		return fmt.Errorf("-out, -keys and -base are required")
	}
	kp := loadKeys(keysDir, 5)
	evidence := map[string][]byte{}
	var all []vec
	for _, c := range slotCases() {
		v, ev := kp.slotVector(c)
		evidence[c.name] = ev
		all = append(all, v)
	}
	pv, rotEv := pinsVectors(baseDir)
	evidence["syn-rotation"] = rotEv
	all = append(all, pv...)
	return writeSet(out, "finality_adiri5/1", "finality_adiri5/manifest/1", evidence, all)
}
