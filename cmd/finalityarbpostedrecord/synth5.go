// Copyright 2026 Certen Protocol

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// build5 writes the vector set finality_arb_posted5 (RB12-ARBFINAL-FIX, BETA audit G2): the binding of the BlockRef to the CONTAINER that
// Kind.Verify judges first (verify.go: container.blockNumber == leg.number, then container.blockHash == leg.hash).
//
// The two cases of finality_arb_posted4 that name this binding (adv_leg_number_differs_from_container, adv_leg_hash_differs_from_container)
// alter the leg's number or hash and leave its header alone, so the leg disagrees with its OWN header as well; the later header checks
// (leg.hash == hash(leg.header), leg.number == header.number) answer the same state with the same fields, and the container binding is
// pinned by no vector: removing it changes no published verdict. These cases give the leg a header of its own that agrees with it, so
// the leg is consistent and ONLY the container disagrees:
//
//   - the leg is block n+5: its header carries number n+5 (so its hash differs as well), the container is about block n:
//     finality_block_mismatch{blockNumber, want n+5, got n}. The number is judged before the hash, so this case also pins the order;
//   - the leg is the block n whose header differs from the container's only in its extraData (same transactions, same number, a different
//     hash), the container is about the original: finality_block_mismatch{blockHash, want the leg's, got the container's}. Without the binding the
//     rest of the evidence verifies and the leg is verified under a hash the container is not about.
//
// The control is the unaltered pair. Every case is synthetic (L1: the 4-key test committee and a synthetic Bridge; L2: the real header of
// finality_arb_posted1 with its transactionsRoot recomputed), as in finality_arb_posted4. Every expected verdict is a canonical literal.
//
//	finalityarbpostedrecord build5 -raw <finality_arb_posted1/raw> -out pkg/finality/arbposted/testdata/finality_arb_posted5
func build5(rawDir, out string) error {
	b := &builder{out: out, files: map[string][]byte{}, pinsRaw: map[string][]byte{}, pinsObj: map[string]*finality.Pins{}, set: "finality_arb_posted5"}
	lj, err := os.ReadFile(rawDir + "/leg.json")
	if err != nil {
		return err
	}
	var leg rawLeg
	if err := json.Unmarshal(lj, &leg); err != nil {
		return err
	}
	b.baseLeg = legFile{Chain: leg.Chain, Number: leg.Number, Hash: leg.Hash, HeaderRLP: leg.HeaderRLP}
	b.legHdr = unhexb(leg.HeaderRLP)
	b.put("raw/leg.json", lj)
	// The pins are the synthetic pins file of finality_arb_posted4, read from that set (byte for byte the file sets 3 and 4 carry), not derived from
	// the embedded pins: the embedded pins grow with the pins channel and a set must regenerate byte for byte whatever the embedded file holds.
	synthPinsRaw, err := os.ReadFile(filepath.Join(rawDir, "..", "..", "finality_arb_posted4", "pins", "synth.json"))
	if err != nil {
		return err
	}
	synthParsed, err := finality.ParsePinsOverride(synthPinsRaw)
	if err != nil {
		return err
	}
	b.pinsRaw["synth"], b.pinsObj["synth"] = synthPinsRaw, synthParsed
	b.put("pins/synth.json", synthPinsRaw)
	k := newSynthKeys()
	committee := k.committee512()
	gvr := sum("gvr")
	croot, _ := ethl1.HashTreeRootSyncCommittee(committee)
	var version [4]byte
	copy(version[:], []byte{0x90, 0, 0, 0xa1})
	const l1Number = uint64(7000000)
	const N = uint64(98)
	before := crypto.Keccak256Hash([]byte("synthetic before 5"))
	h40 := [5]uint64{1790000000, 1790000100, 7000000, 7000100, 0}
	assemble := func(e arbposted.Evidence, l legFile) ([]byte, [32]byte) {
		acc := common.Hash(arbposted.Accumulator(e.BeforeAcc, arbposted.DataHash(e), e.DelayedAcc))
		spine, nodes := synthL1(map[uint64]common.Hash{e.BatchSeq: acc}, nil, l1Number)
		exec := crypto.Keccak256Hash(spine[0])
		e.LC = ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: synthPeriod, AnchorRoot: croot,
			AnchorBody: ethl1.LB{Layout: ethl1.LayoutNone, SSZ: committee}, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: k.finalUpdate(exec, version, gvr)}}
		e.L1Spine, e.Nodes, e.StateBlock = spine, nodes, l1Number
		var num uint64
		fmt.Sscan(l.Number, &num)
		var h [32]byte
		copy(h[:], unhexb(l.Hash))
		return containerBytes(finality.ContainerHeader{Kind: arbposted.KindName, Chain: 421614, Level: finality.LevelL1Posted, BlockNumber: num, BlockHash: h}, e.Encode()), exec
	}
	internal := []byte{0x6a, 0xc0}
	t1 := []byte{0xc4, 0x01, 0x02, 0x03, 0x04}
	txs := [][]byte{internal, t1}
	l := legWith(b.baseLeg, b.legHdr, txs)
	ev, l1h := assemble(arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata,
		Calldata: payloadOf(segment(0, batchMsg(signedMsg(t1))))}, l)
	var num uint64
	fmt.Sscan(l.Number, &num)
	var hash [32]byte
	copy(hash[:], unhexb(l.Hash))
	mismatch := func(field string, want, got any) string {
		return canonState("finality_block_mismatch", "field", field, "want", want, "got", got)
	}
	verified := canonState("verified", "batch_sequence_number", N, "blobs", uint64(0), "kind", arbposted.KindName, "l1_state_block", l1Number, "l1_state_block_hash", l1h,
		"level", finality.LevelL1Posted, "message_ordinal", uint64(0), "messages", uint64(1), "statement", arbposted.Statement)

	var res []synthCase
	add := func(id, desc string, lg legFile, evidence []byte, want string) {
		res = append(res, synthCase{id, desc, "synth", lg, evidence, want})
	}
	add("valid_control_leg_and_container_agree", "the control: the leg and the container are about the same block and the leg's header is its own", l, ev, verified)

	// the leg is block n+5 with a header of its own that carries n+5 (its hash differs too); the container is about block n
	{
		items, err := splitItems(unhexb(l.HeaderRLP))
		if err != nil {
			return err
		}
		items[8] = mustRLP(num + 5)
		hdr, err := rlp.EncodeToBytes(rawList(items))
		if err != nil {
			return err
		}
		h := crypto.Keccak256Hash(hdr)
		other := legFile{Chain: l.Chain, Number: fmt.Sprint(num + 5), Hash: hx(h[:]), HeaderRLP: hx(hdr)}
		add("adv_leg_number_differs_from_container_leg_header_agrees", "the leg is block n+5 and its header (hash and number) agrees with that, the container is about block n: finality_block_mismatch blockNumber, judged before the hash", other, ev, mismatch("blockNumber", num+5, num))
	}
	// the leg is block n with another header (another extraData: same number, same transactions, another hash) of its own; the container is about the original
	{
		items, err := splitItems(unhexb(l.HeaderRLP))
		if err != nil {
			return err
		}
		items[12] = mustRLP([]byte("the other header of block n"))
		hdr, err := rlp.EncodeToBytes(rawList(items))
		if err != nil {
			return err
		}
		h := crypto.Keccak256Hash(hdr)
		other := legFile{Chain: l.Chain, Number: l.Number, Hash: hx(h[:]), HeaderRLP: hx(hdr)}
		if h == common.Hash(hash) {
			return fmt.Errorf("the edited header has the original hash")
		}
		if got := ethproof.TrieRoot(txs); got != common.BytesToHash(items[4][1:]) {
			return fmt.Errorf("the edited header lost its transactions root")
		}
		add("adv_leg_hash_differs_from_container_leg_header_agrees", "the leg is block n with a header of its own whose hash differs (another extraData), the container is about the original header: finality_block_mismatch blockHash", other, ev, mismatch("blockHash", [32]byte(h), hash))
	}
	for _, c := range res {
		if err := b.addFull(c.id, c.desc, c.pins, c.leg, c.ev, c.want); err != nil {
			return err
		}
	}
	return b.flush(rawDir)
}
