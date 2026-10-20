// Copyright 2026 Certen Protocol

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// build3 writes the vector set finality_arb_posted3 (RB11-E2B, second box): a sequencer-batch L2 message is parsed as Nitro parses it
// (arbos/parse_l2.go parseL2Message with no L1 request id), so a message with ANY failing nested message is not a message and
// matches no block. Every case is synthetic (L1: the 4-key test committee and a synthetic Bridge; L2: the real header of
// finality_arb_posted1 with its transactionsRoot recomputed), exactly as in finality_arb_posted2.
//
//	finalityarbpostedrecord build3 -raw <finality_arb_posted1/raw> -out pkg/finality/arbposted/testdata/finality_arb_posted3
func build3(rawDir, out string) error {
	b := &builder{out: out, files: map[string][]byte{}, pinsRaw: map[string][]byte{}, pinsObj: map[string]*finality.Pins{}, set: "finality_arb_posted3"}
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
	b.pinsRaw["main"] = finality.EmbeddedPinsBytes()
	main, err := finality.ParsePinsOverride(b.pinsRaw["main"])
	if err != nil {
		return err
	}
	b.pinsObj["main"] = main
	k := newSynthKeys()
	committee := k.committee512()
	gvr := sum("gvr")
	if err := synthPins(b, committee, gvr); err != nil {
		return err
	}
	croot, _ := ethl1.HashTreeRootSyncCommittee(committee)
	var version [4]byte
	copy(version[:], []byte{0x90, 0, 0, 0xa1})
	const l1Number = uint64(7000000)
	const N = uint64(95)
	before := crypto.Keccak256Hash([]byte("synthetic before 3"))
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
	okWant := func(messages uint64, ordinal uint64, l1hash [32]byte) string {
		return canonState("verified", "batch_sequence_number", N, "blobs", uint64(0), "kind", arbposted.KindName, "l1_state_block", l1Number, "l1_state_block_hash", l1hash,
			"level", finality.LevelL1Posted, "message_ordinal", ordinal, "messages", messages, "statement", arbposted.Statement)
	}
	noMsg := canonState("l1_posted_content_not_found", "reason", "no_matching_message", "batch", N, "messages_scanned", uint64(1), "segments", uint64(1))

	// the block holds two signed transactions; every message below carries them first and then something else
	t1 := []byte{0xc4, 0x01, 0x02, 0x03, 0x04}
	t2 := []byte{0xc4, 0x05, 0x06, 0x07, 0x08}
	txs := [][]byte{{0x6a, 0xc0}, t1, t2}
	l := legWith(b.baseLeg, b.legHdr, txs)
	signed := func(tx []byte) []byte { return signedMsg(tx) }
	good := func(extra ...[]byte) []byte {
		return batchMsg(append([][]byte{signed(t1), signed(t2)}, extra...)...)
	}
	// kind 0 (unsigned user tx) with valid fields: gas, max fee, nonce, to, value, calldata
	unsignedOK := append([]byte{0}, joinBytes(be32(50000), be32(8), be32(1), be32(7), be32(0), []byte{1})...)
	unsignedShort := append([]byte{0}, joinBytes(be32(50000), be32(8))...)
	contract := append([]byte{1}, joinBytes(be32(50000), be32(8), be32(7), be32(0))...)
	type tc struct {
		id, desc string
		msg      []byte
		valid    bool
	}
	nest := func(m []byte, n int) []byte {
		for i := 0; i < n; i++ {
			m = batchMsg(m)
		}
		return m
	}
	badSigned := func(t byte) []byte { return append([]byte{4, t}, 0xc0) }
	cases := []tc{
		{"valid_message_two_signed_txs", "the control: a batch message of exactly the block's two signed transactions", good(), true},
		{"valid_message_with_valid_unsigned_nested", "a nested unsigned user tx (kind 0, fields complete) is built from the poster and is not a signed transaction: it adds none and does not fail the message", good(unsignedOK), true},
		{"valid_message_with_cut_length_tail", "a batch whose last length prefix is cut: Nitro ends the batch quietly and keeps what it has", append(good(), 0, 0, 0), true},
		{"valid_message_with_oversize_length_tail", "a batch whose last nested length exceeds the 256 KiB message limit: it ends the batch quietly", append(good(), binary.BigEndian.AppendUint64(nil, 256*1024+1)...), true},
		{"valid_message_with_cut_nested_tail", "a batch whose last nested message is shorter than its length: it ends the batch quietly", append(good(), append(binary.BigEndian.AppendUint64(nil, 50), 1, 2)...), true},
		{"valid_message_nested_16_deep", "the two signed transactions inside 15 further batches: the deepest batch Nitro accepts (depth 15)", nest(good(), 15), true},
		{"adv_message_nested_nonmutating_call", "a nested message of kind 2 (NonmutatingCall) fails the WHOLE message", good([]byte{2, 0, 0}), false},
		{"adv_message_nested_unknown_kind", "a nested message of an unknown kind (9) fails the whole message", good([]byte{9, 1}), false},
		{"adv_message_nested_heartbeat", "a nested heartbeat (kind 6; disabled since 2022) fails the whole message", good([]byte{6}), false},
		{"adv_message_nested_signed_compressed", "a nested message of kind 7 (SignedCompressedTx) fails the whole message", good([]byte{7, 1, 2}), false},
		{"adv_message_nested_contract_tx", "a nested contract tx (kind 1) needs an L1 request id a sequencer message does not have: it fails the whole message", good(contract), false},
		{"adv_message_nested_unsigned_short", "a nested unsigned user tx cut after its max fee fails the whole message", good(unsignedShort), false},
		{"adv_message_nested_empty_signed", "a nested signed-tx message with no transaction bytes fails the whole message", good([]byte{4}), false},
		{"adv_message_nested_arbitrum_type_tx", "a nested signed-tx message whose transaction is of the Arbitrum deposit type 0x64 fails the whole message", good(badSigned(0x64)), false},
		{"adv_message_nested_blob_type_tx", "a nested signed-tx message whose transaction is of the blob type 0x03 fails the whole message", good(badSigned(0x03)), false},
		{"adv_message_nested_unknown_type_tx", "a nested signed-tx message whose transaction type (0x05) no Nitro version knows fails the whole message", good(badSigned(0x05)), false},
		{"adv_message_inner_batch_fails", "a nested batch whose own nested message fails fails the whole outer message", good(batchMsg(signed(t1), []byte{2})), false},
		{"adv_message_nested_17_deep", "the two signed transactions inside 16 further batches: one deeper than Nitro accepts, the whole message fails", nest(good(), 16), false},
	}
	var res []synthCase
	for _, c := range cases {
		ev, l1h := assemble(arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata,
			Calldata: payloadOf(segment(0, c.msg))}, l)
		want := noMsg
		if c.valid {
			want = okWant(1, 0, l1h)
		}
		res = append(res, synthCase{c.id, c.desc, "synth", l, ev, want})
	}
	// the failing message is still a message of the batch (it keeps its ordinal): a later valid message is found at ordinal 1
	ev, l1h := assemble(arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata,
		Calldata: payloadOf(segment(0, good([]byte{2})), segment(0, good()))}, l)
	res = append(res, synthCase{"valid_second_message_after_a_failed_one", "message 0 fails (nested kind 2), message 1 is the block's: found at ordinal 1 of 2", "synth", l, ev, okWant(2, 1, l1h)})
	for _, c := range res {
		if err := b.addFull(c.id, c.desc, c.pins, c.leg, c.ev, c.want); err != nil {
			return err
		}
	}
	return b.flush(rawDir)
}

func be32(v uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], v)
	return b
}

func joinBytes(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
