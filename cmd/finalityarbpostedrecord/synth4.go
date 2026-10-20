// Copyright 2026 Certen Protocol

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// maxL2Message is Nitro's MaxL2MessageSize (arbos/arbostypes MaxL2MessageSize, 256 KiB).
const maxL2Message = 256 * 1024

// build4 writes the vector set finality_arb_posted4 (RB11-E2-FIX, the findings of the independent completeness review V-E2-A1):
//
//  1. a delayed-origin judgement must prove some content: a block with nothing but the internal start-block transaction (or no
//     transaction) matches a delayed message that derives nothing only vacuously, and is l1_posted_content_not_found{no_standard_transactions};
//  2. a TOP-LEVEL sequencer message larger than MaxL2MessageSize is dropped by Nitro's ParseL2Transactions before a byte of it is read;
//  3. Kind.Verify binds the BlockRef to the container header and to its own header (finality_block_mismatch);
//  4. the numeric pins bold_genesis_l2_block, layout.acc_array_slot and layout.delayed_acc_array_slot are judged by presence
//     (pin_mismatch{field}), never read as 0.
//
// Every case is synthetic (L1: the 4-key test committee and a synthetic Bridge; L2: the real header of finality_arb_posted1 with its
// transactionsRoot recomputed), exactly as in finality_arb_posted3. Every expected verdict is a canonical literal written here.
//
//	finalityarbpostedrecord build4 -raw <finality_arb_posted1/raw> -out pkg/finality/arbposted/testdata/finality_arb_posted4
func build4(rawDir, out string) error {
	b := &builder{out: out, files: map[string][]byte{}, pinsRaw: map[string][]byte{}, pinsObj: map[string]*finality.Pins{}, set: "finality_arb_posted4"}
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
	const N = uint64(97)
	before := crypto.Keccak256Hash([]byte("synthetic before 4"))
	h40 := [5]uint64{1790000000, 1790000100, 7000000, 7000100, 0}
	assemble := func(e arbposted.Evidence, delayed map[uint64]common.Hash, l legFile) ([]byte, [32]byte) {
		acc := common.Hash(arbposted.Accumulator(e.BeforeAcc, arbposted.DataHash(e), e.DelayedAcc))
		spine, nodes := synthL1(map[uint64]common.Hash{e.BatchSeq: acc}, delayed, l1Number)
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
	verified := func(seq, messages uint64, ordinal, delayed int64, l1hash [32]byte) string {
		kv := []any{"batch_sequence_number", seq, "blobs", uint64(0), "kind", arbposted.KindName, "l1_state_block", l1Number, "l1_state_block_hash", l1hash,
			"level", finality.LevelL1Posted, "messages", messages, "statement", arbposted.Statement}
		if ordinal >= 0 {
			kv = append(kv, "message_ordinal", uint64(ordinal))
		}
		if delayed >= 0 {
			kv = append(kv, "delayed_message_index", uint64(delayed))
		}
		return canonState("verified", kv...)
	}
	var res []synthCase
	add := func(id, desc, pins string, l legFile, ev []byte, want string) {
		res = append(res, synthCase{id, desc, pins, l, ev, want})
	}
	internal := []byte{0x6a, 0xc0}
	t1 := []byte{0xc4, 0x01, 0x02, 0x03, 0x04}

	// ---- 1. a delayed message that derives nothing proves nothing ---------------------------------------------------------
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	const kIdx = uint64(41)
	prev := crypto.Keccak256Hash([]byte("synthetic delayed prev 4"))
	delayedBatch := payloadOf(segment(2, nil), segment(2, nil), segment(3, []byte{1}))
	delayedEv := func(txs [][]byte, m arbposted.Delayed) (arbposted.Evidence, map[uint64]common.Hash) {
		mh := arbposted.DelayedMessageHash(m)
		accK := crypto.Keccak256Hash(prev[:], mh[:])
		e := arbposted.Evidence{BlockTxs: txs, BatchSeq: N + 1, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata, Calldata: delayedBatch, DelayedAcc: accK, Delayed: &m}
		e.Header40[4] = kIdx + 1
		return e, map[uint64]common.Hash{kIdx: accK, kIdx - 1: prev}
	}
	emptyBatch := arbposted.Delayed{MsgKind: 3, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: []byte{3}, K: kIdx}
	noContent := canonState("l1_posted_content_not_found", "reason", "no_standard_transactions", "batch", N+1)
	for _, c := range []struct {
		id, desc string
		txs      [][]byte
	}{
		{"adv_delayed_empty_batch_internal_tx_only", "delayed message 41 is an L2 message holding an empty batch (derives no transaction); the block holds only the internal start-block transaction 0x6a: the match is vacuous", [][]byte{internal}},
		{"adv_delayed_empty_batch_no_transactions", "the same delayed message and a block with no transaction at all", nil},
		{"adv_delayed_empty_batch_internal_and_retry_only", "the same delayed message and a block of an internal 0x6a and an execution-derived retry 0x68 transaction", [][]byte{internal, {0x68, 0xc0}}},
	} {
		l := legWith(b.baseLeg, b.legHdr, c.txs)
		e, dm := delayedEv(c.txs, emptyBatch)
		ev, _ := assemble(e, dm, l)
		add(c.id, c.desc, "synth", l, ev, noContent)
	}
	{
		txs := [][]byte{internal, t1}
		l := legWith(b.baseLeg, b.legHdr, txs)
		e, dm := delayedEv(txs, emptyBatch)
		ev, _ := assemble(e, dm, l)
		add("adv_delayed_empty_batch_block_holds_a_transaction", "the delayed message derives nothing but the block holds a signed transaction: the transactions differ, the state stays l1_posted_delayed_origin_unproven", "synth", l, ev,
			canonState("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0}, "header_nonce", headerNonce(b.legHdr), "k", kIdx, "message_kind", uint8(3)))
	}
	{
		// the control: an ETH deposit (kind 12) consumed by this batch is still l1_posted
		value := big.NewInt(12345)
		dmsg := arbposted.Delayed{MsgKind: 12, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, K: kIdx,
			Data: append(append([]byte(nil), to[:]...), common.LeftPadBytes(value.Bytes(), 32)...)}
		type depositTx struct {
			ChainID   *big.Int
			RequestID common.Hash
			From, To  common.Address
			Value     *big.Int
		}
		depRLP, _ := rlp.EncodeToBytes(depositTx{ChainID: big.NewInt(421614), RequestID: w32(kIdx), From: user, To: to, Value: value})
		txs := [][]byte{internal, append([]byte{0x64}, depRLP...)}
		l := legWith(b.baseLeg, b.legHdr, txs)
		e, dm := delayedEv(txs, dmsg)
		ev, l1h := assemble(e, dm, l)
		add("valid_delayed_deposit_control", "the control: a block of the internal transaction and the ETH deposit derived from delayed message 41 is still l1_posted", "synth", l, ev, verified(N+1, 0, -1, int64(kIdx), l1h))
	}

	// ---- 2. a top-level sequencer message is capped like ParseL2Transactions -------------------------------------------------
	txs := [][]byte{internal, t1}
	l := legWith(b.baseLeg, b.legHdr, txs)
	// quiet is a batch message of exactly t1, then an oversize length prefix (it ends the batch quietly), then zero padding up to total bytes
	quiet := func(total int) []byte {
		m := batchMsg(signedMsg(t1))
		m = binary.BigEndian.AppendUint64(m, maxL2Message+1)
		for len(m) < total {
			m = append(m, 0)
		}
		return m
	}
	// seqEv is the evidence of a batch whose payload holds the given messages, each as a kind-0 segment, and the L1 block hash it is judged under
	seqEv := func(msgs ...[]byte) ([]byte, [32]byte) {
		var segs [][]byte
		for _, m := range msgs {
			segs = append(segs, segment(0, m))
		}
		return assemble(arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata, Calldata: payloadOf(segs...)}, nil, l)
	}
	noMatch := canonState("l1_posted_content_not_found", "reason", "no_matching_message", "batch", N, "messages_scanned", uint64(1), "segments", uint64(1))
	{
		ev, h := seqEv(quiet(maxL2Message))
		add("valid_toplevel_message_at_cap_262144", "a top-level kind-0 segment of exactly 262,144 bytes (MaxL2MessageSize): a batch message holding the block's transaction, then a quiet end and zero padding", "synth", l, ev, verified(N, 1, 0, -1, h))
		ev, _ = seqEv(quiet(maxL2Message + 1))
		add("adv_toplevel_message_over_cap_262145", "the same message one byte longer (262,145 bytes): Nitro's ParseL2Transactions drops a message larger than MaxL2MessageSize before reading it", "synth", l, ev, noMatch)
		ev, _ = seqEv(quiet(262194))
		add("adv_toplevel_message_over_cap_262194", "a 262,194-byte top-level kind-0 segment (the reviewer's probe): the block's transaction is inside it but Nitro drops the whole message", "synth", l, ev, noMatch)
		ev, h = seqEv(quiet(maxL2Message+1), batchMsg(signedMsg(t1)))
		add("valid_second_message_after_an_oversize_one", "message 0 is oversize and dropped (it keeps its ordinal), message 1 is the block's: found at ordinal 1 of 2", "synth", l, ev, verified(N, 2, 1, -1, h))
	}

	// ---- 3. Kind.Verify binds the BlockRef ---------------------------------------------------------------------------------
	valid := batchMsg(signedMsg(t1))
	validEv, okHash := seqEv(valid)
	var num uint64
	fmt.Sscan(l.Number, &num)
	var hash [32]byte
	copy(hash[:], unhexb(l.Hash))
	mismatch := func(field string, want, got any) string {
		return canonState("finality_block_mismatch", "field", field, "want", want, "got", got)
	}
	otherHash := hash
	otherHash[0] ^= 0xff
	{
		bad := l
		bad.Number = fmt.Sprint(num + 5)
		add("adv_leg_number_differs_from_container", "the leg's block number is not the number the container is about", "synth", bad, validEv, mismatch("blockNumber", num+5, num))
		bad = l
		bad.Hash = hx(otherHash[:])
		add("adv_leg_hash_differs_from_container", "the leg's block hash is not the hash the container is about", "synth", bad, validEv, mismatch("blockHash", otherHash, hash))
	}
	{
		// the container agrees with the leg, the leg's header does not: another header (another transactions root) under the leg's hash
		otherTxs := [][]byte{internal, t1, t1}
		oh := legWith(b.baseLeg, b.legHdr, otherTxs)
		var ohHash [32]byte
		copy(ohHash[:], unhexb(oh.Hash))
		bad := l
		bad.HeaderRLP = oh.HeaderRLP
		add("adv_leg_header_is_not_the_legs_hash", "the container and the leg agree on the hash, but the leg's header rlp hashes to another value", "synth", bad, validEv, mismatch("blockHash", hash, ohHash))
		// the container agrees with the leg (number n+5), the header carries n
		shifted := l
		shifted.Number = fmt.Sprint(num + 5)
		ev, _ := assemble(arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata, Calldata: payloadOf(segment(0, valid))}, nil, shifted)
		add("adv_leg_header_number_is_not_the_legs_number", "the container and the leg agree on the number (n+5), but the leg's header (whose hash is the leg's hash) carries n", "synth", shifted, ev, mismatch("blockNumber", num+5, num))
	}

	// ---- 4. numeric pins are judged by presence -----------------------------------------------------------------------------
	add("valid_control_pins_present", "the control for the pins cases: the same evidence under the synthetic pins, which carry all three numeric pins", "synth", l, validEv, verified(N, 1, 0, -1, okHash))
	variant := func(name string, mut func(arb map[string]any)) error {
		d := parsePinsMap(b.pinsRaw["synth"])
		mut(arbSection(d))
		raw := encodePins(d)
		p, err := finality.ParsePinsOverride(raw)
		if err != nil {
			return fmt.Errorf("pins %s: %w", name, err)
		}
		b.pinsRaw[name] = raw
		b.pinsObj[name] = p
		b.put("pins/"+name+".json", raw)
		return nil
	}
	for _, c := range []struct {
		name, field string
		mut         func(arb map[string]any)
	}{
		{"bold_genesis_l2_block_absent", "bold_genesis_l2_block", func(a map[string]any) { delete(a, "bold_genesis_l2_block") }},
		{"bold_genesis_l2_block_null", "bold_genesis_l2_block", func(a map[string]any) { a["bold_genesis_l2_block"] = nil }},
		{"acc_array_slot_absent", "layout.acc_array_slot", func(a map[string]any) { delete(a["layout"].(map[string]any), "acc_array_slot") }},
		{"acc_array_slot_null", "layout.acc_array_slot", func(a map[string]any) { a["layout"].(map[string]any)["acc_array_slot"] = nil }},
		{"delayed_acc_array_slot_absent", "layout.delayed_acc_array_slot", func(a map[string]any) { delete(a["layout"].(map[string]any), "delayed_acc_array_slot") }},
		{"delayed_acc_array_slot_null", "layout.delayed_acc_array_slot", func(a map[string]any) { a["layout"].(map[string]any)["delayed_acc_array_slot"] = nil }},
	} {
		if err := variant(c.name, c.mut); err != nil {
			return err
		}
		add("adv_pin_"+c.name, "the pin "+c.field+" is absent or null in the arb_sepolia section: it is refused by name, never read as 0", c.name, l, validEv, canonState("pin_mismatch", "field", c.field))
	}

	for _, c := range res {
		if err := b.addFull(c.id, c.desc, c.pins, c.leg, c.ev, c.want); err != nil {
			return err
		}
	}

	// ---- 5. the seven finality_arb_posted1 cases that paired a synthetic leg with the recorded container, re-bound --------------
	// Their evidence is the recorded live evidence with the block transactions patched; the container header still names the live block, so
	// Kind.Verify now stops at the binding (set 1's SUPERSEDED.md). Here the container header's block hash is replaced by the case leg's
	// hash and nothing else changes: each case keeps its recorded expectation, which pins the match logic it was written for.
	set1 := filepath.Join(rawDir, "..")
	livePins, err := os.ReadFile(filepath.Join(set1, "pins", "main.json"))
	if err != nil {
		return err
	}
	lp, err := finality.ParsePinsOverride(livePins)
	if err != nil {
		return err
	}
	b.pinsRaw["live"], b.pinsObj["live"] = livePins, lp
	b.put("pins/live.json", livePins)
	base, err := os.ReadFile(filepath.Join(rawDir, "evidence.bin"))
	if err != nil {
		return err
	}
	b.base = base
	b.put("raw/evidence.bin", base)
	for _, id := range []string{"adv_tx_altered", "adv_tx_order_swapped", "adv_tx_missing", "adv_tx_extra", "adv_no_standard_transactions", "adv_unsupported_tx_type", "adv_delayed_origin_without_proof"} {
		cj, err := os.ReadFile(filepath.Join(set1, "cases", id+".json"))
		if err != nil {
			return err
		}
		var cf caseFile
		if err := json.Unmarshal(cj, &cf); err != nil {
			return err
		}
		c, err := finality.DecodeContainer(applyPatch(base, cf.Patch), finality.DefaultLimits())
		if err != nil {
			return err
		}
		fmt.Sscan(cf.Leg.Number, &c.Header.BlockNumber)
		copy(c.Header.BlockHash[:], unhexb(cf.Leg.Hash))
		rebound, err := c.Encode()
		if err != nil {
			return err
		}
		if err := b.add(id+"_container_bound", cf.Description+" (finality_arb_posted1 case "+id+" with the container header's block hash replaced by the leg's)", "live", cf.Leg, rebound, cf.Expect); err != nil {
			return err
		}
	}
	return b.flush(rawDir)
}
