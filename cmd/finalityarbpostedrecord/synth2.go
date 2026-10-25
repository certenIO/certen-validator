// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// build2 writes the vector set finality_arb_posted2: RB11-E2B's strictness and completeness cases. Everything on the L1 side is
// synthetic (the 4-key test committee and a synthetic Bridge of synth.go); the L2 leg is the REAL block header of finality_arb_posted1
// (raw/leg.json) with its transactionsRoot recomputed per case. No case is a recording of a live delayed message or zero-heavy batch:
// none occurs on Arbitrum Sepolia in the captured window; the README labels every case synthetic.
//
//	finalityarbpostedrecord build2 -raw <finality_arb_posted1/raw> -out pkg/finality/arbposted/testdata/finality_arb_posted2
func build2(rawDir, out string) error {
	b := &builder{out: out, files: map[string][]byte{}, pinsRaw: map[string][]byte{}, pinsObj: map[string]*finality.Pins{}, set: "finality_arb_posted2"}
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
	b.pinsRaw["main"] = mainPinsAtSets234 // the pins the set was published with (pins_input.go), never the live embedded ones
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
	const N = uint64(91)
	before := crypto.Keccak256Hash([]byte("synthetic before 2"))
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
	calldata := func(data []byte, txs [][]byte, seq uint64) arbposted.Evidence {
		return arbposted.Evidence{BlockTxs: txs, BatchSeq: seq, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata, Calldata: data}
	}
	okWant := func(seq, blobs, messages uint64, ordinal int64, delayed int64, l1hash [32]byte) string {
		kv := []any{"batch_sequence_number", seq, "blobs", blobs, "kind", arbposted.KindName, "l1_state_block", l1Number, "l1_state_block_hash", l1hash,
			"level", finality.LevelL1Posted, "messages", messages, "statement", arbposted.Statement}
		if ordinal >= 0 {
			kv = append(kv, "message_ordinal", uint64(ordinal))
		}
		if delayed >= 0 {
			kv = append(kv, "delayed_message_index", uint64(delayed))
		}
		return canonState("verified", kv...)
	}
	undecodable := func(seq uint64) string {
		return canonState("l1_posted_content_not_found", "reason", "payload_undecodable", "batch", seq)
	}
	var cases []synthCase
	addC := func(id, desc string, l legFile, ev []byte, want string) {
		cases = append(cases, synthCase{id, desc, "synth", l, ev, want})
	}
	internal := []byte{0x6a, 0xc0}
	rnd := rand.New(rand.NewSource(21))
	tail := make([]byte, 48)
	rnd.Read(tail)

	// ---- Brotli strictness (RB11-E2B finding): a stream that ends early is not a stream
	tiny := []byte{0xc4, 0x01, 0x02, 0x03, 0x04} // a type-0 transaction encoding is all the matcher compares
	tinyTxs := [][]byte{internal, tiny}
	tinyLeg := legWith(b.baseLeg, b.legHdr, tinyTxs)
	short := payloadOf(segment(0, signedMsg(tiny)))
	ev, l1h := assemble(calldata(short, tinyTxs, N), nil, tinyLeg)
	addC("valid_brotli_short_stream", "a calldata batch whose whole brotli stream is a few bytes: the control for the truncation cases", tinyLeg, ev, okWant(N, 0, 1, 0, -1, l1h))
	for i := 2; i < len(short); i++ {
		ev, _ := assemble(calldata(short[:i], tinyTxs, N), nil, tinyLeg)
		addC(fmt.Sprintf("adv_brotli_short_stream_cut_to_%02d_of_%02d", i, len(short)), "the same batch with its payload cut to a prefix: the stream is incomplete, never a prefix of the data", tinyLeg, ev, undecodable(N))
	}
	needed := segment(0, signedMsg(tiny))
	withTail := payloadOf(needed, segment(0, signedMsg(tail)))
	ev, l1h = assemble(calldata(withTail, tinyTxs, N), nil, tinyLeg)
	addC("valid_brotli_batch_with_tail", "the needed message first and 48 incompressible bytes behind it: the control for the next cases", tinyLeg, ev, okWant(N, 0, 2, 0, -1, l1h))
	for _, cut := range []int{1, 2, 8, len(withTail) / 2} {
		ev, _ := assemble(calldata(withTail[:len(withTail)-cut], tinyTxs, N), nil, tinyLeg)
		addC(fmt.Sprintf("adv_brotli_batch_cut_%d_byte", cut), fmt.Sprintf("the batch stream ends %d byte(s) early: the library alone returns the prefix that already holds the needed message", cut), tinyLeg, ev, undecodable(N))
	}
	ev, _ = assemble(calldata([]byte{0x00}, tinyTxs, N), nil, tinyLeg)
	addC("adv_brotli_header_only", "the payload is the Brotli header byte and nothing else: the empty stream is refused", tinyLeg, ev, undecodable(N))
	ev, _ = assemble(calldata(append(append([]byte(nil), withTail...), 0x00), tinyTxs, N), nil, tinyLeg)
	addC("adv_brotli_byte_after_stream", "one byte after a complete stream", tinyLeg, ev, undecodable(N))

	// a per-message Brotli segment (segment kind 1) cut short is dropped, not kept as a partial message
	t1 := tiny
	bigTx := append([]byte{0xc0 + 0x3f}, tail...)
	msg := batchMsg(signedMsg(t1), signedMsg(bigTx))
	comp := brotliBytes(msg)
	segTxs := [][]byte{internal, t1, bigTx}
	segLeg := legWith(b.baseLeg, b.legHdr, segTxs)
	ev, l1h = assemble(calldata(payloadOf(segment(1, comp)), segTxs, N), nil, segLeg)
	addC("valid_brotli_message_segment", "a message sent as a Brotli segment: the control", segLeg, ev, okWant(N, 0, 1, 0, -1, l1h))
	firstOnly := [][]byte{internal, t1}
	firstLeg := legWith(b.baseLeg, b.legHdr, firstOnly)
	noMsg := func(msgs uint64, segs uint64) string {
		return canonState("l1_posted_content_not_found", "reason", "no_matching_message", "batch", N, "messages_scanned", msgs, "segments", segs)
	}
	for _, cut := range []int{1, 2, len(comp) / 2} {
		ev, _ := assemble(calldata(payloadOf(segment(1, comp[:len(comp)-cut])), firstOnly, N), nil, firstLeg)
		addC(fmt.Sprintf("adv_brotli_message_segment_cut_%d_byte", cut), "the message's Brotli segment ends early: Nitro drops the message; the library alone would keep the prefix that holds the first transaction", firstLeg, ev, noMsg(0, 1))
	}
	ev, _ = assemble(calldata(payloadOf(segment(1, nil)), firstOnly, N), nil, firstLeg)
	addC("adv_brotli_message_segment_empty", "an empty Brotli message segment", firstLeg, ev, noMsg(0, 1))
	ev, _ = assemble(calldata(payloadOf(segment(1, append(append([]byte(nil), comp...), 0x00))), firstOnly, N), nil, firstLeg)
	addC("adv_brotli_message_segment_byte_after", "a byte after the message's complete Brotli stream", firstLeg, ev, noMsg(0, 1))

	// ---- the zero-heavy layer (Nitro decodes it once, then reads a Brotli payload)
	zh := func(inner []byte) []byte { return append([]byte{0x20}, zhEncodeBytes(inner)...) }
	inner := payloadOf(needed, segment(0, signedMsg(tail)))
	ev, l1h = assemble(calldata(zh(inner), tinyTxs, N), nil, tinyLeg)
	addC("valid_zeroheavy_calldata", "a calldata batch whose payload is 0x20 || zero-heavy(0x00 || brotli(segments))", tinyLeg, ev, okWant(N, 0, 2, 0, -1, l1h))
	blobsZ, vhZ := blobsFor(zh(inner))
	evZ := arbposted.Evidence{BlockTxs: tinyTxs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataBlobs, VersionedHashes: vhZ, Blobs: blobsZ}
	ev, l1h = assemble(evZ, nil, tinyLeg)
	addC("valid_zeroheavy_blob", "the same payload in a KZG-verified blob", tinyLeg, ev, okWant(N, uint64(len(blobsZ)), 2, 0, -1, l1h))
	for _, c := range []struct {
		id, desc string
		inner    []byte
		want     string
	}{
		{"adv_zeroheavy_inner_das_byte", "the layer decodes to a DAS header byte: only the Brotli header is read after the layer", append([]byte{0x80}, inner[1:]...), canonState("l1_batch_header_unknown", "batch", N, "byte", uint8(0x80))},
		{"adv_zeroheavy_second_layer", "a second zero-heavy layer is not decoded", zh(inner), canonState("l1_batch_header_unknown", "batch", N, "byte", uint8(0x20))},
		{"adv_zeroheavy_inner_unknown_byte", "the layer decodes to an unknown header byte", append([]byte{0x07}, inner[1:]...), canonState("l1_batch_header_unknown", "batch", N, "byte", uint8(0x07))},
		{"adv_zeroheavy_inner_stream_cut", "the Brotli stream inside the layer ends early", inner[:len(inner)-1], undecodable(N)},
	} {
		ev, _ := assemble(calldata(zh(c.inner), tinyTxs, N), nil, tinyLeg)
		addC(c.id, c.desc, tinyLeg, ev, c.want)
	}
	ev, _ = assemble(calldata([]byte{0x20}, tinyTxs, N), nil, tinyLeg)
	addC("adv_zeroheavy_header_only", "the flag alone: the layer decodes to nothing", tinyLeg, ev, undecodable(N))
	// ---- delayed-origin blocks beyond the ETH deposit (derivation per nitro arbos/parse_l2.go)
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	refund := common.HexToAddress("0x3333333333333333333333333333333333333333")
	w := func(v *big.Int) []byte { return common.LeftPadBytes(v.Bytes(), 32) }
	wu := func(v uint64) []byte { return w(new(big.Int).SetUint64(v)) }
	wa := func(a common.Address) []byte { return common.LeftPadBytes(a[:], 32) }
	kIdx := uint64(300)
	mkMsg := func(kind uint8, data []byte) arbposted.Delayed {
		d := arbposted.Delayed{MsgKind: kind, Sender: user, MsgBlockNumber: 11, MsgTimestamp: 22, Data: data, K: kIdx}
		d.BaseFeeL1[31] = 7
		return d
	}
	prev := crypto.Keccak256Hash([]byte("synthetic delayed prev 2"))
	delayedCase := func(id, desc string, d arbposted.Delayed, txs [][]byte, valid bool, tamper func(*[][]byte)) {
		want, ok := arbposted.DeriveDelayedTxs(421614, d)
		if !ok {
			panic("generator: no derivation for " + id)
		}
		blockTxs := append([][]byte{internal}, want...)
		if tamper != nil {
			tamper(&blockTxs)
		}
		l := legWith(b.baseLeg, b.legHdr, blockTxs)
		mh := arbposted.DelayedMessageHash(d)
		accK := crypto.Keccak256Hash(prev[:], mh[:])
		e := calldata(payloadOf(segment(2, nil), segment(3, []byte{1})), blockTxs, N+2)
		e.Header40[4] = kIdx + 1
		e.DelayedAcc = accK
		e.Delayed = &d
		ev, l1 := assemble(e, map[uint64]common.Hash{kIdx: accK, kIdx - 1: prev}, l)
		var types []uint64
		for _, t := range blockTxs {
			types = append(types, uint64(txTypeOf(t)))
		}
		if valid {
			addC(id, desc, l, ev, okWant(N+2, 0, 0, -1, int64(kIdx), l1))
		} else {
			addC(id, desc, l, ev, canonState("l1_posted_delayed_origin_unproven", "block_tx_types", types, "header_nonce", headerNonce(b.legHdr), "k", kIdx, "message_kind", d.MsgKind))
		}
	}
	retryData := []byte{0xde, 0xad, 0xbe, 0xef}
	retryable := mkMsg(9, bytes.Join([][]byte{wa(to), wu(5), wu(100), wu(7), wa(refund), wa(refund), wu(21000), wu(3), wu(uint64(len(retryData))), retryData}, nil))
	delayedCase("synth_valid_delayed_submit_retryable", "a block made of one submit-retryable delayed message (type 0x69)", retryable, nil, true, nil)
	delayedCase("adv_synth_delayed_submit_retryable_tx_altered", "the 0x69 transaction's last byte altered", retryable, nil, false, func(t *[][]byte) {
		x := append([]byte(nil), (*t)[1]...)
		x[len(x)-1] ^= 1
		(*t)[1] = x
	})
	unsignedBody := bytes.Join([][]byte{wu(50000), wu(8), wu(4), wa(to), wu(11), {9, 9}}, nil)
	contractBody := bytes.Join([][]byte{wu(60000), wu(8), wa(to), wu(12), {8}}, nil)
	l2unsigned := mkMsg(3, append([]byte{0}, unsignedBody...))
	delayedCase("synth_valid_delayed_unsigned_tx", "an L2 message of kind unsigned user tx (type 0x65)", l2unsigned, nil, true, nil)
	delayedCase("adv_synth_delayed_unsigned_tx_dropped", "the 0x65 transaction missing from the block", l2unsigned, nil, false, func(t *[][]byte) { *t = (*t)[:1] })
	l2contract := mkMsg(3, append([]byte{1}, contractBody...))
	delayedCase("synth_valid_delayed_contract_tx", "an L2 message of kind contract tx (type 0x66, request id = the delayed index)", l2contract, nil, true, nil)
	l2batch := mkMsg(3, batchMsg(append([]byte{0}, unsignedBody...), append([]byte{1}, contractBody...)))
	delayedCase("synth_valid_delayed_batch", "an L2 batch of an unsigned and a contract tx (the contract tx's request id is keccak(requestId || 1))", l2batch, nil, true, nil)
	delayedCase("adv_synth_delayed_batch_order_swapped", "the two transactions of the batch in the other order", l2batch, nil, false, func(t *[][]byte) { (*t)[1], (*t)[2] = (*t)[2], (*t)[1] })
	funded := mkMsg(7, append([]byte{1}, contractBody...))
	delayedCase("synth_valid_delayed_funded_by_l1", "an L2-funded-by-L1 message: a deposit to the poster, then the contract tx under the second sub-request id", funded, nil, true, nil)
	delayedCase("adv_synth_delayed_funded_by_l1_extra_tx", "an extra transaction after the derived pair", funded, nil, false, func(t *[][]byte) { *t = append(*t, (*t)[2]) })
	dep := mkMsg(12, append(append([]byte(nil), to[:]...), w(big.NewInt(12345))...))
	delayedCase("synth_valid_delayed_eth_deposit", "an ETH deposit (type 0x64), with the chain id now part of the compared bytes", dep, nil, true, nil)
	delayedCase("adv_synth_delayed_eth_deposit_wrong_chain", "the deposit transaction carries another chain id (421615)", dep, nil, false, func(t *[][]byte) {
		other, _ := arbposted.DeriveDelayedTxs(421615, dep)
		(*t)[1] = other[0]
	})
	// a message kind with no derivation
	noDeriv := mkMsg(13, []byte{1, 2, 3})
	{
		blockTxs := [][]byte{internal, {0x65, 0xc0}}
		l := legWith(b.baseLeg, b.legHdr, blockTxs)
		mh := arbposted.DelayedMessageHash(noDeriv)
		accK := crypto.Keccak256Hash(prev[:], mh[:])
		e := calldata(payloadOf(segment(2, nil)), blockTxs, N+2)
		e.Header40[4] = kIdx + 1
		e.DelayedAcc = accK
		e.Delayed = &noDeriv
		ev, _ := assemble(e, map[uint64]common.Hash{kIdx: accK, kIdx - 1: prev}, l)
		addC("adv_synth_delayed_batch_posting_report_kind", "message kind 13 (batch posting report) has no derivation here: named, not a weaker level", l, ev,
			canonState("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0x65}, "header_nonce", headerNonce(b.legHdr), "k", kIdx, "message_kind", uint8(13)))
	}

	for _, c := range cases {
		if err := b.addFull(c.id, c.desc, c.pins, c.leg, c.ev, c.want); err != nil {
			return err
		}
	}
	return b.flush(rawDir)
}

func txTypeOf(tx []byte) uint8 {
	if len(tx) == 0 || tx[0] >= 0xc0 {
		return 0
	}
	return tx[0]
}

// zhEncodeBytes is nitro@ccc5c82 zeroheavy.ZeroheavyEncoder over a byte slice.
func zhEncodeBytes(in []byte) []byte {
	var out []byte
	pos, bitsRead := 0, uint8(8)
	var buffer byte
	padding, atEOF := false, false
	next := func() bool {
		if padding {
			return true
		}
		if bitsRead == 8 {
			if pos >= len(in) {
				padding = true
				return false
			}
			buffer = in[pos]
			pos++
			bitsRead = 0
		}
		r := buffer&(1<<(7-bitsRead)) != 0
		bitsRead++
		return r
	}
	for !atEOF {
		var ret byte
		if !next() {
			if next() {
				ret = 1
				for i := 0; i < 6; i++ {
					ret <<= 1
					if next() {
						ret++
					}
				}
				if ret == 64 {
					ret = 1
				} else {
					ret = (ret << 1) & 0x7f
					if next() {
						ret++
					}
				}
			}
		} else {
			ret = 1
			for i := 0; i < 7; i++ {
				ret <<= 1
				if next() {
					ret++
				}
			}
		}
		out = append(out, ret)
		if padding {
			atEOF = true
		}
	}
	return out
}
