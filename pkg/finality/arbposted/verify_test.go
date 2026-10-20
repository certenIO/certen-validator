// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// ---- helpers: a nitro payload encoder (the inverse of the verifier's decode) ----------------------------------------------

func encodeBlobs(payload []byte) [][]byte {
	data, err := rlp.EncodeToBytes(payload)
	if err != nil {
		panic(err)
	}
	var blobs [][]byte
	for len(data) > 0 {
		blob := make([]byte, BlobBytes)
		for fe := 0; fe < fieldElements && len(data) > 0; fe++ {
			n := copy(blob[fe*32+1:fe*32+32], data)
			data = data[n:]
		}
		var acc uint16
		bits := 0
		for fe := 0; fe < fieldElements; fe++ {
			if bits < 6 && len(data) > 0 {
				acc |= uint16(data[0]) << bits
				bits += 8
				data = data[1:]
			}
			blob[fe*32] = byte(acc & 0x3f)
			acc >>= 6
			if bits >= 6 {
				bits -= 6
			} else {
				bits = 0
			}
		}
		blobs = append(blobs, blob)
	}
	return blobs
}

func brotliBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, 5)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func seg(kind byte, body []byte) []byte {
	out, _ := rlp.EncodeToBytes(append([]byte{kind}, body...))
	return out
}

// payloadOf builds a brotli payload (header byte 0x00) from segments.
func payloadOf(segs ...[]byte) []byte {
	return append([]byte{headerBrotli}, brotliBytes(bytes.Join(segs, nil))...)
}

func signedTxMsg(tx []byte) []byte { return append([]byte{l2SignedTx}, tx...) }

func batchMsg(msgs ...[]byte) []byte {
	out := []byte{l2Batch}
	for _, m := range msgs {
		out = binary.BigEndian.AppendUint64(out, uint64(len(m)))
		out = append(out, m...)
	}
	return out
}

// legacyTx is a syntactically plausible legacy transaction encoding (type 0): the verifier compares bytes.
func legacyTx(tag byte) []byte {
	b, _ := rlp.EncodeToBytes([]any{uint64(tag), big.NewInt(1), uint64(21000), make([]byte, 20), big.NewInt(0), []byte{tag}, big.NewInt(27), big.NewInt(1), big.NewInt(2)})
	return b
}

// ---- helpers: an in-memory Bridge state --------------------------------------------------------------------------------

type collector struct{ nodes [][]byte }

func (c *collector) Put(_ []byte, v []byte) error {
	c.nodes = append(c.nodes, append([]byte(nil), v...))
	return nil
}
func (c *collector) Delete([]byte) error { return nil }

func trimmedWord(w common.Hash) []byte {
	i := 0
	for i < 32 && w[i] == 0 {
		i++
	}
	b, _ := rlp.EncodeToBytes(w[i:])
	return b
}

var (
	testBridge   = common.HexToAddress("0x38f918D0E9F1b721EDaA41302E399fa1B79333a9")
	testImpl     = common.HexToAddress("0xed26e46f38957763f83f2c45f6fb6702cfebc7d8")
	testImplCode = crypto.Keccak256Hash([]byte("test bridge implementation code"))
)

// implWordOverride, when set, replaces the EIP-1967 implementation word the synthetic Bridge stores, and absentProve names accounts
// whose (exclusion) proof is added to the nodes. Only the identity tests below set them.
var (
	implWordOverride *common.Hash
	absentProve      []common.Address
	// skipProve names storage slots whose proof nodes are left out of the evidence
	skipProve []common.Hash
)

type synthState struct {
	root  common.Hash
	nodes [][]byte
	arb   *arbPins
}

// newSynthState holds a Bridge proxy (storage: the EIP-1967 slot, sequencerInboxAccs[n] and delayedInboxAccs[k]) and its
// implementation account with testImplCode, and returns the state root and the deduplicated union of the proofs.
func newSynthState(t *testing.T, acc map[uint64]common.Hash, delayed map[uint64]common.Hash) *synthState {
	t.Helper()
	arb := &arbPins{ChainID: finality.ChainArbitrumSepolia, ParentChainID: finality.ChainSepolia, bridge: testBridge, MaxBlobs: 16, MaxSegments: 102400, MaxUncompressedBatch: 16777216,
		Layout:    layoutPins{Name: "nitro-contracts-v3.1.0", AssertionsSlot: 117, AccArraySlot: 7, DelayedAccArraySlot: 6},
		LogicPins: map[string]string{"0x" + common.Bytes2Hex(testImplCode[:]): bridgeImplRole}}
	st := trie.NewEmpty(nil)
	put := func(slot common.Hash, v common.Hash) {
		if err := st.Update(crypto.Keccak256(slot[:]), trimmedWord(v)); err != nil {
			t.Fatal(err)
		}
	}
	var iv common.Hash
	copy(iv[12:], testImpl[:])
	if implWordOverride != nil {
		iv = *implWordOverride
	}
	put(eip1967ImplSlot, iv)
	var slots []common.Hash
	for n, v := range acc {
		s := arrayElementSlot(arb.Layout.AccArraySlot, n)
		put(s, v)
		slots = append(slots, s)
	}
	for k, v := range delayed {
		s := arrayElementSlot(arb.Layout.DelayedAccArraySlot, k)
		put(s, v)
		slots = append(slots, s)
	}
	slots = append(slots, eip1967ImplSlot)
	at := trie.NewEmpty(nil)
	mk := func(root common.Hash, code common.Hash) []byte {
		b, _ := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), root, code.Bytes()})
		return b
	}
	if err := at.Update(crypto.Keccak256(testBridge[:]), mk(st.Hash(), crypto.Keccak256Hash([]byte("proxy")))); err != nil {
		t.Fatal(err)
	}
	if err := at.Update(crypto.Keccak256(testImpl[:]), mk(crypto.Keccak256Hash(nil), testImplCode)); err != nil {
		t.Fatal(err)
	}
	var all [][]byte
	for _, addr := range append([]common.Address{testBridge, testImpl}, absentProve...) {
		var c collector
		if err := at.Prove(crypto.Keccak256(addr[:]), &c); err != nil {
			t.Fatal(err)
		}
		all = append(all, c.nodes...)
	}
	for _, s := range slots {
		skip := false
		for _, k := range skipProve {
			skip = skip || k == s
		}
		if skip {
			continue
		}
		var c collector
		if err := st.Prove(crypto.Keccak256(s[:]), &c); err != nil {
			t.Fatal(err)
		}
		all = append(all, c.nodes...)
	}
	return &synthState{root: at.Hash(), nodes: finality.EncodeNodes(all), arb: arb}
}

func (s *synthState) block() ethl1.L1Block {
	return ethl1.L1Block{Hash: crypto.Keccak256Hash([]byte("s")), Number: 1234, StateRoot: s.root, Timestamp: 1}
}

// l2Header is a minimal 15-item header whose transactionsRoot is the root of txs and whose nonce is nonce.
func l2Header(txs [][]byte, number uint64, nonce uint64) ([]byte, finality.HeaderFields) {
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	items := []any{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), make([]byte, 20), bytes.Repeat([]byte{3}, 32),
		ethproof.TrieRoot(txs).Bytes(), bytes.Repeat([]byte{4}, 32), make([]byte, 256), uint64(1), number, uint64(30000000),
		uint64(1), uint64(1700000000), []byte{}, bytes.Repeat([]byte{5}, 32), nb[:]}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	h, err := finality.ReadHeader(raw)
	if err != nil {
		panic(err)
	}
	return raw, h
}

func calldataEvidence(txs [][]byte, data []byte, n uint64, h40 [5]uint64, delayedAcc common.Hash) Evidence {
	e := Evidence{BlockTxs: txs, BatchSeq: n, Header40: h40, DelayedAcc: delayedAcc, DataKind: DataCalldata, Calldata: data}
	e.BeforeAcc = crypto.Keccak256Hash([]byte("before"))
	return e
}

func accOf(e Evidence) common.Hash {
	return common.Hash(Accumulator(e.BeforeAcc, DataHash(e), e.DelayedAcc))
}

// runState builds the state holding the evidence's accumulator and judges it with verifyState.
func runState(t *testing.T, e Evidence, delayed map[uint64]common.Hash, mutate func(*synthState)) (finality.Verdict, error) {
	t.Helper()
	st := newSynthState(t, map[uint64]common.Hash{e.BatchSeq: accOf(e)}, delayed)
	e.Nodes = st.nodes
	if mutate != nil {
		mutate(st)
	}
	hdrRLP, hdr := l2Header(e.BlockTxs, 400000000, 7)
	return New().verifyState(st.arb, st.block(), finality.BlockRef{Chain: 421614, Number: 400000000, Hash: hdr.Hash, HeaderRLP: hdrRLP}, hdr, e)
}

func canon(err error) string {
	if s, ok := finality.AsNamed(err); ok {
		return string(s.Canonical())
	}
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func want(code string, kv ...any) string { return string(finality.NewState(code, kv...).Canonical()) }

var h40 = [5]uint64{100, 200, 300, 400, 0}

// ---- blobs and payload ------------------------------------------------------------------------------------------------

func TestBlobDecodeIsTheInverseOfNitrosEncoding(t *testing.T) {
	for _, n := range []int{1, 31, 126976, 126977, 200000, 380000} {
		p := make([]byte, n)
		for i := range p {
			p[i] = byte(i*7 + 3)
		}
		blobs := encodeBlobs(p)
		got, err := decodeBlobs(blobs)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("payload of %d bytes over %d blobs: err %v equal %v", n, len(blobs), err, bytes.Equal(got, p))
		}
	}
	blobs := encodeBlobs([]byte("payload"))
	blobs[0][5000] = 1 // a non-zero byte in the zero padding after the payload
	if _, err := decodeBlobs(blobs); err == nil {
		t.Fatal("non-zero padding after the payload was accepted")
	}
	if _, err := decodeBlobs([][]byte{make([]byte, 10)}); err == nil {
		t.Fatal("a short blob was accepted")
	}
}

func TestPayloadHeaderBytesAndBounds(t *testing.T) {
	tx := legacyTx(1)
	good := payloadOf(seg(segL2Message, signedTxMsg(tx)))
	cases := []struct {
		name    string
		payload []byte
		status  payloadStatus
	}{
		{"das", append([]byte{headerDAS}, good[1:]...), payloadOffL1},
		{"das tree", append([]byte{headerDASTree}, good[1:]...), payloadOffL1},
		{"dacert", append([]byte{headerDACert}, good[1:]...), payloadOffL1},
		{"zeroheavy layer over a stream that is not a payload", append([]byte{headerZeroheavy}, good[1:]...), payloadUnknownHeader},
		{"unknown byte", append([]byte{0x05}, good[1:]...), payloadUnknownHeader},
		{"empty", nil, payloadUndecodable},
		{"not brotli", append([]byte{headerBrotli}, bytes.Repeat([]byte{0xff}, 40)...), payloadUndecodable},
		{"ok", good, payloadOK},
	}
	for _, c := range cases {
		if got := decodePayload(c.payload, 1<<20, 100); got.status != c.status {
			t.Errorf("%s: status %d, want %d", c.name, got.status, c.status)
		}
	}
	bomb := append([]byte{headerBrotli}, brotliBytes(bytes.Repeat([]byte{0}, 5<<20))...)
	if len(bomb) > 10000 {
		t.Fatalf("bomb is %d bytes", len(bomb))
	}
	if r := decodePayload(bomb, 1<<20, 100); r.status != payloadTooLarge || !r.exceededUncompressed {
		t.Fatalf("a brotli bomb over the bound: %+v", r)
	}
	if r := decodePayload(bomb, 8<<20, 10<<20); r.status != payloadOK || r.exceededUncompressed {
		t.Fatalf("a stream under the bound was refused: %+v", r)
	}
	var many [][]byte
	for i := 0; i < 11; i++ {
		many = append(many, seg(segAdvanceTime, []byte{1}))
	}
	r := decodePayload(payloadOf(many...), 1<<20, 10)
	if r.status != payloadTooLarge || !r.exceededSegments {
		t.Fatalf("11 segments under a bound of 10: %+v", r)
	}
	if r := decodePayload(payloadOf(many[:10]...), 1<<20, 10); r.status != payloadOK || r.segments != 10 {
		t.Fatalf("exactly the bound must be accepted: %+v", r)
	}
}

func TestSegmentsAndMessages(t *testing.T) {
	a, b, c := legacyTx(1), legacyTx(2), legacyTx(3)
	compressed := brotliBytes(signedTxMsg(c))
	r := decodePayload(payloadOf(
		seg(segAdvanceTime, []byte{9}),
		seg(segL2Message, signedTxMsg(a)),
		seg(segDelayed, nil),
		seg(segL2Message, batchMsg(signedTxMsg(a), signedTxMsg(b))),
		seg(segL2MessageBrotli, compressed),
		seg(segAdvanceL1Block, []byte{1}),
		seg(segL2Message, []byte{0, 1, 2}), // an unsigned user tx: no signed transactions
	), 1<<20, 100)
	if r.status != payloadOK || r.segments != 7 || r.delayedSegments != 1 || len(r.messages) != 4 {
		t.Fatalf("decode: %+v", r)
	}
	if !sameTxs(r.messages[0].txs, [][]byte{a}) || !sameTxs(r.messages[1].txs, [][]byte{a, b}) || !sameTxs(r.messages[2].txs, [][]byte{c}) || len(r.messages[3].txs) != 0 {
		t.Fatal("message transactions are wrong")
	}
	if r.messages[2].ordinal != 2 {
		t.Fatalf("ordinal %d", r.messages[2].ordinal)
	}
	// nesting depth 16 is the limit
	nested := signedTxMsg(a)
	for i := 0; i < 16; i++ {
		nested = batchMsg(nested)
	}
	if got, ok := parseL2(nested, 0); !ok || len(got) != 1 {
		t.Fatalf("16 nested batches: ok %v, %d txs", ok, len(got))
	}
	if got, ok := parseL2(batchMsg(nested), 0); ok || len(got) != 0 {
		t.Fatalf("a 17th nested batch must fail the whole message: ok %v, %d txs", ok, len(got))
	}
	// an oversize or overrunning nested length ends the batch quietly: the message is valid and empty
	over := append([]byte{l2Batch}, binary.BigEndian.AppendUint64(nil, 1<<40)...)
	if got, ok := parseL2(over, 0); !ok || len(got) != 0 {
		t.Fatalf("an oversize nested length: ok %v, %d txs", ok, len(got))
	}
	// an empty signed message, an empty message and a missing kind fail the message
	for _, m := range [][]byte{{l2SignedTx}, nil} {
		if got, ok := parseL2(m, 0); ok || len(got) != 0 {
			t.Fatalf("message %x: ok %v, %d txs", m, ok, len(got))
		}
	}
}

// ---- the judgement under a synthetic Bridge state ------------------------------------------------------------------------

func TestCalldataBatchIsJudgedLikeABlobBatch(t *testing.T) {
	a, b := legacyTx(1), legacyTx(2)
	txs := [][]byte{{0x6a, 0xc0}, a, b}
	data := payloadOf(seg(segL2Message, signedTxMsg(legacyTx(9))), seg(segL2Message, batchMsg(signedTxMsg(a), signedTxMsg(b))))
	e := calldataEvidence(txs, data, 55, h40, common.Hash{})
	v, err := runState(t, e, nil, nil)
	if err != nil {
		t.Fatalf("calldata batch: %v", err)
	}
	if v.Fields["message_ordinal"] != uint64(1) || v.Fields["batch_sequence_number"] != uint64(55) || v.Fields["blobs"] != uint64(0) {
		t.Fatalf("fields %v", v.Fields)
	}
	// the same batch, but the leg's transactions are reordered
	e.BlockTxs = [][]byte{{0x6a, 0xc0}, b, a}
	if _, err := runState(t, e, nil, nil); canon(err) != want("l1_posted_content_not_found", "reason", "no_matching_message", "batch", uint64(55), "messages_scanned", uint64(2), "segments", uint64(2)) {
		t.Fatalf("reordered: %s", canon(err))
	}
	for _, tc := range []struct {
		flag byte
		want string
	}{
		{headerDAS, want("l1_batch_data_off_l1", "batch", uint64(55), "header_byte", uint8(headerDAS))},
		{headerDASTree, want("l1_batch_data_off_l1", "batch", uint64(55), "header_byte", uint8(headerDASTree))},
	} {
		c := calldataEvidence(txs, append([]byte{tc.flag}, data[1:]...), 55, h40, common.Hash{})
		if _, err := runState(t, c, nil, nil); canon(err) != tc.want {
			t.Errorf("flag %#x: %s", tc.flag, canon(err))
		}
	}
	for _, flag := range []byte{0x05, headerDACert} {
		c := calldataEvidence(txs, append([]byte{flag}, data[1:]...), 55, h40, common.Hash{})
		if _, err := runState(t, c, nil, nil); canon(err) != want("l1_batch_header_unknown", "batch", uint64(55), "byte", flag) {
			t.Errorf("flag %#x is not a valid calldata flag: %s", flag, canon(err))
		}
	}
	empty := calldataEvidence(txs, nil, 55, h40, common.Hash{})
	if _, err := runState(t, empty, nil, nil); canon(err) != want("l1_batch_header_unknown", "batch", uint64(55)) {
		t.Errorf("empty calldata: %s", canon(err))
	}
}

func TestAccumulatorIdentityAndProofFailures(t *testing.T) {
	a := legacyTx(1)
	txs := [][]byte{{0x6a, 0xc0}, a}
	data := payloadOf(seg(segL2Message, signedTxMsg(a)))
	good := calldataEvidence(txs, data, 9, h40, common.Hash{})
	if _, err := runState(t, good, nil, nil); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"header40", func(e *Evidence) { e.Header40[3]++ }},
		{"beforeAcc", func(e *Evidence) { e.BeforeAcc[1] ^= 1 }},
		{"delayedAcc", func(e *Evidence) { e.DelayedAcc[1] ^= 1 }},
		{"data byte", func(e *Evidence) { e.Calldata = append(append([]byte(nil), e.Calldata...), 0) }},
	}
	for _, c := range cases {
		e := good
		st := newSynthState(t, map[uint64]common.Hash{9: accOf(good)}, nil)
		c.mutate(&e)
		e.Nodes = st.nodes
		hdrRLP, hdr := l2Header(e.BlockTxs, 400000000, 7)
		_, err := New().verifyState(st.arb, st.block(), finality.BlockRef{HeaderRLP: hdrRLP}, hdr, e)
		if canon(err) != want("l1_posted_content_not_found", "reason", "accumulator_mismatch", "batch", uint64(9)) {
			t.Errorf("%s: %s", c.name, canon(err))
		}
	}
	// the implementation is not pinned
	if _, err := runState(t, good, nil, func(s *synthState) { s.arb.LogicPins = map[string]string{} }); canon(err) !=
		want("contract_identity_unproven", "role", "bridge_impl", "address", testImpl[:], "code_hash", testImplCode[:], "judged_at", uint64(1234)) {
		t.Errorf("unpinned implementation: %s", canon(err))
	}
	// pinned under another role
	if _, err := runState(t, good, nil, func(s *synthState) {
		s.arb.LogicPins = map[string]string{"0x" + common.Bytes2Hex(testImplCode[:]): "rollup_admin_logic"}
	}); err == nil {
		t.Error("a code hash pinned under another role was accepted as the Bridge implementation")
	}
	// another bridge address in the pins: no account
	if _, err := runState(t, good, nil, func(s *synthState) { s.arb.bridge = common.HexToAddress("0x01") }); canon(err) !=
		want("contract_identity_unproven", "role", "bridge_impl", "address", common.HexToAddress("0x01").Bytes(), "code_hash", make([]byte, 32), "judged_at", uint64(1234)) {
		t.Errorf("absent bridge: %s", canon(err))
	}
	// a different state root: the account proof does not resolve
	e := good
	st := newSynthState(t, map[uint64]common.Hash{9: accOf(good)}, nil)
	e.Nodes = st.nodes
	hdrRLP, hdr := l2Header(e.BlockTxs, 400000000, 7)
	blk := st.block()
	blk.StateRoot = crypto.Keccak256Hash([]byte("other"))
	if _, err := New().verifyState(st.arb, blk, finality.BlockRef{HeaderRLP: hdrRLP}, hdr, e); canon(err) != want("l1_state_proof_invalid", "which", "account") {
		t.Errorf("wrong root: %s", canon(err))
	}
	// the batch number selects a slot the state does not hold: it reads as zero and is no accumulator
	g2 := good
	g2.BatchSeq = 10
	g2.Nodes = st.nodes
	if _, err := New().verifyState(st.arb, st.block(), finality.BlockRef{HeaderRLP: hdrRLP}, hdr, g2); canon(err) != want("l1_posted_content_not_found", "reason", "accumulator_mismatch", "batch", uint64(10)) {
		t.Errorf("an unset slot: %s", canon(err))
	}
	// the nodes of the Bridge storage are missing: the slot cannot be read
	g3 := good
	g3.Nodes = nil
	if _, err := New().verifyState(st.arb, st.block(), finality.BlockRef{HeaderRLP: hdrRLP}, hdr, g3); canon(err) != want("l1_state_proof_invalid", "which", "account") {
		t.Errorf("no nodes: %s", canon(err))
	}
}

func TestBlockClassification(t *testing.T) {
	a := legacyTx(1)
	data := payloadOf(seg(segL2Message, signedTxMsg(a)))
	for _, c := range []struct {
		name string
		txs  [][]byte
		want string
	}{
		{"unsupported type", [][]byte{{0x6b, 0xc0}, a}, want("l1_posted_content_not_found", "reason", "unsupported_tx_type", "batch", uint64(9), "tx_type", uint64(0x6b))},
		{"only the internal tx", [][]byte{{0x6a, 0xc0}}, want("l1_posted_content_not_found", "reason", "no_standard_transactions", "batch", uint64(9))},
		{"no transactions", nil, want("l1_posted_content_not_found", "reason", "no_standard_transactions", "batch", uint64(9))},
		{"retry txs are tolerated", [][]byte{{0x6a, 0xc0}, a, {0x68, 0xc0}}, "ok"},
		{"delayed origin without section", [][]byte{{0x6a, 0xc0}, {0x65, 0xc0}, a}, want("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0x65, 0}, "header_nonce", uint64(7))},
	} {
		e := calldataEvidence(c.txs, data, 9, h40, common.Hash{})
		_, err := runState(t, e, nil, nil)
		if canon(err) != c.want {
			t.Errorf("%s: %s", c.name, canon(err))
		}
	}
}

func TestDelayedOriginDeposit(t *testing.T) {
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	value := big.NewInt(12345)
	data := append(append([]byte(nil), to[:]...), common.LeftPadBytes(value.Bytes(), 32)...)
	k := uint64(41)
	msg := Delayed{MsgKind: msgKindEthDeposit, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: data, K: k}
	msg.BaseFeeL1[31] = 9
	prev := crypto.Keccak256Hash([]byte("prev"))
	mh := DelayedMessageHash(msg)
	accK := crypto.Keccak256Hash(prev[:], mh[:])
	dep, _ := rlp.EncodeToBytes(depositTx{ChainID: big.NewInt(421614), RequestID: w32(k), From: user, To: to, Value: value})
	depTx := append([]byte{txDeposit}, dep...)
	txs := [][]byte{{0x6a, 0xc0}, depTx}
	// the batch consumed delayed messages k-1..k (2 delayed segments), afterDelayedMessagesRead = k+1
	pl := payloadOf(seg(segDelayed, nil), seg(segDelayed, nil), seg(segAdvanceTime, []byte{1}))
	h := [5]uint64{100, 200, 300, 400, k + 1}
	mk := func() Evidence {
		e := calldataEvidence(txs, pl, 3, h, accK)
		e.Delayed = &Delayed{MsgKind: msg.MsgKind, Sender: msg.Sender, MsgBlockNumber: msg.MsgBlockNumber, MsgTimestamp: msg.MsgTimestamp, BaseFeeL1: msg.BaseFeeL1, Data: msg.Data, K: k}
		return e
	}
	dm := map[uint64]common.Hash{k: accK, k - 1: prev}
	v, err := runState(t, mk(), dm, nil)
	if err != nil {
		t.Fatalf("delayed deposit: %v", err)
	}
	if v.Fields["delayed_message_index"] != k {
		t.Fatalf("fields %v", v.Fields)
	}
	if _, has := v.Fields["message_ordinal"]; has {
		t.Fatal("a delayed-only block has no message ordinal")
	}
	unproven := func(kk uint64, kind uint8) string {
		return want("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0x64}, "header_nonce", uint64(7), "k", kk, "message_kind", kind)
	}
	t.Run("message altered", func(t *testing.T) {
		e := mk()
		e.Delayed.MsgTimestamp++
		if _, err := runState(t, e, dm, nil); canon(err) != unproven(k, 12) {
			t.Fatal(canon(err))
		}
	})
	t.Run("k outside the consumed range", func(t *testing.T) {
		e := mk()
		e.Header40[4] = k // the batch read up to k-1 only
		if _, err := runState(t, e, dm, nil); canon(err) != unproven(k, 12) {
			t.Fatal(canon(err))
		}
		e = mk()
		e.Header40[4] = k + 3
		if _, err := runState(t, e, dm, nil); canon(err) != unproven(k, 12) {
			t.Fatal(canon(err))
		}
	})
	t.Run("deposit fields differ from the message", func(t *testing.T) {
		for _, v := range []depositTx{
			{ChainID: big.NewInt(421614), RequestID: w32(k + 1), From: user, To: to, Value: value},
			{ChainID: big.NewInt(421614), RequestID: w32(k), From: to, To: to, Value: value},
			{ChainID: big.NewInt(421614), RequestID: w32(k), From: user, To: user, Value: value},
			{ChainID: big.NewInt(421614), RequestID: w32(k), From: user, To: to, Value: big.NewInt(1)},
		} {
			raw, _ := rlp.EncodeToBytes(v)
			e := mk()
			e.BlockTxs = [][]byte{{0x6a, 0xc0}, append([]byte{txDeposit}, raw...)}
			if _, err := runState(t, e, dm, nil); canon(err) != unproven(k, 12) {
				t.Fatalf("%+v: %s", v, canon(err))
			}
		}
	})
	t.Run("accumulator chain does not hold", func(t *testing.T) {
		bad := map[uint64]common.Hash{k: accK, k - 1: crypto.Keccak256Hash([]byte("other"))}
		if _, err := runState(t, mk(), bad, nil); canon(err) != unproven(k, 12) {
			t.Fatal(canon(err))
		}
	})
	t.Run("a delayed kind without a derivation stays unproven", func(t *testing.T) {
		e := mk()
		e.BlockTxs = [][]byte{{0x6a, 0xc0}, {0x69, 0xc0}}
		e.Delayed.MsgKind = 9
		m := *e.Delayed
		m9 := DelayedMessageHash(m)
		acc9 := crypto.Keccak256Hash(prev[:], m9[:])
		e.DelayedAcc = acc9
		got := want("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0x69}, "header_nonce", uint64(7), "k", k, "message_kind", uint8(9))
		if _, err := runState(t, e, map[uint64]common.Hash{k: acc9, k - 1: prev}, nil); canon(err) != got {
			t.Fatal(canon(err))
		}
	})
	t.Run("k = 0 has no predecessor", func(t *testing.T) {
		m0 := msg
		m0.K = 0
		mh0 := DelayedMessageHash(m0)
		acc0 := crypto.Keccak256Hash(make([]byte, 32), mh0[:])
		dep0, _ := rlp.EncodeToBytes(depositTx{ChainID: big.NewInt(421614), RequestID: w32(0), From: user, To: to, Value: value})
		e := calldataEvidence([][]byte{{0x6a, 0xc0}, append([]byte{txDeposit}, dep0...)}, payloadOf(seg(segDelayed, nil)), 3, [5]uint64{1, 2, 3, 4, 1}, acc0)
		e.Delayed = &Delayed{MsgKind: m0.MsgKind, Sender: m0.Sender, MsgBlockNumber: m0.MsgBlockNumber, MsgTimestamp: m0.MsgTimestamp, BaseFeeL1: m0.BaseFeeL1, Data: m0.Data, K: 0}
		if _, err := runState(t, e, map[uint64]common.Hash{0: acc0}, nil); err != nil {
			t.Fatal(err)
		}
	})
}

// ---- the container ------------------------------------------------------------------------------------------------------

func TestContainerRoundTripAndStrictness(t *testing.T) {
	e := Evidence{LC: ethl1.LC{Profile: ethl1.ProfileLC, AnchorKind: 1, AnchorPeriod: 5, AnchorBody: ethl1.LB{SSZ: []byte{1, 2}}, Links: []ethl1.LB{{Layout: ethl1.LayoutGloas, SSZ: []byte{3}}}, FinalUpdate: ethl1.LB{Layout: ethl1.LayoutGloas, SSZ: []byte{4}}},
		L1Spine: [][]byte{{1}, {2}}, StateBlock: 7, BlockTxs: [][]byte{{5}, {6}}, BatchSeq: 8, Header40: [5]uint64{1, 2, 3, 4, 5}, DataKind: DataCalldata, Calldata: []byte{9, 9},
		Delayed: &Delayed{MsgKind: 12, K: 3, Data: []byte{1}}, Nodes: [][]byte{{0xc0}, {0xc1, 0x80}, {0xc2, 0x80, 0x80}}}
	b := DefaultBounds()
	body := e.Encode()
	got, err := Decode(body, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), body) {
		t.Fatal("encode(decode(x)) != x")
	}
	for i := 0; i < len(body); i++ {
		if _, err := Decode(body[:i], b); err == nil {
			t.Fatalf("a body truncated to %d bytes decoded", i)
		}
	}
	if _, err := Decode(append(append([]byte(nil), body...), 0), b); canon(err) != want("finality_evidence_malformed", "part", "body", "reason", "trailing_bytes", "got_len", uint64(1), "want_len", uint64(0)) {
		t.Fatalf("trailing: %s", canon(err))
	}
	// bounds
	tight := b
	tight.MaxBlockTxs = 1
	if _, err := Decode(body, tight); canon(err) != want("finality_evidence_too_large", "part", "blockTxs", "count", uint64(2), "limit", uint64(1)) {
		t.Fatalf("blockTxs bound: %s", canon(err))
	}
	tight = b
	tight.MaxSpineHeaders = 1
	if _, err := Decode(body, tight); canon(err) != want("finality_evidence_too_large", "part", "l1Spine", "count", uint64(2), "limit", uint64(1)) {
		t.Fatalf("spine bound: %s", canon(err))
	}
	tight = b
	tight.MaxLinks = 0
	if _, err := Decode(body, tight); canon(err) != want("finality_evidence_too_large", "part", "lc.links", "count", uint64(1), "limit", uint64(0)) {
		t.Fatalf("links bound: %s", canon(err))
	}
	tight = b
	tight.MaxNodes = 2
	if _, err := Decode(body, tight); canon(err) != want("finality_evidence_too_large", "part", "nodes", "count", uint64(3), "limit", uint64(2)) {
		t.Fatalf("nodes bound: %s", canon(err))
	}
	// blobs: count mismatch and sizes
	e2 := e
	e2.DataKind, e2.Calldata, e2.VersionedHashes, e2.Blobs = DataBlobs, nil, [][32]byte{{1}, {2}, {3}}, nil
	tight = b
	tight.MaxBlobs = 2
	if _, err := Decode(e2.Encode(), tight); canon(err) != want("finality_evidence_too_large", "part", "versionedHashes", "count", uint64(3), "limit", uint64(2)) {
		t.Fatalf("blob bound: %s", canon(err))
	}
	e3 := e
	e3.DataKind, e3.Calldata, e3.Blobs = DataBlobs, nil, []Blob{{Raw: make([]byte, 10)}}
	e3.Nodes = [][]byte{make([]byte, 140000)}
	if _, err := Decode(e3.Encode(), b); canon(err) != want("finality_evidence_malformed", "part", "blobs.raw", "reason", "truncated", "got_len", uint64(10), "want_len", uint64(BlobBytes), "index", uint64(0)) {
		t.Fatalf("short blob: %s", canon(err))
	}
	// enum values
	e4 := e
	e4.DataKind = 9
	if _, err := Decode(e4.Encode(), b); canon(err) != want("finality_evidence_malformed", "part", "dataKind", "reason", "bad_enum_value", "got_len", uint64(9), "want_len", uint64(3)) {
		t.Fatalf("dataKind: %s", canon(err))
	}
	e5 := e
	e5.DataKind, e5.Calldata = DataNone, nil
	if got, err := Decode(e5.Encode(), b); err != nil || got.DataKind != DataNone {
		t.Fatalf("dataKind 3: %v", err)
	}
}

func TestNoDataBatchIsANamedContentState(t *testing.T) {
	a := legacyTx(1)
	txs := [][]byte{{0x6a, 0xc0}, a}
	e := Evidence{BlockTxs: txs, BatchSeq: 4, DataKind: DataNone}
	hdrRLP, hdr := l2Header(txs, 400000000, 7)
	_, err := New().verifyBody(&arbPins{}, ethl1.Pins{}, finality.BlockRef{HeaderRLP: hdrRLP}, hdr, e)
	if canon(err) != want("l1_posted_content_not_found", "reason", "no_data_batch", "batch", uint64(4)) {
		t.Fatalf("%s", canon(err))
	}
	e.BlockTxs = [][]byte{a}
	if _, err := New().verifyBody(&arbPins{}, ethl1.Pins{}, finality.BlockRef{HeaderRLP: hdrRLP}, hdr, e); canon(err) != want("l1_posted_content_not_found", "reason", "block_txs_root_mismatch", "batch", uint64(4)) {
		t.Fatalf("root: %s", canon(err))
	}
}

// The implementation word and the implementation account are judged, not just its code hash: a word with non-zero high bytes is
// not an address, and an absent account has no code even when the pins (wrongly) pin the zero hash.
func TestTheBridgeImplementationWordAndAccountAreJudged(t *testing.T) {
	a := legacyTx(1)
	txs := [][]byte{{0x6a, 0xc0}, a}
	good := calldataEvidence(txs, payloadOf(seg(segL2Message, signedTxMsg(a))), 9, h40, common.Hash{})
	defer func() { implWordOverride, absentProve = nil, nil }()

	var high common.Hash
	copy(high[12:], testImpl[:])
	high[0] = 1
	implWordOverride = &high
	_, err := runState(t, good, nil, nil)
	if canon(err) != want("contract_identity_unproven", "role", "bridge_impl", "address", testImpl[:], "code_hash", testImplCode[:], "judged_at", uint64(1234)) {
		t.Fatalf("a word with non-zero high bytes: %s", canon(err))
	}

	absent := common.HexToAddress("0x00000000000000000000000000000000000000ab")
	var w common.Hash
	copy(w[12:], absent[:])
	implWordOverride, absentProve = &w, []common.Address{absent}
	_, err = runState(t, good, nil, func(s *synthState) {
		s.arb.LogicPins = map[string]string{"0x" + common.Bytes2Hex(make([]byte, 32)): bridgeImplRole}
	})
	if canon(err) != want("contract_identity_unproven", "role", "bridge_impl", "address", absent[:], "code_hash", make([]byte, 32), "judged_at", uint64(1234)) {
		t.Fatalf("an absent implementation account whose zero hash is pinned: %s", canon(err))
	}
}
