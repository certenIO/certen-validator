// Copyright 2026 Certen Protocol

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/andybalholm/brotli"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// The synthetic cases cover what no live batch reaches: a calldata-mode batch, a delayed-origin block, the DAS / DACert payload
// bytes and the two decompression bounds. The L1 side is synthetic: a four-key test committee (secret scalars derived from fixed
// labels at generation time, never stored) signs a Gloas finality update whose finalized execution hash is a synthetic header
// whose state root commits to a synthetic Bridge. The vectors carry only public keys, roots and signatures. Method as in
// finalityethl1record/synth.go (finality_ethl1_v1).
const (
	synthDST    = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
	synthPeriod = 10
	synthGloasE = 2570
	committeeSz = 24624
)

func sum(label string) [32]byte {
	return sha256.Sum256([]byte("finality_arb_posted1/synthetic/" + label))
}

type synthKeys struct {
	sk [4]*big.Int
	pk [4][48]byte
}

func newSynthKeys() synthKeys {
	var k synthKeys
	for i := range k.sk {
		h := sum("key/" + strconv.Itoa(i))
		var e fr.Element
		e.SetBytes(h[:])
		k.sk[i] = e.BigInt(new(big.Int))
		var p bls12381.G1Affine
		p.ScalarMultiplicationBase(k.sk[i])
		k.pk[i] = p.Bytes()
	}
	return k
}

func (k synthKeys) committee512() []byte {
	b := make([]byte, 0, committeeSz)
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

func (k synthKeys) sign(msg [32]byte, n int) [96]byte {
	total := new(big.Int)
	for i := 0; i < n; i++ {
		total.Add(total, k.sk[i%4])
	}
	h, err := bls12381.HashToG2(msg[:], []byte(synthDST))
	if err != nil {
		panic(err)
	}
	var s bls12381.G2Affine
	s.ScalarMultiplication(&h, total)
	return s.Bytes()
}

func beaconBytes(slot uint64, parent, state, body [32]byte) []byte {
	b := make([]byte, 112)
	binary.LittleEndian.PutUint64(b[0:8], slot)
	binary.LittleEndian.PutUint64(b[8:16], 7)
	copy(b[16:48], parent[:])
	copy(b[48:80], state[:])
	copy(b[80:112], body[:])
	return b
}

func lcHeaderBytes(beacon []byte, exec [32]byte, branch [][32]byte) []byte {
	b := append([]byte(nil), beacon...)
	b = append(b, exec[:]...)
	for _, n := range branch {
		b = append(b, n[:]...)
	}
	return b
}

func nodesOf(label string, n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sum(label + "/" + strconv.Itoa(i))
	}
	return out
}

// finalUpdate builds a Gloas finality update whose finalized execution hash is exec, signed by all 512 seats under version.
func (k synthKeys) finalUpdate(exec [32]byte, version [4]byte, gvr [32]byte) []byte {
	attSlot, finSlot, sigSlot := uint64((synthGloasE+2)*32+5), uint64((synthGloasE+1)*32), uint64((synthGloasE+2)*32+6)
	fbranch := nodesOf("fbranch", 11)
	fbody := ethl1.RootFromNormalizedBranch(exec, fbranch, 2856)
	fbeacon := beaconBytes(finSlot, sum("fparent"), sum("fstate"), fbody)
	froot, _ := ethl1.HashTreeRootBeaconBlockHeader(fbeacon)
	finBranch := nodesOf("finbranch", 9)
	state := ethl1.RootFromNormalizedBranch(froot, finBranch, 735)
	aexec := sum("attested-exec")
	abranch := nodesOf("abranch", 11)
	abody := ethl1.RootFromNormalizedBranch(aexec, abranch, 2856)
	abeacon := beaconBytes(attSlot, sum("aparent"), state, abody)
	msg, err := ethl1.SyncCommitteeSigningRoot(abeacon, version, gvr)
	if err != nil {
		panic(err)
	}
	sig := k.sign(msg, 512)
	out := lcHeaderBytes(abeacon, aexec, abranch)
	out = append(out, lcHeaderBytes(fbeacon, exec, fbranch)...)
	for _, n := range finBranch {
		out = append(out, n[:]...)
	}
	bits := make([]byte, 64)
	for i := 0; i < 512; i++ {
		bits[i/8] |= 1 << (uint(i) % 8)
	}
	out = append(out, bits...)
	out = append(out, sig[:]...)
	return binary.LittleEndian.AppendUint64(out, sigSlot)
}

// ---- the synthetic L1: a Bridge state and one header over it ------------------------------------------------------------

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

func w32(v uint64) common.Hash {
	var h common.Hash
	binary.BigEndian.PutUint64(h[24:], v)
	return h
}

func arrayElementSlot(base, n uint64) common.Hash {
	b := new(big.Int).SetBytes(crypto.Keccak256(w32(base).Bytes()))
	b.Add(b, new(big.Int).SetUint64(n))
	return common.BigToHash(b)
}

var (
	bridgeAddr   = common.HexToAddress("0x38f918D0E9F1b721EDaA41302E399fa1B79333a9")
	bridgeImpl   = common.HexToAddress("0xed26e46f38957763f83f2c45f6fb6702cfebc7d8")
	bridgeImplCH = common.HexToHash("0x3bd9637547d75e5b4539449e14c759b86b9d37a7c1f2b47a1524f857e4ff1a0c")
	implSlot     = common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
)

// synthL1 returns a state root over a Bridge whose storage holds the accumulators, the proof nodes for them, and the one-header
// spine whose state root it is.
func synthL1(acc map[uint64]common.Hash, delayed map[uint64]common.Hash, number uint64) (spine [][]byte, nodes [][]byte) {
	st := trie.NewEmpty(nil)
	put := func(slot, v common.Hash) {
		if err := st.Update(crypto.Keccak256(slot[:]), trimmedWord(v)); err != nil {
			panic(err)
		}
	}
	var iv common.Hash
	copy(iv[12:], bridgeImpl[:])
	put(implSlot, iv)
	slots := []common.Hash{implSlot}
	for n, v := range acc {
		s := arrayElementSlot(7, n)
		put(s, v)
		slots = append(slots, s)
	}
	for k, v := range delayed {
		s := arrayElementSlot(6, k)
		put(s, v)
		slots = append(slots, s)
	}
	at := trie.NewEmpty(nil)
	mk := func(root, code common.Hash) []byte {
		b, _ := rlp.EncodeToBytes([]any{uint64(1), big.NewInt(0), root, code.Bytes()})
		return b
	}
	if err := at.Update(crypto.Keccak256(bridgeAddr[:]), mk(st.Hash(), crypto.Keccak256Hash([]byte("synthetic proxy")))); err != nil {
		panic(err)
	}
	if err := at.Update(crypto.Keccak256(bridgeImpl[:]), mk(crypto.Keccak256Hash(nil), bridgeImplCH)); err != nil {
		panic(err)
	}
	var all [][]byte
	for _, a := range []common.Address{bridgeAddr, bridgeImpl} {
		var c collector
		if err := at.Prove(crypto.Keccak256(a[:]), &c); err != nil {
			panic(err)
		}
		all = append(all, c.nodes...)
	}
	for _, s := range slots {
		var c collector
		if err := st.Prove(crypto.Keccak256(s[:]), &c); err != nil {
			panic(err)
		}
		all = append(all, c.nodes...)
	}
	items := []any{bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), make([]byte, 20), at.Hash().Bytes(), bytes.Repeat([]byte{0x44}, 32),
		bytes.Repeat([]byte{0x55}, 32), make([]byte, 256), uint64(0), number, uint64(30000000), uint64(1), uint64(1790000000), []byte("synthetic"),
		bytes.Repeat([]byte{0x66}, 32), make([]byte, 8)}
	raw, err := rlp.EncodeToBytes(items)
	if err != nil {
		panic(err)
	}
	return [][]byte{raw}, finality.EncodeNodes(all)
}

// ---- payload encoders -------------------------------------------------------------------------------------------------

func brotliBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriterLevel(&buf, 5)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func segment(kind byte, body []byte) []byte {
	out, _ := rlp.EncodeToBytes(append([]byte{kind}, body...))
	return out
}

func payloadOf(segs ...[]byte) []byte {
	return append([]byte{0x00}, brotliBytes(bytes.Join(segs, nil))...)
}

func signedMsg(tx []byte) []byte { return append([]byte{4}, tx...) }

func batchMsg(msgs ...[]byte) []byte {
	out := []byte{3}
	for _, m := range msgs {
		out = binary.BigEndian.AppendUint64(out, uint64(len(m)))
		out = append(out, m...)
	}
	return out
}

// encodeBlobs is nitro's EncodeBlobs: RLP string, 31 bytes per field element, then the packed 6-bit groups.
func encodeBlobs(payload []byte) [][]byte {
	data, _ := rlp.EncodeToBytes(payload)
	var blobs [][]byte
	for len(data) > 0 {
		blob := make([]byte, arbposted.BlobBytes)
		for fe := 0; fe < 4096 && len(data) > 0; fe++ {
			n := copy(blob[fe*32+1:fe*32+32], data)
			data = data[n:]
		}
		var acc uint16
		bits := 0
		for fe := 0; fe < 4096; fe++ {
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

func blobsFor(payload []byte) ([]arbposted.Blob, [][32]byte) {
	var out []arbposted.Blob
	var vh [][32]byte
	for _, raw := range encodeBlobs(payload) {
		var kb kzg4844.Blob
		copy(kb[:], raw)
		c, err := kzg4844.BlobToCommitment(&kb)
		if err != nil {
			panic(err)
		}
		p, err := kzg4844.ComputeBlobProof(&kb, c)
		if err != nil {
			panic(err)
		}
		out = append(out, arbposted.Blob{Raw: raw, Commitment: [48]byte(c), Proof: [48]byte(p)})
		vh = append(vh, kzg4844.CalcBlobHashV1(sha256.New(), &c))
	}
	return out, vh
}

// ---- the synthetic cases ----------------------------------------------------------------------------------------------

// synthPins is the embedded pins with a synthetic Sepolia network section: one fork schedule, the 4-key committee as the ledger
// entry of period 10, the participation floor unchanged.
func synthPins(b *builder, committee []byte, gvr [32]byte) error {
	root, err := ethl1.HashTreeRootSyncCommittee(committee)
	if err != nil {
		return err
	}
	return b.addPins("synth", func(d map[string]any) {
		e := d["eth_sepolia"].(map[string]any)
		e["genesis_validators_root"] = "0x" + hex.EncodeToString(gvr[:])
		gl := "gloas"
		e["forks"] = []any{
			map[string]any{"name": "genesis", "epoch": json.Number("0"), "version": "0x900000a0", "layout": nil},
			map[string]any{"name": "gloas", "epoch": json.Number(strconv.Itoa(synthGloasE)), "version": "0x900000a1", "layout": gl},
		}
		e["anchors"] = []any{map[string]any{"period": json.Number(strconv.Itoa(synthPeriod)), "committee_root": "0x" + hex.EncodeToString(root[:]),
			"wsp_epochs": json.Number(strconv.Itoa(wspEpochs)), "link_sha256": hex.EncodeToString(root[:]), "derived_by": []any{"synthetic 4-key test committee"}}}
	})
}

type synthCase struct {
	id, desc, pins string
	leg            legFile
	ev             []byte
	want           string
}

// synthCases builds every synthetic case over the live leg block's header (its transactions root recomputed per case).
func (b *builder) synthCases(txs [][]byte) ([]synthCase, error) {
	k := newSynthKeys()
	committee := k.committee512()
	gvr := sum("gvr")
	if err := synthPins(b, committee, gvr); err != nil {
		return nil, err
	}
	croot, _ := ethl1.HashTreeRootSyncCommittee(committee)
	var version [4]byte
	copy(version[:], []byte{0x90, 0, 0, 0xa1})
	const l1Number = uint64(7000000)
	const N = uint64(77)

	std := []int{}
	for i, t := range txs {
		if ethproof.TxType(t) <= 4 {
			std = append(std, i)
		}
	}
	if len(std) == 0 {
		return nil, fmt.Errorf("the live block has no standard transaction")
	}
	var stdTxs [][]byte
	for _, i := range std {
		stdTxs = append(stdTxs, txs[i])
	}
	// one message holding exactly the block's standard transactions, among others
	var msgs [][]byte
	for _, t := range stdTxs {
		msgs = append(msgs, signedMsg(t))
	}
	message := batchMsg(msgs...)
	if len(stdTxs) == 1 {
		message = signedMsg(stdTxs[0])
	}
	other := signedMsg([]byte{0xc0})
	payloadWith := func(header byte) []byte {
		p := payloadOf(segment(0, other), segment(0, message), segment(3, []byte{1}))
		p[0] = header
		return p
	}
	var cases []synthCase
	legOf := func(txsOf [][]byte) legFile { return legWith(b.baseLeg, b.legHdr, txsOf) }
	h40 := [5]uint64{1790000000, 1790000100, 7000000, 7000100, 0}
	before := crypto.Keccak256Hash([]byte("synthetic before"))

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
		hdr := finality.ContainerHeader{Kind: arbposted.KindName, Chain: 421614, Level: finality.LevelL1Posted, BlockNumber: num, BlockHash: h}
		return containerBytes(hdr, e.Encode()), exec
	}
	calldataEv := func(data []byte, txsOf [][]byte, seq uint64) arbposted.Evidence {
		return arbposted.Evidence{BlockTxs: txsOf, BatchSeq: seq, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataCalldata, Calldata: data}
	}
	// valid calldata batch
	cdData := payloadWith(0x00)
	ev := calldataEv(cdData, txs, N)
	legC := legOf(txs)
	valid, l1h := assemble(ev, nil, legC)
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
	cases = append(cases, synthCase{"synth_valid_calldata", "a calldata-mode batch (SeparateBatchEvent/TxInput form: dataHash = keccak256(header40 || data)) in a synthetic Bridge, finality from a synthetic 4-key committee", "synth", legC, valid, okWant(N, 0, 2, 1, -1, l1h)})
	for _, f := range []struct {
		flag byte
		id   string
		want func(uint64) string
	}{
		{0x80, "adv_synth_calldata_flag_das", func(n uint64) string {
			return canonState("l1_batch_data_off_l1", "batch", n, "header_byte", uint8(0x80))
		}},
		{0x88, "adv_synth_calldata_flag_das_tree", func(n uint64) string {
			return canonState("l1_batch_data_off_l1", "batch", n, "header_byte", uint8(0x88))
		}},
		{0x05, "adv_synth_calldata_flag_unknown", func(n uint64) string { return canonState("l1_batch_header_unknown", "batch", n, "byte", uint8(0x05)) }},
		{0x01, "adv_synth_calldata_flag_dacert", func(n uint64) string { return canonState("l1_batch_header_unknown", "batch", n, "byte", uint8(0x01)) }},
		{0x20, "adv_synth_calldata_flag_zeroheavy", func(n uint64) string { return canonState("l1_batch_header_unknown", "batch", n, "byte", uint8(0x20)) }},
	} {
		d := payloadWith(f.flag)
		e2 := calldataEv(d, txs, N)
		ev2, _ := assemble(e2, nil, legC)
		cases = append(cases, synthCase{f.id, fmt.Sprintf("calldata batch whose data starts with 0x%02x", f.flag), "synth", legC, ev2, f.want(N)})
	}
	// blob-mode payload header bytes (the chain's only mode): a real KZG-proven blob batch whose payload starts with the byte
	for _, f := range []struct {
		flag byte
		id   string
		want string
	}{
		{0x80, "adv_synth_blob_payload_das", canonState("l1_batch_data_off_l1", "batch", N, "header_byte", uint8(0x80))},
		{0x88, "adv_synth_blob_payload_das_tree", canonState("l1_batch_data_off_l1", "batch", N, "header_byte", uint8(0x88))},
		{0x01, "adv_synth_blob_payload_dacert", canonState("l1_batch_data_off_l1", "batch", N, "header_byte", uint8(0x01))},
		{0x20, "adv_synth_blob_payload_zeroheavy", canonState("l1_batch_header_unknown", "batch", N, "byte", uint8(0x20))},
	} {
		bl, vh := blobsFor(payloadWith(f.flag))
		e2 := arbposted.Evidence{BlockTxs: txs, BatchSeq: N, Header40: h40, BeforeAcc: before, DataKind: arbposted.DataBlobs, VersionedHashes: vh, Blobs: bl}
		ev2, _ := assemble(e2, nil, legC)
		cases = append(cases, synthCase{f.id, fmt.Sprintf("blob batch (KZG-proven) whose payload starts with 0x%02x", f.flag), "synth", legC, ev2, f.want})
	}
	// decompression bounds at the pinned defaults
	bomb := append([]byte{0x00}, brotliBytes(bytes.Repeat([]byte{0}, 20<<20))...)
	bombEv, _ := assemble(calldataEv(bomb, txs, N), nil, legC)
	cases = append(cases, synthCase{"adv_synth_brotli_bomb", "a payload that decompresses to more than the pinned 16 MiB (20 MiB of zeros in a few KiB of brotli)", "synth", legC,
		bombEv, canonState("finality_evidence_too_large", "part", "uncompressed_batch", "count", uint64(16777217), "limit", uint64(16777216))})
	manySegs := append([]byte{0x00}, brotliBytes(bytes.Repeat([]byte{0x00}, 102401))...)
	segEv, _ := assemble(calldataEv(manySegs, txs, N), nil, legC)
	cases = append(cases, synthCase{"adv_synth_segments_over_bound", "a payload of 102,401 segments (the pinned bound is 102,400)", "synth", legC,
		segEv, canonState("finality_evidence_too_large", "part", "segments", "count", uint64(102401), "limit", uint64(102400))})

	// delayed-origin block: a deposit (message kind 12) consumed by this batch
	user := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")
	value := big.NewInt(12345)
	ddata := append(append([]byte(nil), to[:]...), common.LeftPadBytes(value.Bytes(), 32)...)
	kIdx := uint64(41)
	dmsg := arbposted.Delayed{MsgKind: 12, Sender: user, MsgBlockNumber: 10, MsgTimestamp: 20, Data: ddata, K: kIdx}
	dmsg.BaseFeeL1[31] = 9
	prev := crypto.Keccak256Hash([]byte("synthetic delayed prev"))
	mh := arbposted.DelayedMessageHash(dmsg)
	accK := crypto.Keccak256Hash(prev[:], mh[:])
	type depositTx struct {
		ChainID   *big.Int
		RequestID common.Hash
		From, To  common.Address
		Value     *big.Int
	}
	depRLP, _ := rlp.EncodeToBytes(depositTx{ChainID: big.NewInt(421614), RequestID: w32(kIdx), From: user, To: to, Value: value})
	depTx := append([]byte{0x64}, depRLP...)
	dTxs := [][]byte{{0x6a, 0xc0}, depTx}
	dLeg := legOf(dTxs)
	dBatch := payloadOf(segment(2, nil), segment(2, nil), segment(3, []byte{1}))
	dEv := func(m arbposted.Delayed, h5 uint64) arbposted.Evidence {
		e := calldataEv(dBatch, dTxs, N+1)
		e.Header40[4] = h5
		e.DelayedAcc = accK
		e.Delayed = &m
		return e
	}
	dm := map[uint64]common.Hash{kIdx: accK, kIdx - 1: prev}
	dValid, dl1h := assemble(dEv(dmsg, kIdx+1), dm, dLeg)
	cases = append(cases, synthCase{"synth_valid_delayed_deposit", "a block made of one ETH-deposit delayed message: the accumulator chain k-1 -> k, the consumption interval and the deposit own fields all verify", "synth", dLeg, dValid, okWant(N+1, 0, 0, -1, int64(kIdx), dl1h)})
	unproven := func(kk uint64, kind uint8) string {
		return canonState("l1_posted_delayed_origin_unproven", "block_tx_types", []uint64{0x6a, 0x64}, "header_nonce", headerNonce(b.legHdr), "k", kk, "message_kind", kind)
	}
	alt := dmsg
	alt.MsgTimestamp++
	dAlt, _ := assemble(dEv(alt, kIdx+1), dm, dLeg)
	cases = append(cases, synthCase{"adv_synth_delayed_message_altered", "the delayed message timestamp altered: its hash no longer extends the proven accumulator", "synth", dLeg, dAlt, unproven(kIdx, 12)})
	dNc, _ := assemble(dEv(dmsg, kIdx), dm, dLeg)
	cases = append(cases, synthCase{"adv_synth_delayed_k_not_consumed", "afterDelayedMessagesRead equals k: this batch did not consume message k", "synth", dLeg, dNc, unproven(kIdx, 12)})
	badPrev := map[uint64]common.Hash{kIdx: accK, kIdx - 1: crypto.Keccak256Hash([]byte("other"))}
	dBp, _ := assemble(dEv(dmsg, kIdx+1), badPrev, dLeg)
	cases = append(cases, synthCase{"adv_synth_delayed_predecessor_wrong", "delayedInboxAccs[k-1] is not the accumulator the message extends", "synth", dLeg, dBp, unproven(kIdx, 12)})
	wrong := dmsg
	wrong.Sender = to
	wh := arbposted.DelayedMessageHash(wrong)
	wAcc := crypto.Keccak256Hash(prev[:], wh[:])
	wEv := dEv(wrong, kIdx+1)
	wEv.DelayedAcc = wAcc
	dSd, _ := assemble(wEv, map[uint64]common.Hash{kIdx: wAcc, kIdx - 1: prev}, dLeg)
	cases = append(cases, synthCase{"adv_synth_delayed_sender_differs", "the message sender differs from the deposit transaction from", "synth", dLeg, dSd, unproven(kIdx, 12)})
	return cases, nil
}

func containerBytes(h finality.ContainerHeader, body []byte) []byte {
	enc, err := finality.Container{Header: h, Body: body}.Encode()
	if err != nil {
		panic(err)
	}
	return enc
}
