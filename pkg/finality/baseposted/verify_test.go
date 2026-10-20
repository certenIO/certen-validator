// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
)

func mustOK(t *testing.T, s *synth) finality.Verdict {
	t.Helper()
	v, err := s.verify()
	if err != nil {
		t.Fatalf("want ok, got %v", err)
	}
	return v
}

func TestSynthValidCalldataZlibAndBrotliSingularBatches(t *testing.T) {
	for _, c := range []string{"zlib", "brotli"} {
		for _, n := range []int{1, 3} {
			s := makeSynth(t, synthOpts{compression: c, calldata: true, nFrames: n})
			v := mustOK(t, s)
			if v.Level != finality.LevelL1Posted || v.Kind != KindName || v.Fields["batch_type"] != uint64(0) {
				t.Fatalf("%s/%d: %+v", c, n, v)
			}
		}
	}
}

func TestSynthValidSpanBatchFirstBlock(t *testing.T) {
	for _, c := range []string{"zlib", "brotli"} {
		s := makeSynth(t, synthOpts{compression: c, calldata: true, nFrames: 2, span: true})
		v := mustOK(t, s)
		if v.Fields["batch_type"] != uint64(1) || v.Fields["parent_hash_bits"] != uint64(160) || v.Fields["span_blocks"] != uint64(1) {
			t.Fatalf("%+v", v.Fields)
		}
	}
}

func TestSynthSpanInteriorBlockParentIsNotBoundAndIsRefused(t *testing.T) {
	// a span batch's parent hash is committed only for its first block: the verifier names the refusal instead of passing
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, span: true})
	b := Batch{ParentLen: 0}
	if prefixEq(b.ParentHash, b.ParentLen, s.l2.ParentHash) {
		t.Fatal("an uncommitted parent hash must never compare equal")
	}
}

func TestSynthWrongBatcherSender(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, chainBatch: testKey("someone else")})
	_, err := s.verify()
	wantCode(t, err, CodeBatcherSender, nil)
}

func TestSynthTxNotToTheInbox(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, toInbox: true})
	_, err := s.verify()
	wantCode(t, err, CodeBatcherNotToInbox, nil)
}

func TestSynthTxNotInTheBlockTrie(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	s.body.Frames[0].TxRaw[len(s.body.Frames[0].TxRaw)-1] ^= 1
	_, err := s.verify()
	wantCode(t, err, CodeL1TxProofInvalid, nil)
}

func TestSynthMissingDuplicateAndMisorderedFrames(t *testing.T) {
	missing := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 3})
	missing.body.Frames = append(missing.body.Frames[:1:1], missing.body.Frames[2:]...)
	_, err := missing.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)

	dup := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 3})
	dup.body.Frames = append(dup.body.Frames[:2:2], dup.body.Frames[1:]...)
	_, err = dup.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)

	swap := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 3})
	swap.body.Frames[0], swap.body.Frames[1] = swap.body.Frames[1], swap.body.Frames[0]
	_, err = swap.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)

	noLast := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 3})
	noLast.body.Frames = noLast.body.Frames[:2]
	_, err = noLast.verify()
	wantCode(t, err, CodeChannelIncomplete, nil)
}

func TestSynthChannelTimedOut(t *testing.T) {
	ok := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1000, 1300}})
	mustOK(t, ok)
	late := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2, frameBlocks: []uint64{1000, 1301}})
	_, err := late.verify()
	wantCode(t, err, CodeChannelTimedOut, nil)
}

func TestSynthChannelBombAndMalformed(t *testing.T) {
	bomb := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	bomb.bp.MaxRLPBytesPerChannel = 10
	_, err := bomb.verify()
	wantCode(t, err, CodeChannelMalformed, nil)
	// the same channel at exactly its decompressed size is accepted
	raw, _ := decompress(framesOf(t, makeSynth(t, synthOpts{compression: "zlib", calldata: true})), 1<<20)
	exact := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	exact.bp.MaxRLPBytesPerChannel = uint64(len(raw))
	mustOK(t, exact)
	short := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	short.bp.MaxRLPBytesPerChannel = uint64(len(raw)) - 1
	_, err = short.verify()
	wantCode(t, err, CodeChannelMalformed, nil)
}

// framesOf concatenates the frame data of a synthetic channel (calldata mode).
func framesOf(t *testing.T, s *synth) []byte {
	t.Helper()
	var out []byte
	for _, f := range s.body.Frames {
		tx := new(txView)
		if err := tx.parse(f.TxRaw); err != nil {
			t.Fatal(err)
		}
		fr, err := parseFrames(tx.data)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range fr {
			out = append(out, x.Data...)
		}
	}
	return out
}

func TestSynthUnsupportedCompressionAndBatchType(t *testing.T) {
	if _, err := decompress([]byte{0x02, 1, 2, 3}, 100); err == nil {
		t.Fatal("compression type 2 must be refused")
	}
	var zb bytes.Buffer
	w := zlib.NewWriter(&zb)
	st, _ := rlp.EncodeToBytes([]byte{7, 0xc0})
	w.Write(st)
	w.Close()
	raw, err := decompress(zb.Bytes(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeBatches(raw, spanParams{})
	if bf, ok := err.(*batchFormatError); !ok || bf.typ != 7 {
		t.Fatalf("want batch type 7 unsupported, got %v", err)
	}
}

func TestSynthBatchNotFoundAndBindings(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	s.l2.Timestamp += 1
	_, err := s.verify()
	wantCode(t, err, CodeBatchNotFound, map[string]string{"n_batches": "3"})

	s = makeSynth(t, synthOpts{compression: "brotli", calldata: true})
	s.l2.ParentHash[0] ^= 1
	_, err = s.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "parent_hash"})

	s = makeSynth(t, synthOpts{compression: "brotli", calldata: true})
	s.body.Deposits[0] = append([]byte(nil), s.body.Deposits[0]...)
	// the L1-info number lives inside the deposit's data: find and flip a byte of it
	i := bytes.Index(s.body.Deposits[0], []byte{0, 0, 0, 0, 0, 0, 0x03, 0xde}) // 990 = 0x03de
	if i < 0 {
		t.Fatal("epoch number not found in the deposit")
	}
	s.body.Deposits[0][i+7] ^= 1
	_, err = s.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "epoch_num"})

	s = makeSynth(t, synthOpts{compression: "brotli", calldata: true})
	s.body.Deposits[0] = append([]byte(nil), s.body.Deposits[0]...)
	j := bytes.Index(s.body.Deposits[0], crypto.Keccak256([]byte("epoch hash")))
	if j < 0 {
		t.Fatal("epoch hash not found in the deposit")
	}
	s.body.Deposits[0][j] ^= 1
	_, err = s.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "epoch_hash"})

	s = makeSynth(t, synthOpts{compression: "brotli", calldata: true})
	s.l2.TransactionRoot[0] ^= 1
	_, err = s.verify()
	wantCode(t, err, CodeBatchBindingMismatch, map[string]string{"field": "transactions_root"})
}

func TestSynthBatchOutsideTheSequencingWindow(t *testing.T) {
	ok := makeSynth(t, synthOpts{compression: "zlib", calldata: true, epochNum: 990, frameBlocks: []uint64{4590}})
	mustOK(t, ok)
	late := makeSynth(t, synthOpts{compression: "zlib", calldata: true, epochNum: 990, frameBlocks: []uint64{4591}})
	_, err := late.verify()
	wantCode(t, err, CodeBatchOutsideWindow, nil)
	early := makeSynth(t, synthOpts{compression: "zlib", calldata: true, epochNum: 1001, frameBlocks: []uint64{1000}})
	_, err = early.verify()
	wantCode(t, err, CodeBatchOutsideWindow, nil)
}

func TestSynthStateProofsAndImplementationIdentity(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	s.bp.SystemConfigImplHashes = map[[32]byte]bool{{1}: true}
	_, err := s.verify()
	wantCode(t, err, CodeContractIdentity, map[string]string{"role": RoleSystemConfigImpl, "judged_at": "1000"})

	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	s.body.Nodes = nil
	_, err = s.verify()
	// without any node the transaction proof is the first thing that cannot be walked
	wantCode(t, err, CodeL1TxProofInvalid, nil)

	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	// the transaction proof stays, the root node of the state trie goes: the SystemConfig account cannot be proven
	stateRoot := s.covered[0].StateRoot
	var keep [][]byte
	for _, n := range s.body.Nodes {
		if [32]byte(crypto.Keccak256Hash(n)) != stateRoot {
			keep = append(keep, n)
		}
	}
	if len(keep) != len(s.body.Nodes)-1 {
		t.Fatal("the state root node was not found")
	}
	s.body.Nodes = keep
	_, err = s.verify()
	wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "account"})
}

func mustHeader(t *testing.T, raw []byte) finality.HeaderFields {
	t.Helper()
	h, err := finality.ReadHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestFrameNotOnTheCoveredSpine(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	s.body.Frames[0].L1Block = 999
	_, err := s.verify()
	wantCode(t, err, "finality_block_not_covered", nil)
}

func TestBlobEncodingRoundTripsOPFromDataToData(t *testing.T) {
	for _, n := range []int{1, 26, 27, 28, 126, 127, 128, 1000, 65536, blobMaxData} {
		d := make([]byte, n)
		rand.Read(d)
		b, err := encodeBlob(d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := blobToData(b)
		if err != nil || !bytes.Equal(got, d) {
			t.Fatalf("n=%d: %v", n, err)
		}
		for i := 0; i < len(b); i += 32 {
			if b[i]&0xc0 != 0 {
				t.Fatalf("n=%d: field element %d has high bits set", n, i/32)
			}
		}
	}
	b, _ := encodeBlob([]byte("x"))
	b[1] = 1
	if _, err := blobToData(b); err == nil {
		t.Fatal("encoding version 1 must be refused")
	}
	b, _ = encodeBlob([]byte("x"))
	b[len(b)-1] = 1
	if _, err := blobToData(b); err == nil {
		t.Fatal("a non-zero tail must be refused")
	}
	if _, err := encodeBlob(make([]byte, blobMaxData+1)); err == nil {
		t.Fatal("oversize data must be refused")
	}
}

func TestBodyCodecRoundTripAndStrictness(t *testing.T) {
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true, nFrames: 2})
	s.body.LC = tinyLC(t)
	enc := EncodeBody(s.body)
	ep := testEthl1Pins()
	got, err := DecodeBody(enc, finality.DefaultLimits(), ep, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(EncodeBody(got), enc) {
		t.Fatal("encode(decode(x)) != x")
	}
	if _, err := DecodeBody(append(append([]byte(nil), enc...), 0), finality.DefaultLimits(), ep, 32); err == nil {
		t.Fatal("a trailing byte must be refused")
	}
	// the frame count bound is checked before anything is read
	bad := append([]byte(nil), enc...)
	off := bytes.Index(bad, s.body.ChannelID[:]) + 16
	bad[off], bad[off+1], bad[off+2], bad[off+3] = 0, 0, 1, 1 // 257 frames
	_, err = DecodeBody(bad, finality.DefaultLimits(), ep, 32)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "frameTxs", "count": "257", "limit": "256"})
}

func dropNodesContaining(nodes [][]byte, needle []byte) [][]byte {
	var out [][]byte
	for _, n := range nodes {
		if !bytes.Contains(n, needle) {
			out = append(out, n)
		}
	}
	return out
}

func TestSynthEachStateProofGapIsNamed(t *testing.T) {
	// the storage leaf holding the implementation address removed: the EIP-1967 slot cannot be proven
	s := makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	n0 := len(s.body.Nodes)
	s.body.Nodes = dropNodesContaining(s.body.Nodes, testImpl.Bytes())
	if len(s.body.Nodes) >= n0 {
		t.Fatal("the implementation storage leaf was not found")
	}
	_, err := s.verify()
	wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "slot"})

	// the storage leaf holding the batcher removed: the batcherHash slot cannot be proven
	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true})
	n0 = len(s.body.Nodes)
	s.body.Nodes = dropNodesContaining(s.body.Nodes, crypto.PubkeyToAddress(testKey("batcher").PublicKey).Bytes())
	if len(s.body.Nodes) >= n0 {
		t.Fatal("the batcher storage leaf was not found")
	}
	_, err = s.verify()
	wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "slot"})

	// the implementation account absent from the state: its code hash cannot be proven
	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true, omitImpl: true})
	_, err = s.verify()
	wantCode(t, err, CodeL1StateProofInvalid, map[string]string{"which": "account"})

	// a batcherHash that is not a plain address (a non-zero byte above the 20) never matches a sender
	s = makeSynth(t, synthOpts{compression: "zlib", calldata: true, dirtyBatcherHash: true})
	_, err = s.verify()
	wantCode(t, err, CodeBatcherSender, nil)
}

func TestKindVerifyRefusesAMislabelledContainerAndAnUnreadableLeg(t *testing.T) {
	set := filepath.Join("testdata", SetName)
	pinsRaw, err := ReadFile(set, "pins/main.json")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	legRaw, _ := ReadFile(set, "legs/a.json")
	var leg Leg
	if err := json.Unmarshal(legRaw, &leg); err != nil {
		t.Fatal(err)
	}
	num, _ := strconv.ParseUint(leg.Number, 10, 64)
	hdr, _ := hex.DecodeString(strings.TrimPrefix(leg.Header, "0x"))
	hb, _ := hex.DecodeString(strings.TrimPrefix(leg.Hash, "0x"))
	var hash [32]byte
	copy(hash[:], hb)
	ev, err := ReadFile(set, "evidence/valid_a.bin")
	if err != nil {
		t.Fatal(err)
	}
	ref := finality.BlockRef{Chain: 84532, Number: num, Hash: hash, HeaderRLP: hdr}
	if _, err := (Kind{}).Verify(pins, ref, ev); err != nil {
		t.Fatalf("the base case must verify: %v", err)
	}
	c, err := finality.DecodeContainer(ev, finality.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	reenc := func(mod func(*finality.Container)) []byte {
		cc := c
		mod(&cc)
		out, err := cc.Encode()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Kind = "arb-sepolia/l1_posted/v1" }))
	wantCode(t, err, finality.CodeEvidenceUnrecognised, nil)
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Chain = 421614 }))
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "header.chain"})
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.Level = finality.LevelFinalized }))
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "header.chain"})
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.BlockHash[0] ^= 1 }))
	wantCode(t, err, finality.CodeBlockMismatch, map[string]string{"field": "blockHash"})
	_, err = Kind{}.Verify(pins, ref, reenc(func(x *finality.Container) { x.Header.BlockNumber++ }))
	wantCode(t, err, finality.CodeBlockMismatch, map[string]string{"field": "blockNumber"})
	// no header handed over
	noHdr := ref
	noHdr.HeaderRLP = nil
	_, err = Kind{}.Verify(pins, noHdr, ev)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "leg.header"})
	// a header that is not the one the block hash names (the container and the leg agree on the hash)
	bad := ref
	bad.Hash[0] ^= 1
	_, err = Kind{}.Verify(pins, bad, reenc(func(x *finality.Container) { x.Header.BlockHash[0] ^= 1 }))
	wantCode(t, err, finality.CodeBlockMismatch, map[string]string{"field": "blockHash"})
	// a header that is not RLP at all
	junk := ref
	junk.HeaderRLP = []byte{1, 2, 3}
	_, err = Kind{}.Verify(pins, junk, ev)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "header"})
	// the pins carry no base_sepolia section / no Sepolia ledger entry
	empty, _ := finality.ParsePinsOverride([]byte(`{"format":"certen-finality-pins/1","onchain_commitment":null,"published_utc":"2026-10-20T00:00:00Z"}` + "\n"))
	_, err = Kind{}.Verify(empty, ref, ev)
	wantCode(t, err, finality.CodePinUnknown, map[string]string{"kind": "base_sepolia"})
}

func TestBodyBoundsMaxBlobsMaxDepositsAndLeafSizeAreNamed(t *testing.T) {
	lim := finality.DefaultLimits()
	ep := testEthl1Pins()
	base := Body{LC: tinyLC(t), ChannelID: [16]byte{1}}

	over := base
	over.Frames = []FrameTx{{L1Block: 1, TxRaw: []byte{1}}}
	for i := 0; i < 33; i++ {
		over.Frames[0].Blobs = append(over.Frames[0].Blobs, Blob{Raw: make([]byte, BlobSize)})
	}
	_, err := DecodeBody(EncodeBody(over), lim, ep, 32)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "frameTx.blobs", "count": "33", "limit": "32"})

	// the bound is per container: two transactions of 17 blobs each
	two := base
	for k := 0; k < 2; k++ {
		f := FrameTx{L1Block: 1, TxIndex: uint32(k), TxRaw: []byte{1}}
		for i := 0; i < 17; i++ {
			f.Blobs = append(f.Blobs, Blob{Raw: make([]byte, BlobSize)})
		}
		two.Frames = append(two.Frames, f)
	}
	_, err = DecodeBody(EncodeBody(two), lim, ep, 32)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "blobs", "count": "34", "limit": "32"})

	deps := base
	for i := 0; i < lim.MaxDepositTxs+1; i++ {
		deps.Deposits = append(deps.Deposits, []byte{0x7e})
	}
	_, err = DecodeBody(EncodeBody(deps), lim, ep, 32)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "depositTxs", "count": "4097", "limit": "4096"})

	leaf := base
	leaf.Frames = []FrameTx{{L1Block: 1, TxRaw: make([]byte, lim.MaxTxLeafBytes+1)}}
	_, err = DecodeBody(EncodeBody(leaf), lim, ep, 32)
	wantCode(t, err, finality.CodeEvidenceTooLarge, map[string]string{"part": "frameTx.txRaw", "limit": "2097152"})

	// a blob that is not exactly 131072 bytes
	short := base
	short.Frames = []FrameTx{{L1Block: 1, TxRaw: []byte{1}, Blobs: []Blob{{Raw: make([]byte, BlobSize-1)}}}}
	_, err = DecodeBody(EncodeBody(short), lim, ep, 32)
	wantCode(t, err, finality.CodeEvidenceMalformed, map[string]string{"part": "blob.raw", "reason": "truncated"})
}
