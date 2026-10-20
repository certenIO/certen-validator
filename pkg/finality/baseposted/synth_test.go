// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// A synthetic Base channel on a synthetic L1 block, built from a test batcher key, drives verifyChannel directly (the LC part is
// exercised by the live vectors and by ethl1's own set). Everything here is generated at test time from fixed labels.

var (
	testInbox     = common.HexToAddress("0xff00000000000000000000000000000000084532")
	testSysConfig = common.HexToAddress("0xf272670eb55e895584501d564afeb048bed26194")
	testImpl      = common.HexToAddress("0xaeb75e200b9bcf9343ff1a2d2b1b3976e7339ca4")
	testImplCode  = crypto.Keccak256Hash([]byte("synthetic syscfg implementation"))
)

func testKey(label string) *ecdsa.PrivateKey {
	k, err := crypto.ToECDSA(crypto.Keccak256([]byte("finality_base_posted1/" + label)))
	if err != nil {
		panic(err)
	}
	return k
}

type synthOpts struct {
	compression      string // "zlib" or "brotli"
	calldata         bool   // frames in tx.input (type-2 tx) instead of blobs
	nFrames          int    // channel split into this many frames (>=1)
	span             bool   // a span batch instead of a singular batch
	batchTs          uint64
	frameBlocks      []uint64 // L1 block of each frame transaction (len nFrames); default all 1000
	epochNum         uint64
	batcher          *ecdsa.PrivateKey // signs the frame txs
	chainBatch       *ecdsa.PrivateKey // the batcher recorded in the SystemConfig (default: the signing key)
	toInbox          bool
	dirtyBatcherHash bool   // the recorded batcherHash has a non-zero byte above its 20-byte address
	dirtyIndex       int    // which of the 12 upper bytes
	dirtyValue       byte   // and its value
	omitImpl         bool   // the implementation account is absent from the state
	rawStream        []byte // the decompressed channel used as given, instead of the batches built here
	txData           []byte // the calldata of every frame transaction, used as given instead of the marshalled frame
	channelLabel     string // another label gives another channel id
	garbageTx        []byte // the frame transaction bytes put in the block trie instead of the signed transaction
}

type synth struct {
	bp      *Pins
	body    Body
	covered []ethl1.L1Block
	l2      finality.HeaderFields
	l2Raw   []byte
	head    ethl1.FinalizedHead
	txs     [][]byte
}

func newPins() *Pins {
	return &Pins{ChainID: 84532, L1ChainID: ethl1.SepoliaChainID, SystemConfig: testSysConfig, BatchInbox: testInbox, SeqWindowSize: 3600, ChannelTimeout: 300, GraniteTime: 1723478400, ChannelTimeoutGranite: 50,
		MaxRLPBytesPerChannel: 100_000_000, DenimTime: 1792605600, MaxBlobs: 32, L2GenesisTime: 1695768288, L2BlockTime: 2,
		KZGSetupSHA256:         "f8e44a31ebf0a6d0734dcb301b0716e2c77f3ae18ed0cab0870fbcc2ca55616f",
		SystemConfigImplHashes: map[[32]byte]bool{[32]byte(testImplCode): true}}
}

func compress(kind string, raw []byte) []byte {
	var buf bytes.Buffer
	if kind == "brotli" {
		buf.WriteByte(1)
		w := brotli.NewWriter(&buf)
		w.Write(raw)
		w.Close()
		return buf.Bytes()
	}
	w := zlib.NewWriter(&buf)
	w.Write(raw)
	w.Close()
	return buf.Bytes()
}

func l1InfoDeposit(number uint64, hash [32]byte) []byte {
	data := make([]byte, 164)
	copy(data[:4], []byte{0x09, 0x89, 0x99, 0xbe})
	binary.BigEndian.PutUint64(data[28:36], number)
	copy(data[100:132], hash[:])
	enc, _ := rlp.EncodeToBytes([]any{common.Hash{1}, common.Address{0xde, 0xad}, common.Address{0x42}, big.NewInt(0), big.NewInt(0), uint64(1_000_000), false, data})
	return append([]byte{0x7e}, enc...)
}

// userTx is a legacy-typed transaction of the synthetic L2 block (the content is irrelevant, only its encoding is committed).
func userTx(nonce uint64) []byte {
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(84532), Nonce: nonce, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000,
		To: &common.Address{9}, Value: big.NewInt(1), V: big.NewInt(0), R: big.NewInt(1), S: big.NewInt(1)})
	b, _ := tx.MarshalBinary()
	return b
}

func makeSynth(t *testing.T, o synthOpts) *synth {
	t.Helper()
	if o.nFrames == 0 {
		o.nFrames = 1
	}
	if o.batcher == nil {
		o.batcher = testKey("batcher")
	}
	if o.chainBatch == nil {
		o.chainBatch = o.batcher
	}
	if o.batchTs == 0 {
		o.batchTs = 1790000000
	}
	if o.epochNum == 0 {
		o.epochNum = 990
	}
	bp := newPins()
	epochHash := crypto.Keccak256Hash([]byte("epoch hash"))
	parent := crypto.Keccak256Hash([]byte("parent"))
	deposit := l1InfoDeposit(o.epochNum, epochHash)
	users := [][]byte{userTx(1), userTx(2)}
	all := append([][]byte{deposit}, users...)
	// the batch
	var batchBytes []byte
	if o.span {
		batchBytes = append([]byte{1}, spanPayload(t, bp, o, parent, epochHash, users)...)
	} else {
		enc, _ := rlp.EncodeToBytes(singularRLP{ParentHash: parent, EpochNum: o.epochNum, EpochHash: epochHash, Timestamp: o.batchTs, Txs: users})
		batchBytes = append([]byte{0}, enc...)
	}
	stream, _ := rlp.EncodeToBytes(batchBytes)
	// pad the stream with a few other batches so the lookup is real
	for i := uint64(1); i <= 2 && !o.span; i++ {
		enc, _ := rlp.EncodeToBytes(singularRLP{ParentHash: crypto.Keccak256Hash([]byte{byte(i)}), EpochNum: o.epochNum, EpochHash: epochHash, Timestamp: o.batchTs + 2*i, Txs: nil})
		b, _ := rlp.EncodeToBytes(append([]byte{0}, enc...))
		stream = append(stream, b...)
	}
	if o.rawStream != nil {
		stream = o.rawStream
	}
	chData := compress(o.compression, stream)
	var id [16]byte
	label := "channel"
	if o.channelLabel != "" {
		label = o.channelLabel
	}
	copy(id[:], crypto.Keccak256([]byte(label)))
	// frames
	per := (len(chData) + o.nFrames - 1) / o.nFrames
	var frameBytes [][]byte
	for i := 0; i < o.nFrames; i++ {
		lo, hi := i*per, (i+1)*per
		if hi > len(chData) {
			hi = len(chData)
		}
		if lo > hi {
			lo = hi
		}
		f := Frame{ID: id, Number: uint16(i), Data: chData[lo:hi], IsLast: i == o.nFrames-1}
		frameBytes = append(frameBytes, append([]byte{0}, MarshalFrame(f)...))
		if o.txData != nil {
			frameBytes[i] = o.txData
		}
	}
	blocks := o.frameBlocks
	if len(blocks) == 0 {
		blocks = make([]uint64, o.nFrames)
		for i := range blocks {
			blocks[i] = 1000
		}
	}
	// per L1 block: state trie with the SystemConfig and its implementation, tx trie of the frame transactions
	signer := types.LatestSignerForChainID(big.NewInt(ethl1.SepoliaChainID))
	s := &synth{bp: bp}
	byBlock := map[uint64][]int{}
	var order []uint64
	for i, b := range blocks {
		if _, ok := byBlock[b]; !ok {
			order = append(order, b)
		}
		byBlock[b] = append(byBlock[b], i)
	}
	batcherHash := common.BytesToHash(crypto.PubkeyToAddress(o.chainBatch.PublicKey).Bytes())
	if o.dirtyBatcherHash {
		batcherHash[o.dirtyIndex] = o.dirtyValue
	}
	for _, blk := range order {
		var raws [][]byte
		for _, i := range byBlock[blk] {
			to := testInbox
			if o.toInbox {
				to = common.Address{0xaa}
			}
			var tx *types.Transaction
			if o.calldata {
				tx = types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(ethl1.SepoliaChainID), Nonce: uint64(i), GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1000), Gas: 100000, To: &to, Data: frameBytes[i]})
			} else {
				t.Fatal("blob frames are exercised by the live vectors")
			}
			stx, err := types.SignTx(tx, signer, o.batcher)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := stx.MarshalBinary()
			if o.garbageTx != nil {
				b = o.garbageTx
			}
			raws = append(raws, b)
		}
		txRoot := ethproof.TrieRoot(raws)
		// state
		st := trie.NewEmpty(nil)
		bv, _ := rlp.EncodeToBytes(bytes.TrimLeft(batcherHash[:], "\x00"))
		iv, _ := rlp.EncodeToBytes(bytes.TrimLeft(common.LeftPadBytes(testImpl.Bytes(), 32), "\x00"))
		st.Update(crypto.Keccak256(batcherHashSlot[:]), bv)
		st.Update(crypto.Keccak256(eip1967ImplSlot[:]), iv)
		storageRoot := st.Hash()
		accTrie := trie.NewEmpty(nil)
		sc, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: storageRoot, CodeHash: crypto.Keccak256([]byte("proxy"))})
		im, _ := rlp.EncodeToBytes(&types.StateAccount{Nonce: 1, Balance: uint256.NewInt(0), Root: types.EmptyRootHash, CodeHash: testImplCode[:]})
		accTrie.Update(crypto.Keccak256(testSysConfig[:]), sc)
		if !o.omitImpl {
			accTrie.Update(crypto.Keccak256(testImpl[:]), im)
		}
		stateRoot := accTrie.Hash()
		var nodes [][]byte
		collect := func(tr *trie.Trie, key []byte) {
			var ns proofSink
			if err := tr.Prove(key, &ns); err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, ns.nodes...)
		}
		collect(accTrie, crypto.Keccak256(testSysConfig[:]))
		collect(accTrie, crypto.Keccak256(testImpl[:]))
		collect(st, crypto.Keccak256(batcherHashSlot[:]))
		collect(st, crypto.Keccak256(eip1967ImplSlot[:]))
		for k, i := range byBlock[blk] {
			p, err := ethproof.Prove(raws, uint64(k), txRoot)
			if err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, p.ProofNodes...)
			s.body.Frames = append(s.body.Frames, FrameTx{L1Block: blk, TxIndex: uint32(k), TxRaw: raws[k]})
			_ = i
		}
		h := &types.Header{Number: new(big.Int).SetUint64(blk), Root: stateRoot, TxHash: txRoot, ParentHash: common.Hash{byte(blk)}, Time: 1790000000 + blk, Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
		raw, _ := rlp.EncodeToBytes(h)
		s.body.L1Spine = append(s.body.L1Spine, raw)
		s.covered = append(s.covered, ethl1.L1Block{Hash: [32]byte(crypto.Keccak256Hash(raw)), Number: blk, StateRoot: [32]byte(stateRoot), Timestamp: h.Time})
		s.body.Nodes = append(s.body.Nodes, nodes...)
	}
	// the spine is contiguous: filler headers for every block between the frame blocks
	have := map[uint64]bool{}
	lo, hi := order[0], order[0]
	for _, b := range order {
		have[b] = true
		if b < lo {
			lo = b
		}
		if b > hi {
			hi = b
		}
	}
	for n := lo; n <= hi; n++ {
		if have[n] {
			continue
		}
		h := &types.Header{Number: new(big.Int).SetUint64(n), Root: common.Hash{byte(n)}, ParentHash: common.Hash{byte(n)}, Time: 1790000000 + n, Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
		raw, _ := rlp.EncodeToBytes(h)
		s.body.L1Spine = append(s.body.L1Spine, raw)
		s.covered = append(s.covered, ethl1.L1Block{Hash: [32]byte(crypto.Keccak256Hash(raw)), Number: n, StateRoot: [32]byte(h.Root), Timestamp: h.Time})
	}
	// verifyChannel expects the covered list and the raw spine descending from the top block
	sortDesc(s)
	s.body.ChannelID = id
	s.body.Deposits = [][]byte{deposit}
	s.body.Nodes = finality.EncodeNodes(s.body.Nodes)
	l2h := &types.Header{ParentHash: parent, Number: big.NewInt(5000), Time: o.batchTs, TxHash: ethproof.TrieRoot(all), Difficulty: big.NewInt(0), UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash}
	if o.span {
		l2h.Time = o.batchTs
	}
	s.l2Raw, _ = rlp.EncodeToBytes(l2h)
	var err error
	if s.l2, err = finality.ReadHeader(s.l2Raw); err != nil {
		t.Fatal(err)
	}
	s.txs = all
	return s
}

// sortDesc orders the synthetic spine and covered list by block number, descending (one raw header per covered entry).
func sortDesc(s *synth) {
	for i := 1; i < len(s.covered); i++ {
		for j := i; j > 0 && s.covered[j].Number > s.covered[j-1].Number; j-- {
			s.covered[j], s.covered[j-1] = s.covered[j-1], s.covered[j]
			s.body.L1Spine[j], s.body.L1Spine[j-1] = s.body.L1Spine[j-1], s.body.L1Spine[j]
		}
	}
}

type proofSink struct{ nodes [][]byte }

func (p *proofSink) Put(_ []byte, v []byte) error {
	p.nodes = append(p.nodes, common.CopyBytes(v))
	return nil
}
func (p *proofSink) Delete([]byte) error { return nil }

// spanPayload encodes a one-block span batch (legacy-free: a single type-2 transaction pair) for the synthetic channel.
func spanPayload(t *testing.T, bp *Pins, o synthOpts, parent, epochHash [32]byte, users [][]byte) []byte {
	t.Helper()
	var out []byte
	uv := func(v uint64) { out = binary.AppendUvarint(out, v) }
	uv(o.batchTs - bp.L2GenesisTime) // rel_timestamp
	uv(o.epochNum)                   // l1_origin_num
	out = append(out, parent[:20]...)
	out = append(out, epochHash[:20]...)
	uv(1) // block_count
	out = append(out, 0x00)
	uv(uint64(len(users)))
	n := uint64(len(users))
	bitsLen := int((n + 7) / 8)
	out = append(out, make([]byte, bitsLen)...) // contract_creation_bits: none
	yp := make([]byte, bitsLen)
	var sigs, tos, datas []byte
	var nonces, gases []uint64
	for i, raw := range users {
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		v, r, s := tx.RawSignatureValues()
		if v.Sign() != 0 {
			yp[i/8] |= 1 << (uint(i) % 8)
		}
		sigs = append(sigs, common.LeftPadBytes(r.Bytes(), 32)...)
		sigs = append(sigs, common.LeftPadBytes(s.Bytes(), 32)...)
		tos = append(tos, tx.To().Bytes()...)
		pl, _ := rlp.EncodeToBytes([]any{uint256.MustFromBig(tx.Value()), uint256.MustFromBig(tx.GasTipCap()), uint256.MustFromBig(tx.GasFeeCap()), tx.Data(), tx.AccessList()})
		datas = append(datas, append([]byte{types.DynamicFeeTxType}, pl...)...)
		nonces = append(nonces, tx.Nonce())
		gases = append(gases, tx.Gas())
	}
	// y_parity_bits is a big-endian integer, bit i = tx i: re-pack
	ypInt := new(big.Int)
	for i := range users {
		if yp[i/8]>>(uint(i)%8)&1 == 1 {
			ypInt.SetBit(ypInt, i, 1)
		}
	}
	out = append(out, ypInt.FillBytes(make([]byte, bitsLen))...)
	out = append(out, sigs...)
	out = append(out, tos...)
	out = append(out, datas...)
	for _, v := range nonces {
		uv(v)
	}
	for _, v := range gases {
		uv(v)
	}
	// protected_bits: no legacy transactions, zero bits
	return out
}

func (s *synth) verify() (finality.Verdict, error) {
	v, err := verifyChannel(s.bp, s.body, s.covered, s.l2, s.head)
	return v, err
}

func wantCode(t *testing.T, err error, code string, fields map[string]string) {
	t.Helper()
	se, ok := finality.AsNamed(err)
	if !ok {
		t.Fatalf("want %s, got %v", code, err)
	}
	if se.Code != code {
		t.Fatalf("want %s, got %s", code, se.Canonical())
	}
	for k, v := range fields {
		got := string(bytes.Trim(se.Canonical(), ""))
		_ = got
		var gotV string
		if x, ok := se.Fields[k]; ok {
			gotV = string(bytes.Trim(canon(x), `"`))
		}
		if gotV != v {
			t.Fatalf("%s: field %s = %q, want %q (%s)", code, k, gotV, v, se.Canonical())
		}
	}
}

func canon(v any) []byte {
	e := finality.NewState("x", "k", v)
	c := e.Canonical()
	// {"code":"x","fields":{"k":<v>}}
	i := bytes.Index(c, []byte(`"k":`))
	return c[i+4 : len(c)-2]
}
