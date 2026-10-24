// Copyright 2026 Certen Protocol

package arbposted

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbposted/capture"
)

// RB12-INDEX-B test world: a synthetic Arbitrum capture store with REAL encodings (blobs, brotli payloads, segments, messages) and L1 header
// rows whose hash is their key, in which the reference reader (LoadBatches + Builder.locate) and the indexed reader (IndexReader.Locate)
// are asked the same questions.

const ixChain = finality.ChainArbitrumSepolia

// ixBatch describes one captured batch.
type ixBatch struct {
	N       uint64
	Block   uint64 // the L1 block of the event
	T       uint64 // the L1 timestamp of that block
	Tag     byte   // distinguishes the block hash of twins (a reorg)
	MinTs   uint64 // 0: T - 86,400
	MaxTs   uint64 // 0: T + 768
	Msgs    [][][]byte
	Loc     uint8 // 0 means capture.LocBlob
	Garbage bool  // the data is not a payload
	Blobs   int   // blob rows stored (0 with Partial false: all)
	Partial bool  // store only Blobs of the blob rows
	NoHdr   bool  // no header row
	AccTag  byte  // changes the batch's beforeAcc, so a twin can be another record of the same N
}

// ixTx returns a plausible signed standard transaction (type 0) distinguished by tag.
func ixTx(tag int) []byte {
	b, _ := rlp.EncodeToBytes([]any{uint64(tag), big.NewInt(1), uint64(21000), make([]byte, 20), big.NewInt(int64(tag)), []byte{byte(tag), byte(tag >> 8)}, big.NewInt(27), big.NewInt(1), big.NewInt(2)})
	return b
}

// ixBigTx is a transaction of about size bytes of data that does not compress (a deterministic expansion of tag), so a batch of them fills blobs.
func ixBigTx(tag, size int) []byte {
	data := make([]byte, 0, size+32)
	for i := 0; len(data) < size; i++ {
		data = append(data, crypto.Keccak256([]byte{byte(tag), byte(tag >> 8), byte(i), byte(i >> 8)})...)
	}
	b, _ := rlp.EncodeToBytes([]any{uint64(tag), big.NewInt(1), uint64(21000), make([]byte, 20), big.NewInt(int64(tag)), data[:size], big.NewInt(27), big.NewInt(1), big.NewInt(2)})
	return b
}

// ixMsg is one L2 message of the given transactions: one transaction is a kind-4 message, several a kind-3 batch.
func ixMsg(txs ...[]byte) [][]byte { return txs }

func ixPayload(msgs [][][]byte) []byte {
	var segs [][]byte
	for _, m := range msgs {
		var body []byte
		if len(m) == 1 {
			body = signedTxMsg(m[0])
		} else {
			parts := make([][]byte, len(m))
			for i, tx := range m {
				parts[i] = signedTxMsg(tx)
			}
			body = batchMsg(parts...)
		}
		segs = append(segs, seg(segL2Message, body))
	}
	return payloadOf(segs...)
}

type ixWorld struct {
	t     *testing.T
	store *capture.MemStore
	pins  *finality.Pins
	arb   *arbPins
	keys  map[uint64][]finality.CaptureKey
	recs  map[finality.CaptureKey]capture.BatchRecord
	top   uint64
	low   uint64
}

func newIxWorld(t *testing.T) *ixWorld {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "finality_arb_posted1", "raw", "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	pins, err := finality.ParsePinsOverride(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := loadArbPins(pins)
	if err != nil {
		t.Fatal(err)
	}
	return &ixWorld{t: t, store: capture.NewMemStore(), pins: pins, arb: a, keys: map[uint64][]finality.CaptureKey{}, recs: map[finality.CaptureKey]capture.BatchRecord{}}
}

func ixHeader(number, time uint64, root common.Hash) ([]byte, [32]byte) {
	h := &types.Header{Number: new(big.Int).SetUint64(number), Time: time, Root: root, ParentHash: common.Hash{byte(number), 1}, Difficulty: big.NewInt(0), BaseFee: big.NewInt(7),
		UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash, TxHash: types.EmptyTxsHash}
	raw, err := rlp.EncodeToBytes(h)
	if err != nil {
		panic(err)
	}
	return raw, crypto.Keccak256Hash(raw)
}

func (w *ixWorld) put(k finality.CaptureKey, b []byte) {
	w.t.Helper()
	if err := w.store.Put(context.Background(), k, b); err != nil {
		w.t.Fatal(err)
	}
}

// add stores a batch the way the capturer does: header + batch record in one unit, then the data rows. It returns the batch's key.
func (w *ixWorld) add(b ixBatch) finality.CaptureKey {
	w.t.Helper()
	hdr, hash := ixHeader(b.Block, b.T, common.Hash{b.Tag})
	if b.Tag != 0 {
		// a twin: another block at the same height
		hdr, hash = ixHeaderTag(b.Block, b.T, b.Tag)
	}
	key := finality.CaptureKey{Chain: ixChain, L1Block: b.Block, L1Hash: hash}
	if !b.NoHdr {
		w.put(withItem(key, capture.ItemHeader), hdr)
	}
	loc := b.Loc
	if loc == 0 {
		loc = capture.LocBlob
	}
	if b.MinTs == 0 {
		b.MinTs = b.T - 86400
	}
	if b.MaxTs == 0 {
		b.MaxTs = b.T + 768
	}
	rec := capture.BatchRecord{N: b.N, BeforeAcc: common.Hash{byte(b.N), 1, b.AccTag}, DelayedAcc: common.Hash{2}, Header40: [5]uint64{b.MinTs, b.MaxTs, b.Block - 7200, b.Block + 64, 0},
		DataLocation: loc, L1Block: b.Block, L1Hash: hash, TxHash: common.Hash{byte(b.N), byte(b.Tag), 9}, TxIndex: b.N % 5, TxRaw: []byte{0x02, 0xc0}}
	payload := ixPayload(b.Msgs)
	if b.Garbage {
		payload = []byte{0x00, 0xde, 0xad, 0xbe, 0xef}
	}
	var blobs [][]byte
	switch loc {
	case capture.LocBlob:
		blobs = encodeBlobs(payload)
		for i := range blobs {
			rec.VersionedHashes = append(rec.VersionedHashes, common.Hash{byte(b.N), byte(i), 0x77})
		}
	case capture.LocTxInput:
		rec.TxRaw = []byte{0x02, 0xc0}
	}
	data := payload
	if loc == capture.LocNoData {
		data = nil
	}
	rec.AfterAcc = Accumulator(rec.BeforeAcc, rec.DataHash(data), rec.DelayedAcc)
	w.put(withItem(key, capture.ItemBatch(b.N)), rec.Encode())
	switch loc {
	case capture.LocBlob:
		n := len(blobs)
		if b.Partial {
			n = b.Blobs
		}
		for j := 0; j < n && j < len(blobs); j++ {
			w.put(withItem(key, capture.ItemBlob(b.N, j)), capture.BlobRecord{Raw: blobs[j]}.Encode())
		}
	case capture.LocTxInput:
		w.put(withItem(key, capture.ItemCalldata(b.N)), ixCalldataInput(payload))
	case capture.LocSeparateBatchEvent:
		w.put(withItem(key, capture.ItemCalldata(b.N)), payload)
	}
	w.keys[b.N] = append(w.keys[b.N], key)
	w.recs[key] = rec
	if b.Block > w.top {
		w.top = b.Block
	}
	if w.low == 0 || b.Block < w.low {
		w.low = b.Block
	}
	return key
}

// ixHeaderTag is a header at the same height as ixHeader's with another hash.
func ixHeaderTag(number, time uint64, tag byte) ([]byte, [32]byte) {
	h := &types.Header{Number: new(big.Int).SetUint64(number), Time: time, Root: common.Hash{tag}, ParentHash: common.Hash{byte(number), tag}, Difficulty: big.NewInt(0), BaseFee: big.NewInt(7),
		UncleHash: types.EmptyUncleHash, ReceiptHash: types.EmptyReceiptsHash, TxHash: types.EmptyTxsHash}
	raw, _ := rlp.EncodeToBytes(h)
	return raw, crypto.Keccak256Hash(raw)
}

// ixCalldataInput wraps batch data as the input of addSequencerL2BatchFromOrigin(uint256 seq, bytes data): selector, seq word, offset word, length word, bytes.
func ixCalldataInput(data []byte) []byte {
	out := []byte{0x8f, 0x11, 0x22, 0x33}
	out = append(out, make([]byte, 32)...)
	off := make([]byte, 32)
	binary.BigEndian.PutUint64(off[24:], 64)
	out = append(out, off...)
	l := make([]byte, 32)
	binary.BigEndian.PutUint64(l[24:], uint64(len(data)))
	out = append(out, l...)
	return append(out, data...)
}

// cursor stores the capture's own cursor row at block (what BlockBoundsOf reads) with a header row, as a capture tick does.
func (w *ixWorld) cursor(block uint64) {
	w.t.Helper()
	hdr, hash := ixHeader(block, 1_790_000_000+block, common.Hash{0xcc})
	key := finality.CaptureKey{Chain: ixChain, L1Block: block, L1Hash: hash}
	w.put(withItem(key, capture.ItemHeader), hdr)
	cur := binary.BigEndian.AppendUint64(nil, block)
	w.put(withItem(key, capture.ItemCursor), append(cur, hash[:]...))
	if block > w.top {
		w.top = block
	}
}

func (w *ixWorld) indexer(cfg IndexConfig) *Indexer {
	w.t.Helper()
	ix, err := NewIndexer(w.store, w.pins, 0, cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	return ix
}

func (w *ixWorld) reader() *IndexReader {
	w.t.Helper()
	r, err := NewIndexReader(w.store, w.pins, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

// stepAll runs steps until the cursor reaches upTo (bounded).
func stepAll(t *testing.T, ix *Indexer, upTo uint64) {
	t.Helper()
	for i := 0; i < 20000; i++ {
		rep, err := ix.Step(context.Background(), upTo)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Through >= upTo && rep.StoppedByCap == "" {
			return
		}
	}
	t.Fatal("the indexer did not reach the target")
}

// index runs a default indexer to the top of the world, after writing the capture cursor.
func (w *ixWorld) index(cfg IndexConfig) *Indexer {
	w.t.Helper()
	w.cursor(w.low - 1)
	w.cursor(w.top + 1)
	ix := w.indexer(cfg)
	stepAll(w.t, ix, w.top+1)
	return ix
}

// outcome is what a reader said about a leg: the batch it located, or the named state / pending reason it ended in.
type outcome struct {
	N, Block uint64
	State    string
}

func (o outcome) String() string { return fmt.Sprintf("N=%d block=%d state=%q", o.N, o.Block, o.State) }

func stateOf(err error) string {
	if err == nil {
		return ""
	}
	if s, ok := finality.AsNamed(err); ok {
		return string(s.Canonical())
	}
	return "error: " + err.Error()
}

// ref asks the REFERENCE reader (every captured batch loaded, every window candidate decoded).
func (w *ixWorld) ref(ts uint64, txs [][]byte) outcome {
	w.t.Helper()
	b := &Builder{Store: w.store, Pins: w.pins}
	batches, err := capture.LoadBatches(context.Background(), w.store, ixChain)
	if err != nil {
		w.t.Fatal(err)
	}
	loc, err := b.locate(context.Background(), batches, finality.HeaderFields{Number: 5, Timestamp: ts}, txs, w.arb)
	if err != nil {
		return outcome{State: stateOf(err)}
	}
	if loc == nil {
		return outcome{State: PendingAwaitingBatchPost}
	}
	return outcome{N: loc.rec.N, Block: loc.rec.L1Block}
}

// idx asks the INDEXED reader.
func (w *ixWorld) idx(r *IndexReader, ts uint64, txs [][]byte) outcome {
	w.t.Helper()
	b := &Builder{Store: w.store, Pins: w.pins, Index: r}
	loc, pend, err := r.Locate(context.Background(), b, finality.HeaderFields{Number: 5, Timestamp: ts}, standardTxs(txs), w.arb)
	switch {
	case err != nil:
		return outcome{State: stateOf(err)}
	case pend != nil:
		return outcome{State: pend.Reason}
	}
	return outcome{N: loc.rec.N, Block: loc.rec.L1Block}
}

func sortedKeys(ks []finality.CaptureKey) []finality.CaptureKey {
	out := append([]finality.CaptureKey(nil), ks...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].L1Block != out[j].L1Block {
			return out[i].L1Block < out[j].L1Block
		}
		if c := strings.Compare(string(out[i].L1Hash[:]), string(out[j].L1Hash[:])); c != 0 {
			return c < 0
		}
		return out[i].Item < out[j].Item
	})
	return out
}

// indexRows returns every index row of the store (item prefix idx/) by key.
func (w *ixWorld) indexRows() map[finality.CaptureKey][]byte {
	w.t.Helper()
	ks, err := w.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, "idx/")
	if err != nil {
		w.t.Fatal(err)
	}
	out := map[finality.CaptureKey][]byte{}
	for _, k := range ks {
		b, _, _ := w.store.Get(context.Background(), k)
		out[k] = b
	}
	return out
}

// clone copies the capture rows (not the index rows) into a new store.
func (w *ixWorld) cloneCapture() *capture.MemStore {
	w.t.Helper()
	out := capture.NewMemStore()
	ks, _ := w.store.ListByRange(context.Background(), ixChain, 0, finality.MaxCaptureBlock, "")
	for _, k := range ks {
		if strings.HasPrefix(k.Item, "idx/") {
			continue
		}
		b, _, _ := w.store.Get(context.Background(), k)
		if err := out.Put(context.Background(), k, b); err != nil {
			w.t.Fatal(err)
		}
	}
	return out
}
