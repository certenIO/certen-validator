// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-A production shape (measured read-only on the live Base capture, 2026-10-23): one channel per captured L1 block, a 6-blob
// transaction (frames 0-5) and a 1-blob transaction (frame 6, closing), every blob row 131,172 bytes, the SystemConfig row 8,536 bytes,
// the header row ~660 bytes, ~2.4 KB of transaction rows, the capture cursor written once per tick. Channels cover 60 L2 blocks (120 s)
// each. Only key names and sizes follow the live rows; frame data is a real zlib channel of singular batches.

const (
	shapeFirstL1 = 11_958_043 // the live first captured inbox block
	shapeSpanL1  = 19_033     // the live span
	shapeTS0     = 1_790_000_000
	shapePerChan = 60 // L2 blocks per channel
)

type shapeBlock struct {
	number uint64
	hash   [32]byte
	txs    []shapeTx
}

type shapeTx struct {
	blob  bool
	datas [][]byte // blob: one derivation payload per blob; calldata: datas[0] is the transaction input
}

func shapeHash(number uint64, variant int) [32]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:], number)
	binary.BigEndian.PutUint64(b[8:], uint64(variant))
	return [32]byte(crypto.Keccak256Hash([]byte("rb12-shape"), b[:]))
}

func bigInt(v int64) *big.Int { return big.NewInt(v) }

func chanLabelID(label string) [16]byte {
	var id [16]byte
	copy(id[:], crypto.Keccak256([]byte("rb12-channel/"+label)))
	return id
}

// channelFrames builds the frames of one channel of n singular batches at timestamps t0, t0+2, ... with L1 origin epoch, split into
// nFrames frames (the last closes it).
func channelFrames(label string, t0 uint64, n int, epoch uint64, nFrames int) []Frame {
	var stream []byte
	epochHash := crypto.Keccak256Hash([]byte("epoch"), []byte(strconv.FormatUint(epoch, 10)))
	for i := 0; i < n; i++ {
		enc, _ := rlp.EncodeToBytes(singularRLP{ParentHash: [32]byte(crypto.Keccak256Hash([]byte(label), []byte{byte(i)})), EpochNum: epoch, EpochHash: [32]byte(epochHash),
			Timestamp: t0 + 2*uint64(i), Txs: [][]byte{userTx(uint64(i))}})
		b, _ := rlp.EncodeToBytes(append([]byte{0}, enc...))
		stream = append(stream, b...)
	}
	data := compress("zlib", stream)
	id := chanLabelID(label)
	per := (len(data) + nFrames - 1) / nFrames
	var out []Frame
	for i := 0; i < nFrames; i++ {
		lo, hi := i*per, (i+1)*per
		if hi > len(data) {
			hi = len(data)
		}
		if lo > hi {
			lo = hi
		}
		out = append(out, Frame{ID: id, Number: uint16(i), Data: data[lo:hi], IsLast: i == nFrames-1})
	}
	return out
}

func payloadOf(frames ...Frame) []byte {
	out := []byte{0}
	for _, f := range frames {
		out = append(out, MarshalFrame(f)...)
	}
	return out
}

// blobTx and calldataTx are the consensus encodings of a batch-inbox transaction (unsigned: the builder reads, the verifier checks).
func blobTxRaw(bp *Pins, nonce uint64, nBlobs int) []byte {
	hashes := make([]common.Hash, nBlobs)
	for i := range hashes {
		hashes[i] = common.Hash{1, byte(nonce), byte(i)}
	}
	tx := types.NewTx(&types.BlobTx{ChainID: uint256.NewInt(11155111), Nonce: nonce, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(2), Gas: 21000,
		To: common.Address(bp.BatchInbox), BlobFeeCap: uint256.NewInt(1), BlobHashes: hashes, V: uint256.NewInt(0), R: uint256.NewInt(1), S: uint256.NewInt(1)})
	raw, _ := tx.MarshalBinary()
	return raw
}

func calldataTxRaw(bp *Pins, nonce uint64, input []byte) []byte {
	to := common.Address(bp.BatchInbox)
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: bigInt(11155111), Nonce: nonce, GasTipCap: bigInt(1), GasFeeCap: bigInt(2), Gas: 21000, To: &to, Data: input})
	raw, _ := tx.MarshalBinary()
	return raw
}

// row is one capture row of the block exactly as the Capturer writes it (false: the block has no such row).
func (sb shapeBlock) row(bp *Pins, item string) ([]byte, bool) {
	switch item {
	case ItemInbox:
		var w finality.Writer
		w.Count(len(sb.txs))
		for i := range sb.txs {
			w.U32(uint32(i))
		}
		return w.Bytes(), true
	case ItemHeader:
		return make([]byte, 660), true
	case ItemSysCfg:
		var sw finality.Writer
		sw.LPList([][]byte{make([]byte, 8000), make([]byte, 400)})
		return sw.Bytes(), true
	}
	var idx uint32
	var j int
	switch {
	case strings.HasPrefix(item, "txnodes/"):
		if _, err := fmt.Sscanf(item, "txnodes/%d", &idx); err != nil || int(idx) >= len(sb.txs) {
			return nil, false
		}
		var nw finality.Writer
		nw.LPList([][]byte{make([]byte, 300), make([]byte, 300), make([]byte, 300)})
		return nw.Bytes(), true
	case strings.HasPrefix(item, "tx/"):
		if _, err := fmt.Sscanf(item, "tx/%d", &idx); err != nil || int(idx) >= len(sb.txs) {
			return nil, false
		}
		t := sb.txs[idx]
		if t.blob {
			return blobTxRaw(bp, uint64(idx), len(t.datas)), true
		}
		return calldataTxRaw(bp, uint64(idx), t.datas[0]), true
	case strings.HasPrefix(item, "blob/"):
		if _, err := fmt.Sscanf(item, "blob/%d/%d", &idx, &j); err != nil || int(idx) >= len(sb.txs) || !sb.txs[idx].blob || j >= len(sb.txs[idx].datas) {
			return nil, false
		}
		blob, err := encodeBlob(sb.txs[idx].datas[j])
		if err != nil {
			panic(err)
		}
		var bw finality.Writer
		bw.LP(blob)
		bw.Fixed(make([]byte, 48))
		bw.Fixed(make([]byte, 48))
		return bw.Bytes(), true
	}
	return nil, false
}

// rows are all the capture rows of one block.
func (sb shapeBlock) rows(bp *Pins) map[string][]byte {
	out := map[string][]byte{}
	items := []string{ItemInbox, ItemHeader, ItemSysCfg}
	for i, t := range sb.txs {
		items = append(items, ItemTx(uint32(i)), ItemTxNodes(uint32(i)))
		if t.blob {
			for j := range t.datas {
				items = append(items, ItemBlob(uint32(i), j))
			}
		}
	}
	for _, it := range items {
		if b, ok := sb.row(bp, it); ok {
			out[it] = b
		}
	}
	return out
}

func (sb shapeBlock) put(t testing.TB, st finality.CaptureStore, bp *Pins) {
	t.Helper()
	for item, data := range sb.rows(bp) {
		if err := st.Put(context.Background(), CaptureKey{Chain: uint64(Chain), L1Block: sb.number, L1Hash: sb.hash, Item: item}, data); err != nil {
			t.Fatal(err)
		}
	}
}

// ---- the lazy production-shaped world: nothing of it is resident ----

// shapeWorld has N channels, one per captured block, Stride L1 blocks apart from First. Rows are generated on Get; a Put (the index rows,
// the cursor) is kept. Holes are channel ranges with no rows at all (a capture gap); ForkAt names one channel whose block exists under a
// second hash with the same frames (a reorged height, as the live table has).
type shapeWorld struct {
	bp     *Pins
	N      int
	Stride uint64
	First  uint64
	Holes  [][2]int
	ForkAt int // -1: none
	mu     sync.Mutex
	extra  map[CaptureKey][]byte
	cache  map[int][]Frame
}

func newShapeWorld(t testing.TB, bp *Pins, channels int, stride uint64) *shapeWorld {
	t.Helper()
	w := &shapeWorld{bp: bp, N: channels, Stride: stride, First: shapeFirstL1, ForkAt: -1, extra: map[CaptureKey][]byte{}, cache: map[int][]Frame{}}
	last := w.numberOf(channels - 1)
	for _, blk := range []uint64{w.First + 31, last + 200} { // the loop keeps scanning (empty) blocks past the last captured one
		var v [8]byte
		binary.BigEndian.PutUint64(v[:], blk)
		w.extra[CaptureKey{Chain: uint64(Chain), L1Block: blk, Item: finality.CaptureCursorItem}] = v[:]
	}
	return w
}

func (w *shapeWorld) numberOf(c int) uint64 { return w.First + uint64(c)*w.Stride }

func (w *shapeWorld) inHole(c int) bool {
	for _, h := range w.Holes {
		if c >= h[0] && c <= h[1] {
			return true
		}
	}
	return false
}

// T0 is the timestamp of the first batch of channel c; the leg timestamp for batch k of it is T0(c)+2k.
func (w *shapeWorld) T0(c int) uint64 { return shapeTS0 + uint64(c)*2*shapePerChan }

// Epoch is the L1 origin the batches of channel c name: a few blocks before the block that carries it.
func (w *shapeWorld) Epoch(c int) uint64 { return w.numberOf(c) - 3 }

func (w *shapeWorld) frames(c int) []Frame {
	w.mu.Lock()
	defer w.mu.Unlock()
	if f, ok := w.cache[c]; ok {
		return f
	}
	if len(w.cache) > 512 {
		w.cache = map[int][]Frame{}
	}
	f := channelFrames("shape/"+strconv.Itoa(c), w.T0(c), shapePerChan, w.Epoch(c), 7)
	w.cache[c] = f
	return f
}

// block is the block of channel c under hash variant v.
func (w *shapeWorld) block(c, v int) shapeBlock {
	fr := w.frames(c)
	first := shapeTx{blob: true}
	for _, f := range fr[:6] {
		first.datas = append(first.datas, payloadOf(f))
	}
	last := shapeTx{blob: true, datas: [][]byte{payloadOf(fr[6])}}
	return shapeBlock{number: w.numberOf(c), hash: shapeHash(w.numberOf(c), v), txs: []shapeTx{first, last}}
}

// locate maps a block number and hash to its channel and variant, if the world holds such a block.
func (w *shapeWorld) locate(number uint64, hash [32]byte) (int, int, bool) {
	if number < w.First || (number-w.First)%w.Stride != 0 {
		return 0, 0, false
	}
	c := int((number - w.First) / w.Stride)
	if c >= w.N || w.inHole(c) {
		return 0, 0, false
	}
	if hash == shapeHash(number, 0) {
		return c, 0, true
	}
	if c == w.ForkAt && hash == shapeHash(number, 1) {
		return c, 1, true
	}
	return 0, 0, false
}

func (w *shapeWorld) variants(c int) []int {
	if c == w.ForkAt {
		return []int{0, 1}
	}
	return []int{0}
}

// itemNames is the sorted item list of every block of the world.
var shapeItems = func() []string {
	items := []string{ItemHeader, ItemInbox, ItemSysCfg, ItemTx(0), ItemTx(1), ItemTxNodes(0), ItemTxNodes(1), ItemBlob(1, 0)}
	for j := 0; j < 6; j++ {
		items = append(items, ItemBlob(0, j))
	}
	sort.Strings(items)
	return items
}()

func (w *shapeWorld) Put(_ context.Context, k CaptureKey, data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if c, v, ok := w.locate(k.L1Block, k.L1Hash); ok {
		_ = c
		_ = v
		for _, it := range shapeItems {
			if it == k.Item {
				cur, _, _ := w.getLocked(k)
				if bytes.Equal(cur, data) {
					return nil
				}
				return finality.ErrCaptureConflict
			}
		}
	}
	if old, ok := w.extra[k]; ok {
		if bytes.Equal(old, data) {
			return nil
		}
		return finality.ErrCaptureConflict
	}
	w.extra[k] = append([]byte(nil), data...)
	return nil
}

func (w *shapeWorld) getLocked(k CaptureKey) ([]byte, bool, error) {
	if b, ok := w.extra[k]; ok {
		return b, true, nil
	}
	if k.Chain != uint64(Chain) {
		return nil, false, nil
	}
	c, v, ok := w.locate(k.L1Block, k.L1Hash)
	if !ok {
		return nil, false, nil
	}
	w.mu.Unlock()
	b, ok := w.block(c, v).row(w.bp, k.Item)
	w.mu.Lock()
	return b, ok, nil
}

func (w *shapeWorld) Get(_ context.Context, k CaptureKey) ([]byte, bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.getLocked(k)
}

func (w *shapeWorld) ListByRange(_ context.Context, chain, from, to uint64, prefix string) ([]CaptureKey, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []CaptureKey
	if chain == uint64(Chain) {
		c0 := 0
		if from > w.First {
			c0 = int((from - w.First + w.Stride - 1) / w.Stride)
		}
		for c := c0; c < w.N && w.numberOf(c) <= to; c++ {
			if w.inHole(c) {
				continue
			}
			for _, v := range w.variants(c) {
				for _, it := range shapeItems {
					if strings.HasPrefix(it, prefix) {
						out = append(out, CaptureKey{Chain: chain, L1Block: w.numberOf(c), L1Hash: shapeHash(w.numberOf(c), v), Item: it})
					}
				}
			}
		}
	}
	for k := range w.extra {
		if k.Chain == chain && k.L1Block >= from && k.L1Block <= to && strings.HasPrefix(k.Item, prefix) {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].L1Block != out[j].L1Block {
			return out[i].L1Block < out[j].L1Block
		}
		if c := bytes.Compare(out[i].L1Hash[:], out[j].L1Hash[:]); c != 0 {
			return c < 0
		}
		return out[i].Item < out[j].Item
	})
	return out, nil
}

func (w *shapeWorld) ListByBlock(ctx context.Context, chain, l1Block uint64) ([]finality.CaptureRow, error) {
	keys, err := w.ListByRange(ctx, chain, l1Block, l1Block, "")
	if err != nil {
		return nil, err
	}
	var out []finality.CaptureRow
	for _, k := range keys {
		b, _, _ := w.Get(ctx, k)
		out = append(out, finality.CaptureRow{CaptureKey: k, Bytes: b})
	}
	return out, nil
}

// BlockBounds answers from the geometry (the aggregate query of the database store).
func (w *shapeWorld) BlockBounds(ctx context.Context, chain uint64, item string) (lo, hi uint64, ok bool, err error) {
	ks, err := w.ListByRange(ctx, chain, 0, finality.MaxCaptureBlock, item)
	if err != nil {
		return 0, 0, false, err
	}
	for _, k := range ks {
		if k.Item != item {
			continue
		}
		if !ok || k.L1Block < lo {
			lo = k.L1Block
		}
		if !ok || k.L1Block > hi {
			hi = k.L1Block
		}
		ok = true
	}
	return lo, hi, ok, nil
}

// bytes of the world's rows (stored size) for the budget of a test.
func (w *shapeWorld) StoredBytes() int64 {
	per := int64(7*131172 + 8536 + 660 + 2*(260+920) + 20)
	return per * int64(w.N-countHoles(w.Holes))
}

func countHoles(h [][2]int) int {
	n := 0
	for _, r := range h {
		n += r[1] - r[0] + 1
	}
	return n
}

// legAt returns the leg timestamp and the origin for batch k of channel c.
func (w *shapeWorld) legAt(c, k int) (ts, origin uint64) {
	return w.T0(c) + 2*uint64(k), w.Epoch(c)
}

func (w *shapeWorld) String() string {
	return fmt.Sprintf("shape world: %d channels, stride %d, holes %v, fork %d", w.N, w.Stride, w.Holes, w.ForkAt)
}

var _ finality.CaptureStore = (*shapeWorld)(nil)
