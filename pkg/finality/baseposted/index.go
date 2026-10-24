// Copyright 2026 Certen Protocol

package baseposted

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/metrics"
)

// RB12-INDEX-A: the Base capture index (design/RB12_CAPTURE_INDEX.md). Rows live in the capture store under
// idx/g<generation>/bi/...:
//
//	f              block digest, at the captured block's own key: the frames each batch-inbox transaction carries
//	c/<tmin>/<tmax>/<channel>   channel entry, at the key of the block holding the channel's LAST frame: the transactions that carry
//	                            it and the L2 timestamps its batches cover (the name carries the timestamp range)
//	x/<channel>    duplicate-after-close marker, at the entry's key
//	cursor         the L1 block the indexer has processed through (8 bytes, zero hash)
//
// Every row is a pure function of captured bytes (and the pins that decide how a channel is decoded): two validators that index the
// same block write the same bytes, and a different row under an existing key is the named error finality.ErrIndexConflict.
// The index is a locator, never evidence: Builder assembles the evidence from the captured rows and the kind's verifier judges it.

// FamilyBaseInbox is the family name of the Base batch-inbox index.
const FamilyBaseInbox = "bi"

const (
	itemDigest  = "f"
	itemChannel = "c"
	itemMarker  = "x"
	// itemQuarantine is the self-check mismatch record of a channel: written at the entry's key by the first validator whose self-check finds the
	// entry different from what the captured rows give, shared through the table, read by every build that would use the entry.
	itemQuarantine = "q"
	// itemUnindexable is the record of a captured block the indexer cannot read (Note (a)): insert-only, at the block's key, the reason as content.
	itemUnindexable = "u"
)

const (
	// digestVersion 2 carries the pins digest in the row (RB12-INDEX-FIX): the digest bytes depend on the SystemConfig, its implementation hashes
	// and the L1 chain id (the batcher filter), so a digest written under other pins is the named stale-pins state, never a conflicting write.
	// Nothing of version 1 has shipped, so generation 1 is unchanged.
	digestVersion = 2
	// entryVersion 2 adds the position of the first frame inside its transaction (FirstFrame), the last part of the order between channels
	// (RB12-INDEX-FIX D5). Generation 1 is unchanged because no entry of version 1 has shipped.
	entryVersion = 2
)

// Entry status.
const (
	entryDecoded          uint8 = 1 // complete channel, decompressed and decoded; runs hold the covered timestamps
	entryDecodeFailed     uint8 = 2 // complete channel that does not decompress or decode: it carries no batch (findChannel skips it too)
	entryCoverageOverflow uint8 = 3 // more coverage runs than maxRuns: not served by the index (named, never guessed)
)

// maxRuns bounds the coverage runs of one channel entry (65,536 runs ~ 1.6 MB).
const maxRuns = 1 << 16

// Kinds of a digested transaction.
const (
	kindCalldata uint8 = 0
	kindBlob     uint8 = 1
)

// ---- digest ----

type digestFrame struct {
	ID     [16]byte
	Number uint16
	Last   bool
	Len    uint32
}

type digestTx struct {
	Index  uint32
	Blobs  uint32
	Kind   uint8
	Frames []digestFrame
}

// blockDigest is the frames of one captured block (chain, number, hash).
type blockDigest struct {
	Block uint64
	Hash  [32]byte
	Pins  [8]byte
	Txs   []digestTx
}

func sumTrailer(body []byte) []byte {
	s := sha256.Sum256(body)
	return s[:8]
}

func (d *blockDigest) encode() []byte {
	var w finality.Writer
	w.U8(digestVersion)
	w.Fixed(d.Pins[:])
	w.Count(len(d.Txs))
	for _, t := range d.Txs {
		w.U32(t.Index)
		w.U32(t.Blobs)
		w.U8(t.Kind)
		w.Count(len(t.Frames))
		for _, f := range t.Frames {
			w.Fixed(f.ID[:])
			w.U32(uint32(f.Number))
			if f.Last {
				w.U8(1)
			} else {
				w.U8(0)
			}
			w.U32(f.Len)
		}
	}
	return append(w.Bytes(), sumTrailer(w.Bytes())...)
}

func checked(b []byte) ([]byte, error) {
	if len(b) < 9 {
		return nil, fmt.Errorf("index row is %d bytes", len(b))
	}
	body, sum := b[:len(b)-8], b[len(b)-8:]
	if !bytes.Equal(sumTrailer(body), sum) {
		return nil, fmt.Errorf("index row checksum")
	}
	return body, nil
}

func decodeDigest(k finality.CaptureKey, b []byte) (*blockDigest, error) {
	body, err := checked(b)
	if err != nil {
		return nil, err
	}
	r := finality.NewReader(body, finality.DefaultLimits())
	v, err := r.U8("digest.version")
	if err != nil || v != digestVersion {
		return nil, fmt.Errorf("digest version %d", v)
	}
	d := &blockDigest{Block: k.L1Block, Hash: k.L1Hash}
	p, err := r.Fixed("digest.pins", 8)
	if err != nil {
		return nil, err
	}
	copy(d.Pins[:], p)
	n, err := r.Count("digest.txs", 1<<16, 13)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		var t digestTx
		if t.Index, err = r.U32("digest.tx.index"); err != nil {
			return nil, err
		}
		if t.Blobs, err = r.U32("digest.tx.blobs"); err != nil {
			return nil, err
		}
		if t.Kind, err = r.U8("digest.tx.kind"); err != nil {
			return nil, err
		}
		m, err := r.Count("digest.frames", 1<<20, 25)
		if err != nil {
			return nil, err
		}
		for j := 0; j < m; j++ {
			var f digestFrame
			id, err := r.Fixed("digest.frame.id", 16)
			if err != nil {
				return nil, err
			}
			copy(f.ID[:], id)
			num, err := r.U32("digest.frame.number")
			if err != nil || num > 0xffff {
				return nil, fmt.Errorf("digest frame number")
			}
			f.Number = uint16(num)
			last, err := r.U8("digest.frame.last")
			if err != nil || last > 1 {
				return nil, fmt.Errorf("digest frame last")
			}
			f.Last = last == 1
			if f.Len, err = r.U32("digest.frame.len"); err != nil {
				return nil, err
			}
			t.Frames = append(t.Frames, f)
		}
		d.Txs = append(d.Txs, t)
	}
	if err := r.End("digest"); err != nil {
		return nil, err
	}
	return d, nil
}

// ---- entry ----

type entryTx struct {
	Block uint64
	Hash  [32]byte
	Index uint32
	Blobs uint32
}

type covRun struct {
	First uint64 // timestamp of the first batch
	Count uint32 // batches in the run, one L2 block time apart
	Type  uint8  // batch type (0 singular, 1 span)
	Epoch uint64 // L1 origin number of the batches
}

type chanEntry struct {
	Status uint8
	Pins   [8]byte
	ID     [16]byte
	// the position of the first frame in capture order (the order between channels that cover one timestamp)
	FirstBlock uint64
	FirstHash  [32]byte
	FirstTx    uint32
	FirstFrame uint32 // the position of the first frame inside its transaction
	NFrames    uint32
	TMin, TMax uint64
	Txs        []entryTx
	Runs       []covRun
}

func (e *chanEntry) encode() []byte {
	var w finality.Writer
	w.U8(entryVersion)
	w.U8(e.Status)
	w.Fixed(e.Pins[:])
	w.Fixed(e.ID[:])
	w.U64(e.FirstBlock)
	w.B32(e.FirstHash)
	w.U32(e.FirstTx)
	w.U32(e.FirstFrame)
	w.U32(e.NFrames)
	w.U64(e.TMin)
	w.U64(e.TMax)
	w.Count(len(e.Txs))
	for _, t := range e.Txs {
		w.U64(t.Block)
		w.B32(t.Hash)
		w.U32(t.Index)
		w.U32(t.Blobs)
	}
	w.Count(len(e.Runs))
	for _, r := range e.Runs {
		w.U64(r.First)
		w.U32(r.Count)
		w.U8(r.Type)
		w.U64(r.Epoch)
	}
	return append(w.Bytes(), sumTrailer(w.Bytes())...)
}

func decodeEntry(b []byte) (*chanEntry, error) {
	body, err := checked(b)
	if err != nil {
		return nil, err
	}
	r := finality.NewReader(body, finality.DefaultLimits())
	v, err := r.U8("entry.version")
	if err != nil || v != entryVersion {
		return nil, fmt.Errorf("entry version %d", v)
	}
	e := &chanEntry{}
	if e.Status, err = r.U8("entry.status"); err != nil {
		return nil, err
	}
	if e.Status < entryDecoded || e.Status > entryCoverageOverflow {
		return nil, fmt.Errorf("entry status %d", e.Status)
	}
	p, err := r.Fixed("entry.pins", 8)
	if err != nil {
		return nil, err
	}
	copy(e.Pins[:], p)
	id, err := r.Fixed("entry.id", 16)
	if err != nil {
		return nil, err
	}
	copy(e.ID[:], id)
	if e.FirstBlock, err = r.U64("entry.first_block"); err != nil {
		return nil, err
	}
	if e.FirstHash, err = r.B32("entry.first_hash"); err != nil {
		return nil, err
	}
	if e.FirstTx, err = r.U32("entry.first_tx"); err != nil {
		return nil, err
	}
	if e.FirstFrame, err = r.U32("entry.first_frame"); err != nil {
		return nil, err
	}
	if e.NFrames, err = r.U32("entry.frames"); err != nil {
		return nil, err
	}
	if e.TMin, err = r.U64("entry.tmin"); err != nil {
		return nil, err
	}
	if e.TMax, err = r.U64("entry.tmax"); err != nil {
		return nil, err
	}
	n, err := r.Count("entry.txs", 1<<16, 48)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		var t entryTx
		if t.Block, err = r.U64("entry.tx.block"); err != nil {
			return nil, err
		}
		if t.Hash, err = r.B32("entry.tx.hash"); err != nil {
			return nil, err
		}
		if t.Index, err = r.U32("entry.tx.index"); err != nil {
			return nil, err
		}
		if t.Blobs, err = r.U32("entry.tx.blobs"); err != nil {
			return nil, err
		}
		e.Txs = append(e.Txs, t)
	}
	m, err := r.Count("entry.runs", maxRuns, 21)
	if err != nil {
		return nil, err
	}
	for i := 0; i < m; i++ {
		var c covRun
		if c.First, err = r.U64("entry.run.first"); err != nil {
			return nil, err
		}
		if c.Count, err = r.U32("entry.run.count"); err != nil {
			return nil, err
		}
		if c.Type, err = r.U8("entry.run.type"); err != nil {
			return nil, err
		}
		if c.Epoch, err = r.U64("entry.run.epoch"); err != nil {
			return nil, err
		}
		e.Runs = append(e.Runs, c)
	}
	if err := r.End("entry"); err != nil {
		return nil, err
	}
	// a channel has at least one frame and every transaction of the entry carries at least one of them: anything else is corruption that a
	// valid checksum does not excuse (a build would otherwise index an empty list)
	if e.NFrames == 0 || len(e.Txs) == 0 || uint32(len(e.Txs)) > e.NFrames {
		return nil, fmt.Errorf("entry with %d frames and %d transactions", e.NFrames, len(e.Txs))
	}
	return e, nil
}

// covers reports whether a run holds a batch at timestamp t when batches are step seconds apart.
func (c covRun) covers(t, step uint64) bool {
	if c.Count == 0 || step == 0 || t < c.First {
		return false
	}
	d := t - c.First
	return d%step == 0 && d/step < uint64(c.Count)
}

// pinsDigest binds an index row to the pins that decide how a channel is decoded.
func pinsDigest(bp *Pins) [8]byte {
	// every pin the bytes of the digests and entries depend on: how a channel is decoded (chain, genesis, block time, size bound), which
	// frames belong to the batcher (the L1 chain id of the signer, the SystemConfig and the implementations it may run) and which channels
	// have an entry (the sequencing window)
	impls := make([]string, 0, len(bp.SystemConfigImplHashes))
	for h, ok := range bp.SystemConfigImplHashes {
		if ok {
			impls = append(impls, hex.EncodeToString(h[:]))
		}
	}
	sort.Strings(impls)
	s := sha256.Sum256([]byte(fmt.Sprintf("certen/baseposted-index/2|chain=%d|l1=%d|genesis=%d|blocktime=%d|maxrlp=%d|seqwin=%d|syscfg=%x|impls=%s",
		bp.ChainID, bp.L1ChainID, bp.L2GenesisTime, bp.L2BlockTime, bp.MaxRLPBytesPerChannel, bp.SeqWindowSize, bp.SystemConfig, strings.Join(impls, ","))))
	var out [8]byte
	copy(out[:], s[:8])
	return out
}

// runsOf folds decoded batches, in order, into coverage runs (a run breaks at a timestamp that is not the next block time, at a type
// change and at an epoch change). ok is false above maxRuns.
func runsOf(batches []Batch, step uint64) (runs []covRun, tmin, tmax uint64, ok bool) {
	ok = true
	for i := range batches {
		b := &batches[i]
		if i == 0 || b.Timestamp < tmin {
			tmin = b.Timestamp
		}
		if i == 0 || b.Timestamp > tmax {
			tmax = b.Timestamp
		}
		if n := len(runs); n > 0 {
			last := &runs[n-1]
			if last.Type == b.Type && last.Epoch == b.EpochNum && last.Count < 1<<31 && b.Timestamp == last.First+uint64(last.Count)*step {
				last.Count++
				continue
			}
		}
		if len(runs) >= maxRuns {
			ok = false // the range is still computed: the entry names it, the runs are not stored
			continue
		}
		runs = append(runs, covRun{First: b.Timestamp, Count: 1, Type: b.Type, Epoch: b.EpochNum})
	}
	return runs, tmin, tmax, ok
}

// ---- names ----

func (r *IndexReader) item(parts ...string) string {
	return finality.IndexItem(r.Gen, FamilyBaseInbox, parts...)
}

func channelItem(gen uint32, tmin, tmax uint64, id [16]byte) string {
	return finality.IndexItem(gen, FamilyBaseInbox, itemChannel, strconv.FormatUint(tmin, 10), strconv.FormatUint(tmax, 10), hex.EncodeToString(id[:]))
}

func markerItem(gen uint32, id [16]byte) string {
	return finality.IndexItem(gen, FamilyBaseInbox, itemMarker, hex.EncodeToString(id[:]))
}

func quarantineItem(gen uint32, id [16]byte) string {
	return finality.IndexItem(gen, FamilyBaseInbox, itemQuarantine, hex.EncodeToString(id[:]))
}

// entryName is a channel entry key as the key listing shows it.
type entryName struct {
	Key        finality.CaptureKey
	TMin, TMax uint64
	ID         [16]byte
}

// parseEntryName reads idx/g<gen>/bi/c/<tmin>/<tmax>/<id>.
func parseEntryName(gen uint32, k finality.CaptureKey) (entryName, bool) {
	prefix := finality.IndexItem(gen, FamilyBaseInbox, itemChannel) + "/"
	if !strings.HasPrefix(k.Item, prefix) {
		return entryName{}, false
	}
	parts := strings.Split(k.Item[len(prefix):], "/")
	if len(parts) != 3 {
		return entryName{}, false
	}
	tmin, e1 := strconv.ParseUint(parts[0], 10, 64)
	tmax, e2 := strconv.ParseUint(parts[1], 10, 64)
	id, e3 := hex.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil || len(id) != 16 || tmin > tmax {
		return entryName{}, false
	}
	n := entryName{Key: k, TMin: tmin, TMax: tmax}
	copy(n.ID[:], id)
	return n, true
}

// unindexableError marks a failure that comes from the CONTENT of a captured block's rows (not from the store): the indexer records the block
// as unindexable and goes on, because the rows will not change.
type unindexableError struct {
	Reason string
	Err    error
}

func (e *unindexableError) Error() string { return "unindexable (" + e.Reason + "): " + e.Err.Error() }
func (e *unindexableError) Unwrap() error { return e.Err }

func unindexableItem(gen uint32) string {
	return finality.IndexItem(gen, FamilyBaseInbox, itemUnindexable)
}

// ---- loading the rows of a transaction ----

// loadedTx is one batch-inbox transaction with its blob rows (and, when asked, the frames it carries).
type loadedTx struct {
	key     finality.CaptureKey // (chain, block, hash, ItemInbox): the same key loadRange gives its capturedTx
	index   uint32
	raw     []byte
	blobs   []Blob
	frames  []Frame
	isBlob  bool
	foreign bool  // the batcher of the block did not send it: no blob row was read and no frame taken (F19)
	read    int64 // stored bytes read
}

// loadTxRows reads the rows of one inbox transaction of the captured block bk (chain, block, hash): the transaction and, for a blob
// transaction, every blob row. It is the per-transaction body of loadRange (the reference), with the frames parsed only when asked.
// Every row read is reserved against hold first (nil: unbounded).
func loadTxRows(ctx context.Context, store finality.CaptureStore, bk finality.CaptureKey, idx uint32, hold *finality.Hold, parse bool, flt *senderFilter) (loadedTx, error) {
	chain := bk.Chain
	reserve := func(n int) error {
		if hold == nil {
			return nil
		}
		return hold.Add(rowCost(n))
	}
	bk.Item = ItemInbox
	lt := loadedTx{key: bk, index: idx}
	tk := bk
	tk.Item = ItemTx(idx)
	txb, ok, err := store.Get(ctx, tk)
	if err != nil {
		return lt, err
	}
	if !ok {
		return lt, finality.IndexInconsistent(chain, FamilyBaseInbox, finality.IndexRowMissing, "item", tk.Item, "l1_block", bk.L1Block)
	}
	lt.read += int64(len(txb))
	if err := reserve(len(txb)); err != nil {
		return lt, err
	}
	lt.raw = txb
	var tx txView
	if err := tx.parse(txb); err != nil {
		return lt, &unindexableError{Reason: finality.UnindexableTxUnparseable, Err: err}
	}
	lt.isBlob = tx.isBlob
	if flt.foreign(txb) {
		lt.foreign = true
		return lt, nil
	}
	var datas [][]byte
	if tx.isBlob {
		for j := 0; ; j++ {
			bkk := bk
			bkk.Item = ItemBlob(idx, j)
			bb, ok, err := store.Get(ctx, bkk)
			if err != nil {
				return lt, err
			}
			if !ok {
				break
			}
			lt.read += int64(len(bb))
			if err := reserve(len(bb)); err != nil {
				return lt, err
			}
			br := finality.NewReader(bb, finality.DefaultLimits())
			var bl Blob
			if bl.Raw, err = br.LP("blob.raw", BlobSize); err != nil {
				return lt, &unindexableError{Reason: finality.UnindexableBlobRowMalformed, Err: err}
			}
			c, _ := br.Fixed("blob.commitment", 48)
			p, _ := br.Fixed("blob.proof", 48)
			copy(bl.Commitment[:], c)
			copy(bl.Proof[:], p)
			lt.blobs = append(lt.blobs, bl)
			if !parse {
				continue
			}
			d, err := blobToData(bl.Raw)
			if err != nil {
				continue // a blob that is not frame data belongs to no channel
			}
			datas = append(datas, d)
		}
	} else if parse {
		datas = append(datas, tx.data)
	}
	if parse && tx.isBlob && len(lt.blobs) != tx.nBlobs {
		// the capturer writes every blob row of a transaction or none: fewer rows (a missing or non-contiguous index) is a block that was not
		// captured whole, and the frames it carries cannot be told from the frames it lost
		return lt, &unindexableError{Reason: finality.UnindexableBlobRowsInconsistent, Err: fmt.Errorf("%d blob rows for a transaction naming %d blobs", len(lt.blobs), tx.nBlobs)}
	}
	if parse {
		for _, d := range datas {
			if fr, err := parseFrames(d); err == nil {
				lt.frames = append(lt.frames, fr...)
			}
		}
	}
	return lt, nil
}

// loadBlockTxs reads every inbox transaction of one captured block (chain, number, hash) with its frames: the digest of the block is
// built from it. A block whose inbox row is absent is a block without the capturer's completion row.
func loadBlockTxs(ctx context.Context, store finality.CaptureStore, bk finality.CaptureKey, bp *Pins, hold *finality.Hold) ([]loadedTx, error) {
	ik := bk
	ik.Item = ItemInbox
	raw, ok, err := store.Get(ctx, ik)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, finality.IndexInconsistent(bk.Chain, FamilyBaseInbox, finality.IndexRowMissing, "item", ItemInbox, "l1_block", bk.L1Block)
	}
	if hold != nil {
		if err := hold.Add(rowCost(len(raw))); err != nil {
			return nil, err
		}
	}
	flt, err := loadSenderFilter(ctx, store, bk, bp, hold, true)
	if err != nil {
		return nil, err
	}
	r := finality.NewReader(raw, finality.DefaultLimits())
	n, err := r.Count("inbox", 4096, 4)
	if err != nil {
		reason := finality.UnindexableInboxMalformed
		if len(raw) >= 4 && uint32(raw[0])<<24|uint32(raw[1])<<16|uint32(raw[2])<<8|uint32(raw[3]) > 4096 {
			reason = finality.UnindexableInboxOverLimit
		}
		return nil, &unindexableError{Reason: reason, Err: err}
	}
	var out []loadedTx
	for i := 0; i < n; i++ {
		idx, err := r.U32("inbox.index")
		if err != nil {
			return nil, &unindexableError{Reason: finality.UnindexableInboxMalformed, Err: err}
		}
		lt, err := loadTxRows(ctx, store, bk, idx, hold, true, flt)
		if err != nil {
			return nil, err
		}
		if lt.foreign {
			metrics.AddFinalityCaptureForeignTxs(bk.Chain, 1)
			continue
		}
		out = append(out, lt)
	}
	return out, nil
}

// digestOf builds the digest of a block from its loaded transactions.
func digestOf(bk finality.CaptureKey, txs []loadedTx) *blockDigest {
	d := &blockDigest{Block: bk.L1Block, Hash: bk.L1Hash}
	for _, t := range txs {
		dt := digestTx{Index: t.index, Blobs: uint32(len(t.blobs)), Kind: kindCalldata}
		if t.isBlob {
			dt.Kind = kindBlob
		}
		for _, f := range t.frames {
			dt.Frames = append(dt.Frames, digestFrame{ID: f.ID, Number: f.Number, Last: f.IsLast, Len: uint32(len(f.Data))})
		}
		d.Txs = append(d.Txs, dt)
	}
	return d
}

// ---- the frame table: the channels of the digests, in capture order ----

type frameRef struct {
	Block    uint64
	Hash     [32]byte
	TxPos    int // position of the transaction in the block's inbox order
	TxIndex  uint32
	Blobs    uint32
	FrameIdx int // position of the frame in its transaction
	Number   uint16
	Last     bool
}

func (a frameRef) less(b frameRef) bool {
	if a.Block != b.Block {
		return a.Block < b.Block
	}
	if c := bytes.Compare(a.Hash[:], b.Hash[:]); c != 0 {
		return c < 0
	}
	if a.TxPos != b.TxPos {
		return a.TxPos < b.TxPos
	}
	return a.FrameIdx < b.FrameIdx
}

// frameTable holds the frames of a set of block digests by channel id, each channel's frames in capture order: (block, hash, inbox
// position, position in the transaction), the order findChannel assembles them in.
type frameTable struct {
	digests map[finality.CaptureKey]*blockDigest
	byCh    map[[16]byte][]frameRef
}

func newFrameTable() *frameTable {
	return &frameTable{digests: map[finality.CaptureKey]*blockDigest{}, byCh: map[[16]byte][]frameRef{}}
}

func digestKey(chain uint64, d *blockDigest) finality.CaptureKey {
	return finality.CaptureKey{Chain: chain, L1Block: d.Block, L1Hash: d.Hash}
}

// channelIDs is the channel ids a digest carries frames of, in order of first appearance.
func channelIDs(d *blockDigest) [][16]byte {
	seen := map[[16]byte]bool{}
	var ids [][16]byte
	for _, t := range d.Txs {
		for _, f := range t.Frames {
			if !seen[f.ID] {
				seen[f.ID] = true
				ids = append(ids, f.ID)
			}
		}
	}
	return ids
}

// add inserts a digest (once).
func (ft *frameTable) add(chain uint64, d *blockDigest) {
	k := digestKey(chain, d)
	if _, dup := ft.digests[k]; dup {
		return
	}
	ft.digests[k] = d
	for pos, t := range d.Txs {
		for fi, f := range t.Frames {
			ref := frameRef{Block: d.Block, Hash: d.Hash, TxPos: pos, TxIndex: t.Index, Blobs: t.Blobs, FrameIdx: fi, Number: f.Number, Last: f.Last}
			s := ft.byCh[f.ID]
			i := sort.Search(len(s), func(i int) bool { return ref.less(s[i]) })
			s = append(s, frameRef{})
			copy(s[i+1:], s[i:])
			s[i] = ref
			ft.byCh[f.ID] = s
		}
	}
}

// prune drops the digests of blocks below block and the frames they carry.
func (ft *frameTable) prune(block uint64) {
	var drop bool
	for k := range ft.digests {
		if k.L1Block < block {
			delete(ft.digests, k)
			drop = true
		}
	}
	if !drop {
		return
	}
	for id, s := range ft.byCh {
		out := s[:0]
		for _, f := range s {
			if f.Block >= block {
				out = append(out, f)
			}
		}
		if len(out) == 0 {
			delete(ft.byCh, id)
		} else {
			ft.byCh[id] = out
		}
	}
}

// complete is verifyChannel's O4 (and findChannel's) predicate on the ordered frames of one channel: numbered 0..n-1, only the last
// closes.
func complete(fr []frameRef) bool {
	if len(fr) == 0 {
		return false
	}
	for i, f := range fr {
		if uint64(f.Number) != uint64(i) || f.Last != (i == len(fr)-1) {
			return false
		}
	}
	return true
}

// txsOf is the distinct transactions that carry the frames, in capture order.
func txsOf(fr []frameRef) []entryTx {
	var out []entryTx
	for _, f := range fr {
		t := entryTx{Block: f.Block, Hash: f.Hash, Index: f.TxIndex, Blobs: f.Blobs}
		if n := len(out); n > 0 && out[n-1] == t {
			continue
		}
		out = append(out, t)
	}
	return out
}

// openChannels is the number of channels of the table that are not complete.
func (ft *frameTable) openChannels() int {
	n := 0
	for _, s := range ft.byCh {
		if !complete(s) {
			n++
		}
	}
	return n
}
