// Copyright 2026 Certen Protocol

package arbposted

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/finality"
)

// RB12-INDEX-B: the Arbitrum batch index (design/RB12_CAPTURE_INDEX.md section 8) on the generic framework of pkg/finality/capindex.go. Rows
// live in the capture store under idx/g<generation>/arb/...:
//
//	f/<T>                    block digest at the captured block's own key (L1 block E, its hash): the batches of the block, once ALL of
//	                         their data rows are stored. T is the L1 timestamp of E (the name lets a lookup find a time in the digests)
//	e/<minTs>/<maxTs>/<N>    batch entry at the same key: the batch's time bounds, what its payload decoded to (the fingerprints of its
//	                         messages' standard-transaction lists) and the binding to the batch row it was made from
//	q/<N>                    self-check quarantine record at the entry's key
//	u                        record of a captured block the indexer cannot read (insert-only, the reason as content)
//	cursor                   the L1 block the indexer has processed through (8 bytes, zero hash)
//
// What the index is for. The reference reader (Builder.locate) loads and brotli-decodes EVERY captured batch whose time bounds hold the
// leg's L2 timestamp (a window of 87,168 s = about a thousand batches, 3 blobs each) before it can say that no batch holds the leg; the
// index decodes each batch ONCE, ever, and a lookup reads only the entries of the window and the rows of the one batch it locates.
//
// How a batch is located, established from the code and the spec (not assumed): the verifier binds neither a time window nor an absolute
// message position (verify.go verifyState; research A6.4: poster-reported message counts are not evidence). It accepts any batch N the
// Bridge holds whose payload has a message whose signed transactions are the block's. The builder narrows the candidates by the batch's
// own time bounds (a hint) and serves the FIRST candidate in (N, L1 block) order that holds the message. The index reproduces exactly that
// rule: candidates are the entries whose [minTs, maxTs] holds the leg timestamp, in the same order, and a candidate is tried only when the
// 8-byte fingerprint of the leg's standard-transaction list is among the fingerprints of its messages. A fingerprint is a pre-filter: the
// located batch is loaded and judged by the SAME per-candidate function as the reference (matchCandidate), so a collision costs one decode
// and can never serve a batch that does not hold the message.
//
// The index is a locator, never evidence (a wrong row yields a named state or a pending, never an addendum the reference would not also
// produce); every row is a pure function of captured rows and the pins digest; a different row under an existing key is the named error
// finality.ErrIndexConflict.

// FamilyArb is the family name of the Arbitrum batch index.
const FamilyArb = "arb"

// batchKeyPrefix is the prefix of the capture items of the batch records (capture.ItemBatch).
const batchKeyPrefix = "batch/"

const (
	ixDigest     = "f"
	ixEntry      = "e"
	ixQuarantine = "q"
	ixUnindexed  = "u"
)

const (
	ixDigestVersion = 1
	ixEntryVersion  = 1
)

// Entry status.
const (
	entryDecoded  uint8 = 1 // the payload decodes: fps are the fingerprints of its messages
	entrySkipped  uint8 = 2 // the batch cannot be read as messages (the reference skips such a candidate): no fingerprint
	entryNoData   uint8 = 3 // no data on L1 (forced inclusion, an unknown data location): nothing to match
	entryOverflow uint8 = 4 // more messages than an entry stores: not served by the index (named, never guessed)
)

// maxFps bounds the fingerprints of one entry (131,072 x 8 B = 1 MB); the segments pin bounds a batch at 102,400.
const maxFps = 1 << 17

// The time bounds of the SequencerInbox are f(block.timestamp): minTs = T - delaySeconds, maxTs = T + futureSeconds (SequencerInbox
// getTimeBounds, owner-configurable). A lookup finds the batches that can hold a timestamp ts by the time T of their L1 block, which needs a
// bound on both distances. Production: 86,400 and 768 for every one of the 3,229 captured batches. A batch beyond a cap is recorded as
// index_block_unindexable{window_beyond_cap} (named, never silently dropped) and the caps belong to the pins digest.
const (
	windowDelayCap  uint64 = 100_000
	windowFutureCap uint64 = 4_000
)

// ---- digest ----

type digestBatch struct {
	N         uint64
	Loc       uint8
	Parts     uint32 // blob rows (blob batch) or 1 (calldata row); 0 for no data
	RowLen    uint32 // the batch row's stored length
	DataBytes uint64 // the stored length of the data rows
}

type arbDigest struct {
	Block   uint64
	Hash    [32]byte
	T       uint64
	Pins    [8]byte
	Batches []digestBatch
}

func sumTrailer(body []byte) []byte {
	s := sha256.Sum256(body)
	return s[:8]
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

func (d *arbDigest) encode() []byte {
	var w finality.Writer
	w.U8(ixDigestVersion)
	w.Fixed(d.Pins[:])
	w.U64(d.T)
	w.Count(len(d.Batches))
	for _, b := range d.Batches {
		w.U64(b.N)
		w.U8(b.Loc)
		w.U32(b.Parts)
		w.U32(b.RowLen)
		w.U64(b.DataBytes)
	}
	return append(w.Bytes(), sumTrailer(w.Bytes())...)
}

func decodeDigest(k finality.CaptureKey, b []byte) (*arbDigest, error) {
	body, err := checked(b)
	if err != nil {
		return nil, err
	}
	r := finality.NewReader(body, finality.DefaultLimits())
	v, err := r.U8("digest.version")
	if err != nil || v != ixDigestVersion {
		return nil, fmt.Errorf("digest version %d", v)
	}
	d := &arbDigest{Block: k.L1Block, Hash: k.L1Hash}
	p, err := r.Fixed("digest.pins", 8)
	if err != nil {
		return nil, err
	}
	copy(d.Pins[:], p)
	if d.T, err = r.U64("digest.t"); err != nil {
		return nil, err
	}
	n, err := r.Count("digest.batches", 1<<16, 21)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		var x digestBatch
		if x.N, err = r.U64("digest.n"); err != nil {
			return nil, err
		}
		if x.Loc, err = r.U8("digest.loc"); err != nil {
			return nil, err
		}
		if x.Parts, err = r.U32("digest.parts"); err != nil {
			return nil, err
		}
		if x.RowLen, err = r.U32("digest.rowlen"); err != nil {
			return nil, err
		}
		if x.DataBytes, err = r.U64("digest.databytes"); err != nil {
			return nil, err
		}
		if i > 0 && x.N <= d.Batches[i-1].N {
			return nil, fmt.Errorf("digest batches are not ascending")
		}
		d.Batches = append(d.Batches, x)
	}
	if err := r.End("digest"); err != nil {
		return nil, err
	}
	return d, nil
}

// ---- entry ----

type arbEntry struct {
	Status       uint8
	Pins         [8]byte
	N            uint64
	L1Block      uint64
	L1Hash       [32]byte
	T            uint64 // the L1 timestamp of the batch's block
	MinTs, MaxTs uint64 // header40 time bounds
	Loc          uint8
	Parts        uint32
	TxIndex      uint64
	TxHash       [32]byte
	RowLen       uint32 // the batch row this entry was made from: its length and the first 8 bytes of its SHA-256
	RowSum       [8]byte
	Segments     uint32
	Messages     uint32 // L2-message segments (the covered message range is ordinals 0..Messages-1)
	Delayed      uint32 // delayed-message segments
	Fps          [][8]byte
}

func (e *arbEntry) encode() []byte {
	var w finality.Writer
	w.U8(ixEntryVersion)
	w.U8(e.Status)
	w.Fixed(e.Pins[:])
	w.U64(e.N)
	w.U64(e.L1Block)
	w.B32(e.L1Hash)
	w.U64(e.T)
	w.U64(e.MinTs)
	w.U64(e.MaxTs)
	w.U8(e.Loc)
	w.U32(e.Parts)
	w.U64(e.TxIndex)
	w.B32(e.TxHash)
	w.U32(e.RowLen)
	w.Fixed(e.RowSum[:])
	w.U32(e.Segments)
	w.U32(e.Messages)
	w.U32(e.Delayed)
	w.Count(len(e.Fps))
	for _, f := range e.Fps {
		w.Fixed(f[:])
	}
	return append(w.Bytes(), sumTrailer(w.Bytes())...)
}

func decodeEntry(b []byte) (*arbEntry, error) {
	body, err := checked(b)
	if err != nil {
		return nil, err
	}
	r := finality.NewReader(body, finality.DefaultLimits())
	v, err := r.U8("entry.version")
	if err != nil || v != ixEntryVersion {
		return nil, fmt.Errorf("entry version %d", v)
	}
	e := &arbEntry{}
	if e.Status, err = r.U8("entry.status"); err != nil {
		return nil, err
	}
	if e.Status < entryDecoded || e.Status > entryOverflow {
		return nil, fmt.Errorf("entry status %d", e.Status)
	}
	p, err := r.Fixed("entry.pins", 8)
	if err != nil {
		return nil, err
	}
	copy(e.Pins[:], p)
	if e.N, err = r.U64("entry.n"); err != nil {
		return nil, err
	}
	if e.L1Block, err = r.U64("entry.l1block"); err != nil {
		return nil, err
	}
	if e.L1Hash, err = r.B32("entry.l1hash"); err != nil {
		return nil, err
	}
	if e.T, err = r.U64("entry.t"); err != nil {
		return nil, err
	}
	if e.MinTs, err = r.U64("entry.mints"); err != nil {
		return nil, err
	}
	if e.MaxTs, err = r.U64("entry.maxts"); err != nil {
		return nil, err
	}
	if e.Loc, err = r.U8("entry.loc"); err != nil {
		return nil, err
	}
	if e.Parts, err = r.U32("entry.parts"); err != nil {
		return nil, err
	}
	if e.TxIndex, err = r.U64("entry.txindex"); err != nil {
		return nil, err
	}
	if e.TxHash, err = r.B32("entry.txhash"); err != nil {
		return nil, err
	}
	if e.RowLen, err = r.U32("entry.rowlen"); err != nil {
		return nil, err
	}
	rs, err := r.Fixed("entry.rowsum", 8)
	if err != nil {
		return nil, err
	}
	copy(e.RowSum[:], rs)
	if e.Segments, err = r.U32("entry.segments"); err != nil {
		return nil, err
	}
	if e.Messages, err = r.U32("entry.messages"); err != nil {
		return nil, err
	}
	if e.Delayed, err = r.U32("entry.delayed"); err != nil {
		return nil, err
	}
	n, err := r.Count("entry.fps", maxFps, 8)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		f, err := r.Fixed("entry.fp", 8)
		if err != nil {
			return nil, err
		}
		var x [8]byte
		copy(x[:], f)
		if i > 0 && bytes.Compare(e.Fps[i-1][:], x[:]) >= 0 {
			return nil, fmt.Errorf("entry fingerprints are not strictly ascending")
		}
		e.Fps = append(e.Fps, x)
	}
	if err := r.End("entry"); err != nil {
		return nil, err
	}
	// the shape rules a valid checksum does not excuse: only a decoded entry carries fingerprints, a messages count bounds them, and a
	// batch row is never empty
	if e.Status != entryDecoded && len(e.Fps) != 0 {
		return nil, fmt.Errorf("entry status %d with %d fingerprints", e.Status, len(e.Fps))
	}
	if uint64(len(e.Fps)) > uint64(e.Messages) || e.RowLen == 0 {
		return nil, fmt.Errorf("entry with %d fingerprints, %d messages and a row of %d bytes", len(e.Fps), e.Messages, e.RowLen)
	}
	return e, nil
}

// rowSum is the binding of an entry to the batch row it was made from.
func rowSum(row []byte) [8]byte {
	s := sha256.Sum256(row)
	var out [8]byte
	copy(out[:], s[:8])
	return out
}

// ---- fingerprints ----

// messageFp is the 8-byte fingerprint of a message's signed-transaction list: the first bytes of SHA-256 over a domain tag, the count and
// the length-prefixed transactions. Two lists with equal fingerprints are compared byte for byte by the per-candidate judgement; two
// equal lists always have equal fingerprints (sameTxs is list equality).
func messageFp(txs [][]byte) [8]byte {
	h := sha256.New()
	h.Write([]byte("certen/arbposted-index/msg/1"))
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(txs)))
	h.Write(n[:])
	for _, tx := range txs {
		binary.BigEndian.PutUint32(n[:], uint32(len(tx)))
		h.Write(n[:])
		h.Write(tx)
	}
	var out [8]byte
	copy(out[:], h.Sum(nil)[:8])
	return out
}

// fpsOf is the sorted, distinct fingerprints of the messages that carry at least one signed transaction (a message without one can match no
// block: the leg's standard list is never empty on the index path).
func fpsOf(msgs []l2Message) [][8]byte {
	seen := map[[8]byte]bool{}
	var out [][8]byte
	for _, m := range msgs {
		if len(m.txs) == 0 {
			continue
		}
		f := messageFp(m.txs)
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

func hasFp(fps [][8]byte, f [8]byte) bool {
	i := sort.Search(len(fps), func(i int) bool { return bytes.Compare(fps[i][:], f[:]) >= 0 })
	return i < len(fps) && fps[i] == f
}

// ---- pins ----

// pinsDigest binds an index row to everything its bytes depend on: how a batch is decoded (the segment and size bounds), which record is a
// batch the Bridge holds (the Bridge and its accumulator slot), the chain, the window caps that decide where a lookup looks, and the
// fingerprint version.
func pinsDigest(a *arbPins) [8]byte {
	s := sha256.Sum256([]byte(fmt.Sprintf("certen/arbposted-index/1|chain=%d|parent=%d|bridge=%x|accslot=%d|maxblobs=%d|maxseg=%d|maxuncomp=%d|dcap=%d|fcap=%d|fp=1",
		a.ChainID, a.ParentChainID, a.bridge[:], a.Layout.AccArraySlot, a.MaxBlobs, a.MaxSegments, a.MaxUncompressedBatch, windowDelayCap, windowFutureCap)))
	var out [8]byte
	copy(out[:], s[:8])
	return out
}

// ---- names ----

func ixItem(gen uint32, parts ...string) string { return finality.IndexItem(gen, FamilyArb, parts...) }

func digestItem(gen uint32, t uint64) string {
	return ixItem(gen, ixDigest, strconv.FormatUint(t, 10))
}

func entryItem(gen uint32, minTs, maxTs, n uint64) string {
	return ixItem(gen, ixEntry, strconv.FormatUint(minTs, 10), strconv.FormatUint(maxTs, 10), strconv.FormatUint(n, 10))
}

func quarantineItem(gen uint32, n uint64) string {
	return ixItem(gen, ixQuarantine, strconv.FormatUint(n, 10))
}

func unindexedItem(gen uint32) string { return ixItem(gen, ixUnindexed) }

// entryName is an entry key as the key listing shows it.
type entryName struct {
	Key          finality.CaptureKey
	MinTs, MaxTs uint64
	N            uint64
}

// parseEntryName reads idx/g<gen>/arb/e/<minTs>/<maxTs>/<N>.
func parseEntryName(gen uint32, k finality.CaptureKey) (entryName, bool) {
	prefix := ixItem(gen, ixEntry) + "/"
	if !strings.HasPrefix(k.Item, prefix) {
		return entryName{}, false
	}
	parts := strings.Split(k.Item[len(prefix):], "/")
	if len(parts) != 3 {
		return entryName{}, false
	}
	lo, e1 := strconv.ParseUint(parts[0], 10, 64)
	hi, e2 := strconv.ParseUint(parts[1], 10, 64)
	n, e3 := strconv.ParseUint(parts[2], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || lo > hi || strconv.FormatUint(lo, 10) != parts[0] || strconv.FormatUint(hi, 10) != parts[1] || strconv.FormatUint(n, 10) != parts[2] {
		return entryName{}, false
	}
	return entryName{Key: k, MinTs: lo, MaxTs: hi, N: n}, true
}

// parseDigestName reads idx/g<gen>/arb/f/<T>.
func parseDigestName(gen uint32, k finality.CaptureKey) (uint64, bool) {
	prefix := ixItem(gen, ixDigest) + "/"
	if !strings.HasPrefix(k.Item, prefix) {
		return 0, false
	}
	s := k.Item[len(prefix):]
	t, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(t, 10) != s {
		return 0, false
	}
	return t, true
}

// batchNumber reads N from a capture item name batch/<N>.
func batchNumber(item string) (uint64, bool) {
	s, ok := strings.CutPrefix(item, batchKeyPrefix)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s {
		return 0, false
	}
	return n, true
}

func hexShort(b [32]byte) string { return hex.EncodeToString(b[:4]) }

// ioCount counts the stored bytes a lookup read.
type ioCount struct{ n int64 }

func (c *ioCount) add(n int) {
	if c != nil {
		c.n += int64(n)
	}
}

// blockID identifies a captured block (number and hash) as a map key.
func blockID(k finality.CaptureKey) [40]byte {
	var out [40]byte
	binary.BigEndian.PutUint64(out[:8], k.L1Block)
	copy(out[8:], k.L1Hash[:])
	return out
}
