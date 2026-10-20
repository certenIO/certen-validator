// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// ---- THE ITEMS (every name a capture row can carry) ------------------------------------------------------------------
//
// chain is the rollup chain id (421614) for every row. A row is keyed at the L1 block named below.
//
//	header                 key (B, hash(B)). The raw RLP header of L1 block B, exactly as hashed (keccak256 = hash(B)). Written for
//	                       every block that carries a batch event and for every proof block.
//	cursor                 key (B, hash(B)). The scan cursor: logs of the SequencerInbox were read through B. Value be64(B) || B32 hash(B).
//	batch/<N>              key (E, hash(E)) with E the L1 block of the SequencerBatchDelivered event of batch N. A BatchRecord.
//	blob/<N>/<j>           key (E, hash(E)). Blob j (0-based, in the order of the batch transaction's blobVersionedHashes) of batch N:
//	                       raw blob (131072) || KZG commitment (48) || blob proof (48). The versioned hash is
//	                       0x01 || sha256(commitment)[1:] and equals BatchRecord.VersionedHashes[j] (checked before the row is written).
//	calldata/<N>           key (E, hash(E)). dataLocation 0 (TxInput): the batch transaction's input (use ExtractTxInputData for the
//	                       batch bytes); dataLocation 1 (SeparateBatchEvent): the `data` of the SequencerBatchData(N, data) event.
//	proof/<N>              key (P, hash(P)) with P the PROOF block (near the head when captured). A ProofRecord of kind ProofBatchAcc:
//	                       Bridge.sequencerInboxAccs[N] (slot 7), the Bridge EIP-1967 implementation slot and the implementation account.
//	delayedproof/<k>       key (P, hash(P)). A ProofRecord of kind ProofDelayedAcc: Bridge.delayedInboxAccs[k] and [k-1] (slot 6), the
//	                       implementation slot and the implementation account. Written for k registered by Capturer.WantDelayed.
//	unavailable/<N>        key (P, hash(P)) with P the head at which a proof could not be obtained. An UnavailableRecord: the redacted
//	                       provider failures behind l1_proof_window_unavailable{l1_block, providers}.
//	blobunavailable/<N>    key (E, hash(E)). A BlobUnavailableRecord: the data behind l1_blob_unavailable{l1_block, versioned_hashes,
//	                       beacon_slot, http_status}. Written once, when the capturer gives up retrying.
//
// Encodings: integers big-endian; B32/B20 raw; LP = u32 length || bytes; LIST = u32 count || elements.

// Item name constructors.
const (
	ItemHeader = "header"
	ItemCursor = "cursor"
)

func ItemBatch(n uint64) string           { return fmt.Sprintf("batch/%d", n) }
func ItemBlob(n uint64, j int) string     { return fmt.Sprintf("blob/%d/%d", n, j) }
func ItemCalldata(n uint64) string        { return fmt.Sprintf("calldata/%d", n) }
func ItemProof(n uint64) string           { return fmt.Sprintf("proof/%d", n) }
func ItemDelayedProof(k uint64) string    { return fmt.Sprintf("delayedproof/%d", k) }
func ItemUnavailable(n uint64) string     { return fmt.Sprintf("unavailable/%d", n) }
func ItemBlobUnavailable(n uint64) string { return fmt.Sprintf("blobunavailable/%d", n) }

// DataLocation is the batch data location of SequencerBatchDelivered (nitro-contracts v3.1.0 IBridge.BatchDataLocation).
const (
	LocTxInput            uint8 = 0
	LocSeparateBatchEvent uint8 = 1
	LocNoData             uint8 = 2
	LocBlob               uint8 = 3
)

// MaxNodes bounds a decoded node set so a corrupt row never allocates without limit.
const (
	maxNodes     = 8192
	maxNodeBytes = 1 << 20
	maxVHashes   = 64
	maxTxBytes   = 4 << 20
)

type wr struct{ b []byte }

func (w *wr) u8(v uint8)     { w.b = append(w.b, v) }
func (w *wr) u32(v uint32)   { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *wr) u64(v uint64)   { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *wr) raw(b []byte)   { w.b = append(w.b, b...) }
func (w *wr) lp(b []byte)    { w.u32(uint32(len(b))); w.raw(b) }
func (w *wr) b32(b [32]byte) { w.raw(b[:]) }

var errShort = errors.New("capture: record truncated")

type rd struct {
	b   []byte
	off int
	err error
}

func (r *rd) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = errShort
		return false
	}
	return true
}
func (r *rd) u8() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}
func (r *rd) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v
}
func (r *rd) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v
}
func (r *rd) fixed(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := append([]byte(nil), r.b[r.off:r.off+n]...)
	r.off += n
	return v
}
func (r *rd) b32() (out [32]byte) { copy(out[:], r.fixed(32)); return }
func (r *rd) lp(max int) []byte {
	n := r.u32()
	if r.err != nil {
		return nil
	}
	if int64(n) > int64(max) {
		r.err = fmt.Errorf("capture: field of %d bytes exceeds %d", n, max)
		return nil
	}
	return r.fixed(int(n))
}
func (r *rd) end() error {
	if r.err == nil && r.off != len(r.b) {
		r.err = fmt.Errorf("capture: %d trailing bytes", len(r.b)-r.off)
	}
	return r.err
}

// ---- BatchRecord ----------------------------------------------------------------------------------------------------

const batchMagic = "ACB1"

// BatchRecord is one SequencerBatchDelivered event with its transaction: everything the verifier's preimage needs except the
// proof and the data. Encoding: "ACB1" || u64 N || B32 beforeAcc || B32 afterAcc || B32 delayedAcc || 5 x u64 header40 (in
// packHeader order: minTimestamp, maxTimestamp, minBlockNumber, maxBlockNumber, afterDelayedMessagesRead) || u8 dataLocation ||
// u64 l1Block || B32 l1Hash || B32 txHash || u64 txIndex || LP txRaw || LIST<B32> versionedHashes.
type BatchRecord struct {
	N               uint64
	BeforeAcc       [32]byte
	AfterAcc        [32]byte
	DelayedAcc      [32]byte
	Header40        [5]uint64
	DataLocation    uint8
	L1Block         uint64
	L1Hash          [32]byte
	TxHash          [32]byte
	TxIndex         uint64
	TxRaw           []byte
	VersionedHashes [][32]byte
}

func (r BatchRecord) Encode() []byte {
	var w wr
	w.raw([]byte(batchMagic))
	w.u64(r.N)
	w.b32(r.BeforeAcc)
	w.b32(r.AfterAcc)
	w.b32(r.DelayedAcc)
	for _, v := range r.Header40 {
		w.u64(v)
	}
	w.u8(r.DataLocation)
	w.u64(r.L1Block)
	w.b32(r.L1Hash)
	w.b32(r.TxHash)
	w.u64(r.TxIndex)
	w.lp(r.TxRaw)
	w.u32(uint32(len(r.VersionedHashes)))
	for _, h := range r.VersionedHashes {
		w.b32(h)
	}
	return w.b
}

func DecodeBatchRecord(b []byte) (BatchRecord, error) {
	var out BatchRecord
	r := &rd{b: b}
	if string(r.fixed(4)) != batchMagic {
		return out, errors.New("capture: not a batch record")
	}
	out.N = r.u64()
	out.BeforeAcc, out.AfterAcc, out.DelayedAcc = r.b32(), r.b32(), r.b32()
	for i := range out.Header40 {
		out.Header40[i] = r.u64()
	}
	out.DataLocation = r.u8()
	out.L1Block = r.u64()
	out.L1Hash = r.b32()
	out.TxHash = r.b32()
	out.TxIndex = r.u64()
	out.TxRaw = r.lp(maxTxBytes)
	n := r.u32()
	if r.err == nil && n > maxVHashes {
		r.err = fmt.Errorf("capture: %d versioned hashes", n)
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		out.VersionedHashes = append(out.VersionedHashes, r.b32())
	}
	return out, r.end()
}

// Header40Bytes is the 40-byte packHeader of the batch: the 5 u64 big-endian, concatenated.
func (r BatchRecord) Header40Bytes() []byte {
	var w wr
	for _, v := range r.Header40 {
		w.u64(v)
	}
	return w.b
}

// DataHash is the accumulator's data hash of a blob batch: keccak256(header40 || 0x50 || versionedHashes...). For the calldata
// locations pass the batch data: keccak256(header40 || data).
func (r BatchRecord) DataHash(data []byte) [32]byte {
	var pre []byte
	pre = append(pre, r.Header40Bytes()...)
	if r.DataLocation == LocBlob {
		pre = append(pre, 0x50)
		for _, h := range r.VersionedHashes {
			pre = append(pre, h[:]...)
		}
	} else {
		pre = append(pre, data...)
	}
	return crypto.Keccak256Hash(pre)
}

// ConsistentAcc checks keccak256(beforeAcc || dataHash || delayedAcc) == afterAcc for the record (a capture-time sanity check;
// the verifier recomputes it from the evidence and compares with the PROVEN value, never with the event).
func (r BatchRecord) ConsistentAcc(data []byte) bool {
	acc := crypto.Keccak256Hash(r.BeforeAcc[:], func() []byte { h := r.DataHash(data); return h[:] }(), r.DelayedAcc[:])
	return acc == r.AfterAcc
}

// ---- Blob rows -------------------------------------------------------------------------------------------------------

// BlobRecord is a blob row: raw || commitment || proof.
type BlobRecord struct {
	Raw        []byte // 131072
	Commitment [48]byte
	Proof      [48]byte
}

const BlobBytes = 131072

func (b BlobRecord) Encode() []byte {
	out := make([]byte, 0, BlobBytes+96)
	out = append(out, b.Raw...)
	out = append(out, b.Commitment[:]...)
	return append(out, b.Proof[:]...)
}

func DecodeBlobRecord(b []byte) (BlobRecord, error) {
	var out BlobRecord
	if len(b) != BlobBytes+96 {
		return out, fmt.Errorf("capture: blob row of %d bytes, want %d", len(b), BlobBytes+96)
	}
	out.Raw = append([]byte(nil), b[:BlobBytes]...)
	copy(out.Commitment[:], b[BlobBytes:BlobBytes+48])
	copy(out.Proof[:], b[BlobBytes+48:])
	return out, nil
}

// ---- ProofRecord -----------------------------------------------------------------------------------------------------

const proofMagic = "ACP1"

// Proof kinds.
const (
	ProofBatchAcc   uint8 = 1
	ProofDelayedAcc uint8 = 2
)

// ProofRecord is the captured Merkle-Patricia proof set at one proof block. Encoding: "ACP1" || u8 kind || u64 index ||
// u64 proofBlock || B32 proofBlockHash || B20 bridge || B20 implementation (hint: read from the proven slot) || B32 valueN
// (hint: the proven slot value; for kind 2 the value at [index]) || B32 valuePrev (hint; kind 2: the value at [index-1], else 0) ||
// NODES. NODES = u32 count || LP node..., strictly ascending by keccak256(node) and unique: the deduplicated union of the Bridge
// account proof, the storage proofs of the requested slots and the implementation slot, and the implementation account proof.
// The hints are NOT evidence: the verifier selects nodes by root and recomputes every value.
type ProofRecord struct {
	Kind           uint8
	Index          uint64
	ProofBlock     uint64
	ProofBlockHash [32]byte
	Bridge         [20]byte
	Implementation [20]byte
	ValueN         [32]byte
	ValuePrev      [32]byte
	Nodes          [][]byte
}

// SortNodes returns nodes ascending by keccak256, duplicates dropped.
func SortNodes(nodes [][]byte) [][]byte {
	type kv struct {
		h [32]byte
		n []byte
	}
	seen := map[[32]byte]bool{}
	var list []kv
	for _, n := range nodes {
		h := crypto.Keccak256Hash(n)
		if !seen[h] {
			seen[h] = true
			list = append(list, kv{h, n})
		}
	}
	sort.Slice(list, func(i, j int) bool { return bytes.Compare(list[i].h[:], list[j].h[:]) < 0 })
	out := make([][]byte, len(list))
	for i := range list {
		out[i] = list[i].n
	}
	return out
}

func (p ProofRecord) Encode() []byte {
	var w wr
	w.raw([]byte(proofMagic))
	w.u8(p.Kind)
	w.u64(p.Index)
	w.u64(p.ProofBlock)
	w.b32(p.ProofBlockHash)
	w.raw(p.Bridge[:])
	w.raw(p.Implementation[:])
	w.b32(p.ValueN)
	w.b32(p.ValuePrev)
	nodes := SortNodes(p.Nodes)
	w.u32(uint32(len(nodes)))
	for _, n := range nodes {
		w.lp(n)
	}
	return w.b
}

func DecodeProofRecord(b []byte) (ProofRecord, error) {
	var out ProofRecord
	r := &rd{b: b}
	if string(r.fixed(4)) != proofMagic {
		return out, errors.New("capture: not a proof record")
	}
	out.Kind = r.u8()
	out.Index = r.u64()
	out.ProofBlock = r.u64()
	out.ProofBlockHash = r.b32()
	copy(out.Bridge[:], r.fixed(20))
	copy(out.Implementation[:], r.fixed(20))
	out.ValueN, out.ValuePrev = r.b32(), r.b32()
	n := r.u32()
	if r.err == nil && n > maxNodes {
		r.err = fmt.Errorf("capture: %d proof nodes", n)
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		out.Nodes = append(out.Nodes, r.lp(maxNodeBytes))
	}
	return out, r.end()
}

// ---- Unavailable records ---------------------------------------------------------------------------------------------

const unavailMagic = "ACU1"

// UnavailableRecord: "ACU1" || u64 N || u64 eventL1Block || u64 headAtAttempt || LIST<LP failure> where every failure is the
// REDACTED text "provider: error" (pkg/ethrpc RedactText). It is l1_proof_window_unavailable{l1_block = eventL1Block, providers}.
type UnavailableRecord struct {
	N          uint64
	EventBlock uint64
	Head       uint64
	Providers  []string
}

func (u UnavailableRecord) Encode() []byte {
	var w wr
	w.raw([]byte(unavailMagic))
	w.u64(u.N)
	w.u64(u.EventBlock)
	w.u64(u.Head)
	w.u32(uint32(len(u.Providers)))
	for _, p := range u.Providers {
		w.lp([]byte(p))
	}
	return w.b
}

func DecodeUnavailableRecord(b []byte) (UnavailableRecord, error) {
	var out UnavailableRecord
	r := &rd{b: b}
	if string(r.fixed(4)) != unavailMagic {
		return out, errors.New("capture: not an unavailable record")
	}
	out.N, out.EventBlock, out.Head = r.u64(), r.u64(), r.u64()
	n := r.u32()
	if r.err == nil && n > 256 {
		r.err = fmt.Errorf("capture: %d provider failures", n)
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		out.Providers = append(out.Providers, string(r.lp(4096)))
	}
	return out, r.end()
}

const blobUnavailMagic = "ACV1"

// BlobUnavailableRecord: "ACV1" || u64 N || u64 l1Block || u64 beaconSlot || u32 httpStatus (0: transport error) || LIST<B32>
// versionedHashes || LP redacted error text.
type BlobUnavailableRecord struct {
	N               uint64
	L1Block         uint64
	BeaconSlot      uint64
	HTTPStatus      uint32
	VersionedHashes [][32]byte
	Err             string
}

func (u BlobUnavailableRecord) Encode() []byte {
	var w wr
	w.raw([]byte(blobUnavailMagic))
	w.u64(u.N)
	w.u64(u.L1Block)
	w.u64(u.BeaconSlot)
	w.u32(u.HTTPStatus)
	w.u32(uint32(len(u.VersionedHashes)))
	for _, h := range u.VersionedHashes {
		w.b32(h)
	}
	w.lp([]byte(u.Err))
	return w.b
}

func DecodeBlobUnavailableRecord(b []byte) (BlobUnavailableRecord, error) {
	var out BlobUnavailableRecord
	r := &rd{b: b}
	if string(r.fixed(4)) != blobUnavailMagic {
		return out, errors.New("capture: not a blob-unavailable record")
	}
	out.N, out.L1Block, out.BeaconSlot, out.HTTPStatus = r.u64(), r.u64(), r.u64(), r.u32()
	n := r.u32()
	if r.err == nil && n > maxVHashes {
		r.err = fmt.Errorf("capture: %d versioned hashes", n)
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		out.VersionedHashes = append(out.VersionedHashes, r.b32())
	}
	out.Err = string(r.lp(4096))
	return out, r.end()
}

// ---- Calldata ---------------------------------------------------------------------------------------------------------

// ExtractTxInputData returns the batch `data` argument of addSequencerL2BatchFromOrigin (both the 4-argument and 6-argument
// variants carry (uint256 sequenceNumber, bytes data, ...) with `data` as the second argument): the ABI offset word, the length
// word and the bytes. It does not check the selector; the caller has the batch record and the accumulator for that.
func ExtractTxInputData(input []byte) ([]byte, error) {
	if len(input) < 4+64 {
		return nil, errors.New("capture: input too short for an ABI call")
	}
	args := input[4:]
	off := binary.BigEndian.Uint64(args[56:64])
	if !isSmallWord(args[32:56]) || off > uint64(len(args)) || off+32 > uint64(len(args)) {
		return nil, errors.New("capture: bad ABI offset of the data argument")
	}
	if !isSmallWord(args[off : off+24]) {
		return nil, errors.New("capture: bad ABI length of the data argument")
	}
	n := binary.BigEndian.Uint64(args[off+24 : off+32])
	if off+32+n > uint64(len(args)) {
		return nil, errors.New("capture: data argument overruns the input")
	}
	return append([]byte(nil), args[off+32:off+32+n]...), nil
}

func isSmallWord(hi []byte) bool {
	for _, b := range hi {
		if b != 0 {
			return false
		}
	}
	return true
}

// ---- Finding the batch ------------------------------------------------------------------------------------------------

// LoadBatches returns every stored BatchRecord, ascending by N then l1Block (a reorg can give one N under two blocks).
func LoadBatches(s CaptureStore, chain uint64) ([]BatchRecord, error) {
	keys, err := s.Keys(chain, "batch/")
	if err != nil {
		return nil, err
	}
	var out []BatchRecord
	for _, k := range keys {
		b, ok, err := s.Get(k)
		if err != nil || !ok {
			return nil, fmt.Errorf("capture: row %s unreadable: %v", k, err)
		}
		rec, err := DecodeBatchRecord(b)
		if err != nil {
			return nil, fmt.Errorf("capture: row %s: %w", k, err)
		}
		out = append(out, rec)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N < out[j].N
		}
		return out[i].L1Block < out[j].L1Block
	})
	return out, nil
}

// FindBatchContaining returns the captured batches whose [minTimestamp, maxTimestamp] window contains the L2 block timestamp
// ts, newest N last. The time bounds are the sequencer's own commitment (they are in the accumulator preimage, header40); a
// block's batch is among them but the window is wide, so the BUILDER decides by decoding (the verifier needs the message that
// matches the block's transactions, not the window). Hints are never evidence.
func FindBatchContaining(batches []BatchRecord, ts uint64) []BatchRecord {
	var out []BatchRecord
	for _, b := range batches {
		if ts >= b.Header40[0] && ts <= b.Header40[1] {
			out = append(out, b)
		}
	}
	return out
}

// LoadBlobs returns the stored blob rows of batch N under the event key, in order, until the first missing index.
func LoadBlobs(s CaptureStore, chain uint64, rec BatchRecord) ([]BlobRecord, error) {
	var out []BlobRecord
	for j := range rec.VersionedHashes {
		b, ok, err := s.Get(Key{Chain: chain, L1Block: rec.L1Block, L1Hash: rec.L1Hash, Item: ItemBlob(rec.N, j)})
		if err != nil {
			return nil, err
		}
		if !ok {
			return out, nil
		}
		br, err := DecodeBlobRecord(b)
		if err != nil {
			return nil, err
		}
		out = append(out, br)
	}
	return out, nil
}

// LoadProofs returns every ProofRecord stored for batch N (any proof block), ascending by proof block.
func LoadProofs(s CaptureStore, chain uint64, n uint64) ([]ProofRecord, error) {
	keys, err := s.Keys(chain, ItemProof(n))
	if err != nil {
		return nil, err
	}
	var out []ProofRecord
	for _, k := range keys {
		if k.Item != ItemProof(n) {
			continue
		}
		b, ok, err := s.Get(k)
		if err != nil || !ok {
			return nil, fmt.Errorf("capture: row %s unreadable: %v", k, err)
		}
		p, err := DecodeProofRecord(b)
		if err != nil {
			return nil, fmt.Errorf("capture: row %s: %w", k, err)
		}
		out = append(out, p)
	}
	return out, nil
}
