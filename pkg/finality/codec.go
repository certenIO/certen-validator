// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/binary"

	"github.com/ethereum/go-ethereum/crypto"
)

// This file is the strict codec of the CFE1 evidence container (V2_SPEC_S7 sections 0 and 3). Integers are unsigned
// big-endian; lp(x) = u32be(len(x)) || x; STR = lp(ASCII) with no NUL; LIST<T> = u32be(count) || T...; NODES is a LIST of
// lp() trie nodes, strictly ascending by keccak256(node) and unique. Decoding is strict: a short field, a count above its
// bound, an unordered node set or a trailing byte is a named refusal, and encode(decode(x)) == x for every x accepted.

// Limits are the DoS bounds of V2_SPEC_S7 section 8.2. Exceeding one reports the number and refuses; it never truncates.
type Limits struct {
	MaxEvidenceBytes     int // evidence container, 64 MiB
	MaxLinks             int
	MaxSpineHeaders      int // Sepolia/Base L1 spines and Adiri max_headers
	MaxHeaderChain       int // Arbitrum
	MaxL2Headers         int // Base
	MaxBlobsBase         int
	MaxBlobsArbitrum     int
	MaxFrameTxs          int
	MaxDepositTxs        int
	MaxBlockTxs          int
	MaxNodes             int // per NODES set
	MaxNodeBytes         int // state and storage trie nodes
	MaxTxLeafBytes       int // transaction and receipt trie nodes
	MaxCodeBytes         int // gameCode
	MaxCFA1Tables        int
	MaxCFA1Records       int
	MaxSigners           int
	MaxSegments          int
	MaxUncompressedBatch int
	MaxStringBytes       int // any STR
}

// DefaultLimits are the section 8.2 values. The pins file of section 4.2 carries the per-chain ones; the generic ones
// (max_nodes, max_node_bytes, max_tx_leaf_bytes, max_frame_txs, ...) have no pins section in the spec and are held here:
// raising one is a verifier release, recorded as a finding of RB11-B2A.
func DefaultLimits() Limits {
	return Limits{
		MaxEvidenceBytes: 64 << 20, MaxLinks: 64, MaxSpineHeaders: 16384, MaxHeaderChain: 32768, MaxL2Headers: 1024,
		MaxBlobsBase: 32, MaxBlobsArbitrum: 16, MaxFrameTxs: 256, MaxDepositTxs: 4096, MaxBlockTxs: 65536,
		MaxNodes: 8192, MaxNodeBytes: 4096, MaxTxLeafBytes: 2097152, MaxCodeBytes: 262144,
		MaxCFA1Tables: 64, MaxCFA1Records: 65536, MaxSigners: 255, MaxSegments: 102400, MaxUncompressedBatch: 16777216,
		MaxStringBytes: 255,
	}
}

// Writer builds a container body.
type Writer struct{ b []byte }

func (w *Writer) U8(v uint8)     { w.b = append(w.b, v) }
func (w *Writer) U32(v uint32)   { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *Writer) U64(v uint64)   { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *Writer) Fixed(b []byte) { w.b = append(w.b, b...) }
func (w *Writer) B32(b [32]byte) { w.b = append(w.b, b[:]...) }
func (w *Writer) LP(b []byte)    { w.U32(uint32(len(b))); w.b = append(w.b, b...) }
func (w *Writer) STR(s string)   { w.LP([]byte(s)) }
func (w *Writer) Count(n int)    { w.U32(uint32(n)) }
func (w *Writer) Bytes() []byte  { return w.b }
func (w *Writer) LPList(l [][]byte) {
	w.Count(len(l))
	for _, e := range l {
		w.LP(e)
	}
}

// Nodes writes a NODES set. The caller passes nodes in strictly ascending keccak256 order; EncodeNodes sorts and
// deduplicates for it.
func (w *Writer) Nodes(sorted [][]byte) { w.LPList(sorted) }

// Reader decodes a container body strictly. Every method names the part it reads so that a refusal says where.
type Reader struct {
	b   []byte
	off int
	lim Limits
}

// NewReader reads b under lim.
func NewReader(b []byte, lim Limits) *Reader { return &Reader{b: b, lim: lim} }

// Left is the number of unread bytes.
func (r *Reader) Left() int { return len(r.b) - r.off }

func (r *Reader) short(part string, want int) *StateError {
	return Malformed(part, ReasonTruncated, r.Left(), want)
}

func (r *Reader) U8(part string) (uint8, error) {
	if r.Left() < 1 {
		return 0, r.short(part, 1)
	}
	v := r.b[r.off]
	r.off++
	return v, nil
}

func (r *Reader) U32(part string) (uint32, error) {
	if r.Left() < 4 {
		return 0, r.short(part, 4)
	}
	v := binary.BigEndian.Uint32(r.b[r.off:])
	r.off += 4
	return v, nil
}

func (r *Reader) U64(part string) (uint64, error) {
	if r.Left() < 8 {
		return 0, r.short(part, 8)
	}
	v := binary.BigEndian.Uint64(r.b[r.off:])
	r.off += 8
	return v, nil
}

// Fixed reads exactly n bytes (B16, B20, B32, B48...).
func (r *Reader) Fixed(part string, n int) ([]byte, error) {
	if r.Left() < n {
		return nil, r.short(part, n)
	}
	out := append([]byte(nil), r.b[r.off:r.off+n]...)
	r.off += n
	return out, nil
}

func (r *Reader) B32(part string) ([32]byte, error) {
	var out [32]byte
	b, err := r.Fixed(part, 32)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// LP reads a length-prefixed byte string of at most max bytes (max < 0: only the remaining length bounds it). The length is
// checked against the bound and against what remains before anything is sliced.
func (r *Reader) LP(part string, max int) ([]byte, error) {
	n, err := r.U32(part + ".len")
	if err != nil {
		return nil, err
	}
	if max >= 0 && uint64(n) > uint64(max) {
		return nil, EvidenceTooLarge(part, uint64(n), uint64(max))
	}
	if uint64(n) > uint64(r.Left()) {
		return nil, Malformed(part, ReasonLengthExceedsRemaining, r.Left(), int(n))
	}
	out := append([]byte(nil), r.b[r.off:r.off+int(n)]...)
	r.off += int(n)
	return out, nil
}

// STR reads an ASCII string with no NUL, at most MaxStringBytes long.
func (r *Reader) STR(part string) (string, error) {
	b, err := r.LP(part, r.lim.MaxStringBytes)
	if err != nil {
		return "", err
	}
	for i, c := range b {
		if c == 0 || c > 0x7f {
			return "", MalformedAt(part, i, ReasonStrNotASCIIOrNUL, len(b), len(b))
		}
	}
	return string(b), nil
}

// Count reads a LIST count and refuses one above limit (finality_evidence_too_large) or one that cannot fit in the remaining
// bytes at minElem bytes per element (finality_evidence_malformed), so a hostile count never allocates.
func (r *Reader) Count(part string, limit, minElem int) (int, error) {
	n, err := r.U32(part + ".count")
	if err != nil {
		return 0, err
	}
	if uint64(n) > uint64(limit) {
		return 0, EvidenceTooLarge(part, uint64(n), uint64(limit))
	}
	if minElem > 0 && uint64(n)*uint64(minElem) > uint64(r.Left()) {
		return 0, Malformed(part, ReasonCountExceedsRemaining, r.Left(), int(n)*minElem)
	}
	return int(n), nil
}

// LPList reads LIST<LP>: at most limit elements of at most maxElem bytes each.
func (r *Reader) LPList(part string, limit, maxElem int) ([][]byte, error) {
	n, err := r.Count(part, limit, 4)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		e, err := r.LP(part, maxElem)
		if err != nil {
			return nil, withIndex(err, i)
		}
		out = append(out, e)
	}
	return out, nil
}

// Nodes reads a NODES set: at most MaxNodes nodes, strictly ascending by keccak256 and unique, each at most maxNodeBytes
// (MaxNodeBytes for state and storage tries, MaxTxLeafBytes for transaction and receipt tries).
func (r *Reader) Nodes(part string, maxNodeBytes int) ([][]byte, error) {
	nodes, err := r.LPList(part, r.lim.MaxNodes, maxNodeBytes)
	if err != nil {
		return nil, err
	}
	var prev [32]byte
	for i, n := range nodes {
		h := crypto.Keccak256Hash(n)
		if i > 0 && string(h[:]) <= string(prev[:]) {
			return nil, MalformedAt(part, i, ReasonNodesNotAscendingUnique, 0, 0)
		}
		prev = h
	}
	return nodes, nil
}

// End refuses a trailing byte.
func (r *Reader) End(part string) error {
	if r.Left() != 0 {
		return Malformed(part, ReasonTrailingBytes, r.Left(), 0)
	}
	return nil
}

func withIndex(err error, i int) error {
	if s, ok := err.(*StateError); ok {
		out := NewState(s.Code)
		for k, v := range s.Fields {
			out.Fields[k] = v
		}
		if _, has := out.Fields["index"]; !has {
			out.Fields["index"] = uint64(i)
		}
		return out
	}
	return err
}

// EncodeNodes sorts nodes ascending by keccak256 and drops duplicates: the canonical NODES order.
func EncodeNodes(nodes [][]byte) [][]byte {
	type kv struct {
		h [32]byte
		n []byte
	}
	list := make([]kv, 0, len(nodes))
	seen := map[[32]byte]bool{}
	for _, n := range nodes {
		h := crypto.Keccak256Hash(n)
		if seen[h] {
			continue
		}
		seen[h] = true
		list = append(list, kv{h, n})
	}
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && string(list[j].h[:]) < string(list[j-1].h[:]); j-- {
			list[j], list[j-1] = list[j-1], list[j]
		}
	}
	out := make([][]byte, len(list))
	for i := range list {
		out[i] = list[i].n
	}
	return out
}

// ---- the container header (3.1) ----

// ContainerMagic opens every evidence container.
const ContainerMagic = "CFE1"

// ContainerHeader is the header of every kind: "CFE1"(4) || STR kind || u64 chain || u8 level || u64 blockNumber || B32 blockHash.
// kind, chain and level must equal the addendum's; (chain, blockNumber, blockHash) is the leg the evidence is about.
type ContainerHeader struct {
	Kind        string
	Chain       uint64
	Level       Level
	BlockNumber uint64
	BlockHash   [32]byte
}

// Container is a header and the kind's own body (the bytes after the header, parsed by the chain package with a Reader).
type Container struct {
	Header ContainerHeader
	Body   []byte
}

// Encode is the canonical encoding. A level that is not stored (1 included is derived, 0 none) is refused.
func (c Container) Encode() ([]byte, error) {
	if !c.Header.Level.Stored() {
		return nil, Malformed("header.level", ReasonLevelNotStored, int(c.Header.Level), 2)
	}
	var w Writer
	w.Fixed([]byte(ContainerMagic))
	w.STR(c.Header.Kind)
	w.U64(c.Header.Chain)
	w.U8(uint8(c.Header.Level))
	w.U64(c.Header.BlockNumber)
	w.B32(c.Header.BlockHash)
	w.Fixed(c.Body)
	return w.Bytes(), nil
}

// DecodeContainer parses the header strictly and returns the body bytes. The container size is bounded first
// (max 64 MiB); the magic, the kind STR, the level (2 or 3 only) and the header's fixed fields each have a named refusal.
func DecodeContainer(b []byte, lim Limits) (Container, error) {
	var c Container
	if len(b) > lim.MaxEvidenceBytes {
		return c, EvidenceTooLarge("evidence", uint64(len(b)), uint64(lim.MaxEvidenceBytes))
	}
	r := NewReader(b, lim)
	magic, err := r.Fixed("header.magic", 4)
	if err != nil {
		return c, err
	}
	if string(magic) != ContainerMagic {
		return c, EvidenceUnrecognised("", "magic:"+hexLower(magic))
	}
	if c.Header.Kind, err = r.STR("header.kind"); err != nil {
		return c, err
	}
	if c.Header.Chain, err = r.U64("header.chain"); err != nil {
		return c, err
	}
	lv, err := r.U8("header.level")
	if err != nil {
		return c, err
	}
	if !Level(lv).Stored() {
		return c, Malformed("header.level", ReasonLevelNotStored, int(lv), 2)
	}
	c.Header.Level = Level(lv)
	if c.Header.BlockNumber, err = r.U64("header.blockNumber"); err != nil {
		return c, err
	}
	if c.Header.BlockHash, err = r.B32("header.blockHash"); err != nil {
		return c, err
	}
	c.Body = append([]byte(nil), b[r.off:]...)
	return c, nil
}
