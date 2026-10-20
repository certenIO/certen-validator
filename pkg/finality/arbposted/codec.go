// Copyright 2026 Certen Protocol

// Package arbposted is the Arbitrum Sepolia `l1_posted` level of V2_SPEC_S7 (kind arb-sepolia/l1_posted/v1, spec 3.3 and
// 5.6, annex R11-arbitrum-sepolia A6): the offline verifier, the build logic (capture, then attest) and the evidence codec.
//
// What the level proves, verbatim (spec 1.1): "the sequencer committed in finalized L1 state to batch N whose payload contains
// a message whose signed transactions are exactly this block's signed transactions. It does not prove the block hash or state
// root, nor the message's absolute position." Nothing here claims more.
package arbposted

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// KindName is the evidence kind of this package (spec section 1 table).
const KindName = "arb-sepolia/l1_posted/v1"

// Statement is the section 1.1 wording of what the level proves; the report shows it verbatim and nothing may strengthen it.
const Statement = "the sequencer committed in finalized L1 state to batch N whose payload contains a message whose signed transactions are exactly this block's signed transactions. It does not prove the block hash or state root, nor the message's absolute position."

// Data kinds of the container (spec 3.3: Data = (1 blobs) | (2 calldata) | (3 none)).
const (
	DataBlobs    uint8 = 1
	DataCalldata uint8 = 2
	DataNone     uint8 = 3
)

// BlobBytes is the size of one raw blob.
const BlobBytes = 131072

// maxHeaderBytes bounds one L1 spine header (a header is about 600-700 bytes; the bound only keeps a hostile length from
// allocating). It is a code constant of this package, recorded as a finding for the pins' generic-bounds section.
const maxHeaderBytes = 8192

// Blob is one raw blob with its KZG commitment and blob proof (spec 3.3: Blob = LP raw(131072) || B48 commitment || B48 proof).
type Blob struct {
	Raw        []byte
	Commitment [48]byte
	Proof      [48]byte
}

// Delayed is the delayed-message section (spec 3.3, annex A6.5): the message and the index k of its Bridge delayed accumulator.
type Delayed struct {
	MsgKind        uint8
	Sender         [20]byte
	MsgBlockNumber uint64
	MsgTimestamp   uint64
	BaseFeeL1      [32]byte
	Data           []byte
	K              uint64
}

// Evidence is the body of an arb-sepolia/l1_posted/v1 container, after the CFE1 header.
//
//	LC ||  LIST<LP> l1Spine || u64 stateBlock || LIST<LP> blockTxs || u64 batchSeq || 5 x u64 header40 || B32 beforeAcc || B32 delayedAcc
//	|| u8 dataKind || Data || u8 delayedFlag || [Delayed] || NODES
type Evidence struct {
	LC         ethl1.LC
	L1Spine    [][]byte
	StateBlock uint64
	BlockTxs   [][]byte
	BatchSeq   uint64
	// Header40 is minTimestamp, maxTimestamp, minBlockNumber, maxBlockNumber, afterDelayedMessagesRead, in that order.
	Header40        [5]uint64
	BeforeAcc       [32]byte
	DelayedAcc      [32]byte
	DataKind        uint8
	VersionedHashes [][32]byte // DataBlobs
	Blobs           []Blob     // DataBlobs, one per versioned hash
	Calldata        []byte     // DataCalldata
	Delayed         *Delayed
	Nodes           [][]byte
}

// Bounds are the counts the decoder enforces: the generic ones of finality.DefaultLimits and the pins' per-chain ones.
type Bounds struct {
	finality.Limits
	MaxLinks        int
	MaxSpineHeaders int
	MaxBlobs        int
}

// Encode renders the container body. Nodes are sorted and deduplicated into the canonical NODES order. It does not validate
// the evidence (the vector generator builds invalid evidence on purpose); Decode is the strict half.
func (e Evidence) Encode() []byte {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(e.LC))
	w.LPList(e.L1Spine)
	w.U64(e.StateBlock)
	w.LPList(e.BlockTxs)
	w.U64(e.BatchSeq)
	for _, v := range e.Header40 {
		w.U64(v)
	}
	w.B32(e.BeforeAcc)
	w.B32(e.DelayedAcc)
	w.U8(e.DataKind)
	switch e.DataKind {
	case DataBlobs:
		w.Count(len(e.VersionedHashes))
		for _, h := range e.VersionedHashes {
			w.B32(h)
		}
		w.Count(len(e.Blobs))
		for _, b := range e.Blobs {
			w.LP(b.Raw)
			w.Fixed(b.Commitment[:])
			w.Fixed(b.Proof[:])
		}
	case DataCalldata:
		w.LP(e.Calldata)
	}
	if e.Delayed == nil {
		w.U8(0)
	} else {
		d := e.Delayed
		w.U8(1)
		w.U8(d.MsgKind)
		w.Fixed(d.Sender[:])
		w.U64(d.MsgBlockNumber)
		w.U64(d.MsgTimestamp)
		w.B32(d.BaseFeeL1)
		w.LP(d.Data)
		w.U64(d.K)
	}
	w.Nodes(finality.EncodeNodes(e.Nodes))
	return w.Bytes()
}

// readLC reads the LC part from the container stream (spec 3.2) into an ethl1.LC. Layout bytes and ssz lengths are judged by
// ethl1 itself; here only the framing is strict.
func readLC(r *finality.Reader, maxLinks int) (ethl1.LC, error) {
	var lc ethl1.LC
	var err error
	if lc.Profile, err = r.STR("lc.profile"); err != nil {
		return lc, err
	}
	k, err := r.U8("lc.anchorKind")
	if err != nil {
		return lc, err
	}
	lc.AnchorKind = k
	if lc.AnchorPeriod, err = r.U64("lc.anchorPeriod"); err != nil {
		return lc, err
	}
	if lc.AnchorRoot, err = r.B32("lc.anchorRoot"); err != nil {
		return lc, err
	}
	lb := func(part string) (ethl1.LB, error) {
		l, err := r.U8(part + ".layout")
		if err != nil {
			return ethl1.LB{}, err
		}
		ssz, err := r.LP(part, -1)
		if err != nil {
			return ethl1.LB{}, err
		}
		return ethl1.LB{Layout: ethl1.Layout(l), SSZ: ssz}, nil
	}
	if lc.AnchorBody, err = lb("lc.anchorBody"); err != nil {
		return lc, err
	}
	n, err := r.Count("lc.links", maxLinks, 5)
	if err != nil {
		return lc, err
	}
	lc.Links = make([]ethl1.LB, 0, n)
	for i := 0; i < n; i++ {
		l, err := lb("lc.link")
		if err != nil {
			return lc, err
		}
		lc.Links = append(lc.Links, l)
	}
	if lc.FinalUpdate, err = lb("lc.finalUpdate"); err != nil {
		return lc, err
	}
	return lc, nil
}

// Decode parses a container body strictly: no trailing byte, every count within its bound before anything is allocated,
// NODES ascending and unique, and encode(decode(x)) == x.
func Decode(body []byte, b Bounds) (Evidence, error) {
	var e Evidence
	r := finality.NewReader(body, b.Limits)
	var err error
	if e.LC, err = readLC(r, b.MaxLinks); err != nil {
		return e, err
	}
	if e.L1Spine, err = r.LPList("l1Spine", b.MaxSpineHeaders, maxHeaderBytes); err != nil {
		return e, err
	}
	if e.StateBlock, err = r.U64("stateBlock"); err != nil {
		return e, err
	}
	if e.BlockTxs, err = r.LPList("blockTxs", b.MaxBlockTxs, b.MaxTxLeafBytes); err != nil {
		return e, err
	}
	if e.BatchSeq, err = r.U64("batchSeq"); err != nil {
		return e, err
	}
	for i := range e.Header40 {
		if e.Header40[i], err = r.U64("header40"); err != nil {
			return e, err
		}
	}
	if e.BeforeAcc, err = r.B32("beforeAcc"); err != nil {
		return e, err
	}
	if e.DelayedAcc, err = r.B32("delayedAcc"); err != nil {
		return e, err
	}
	if e.DataKind, err = r.U8("dataKind"); err != nil {
		return e, err
	}
	switch e.DataKind {
	case DataBlobs:
		n, err := r.Count("versionedHashes", b.MaxBlobs, 32)
		if err != nil {
			return e, err
		}
		for i := 0; i < n; i++ {
			h, err := r.B32("versionedHashes")
			if err != nil {
				return e, err
			}
			e.VersionedHashes = append(e.VersionedHashes, h)
		}
		m, err := r.Count("blobs", b.MaxBlobs, 4+BlobBytes+96)
		if err != nil {
			return e, err
		}
		for i := 0; i < m; i++ {
			raw, err := r.LP("blobs.raw", BlobBytes)
			if err != nil {
				return e, err
			}
			if len(raw) != BlobBytes {
				return e, finality.MalformedAt("blobs.raw", i, finality.ReasonTruncated, len(raw), BlobBytes)
			}
			bl := Blob{Raw: raw}
			c, err := r.Fixed("blobs.commitment", 48)
			if err != nil {
				return e, err
			}
			copy(bl.Commitment[:], c)
			p, err := r.Fixed("blobs.proof", 48)
			if err != nil {
				return e, err
			}
			copy(bl.Proof[:], p)
			e.Blobs = append(e.Blobs, bl)
		}
	case DataCalldata:
		if e.Calldata, err = r.LP("calldata", b.MaxTxLeafBytes); err != nil {
			return e, err
		}
	case DataNone:
	default:
		return e, finality.Malformed("dataKind", finality.ReasonBadEnumValue, int(e.DataKind), 3)
	}
	flag, err := r.U8("delayedFlag")
	if err != nil {
		return e, err
	}
	switch flag {
	case 0:
	case 1:
		var d Delayed
		if d.MsgKind, err = r.U8("delayed.msgKind"); err != nil {
			return e, err
		}
		s, err := r.Fixed("delayed.sender", 20)
		if err != nil {
			return e, err
		}
		copy(d.Sender[:], s)
		if d.MsgBlockNumber, err = r.U64("delayed.msgBlockNumber"); err != nil {
			return e, err
		}
		if d.MsgTimestamp, err = r.U64("delayed.msgTimestamp"); err != nil {
			return e, err
		}
		if d.BaseFeeL1, err = r.B32("delayed.baseFeeL1"); err != nil {
			return e, err
		}
		if d.Data, err = r.LP("delayed.data", b.MaxTxLeafBytes); err != nil {
			return e, err
		}
		if d.K, err = r.U64("delayed.k"); err != nil {
			return e, err
		}
		e.Delayed = &d
	default:
		return e, finality.Malformed("delayedFlag", finality.ReasonBadEnumValue, int(flag), 1)
	}
	if e.Nodes, err = r.Nodes("nodes", b.MaxNodeBytes); err != nil {
		return e, err
	}
	if err := r.End("body"); err != nil {
		return e, err
	}
	return e, nil
}
