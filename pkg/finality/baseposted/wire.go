// Copyright 2026 Certen Protocol

package baseposted

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
	"github.com/certen/independant-validator/pkg/finality/l1adapt"
)

// BlobSize is a raw EIP-4844 blob.
const BlobSize = 131072

// Blob is Blob = LP raw(131072) || B48 commitment || B48 proof.
type Blob struct {
	Raw        []byte
	Commitment [48]byte
	Proof      [48]byte
}

// FrameTx is FrameTx = u64 l1Block || u32 txIndex || LP txRaw || LIST<Blob>.
type FrameTx struct {
	L1Block uint64
	TxIndex uint32
	TxRaw   []byte
	Blobs   []Blob
}

// Body is the body of a base-sepolia/l1_posted/v1 container after the CFE1 header (V2_SPEC_S7 section 3.3):
// LC || LIST<LP> l1Spine || B16 channelId || LIST<FrameTx> || LIST<LP> depositTxs || NODES.
type Body struct {
	LC        ethl1.LC
	L1Spine   [][]byte
	ChannelID [16]byte
	Frames    []FrameTx
	Deposits  [][]byte
	Nodes     [][]byte // strictly ascending by keccak256, unique
}

// EncodeBody is the canonical encoding. Nodes are sorted and deduplicated.
func EncodeBody(b Body) []byte {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(b.LC))
	w.LPList(b.L1Spine)
	w.Fixed(b.ChannelID[:])
	w.Count(len(b.Frames))
	for _, f := range b.Frames {
		w.U64(f.L1Block)
		w.U32(f.TxIndex)
		w.LP(f.TxRaw)
		w.Count(len(f.Blobs))
		for _, bl := range f.Blobs {
			w.LP(bl.Raw)
			w.Fixed(bl.Commitment[:])
			w.Fixed(bl.Proof[:])
		}
	}
	w.LPList(b.Deposits)
	w.Nodes(finality.EncodeNodes(b.Nodes))
	return w.Bytes()
}

// maxLCPart bounds one SSZ blob of the LC part while it is being delimited; the exact sizes are checked by ethl1.
const maxLCPart = 1 << 20

// lcExtent walks the LC part (spec 3.2) and returns its byte length, without interpreting any SSZ.
func lcExtent(body []byte, lim finality.Limits, maxLinks int) (int, error) {
	r := finality.NewReader(body, lim)
	if _, err := r.STR("lc.profile"); err != nil {
		return 0, err
	}
	if _, err := r.U8("lc.anchorKind"); err != nil {
		return 0, err
	}
	if _, err := r.U64("lc.anchorPeriod"); err != nil {
		return 0, err
	}
	if _, err := r.Fixed("lc.anchorRoot", 32); err != nil {
		return 0, err
	}
	lb := func(part string) error {
		if _, err := r.U8(part + ".layout"); err != nil {
			return err
		}
		_, err := r.LP(part, maxLCPart)
		return err
	}
	if err := lb("lc.anchorBody"); err != nil {
		return 0, err
	}
	n, err := r.Count("lc.links", maxLinks, 5)
	if err != nil {
		return 0, err
	}
	for i := 0; i < n; i++ {
		if err := lb("lc.links"); err != nil {
			return 0, err
		}
	}
	if err := lb("lc.finalUpdate"); err != nil {
		return 0, err
	}
	return len(body) - r.Left(), nil
}

// DecodeBody is the strict inverse of EncodeBody under the bounds of lim and the pins (max_blobs, max spine headers, max
// links). Every refusal is a framework named state; nothing is truncated.
func DecodeBody(body []byte, lim finality.Limits, ep ethl1.Pins, maxBlobs int) (Body, error) {
	var out Body
	n, err := lcExtent(body, lim, ep.MaxLinks)
	if err != nil {
		return out, err
	}
	if out.LC, err = ep.DecodeLC(body[:n]); err != nil {
		return out, l1adapt.State(err)
	}
	r := finality.NewReader(body[n:], lim)
	spineMax := ep.MaxSpineHeaders
	if spineMax <= 0 || spineMax > lim.MaxSpineHeaders {
		spineMax = lim.MaxSpineHeaders
	}
	if out.L1Spine, err = r.LPList("l1Spine", spineMax, lim.MaxNodeBytes); err != nil {
		return out, err
	}
	cid, err := r.Fixed("channelId", 16)
	if err != nil {
		return out, err
	}
	copy(out.ChannelID[:], cid)
	fc, err := r.Count("frameTxs", lim.MaxFrameTxs, 8+4+4+4)
	if err != nil {
		return out, err
	}
	totalBlobs := 0
	for i := 0; i < fc; i++ {
		var f FrameTx
		if f.L1Block, err = r.U64("frameTx.l1Block"); err != nil {
			return out, err
		}
		if f.TxIndex, err = r.U32("frameTx.txIndex"); err != nil {
			return out, err
		}
		if f.TxRaw, err = r.LP("frameTx.txRaw", lim.MaxTxLeafBytes); err != nil {
			return out, err
		}
		bc, err := r.Count("frameTx.blobs", maxBlobs, 4+48+48)
		if err != nil {
			return out, err
		}
		totalBlobs += bc
		if totalBlobs > maxBlobs {
			return out, finality.EvidenceTooLarge("blobs", uint64(totalBlobs), uint64(maxBlobs))
		}
		for j := 0; j < bc; j++ {
			var bl Blob
			if bl.Raw, err = r.LP("blob.raw", BlobSize); err != nil {
				return out, err
			}
			if len(bl.Raw) != BlobSize {
				return out, finality.MalformedAt("blob.raw", j, finality.ReasonTruncated, len(bl.Raw), BlobSize)
			}
			c, err := r.Fixed("blob.commitment", 48)
			if err != nil {
				return out, err
			}
			copy(bl.Commitment[:], c)
			p, err := r.Fixed("blob.proof", 48)
			if err != nil {
				return out, err
			}
			copy(bl.Proof[:], p)
			f.Blobs = append(f.Blobs, bl)
		}
		out.Frames = append(out.Frames, f)
	}
	if out.Deposits, err = r.LPList("depositTxs", lim.MaxDepositTxs, lim.MaxTxLeafBytes); err != nil {
		return out, err
	}
	if out.Nodes, err = r.Nodes("nodes", lim.MaxTxLeafBytes); err != nil {
		return out, err
	}
	return out, r.End("body")
}
