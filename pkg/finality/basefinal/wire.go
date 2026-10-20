// Copyright 2026 Certen Protocol

package basefinal

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Body is the body of a base-sepolia/finalized/v1 container after the CFE1 header (V2_SPEC_S7 section 3.3):
//
//	LC || LIST<LP> l1Spine || u64 stateBlock || B20 gameProxy || LP gameCode || u32 outputRootIndex || LIST<LP> l2Spine || NODES
//
// outputRootIndex 0 = rootClaim, i+1 = intermediate root i; l2Spine: h_0 = the output-root block ... h_k = the leg block.
type Body struct {
	LC              ethl1.LC
	L1Spine         [][]byte
	StateBlock      uint64
	GameProxy       [20]byte
	GameCode        []byte
	OutputRootIndex uint32
	L2Spine         [][]byte
	Nodes           [][]byte // strictly ascending by keccak256, unique
}

// EncodeBody is the canonical encoding. Nodes are sorted and deduplicated.
func EncodeBody(b Body) []byte {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(b.LC))
	w.LPList(b.L1Spine)
	w.U64(b.StateBlock)
	w.Fixed(b.GameProxy[:])
	w.LP(b.GameCode)
	w.U32(b.OutputRootIndex)
	w.LPList(b.L2Spine)
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

// DecodeBody is the strict inverse of EncodeBody under the bounds of lim, the L1 pins (max links, max spine headers) and
// maxL2 (the pins' max_l2_headers). Every refusal is a framework named state; nothing is truncated.
func DecodeBody(body []byte, lim finality.Limits, ep ethl1.Pins, maxL2 int) (Body, error) {
	var out Body
	n, err := lcExtent(body, lim, ep.MaxLinks)
	if err != nil {
		return out, err
	}
	if out.LC, err = ep.DecodeLC(body[:n]); err != nil {
		return out, stateOf(err)
	}
	r := finality.NewReader(body[n:], lim)
	spineMax := ep.MaxSpineHeaders
	if spineMax <= 0 || spineMax > lim.MaxSpineHeaders {
		spineMax = lim.MaxSpineHeaders
	}
	if out.L1Spine, err = r.LPList("l1Spine", spineMax, lim.MaxNodeBytes); err != nil {
		return out, err
	}
	if out.StateBlock, err = r.U64("stateBlock"); err != nil {
		return out, err
	}
	gp, err := r.Fixed("gameProxy", 20)
	if err != nil {
		return out, err
	}
	copy(out.GameProxy[:], gp)
	if out.GameCode, err = r.LP("gameCode", lim.MaxCodeBytes); err != nil {
		return out, err
	}
	if out.OutputRootIndex, err = r.U32("outputRootIndex"); err != nil {
		return out, err
	}
	l2Max := maxL2
	if l2Max <= 0 || l2Max > lim.MaxL2Headers {
		l2Max = lim.MaxL2Headers
	}
	if out.L2Spine, err = r.LPList("l2Spine", l2Max, lim.MaxNodeBytes); err != nil {
		return out, err
	}
	if out.Nodes, err = r.Nodes("nodes", lim.MaxNodeBytes); err != nil {
		return out, err
	}
	return out, r.End("body")
}
