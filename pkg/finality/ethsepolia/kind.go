// Copyright 2026 Certen Protocol

// Package ethsepolia is the `eth-sepolia/finalized/v1` kind of V2_SPEC_S7 (sections 3.3 and 5.3): a block of Ethereum Sepolia
// is final iff it is an ancestor of the execution block that Ethereum's finalized checkpoint commits, attested by at least
// 342 of 512 sync-committee signatures chained from a published pin. The kind is the container codec, the verifier (a thin
// judgement over pkg/finality/ethl1, which does the beacon light-client work), the builder (a finality.Prover with an LC
// source and an execution header source) and the vector generator.
//
// Registration is explicit (Register); the package has no init().
package ethsepolia

import (
	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/ethl1"
)

// Name is the kind string (V2_SPEC_S7 section 1).
const Name = "eth-sepolia/finalized/v1"

// Body is the kind's body after the CFE1 header (3.3): LC ‖ LIST<LP> spine, with the spine h_0 = the finalized execution head
// down to h_k = the leg block (section 0).
type Body struct {
	LC    ethl1.LC
	Spine [][]byte
}

// Encode is the canonical body: ethl1.EncodeLC followed by the spine as LIST<LP>.
func (b Body) Encode() []byte {
	var w finality.Writer
	w.Fixed(ethl1.EncodeLC(b.LC))
	w.LPList(b.Spine)
	return w.Bytes()
}

// readLC reads the LC part from the container stream (spec 3.2) into an ethl1.LC. The layout byte of each LB and the ssz
// lengths are judged by ethl1; this reader only frames them, strictly and under the link bound.
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

// DecodeBody decodes the body strictly: the spine count is bounded by min(maxSpine, lim.MaxSpineHeaders) and the link count by
// maxLinks before anything is allocated, a trailing byte is refused, and encode(decode(x)) == x.
func DecodeBody(body []byte, lim finality.Limits, maxLinks, maxSpine int) (Body, error) {
	var b Body
	r := finality.NewReader(body, lim)
	var err error
	if b.LC, err = readLC(r, maxLinks); err != nil {
		return Body{}, err
	}
	limit := lim.MaxSpineHeaders
	if maxSpine > 0 && maxSpine < limit {
		limit = maxSpine
	}
	if b.Spine, err = r.LPList("spine", limit, lim.MaxNodeBytes); err != nil {
		return Body{}, err
	}
	if len(b.Spine) == 0 {
		return Body{}, finality.Malformed("spine", finality.ReasonSpineEmpty, 0, 1)
	}
	if err := r.End("body"); err != nil {
		return Body{}, err
	}
	return b, nil
}

// BuildContainer wraps a body in the CFE1 container for the leg block.
func BuildContainer(leg finality.BlockRef, b Body) ([]byte, error) {
	return finality.Container{
		Header: finality.ContainerHeader{Kind: Name, Chain: finality.ChainSepolia, Level: finality.LevelFinalized, BlockNumber: leg.Number, BlockHash: leg.Hash},
		Body:   b.Encode(),
	}.Encode()
}
