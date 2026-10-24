// Copyright 2026 Certen Protocol

package capture

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/ethereum/go-ethereum/core/types"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
)

// HopChain is the hop chain of one leg (link 1, WP-S8-3c): the numbers of H_0 (= B_v), H_1 .. H_k, the raw headers of H_1 .. H_k
// (hopHeaders) and the verified nodes of the EIP-2935 slot proofs of H_0 .. H_{k-1} (the slot of H_k is read under the settlement root by E2).
type HopChain struct {
	Numbers []uint64
	Headers [][]byte
	Nodes   [][]byte
}

// ErrHopRowMismatch: a stored row does not say what its key says.
var ErrHopRowMismatch = errors.New("capture: a stored hop row does not match its key")

type hopVertex struct {
	dist   int
	parent uint64 // 0: the first link
	key    Key
	first  bool
}

// BuildHopChain ties B_v to the settlement block n by the stored ticks: the first link of the anchor, then the shortest chain of stored
// ticks, each linked to the one before it by a slot proof, to a tick at most W blocks before n. At most max_attest_hops (16) ticks are
// carried. A leg no chain reaches is an OutOfReachError carrying how far the chain it has does reach (hops_carried, last_hop); a store
// error is returned as an error and is never a verdict about the leg.
func BuildHopChain(ctx context.Context, st Store, m *ci.Manifest, chain uint64, anchorID [32]byte, bv ci.BlockRef, n uint64) (*HopChain, error) {
	h, w, err := TickSpacing(m, chain)
	if err != nil {
		return nil, err
	}
	if n <= bv.Number {
		return nil, fmt.Errorf("capture: the settlement block %d is not after the attestation block %d", n, bv.Number)
	}
	gap := n - bv.Number
	out := func(carried int, last uint64) error {
		return &OutOfReachError{Gap: gap, Window: w, HopsCarried: carried, LastHop: last}
	}
	maxHops := ci.DefaultLimits().MaxAttestHops
	keys, err := st.ListByAnchor(ctx, chain, anchorID)
	if err != nil {
		return nil, err
	}
	if len(keys) > maxTickKeys {
		return nil, fmt.Errorf("%w: %d keys of anchor %x", ErrTickListTooLarge, len(keys), anchorID[:4])
	}
	verts := map[uint64]*hopVertex{}
	for _, k := range keys {
		if k.BlockHash != bv.Hash {
			continue
		}
		t, ok := parseFirstItem(k.Item)
		if !ok || t <= bv.Number || t-bv.Number > w || t >= n {
			continue
		}
		if old, has := verts[t]; !has || hashBefore(k, old.key) {
			verts[t] = &hopVertex{dist: 1, key: k, first: true}
		}
	}
	if len(verts) == 0 {
		return nil, out(0, bv.Number)
	}
	firstT := ^uint64(0)
	for t := range verts {
		if t < firstT {
			firstT = t
		}
	}
	ticks, err := listTicks(ctx, st, chain, h, epochOf(h, firstT), epochOf(h, n))
	if err != nil {
		return nil, err
	}
	sort.Slice(ticks, func(i, j int) bool {
		if ticks[i].Number != ticks[j].Number {
			return ticks[i].Number < ticks[j].Number
		}
		if ticks[i].Prev != ticks[j].Prev {
			return ticks[i].Prev < ticks[j].Prev
		}
		return string(ticks[i].Key.BlockHash[:]) < string(ticks[j].Key.BlockHash[:])
	})
	for _, r := range ticks {
		if r.Number >= n || r.Prev == 0 {
			continue
		}
		p, ok := verts[r.Prev]
		if !ok || r.Number-r.Prev > w || p.dist+1 > maxHops {
			continue
		}
		if cur, has := verts[r.Number]; !has || p.dist+1 < cur.dist {
			verts[r.Number] = &hopVertex{dist: p.dist + 1, parent: r.Prev, key: r.Key}
		}
	}
	var best uint64
	farthest, farthestT := 0, bv.Number
	for t, v := range verts {
		if t > farthestT {
			farthest, farthestT = v.dist, t
		}
		if n-t <= w && (best == 0 || v.dist < verts[best].dist || (v.dist == verts[best].dist && t > best)) {
			best = t
		}
	}
	if best == 0 {
		return nil, out(farthest, farthestT)
	}
	var path []uint64
	for t := best; ; t = verts[t].parent {
		path = append([]uint64{t}, path...)
		if verts[t].first {
			break
		}
	}
	hc := &HopChain{Numbers: []uint64{bv.Number}}
	var nodes [][]byte
	for i, t := range path {
		v := verts[t]
		raw, ok, gerr := st.Get(ctx, v.key)
		if gerr != nil {
			return nil, gerr
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s is listed and absent", ErrHopRowMismatch, v.key)
		}
		var hdr, rn = []byte(nil), [][]byte(nil)
		if v.first {
			fr, derr := decodeFirst(raw)
			if derr != nil {
				return nil, derr
			}
			if fr.Bv != bv || fr.Tick != t {
				return nil, fmt.Errorf("%w: %s", ErrHopRowMismatch, v.key)
			}
			hdr, rn = fr.Header, fr.Nodes
		} else {
			tr, derr := decodeTick(raw)
			if derr != nil {
				return nil, derr
			}
			if tr.Number != t || tr.Prev != path[i-1] || tr.Hash != v.key.BlockHash {
				return nil, fmt.Errorf("%w: %s", ErrHopRowMismatch, v.key)
			}
			hdr, rn = tr.Header, tr.Nodes
		}
		hc.Numbers = append(hc.Numbers, t)
		hc.Headers = append(hc.Headers, hdr)
		nodes = append(nodes, rn...)
	}
	hc.Nodes = sortNodes(nodes)
	return hc, nil
}

func hashBefore(a, b Key) bool { return string(a.BlockHash[:])+a.Item < string(b.BlockHash[:])+b.Item }

// PlanLink chooses the link of B_v to the settlement block n: ChooseLink, and, beyond the history window, the stored tick chain. A nil
// HopChain means no hops are carried (links 0 and 2, and link 1 with k = 0). The error is an *OutOfReachError for a leg no carried link
// covers; its hops_carried and last_hop describe the chain that was found.
func PlanLink(ctx context.Context, st Store, m *ci.Manifest, chain uint64, anchorID [32]byte, bv ci.BlockRef, n uint64) (LinkPlan, *HopChain, error) {
	plan, err := ChooseLink(m, chain, bv.Number, n, 0)
	var oor *OutOfReachError
	if err == nil || !errors.As(err, &oor) || oor.Window == 0 {
		return plan, nil, err
	}
	hc, herr := BuildHopChain(ctx, st, m, chain, anchorID, bv, n)
	if herr != nil {
		return LinkPlan{}, nil, herr
	}
	return LinkPlan{Link: ci.LinkHops, HopNumbers: hc.Numbers}, hc, nil
}

// BuildAttestPartHops is BuildAttestPart for a leg whose link carries hops: the hop headers become hopHeaders and the slot proofs of the
// hops below the last join the attestation part's nodes (the plan reads them under the hop stations, not under the settlement root).
func BuildAttestPartHops(ctx context.Context, src AttestSource, r *AttestResult, settleHeader *types.Header, plan LinkPlan, hc *HopChain) (*AttestPart, error) {
	if hc == nil {
		return BuildAttestPart(ctx, src, r, settleHeader, plan, nil)
	}
	part, err := BuildAttestPart(ctx, src, r, settleHeader, plan, hc.Headers)
	if err != nil || part.Proof == nil {
		return part, err
	}
	part.Nodes = sortNodes(append(append([][]byte(nil), part.Nodes...), hc.Nodes...))
	return part, nil
}
