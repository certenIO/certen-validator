// Copyright 2026 Certen Protocol

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/finality"
)

// AttestPart is the attestation station's contribution to a container (WP-S8-3b produces it, E1b adds the hop headers): the Proof, the
// verified nodes and codes it read, or a Stated part.
type AttestPart struct {
	Proof  *ci.AttestProof
	Codes  []ci.Code
	Nodes  [][]byte // canonical
	Stated *ci.Stated
}

// Parts are the pieces of one container.
type Parts struct {
	Chain  uint64
	Leg    ci.BlockRef // the settlement block
	Facts  *Facts      // the plan inputs (DeriveFacts + the attestation's facts); required when a part is captured
	Settle *SettleResult
	Attest *AttestPart
}

// Assembly refusals. All are builder errors: the container is not built, nothing is stored.
var (
	ErrNoParts         = errors.New("capture: both parts are required (a missing station is an explicit Stated part)")
	ErrPartsDisagree   = errors.New("capture: the parts do not describe one leg")
	ErrCodeConflict    = errors.New("capture: one address carries two different codes")
	ErrCodeUnproven    = errors.New("capture: a carried code is no code any station of the plan proved")
	ErrBadStatedReason = errors.New("capture: a Stated reason outside the six builder reasons")
)

// NodesUnreferencedError: a node is carried that no read of the plan visits (step 22b), or a read of the plan has no node.
type NodesUnreferencedError struct{ Index, Total int }

func (e *NodesUnreferencedError) Error() string {
	return fmt.Sprintf("capture: node %d of %d is carried and no read of the plan visits it (nodes_unreferenced)", e.Index, e.Total)
}

func mergeCodes(lists ...[]ci.Code) ([]ci.Code, error) {
	m := map[common.Address][]byte{}
	for _, l := range lists {
		for _, c := range l {
			a := common.Address(c.Address)
			if old, ok := m[a]; ok && !bytes.Equal(old, c.Runtime) {
				return nil, fmt.Errorf("%w: %s", ErrCodeConflict, a.Hex())
			}
			m[a] = c.Runtime
		}
	}
	return sortCodes(m, nil), nil
}

// Assemble builds the CIE1 container of the parts and proves its NODES are EXACTLY the nodes of the verifier's read plan: the plan is run
// over the container's nodes with the strict reads of package contractidentity, a missing node or an unvisited node is an error, and every
// carried code must hash to a code hash a station of the plan proved. A Stated reason outside the six builder reasons is refused.
func Assemble(p Parts) (*ci.Container, []byte, error) {
	if p.Settle == nil || p.Attest == nil {
		return nil, nil, ErrNoParts
	}
	if p.Chain == 0 || p.Settle.Block != p.Leg || (p.Settle.Stated != nil && p.Settle.Stated.JudgedHash != p.Leg.Hash) {
		return nil, nil, fmt.Errorf("%w: settle part at block %d, leg %d", ErrPartsDisagree, p.Settle.Block.Number, p.Leg.Number)
	}
	c := &ci.Container{Chain: p.Chain, Leg: p.Leg}
	settleOK, attestOK := p.Settle.Stated == nil, p.Attest.Stated == nil
	if settleOK {
		c.Settle = ci.Part{Tag: ci.TagCaptured}
	} else {
		c.Settle = ci.Part{Tag: ci.TagStated, Stated: p.Settle.Stated}
	}
	if attestOK {
		if p.Attest.Proof == nil {
			return nil, nil, fmt.Errorf("%w: a captured attest part without a proof", ErrPartsDisagree)
		}
		c.Attest = ci.Part{Tag: ci.TagCaptured, Attest: p.Attest.Proof}
	} else {
		c.Attest = ci.Part{Tag: ci.TagStated, Stated: p.Attest.Stated}
	}
	var sc, ac []ci.Code
	var sn, an [][]byte
	if settleOK {
		sc, sn = p.Settle.Codes, p.Settle.Nodes
	}
	if attestOK {
		ac, an = p.Attest.Codes, p.Attest.Nodes
	}
	var err error
	if c.Codes, err = mergeCodes(sc, ac); err != nil {
		return nil, nil, err
	}
	c.Nodes = sortNodes(append(append([][]byte(nil), sn...), an...))
	if se := c.CheckStatedReasons(); se != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrBadStatedReason, se)
	}
	if settleOK || attestOK {
		if err := proveExact(p, c, settleOK, attestOK); err != nil {
			return nil, nil, err
		}
	} else if len(c.Nodes) != 0 || len(c.Codes) != 0 {
		return nil, nil, fmt.Errorf("%w: two Stated parts carry no nodes", ErrPartsDisagree)
	}
	raw, err := ci.Encode(c, ci.DefaultLimits())
	if err != nil {
		return nil, nil, err
	}
	return c, raw, nil
}

// proveExact runs the plan of the captured parts strictly over the container.
func proveExact(p Parts, c *ci.Container, settleOK, attestOK bool) error {
	f := p.Facts
	if f == nil || f.Manifest == nil {
		return fmt.Errorf("%w: a captured part needs the plan facts", ErrPartsDisagree)
	}
	ns, err := ci.NewNodeSet(c.Nodes)
	if err != nil {
		return err
	}
	roots := map[string]common.Hash{}
	if settleOK {
		roots[StationSettle] = p.Settle.StateRoot
	}
	var txRoot, rcRoot common.Hash
	if attestOK {
		ap := p.Attest.Proof
		if ap.Link != f.Link {
			return fmt.Errorf("%w: attest link %d, facts link %d", ErrPartsDisagree, ap.Link, f.Link)
		}
		hv, err := finality.ReadHeader(ap.HeaderV)
		if err != nil {
			return err
		}
		hp, err := finality.ReadHeader(ap.HeaderVParent)
		if err != nil {
			return err
		}
		roots[StationPre], roots[StationPost] = hp.StateRoot, hv.StateRoot
		txRoot, rcRoot = hv.TransactionRoot, hv.ReceiptsRoot
		if f.Link == ci.LinkHops {
			if len(f.HopNumbers) != len(ap.HopHeaders)+1 || f.HopNumbers[0] != hv.Number {
				return fmt.Errorf("%w: hop numbers %v do not match B_v %d and %d hop headers", ErrPartsDisagree, f.HopNumbers, hv.Number, len(ap.HopHeaders))
			}
			for i, h := range ap.HopHeaders {
				hh, err := finality.ReadHeader(h)
				if err != nil {
					return err
				}
				if f.HopNumbers[i+1] != hh.Number {
					return fmt.Errorf("%w: hop %d is block %d, the facts say %d", ErrPartsDisagree, i+1, hh.Number, f.HopNumbers[i+1])
				}
				roots[HopStation(i+1)] = hh.StateRoot
			}
		}
		if ap.TxIndex != f.TxIndex {
			return fmt.Errorf("%w: attest txIndex %d, facts %d", ErrPartsDisagree, ap.TxIndex, f.TxIndex)
		}
	}
	st := newStrict(ns, roots, c.Codes)
	st.txRoot, st.rcRoot = txRoot, rcRoot
	var pending bool
	switch {
	case settleOK && attestOK:
		pending, err = RunAll(st, f)
	case settleOK:
		pending, err = RunSettle(st, f)
	default:
		pending, err = RunAttest(st, f)
	}
	if err != nil {
		return err
	}
	if pending {
		return &PlanError{Station: StationSettle, Reason: "strict_reader_pending"}
	}
	if un := ns.Unvisited(); len(un) != 0 {
		return &NodesUnreferencedError{Index: un[0], Total: len(c.Nodes)}
	}
	for _, code := range c.Codes {
		if !st.proven[common.Address(code.Address)] {
			return fmt.Errorf("%w: %s", ErrCodeUnproven, common.Address(code.Address).Hex())
		}
	}
	return nil
}

// RunAttest executes the attestation block's plan alone (both stations, transaction, receipt, hops below the last); used when the settle
// part is Stated.
func RunAttest(rd Reader, f *Facts) (pending bool, err error) {
	p := &planner{rd: rd, f: f}
	p.runAttest()
	return p.pending, p.err
}

// ---- Append ----

// Sink receives an accepted container. The production sink (WP-S8-5) is the repository over proof_contract_identity (greatest seq served,
// a better capture later is a new row); StoreSink writes into a capture Store.
type Sink interface {
	AppendContainer(ctx context.Context, chain uint64, leg ci.BlockRef, container []byte, digest [32]byte) error
}

// Appender is the only write path of containers: it assembles, asks the INJECTED verifier and stores nothing a verifier refuses.
type Appender struct {
	sink Sink
	v    ci.Verifier
	m    *ci.Manifest
}

// NewAppender is a construction error for a nil sink, verifier or manifest: there is no default verifier and no fallback.
func NewAppender(sink Sink, v ci.Verifier, m *ci.Manifest) (*Appender, error) {
	switch {
	case sink == nil:
		return nil, errors.New("capture: Appender needs a sink")
	case v == nil:
		return nil, errors.New("capture: Appender needs a verifier (no default, no fallback)")
	case m == nil:
		return nil, errors.New("capture: Appender needs a manifest")
	}
	return &Appender{sink: sink, v: v, m: m}, nil
}

// RefusedError: the verifier refused the assembled container at level included; nothing is stored.
type RefusedError struct{ Report ci.Report }

func (e *RefusedError) Error() string {
	first := ""
	if e.Report.Headline.First != nil {
		first = e.Report.Headline.First.Code
	}
	return "capture: the verifier refused the assembled container (" + first + "); nothing stored"
}

// Appended is the result of an accepted Append.
type Appended struct {
	Container []byte
	Digest    [32]byte
	Report    ci.Report
}

// Append assembles the parts, runs the verifier on the container with the leg's context, and stores the container unless the headline is a
// refusal (any part in an R state). Unproven and pending parts are stored: they are facts about availability and finality. A verifier
// error is never a verdict: nothing is stored.
func (a *Appender) Append(ctx context.Context, lc ci.LegContext, p Parts) (*Appended, error) {
	_, raw, err := Assemble(p)
	if err != nil {
		return nil, err
	}
	rep, err := a.v.Verify(lc, raw, a.m)
	if err != nil {
		return nil, fmt.Errorf("capture: the verifier failed: %w", err)
	}
	if rep.Headline.Kind == ci.HeadlineRefused {
		return nil, &RefusedError{Report: rep}
	}
	digest := ci.DigestOf(p.Chain, p.Leg.Number, p.Leg.Hash, raw)
	if err := a.sink.AppendContainer(ctx, p.Chain, p.Leg, raw, digest); err != nil {
		return nil, err
	}
	return &Appended{Container: raw, Digest: digest, Report: rep}, nil
}

// ItemContainer is the item StoreSink writes.
const ItemContainer = "container"

// StoreSink writes accepted containers into a capture Store under (chain, anchor, leg hash, "container").
type StoreSink struct {
	Store    Store
	AnchorID [32]byte
}

func (s StoreSink) AppendContainer(ctx context.Context, chain uint64, leg ci.BlockRef, container []byte, _ [32]byte) error {
	return s.Store.Put(ctx, Key{Chain: chain, AnchorID: s.AnchorID, BlockHash: leg.Hash, Item: ItemContainer}, container)
}
