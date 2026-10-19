// Copyright 2026 Certen Protocol
//
// The anchored certify form, built (RB9-F5 package F5-2). The 2.0 builder keeps every minor-root run between the last major block and the
// certified anchor, each with its root proof; evidence 2.1 keeps only the runs that APPLY a network or globals update, and the final
// run, and joins each kept run to the previously verified root chain anchor with one O(log n) link: a receipt of the Directory's
// `anchor(directory)-root` account chain, served by `query acc://dn.acme/anchors {chain, name, entry: <previous root>,
// includeReceipt: {forHeight: <the run's RootChainIndex>}}` (V-E A1). A run that applies no update is dropped; an oracle- or
// routing-only run is NOT update-bearing for this purpose, because the verifier refuses a non-final anchored item that applies nothing
// (certify_item_without_effect), and so the selection is "the walk applied an update", never "the record carries updates".

package proofv2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ErrLinkNotAnchored is a LinkSource's answer when the previous root chain anchor is recorded in the anchor chain but not yet anchored at
// or below the requested height (probe V4: the newest quorum anchor's own root is anchored a few entries later than its RootChainIndex),
// so no receipt can join it into that height. It is the one condition under which the builder emits a continuous item for the hop.
var ErrLinkNotAnchored = errors.New("the previous root chain anchor is not anchored at or below the requested height")

// LinkSource serves the link of an anchored item: a receipt that starts at prev (the previously verified root chain anchor, an entry of the
// Directory's anchor(directory)-root chain) and ends at the root chain anchor of the Directory chain at height (the item's RootChainIndex).
type LinkSource interface {
	Link(ctx context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error)
}

type clientLinks struct{ c *jsonrpc.Client }

// NewClientLinks is the LinkSource of a live Accumulate API endpoint.
func NewClientLinks(c *jsonrpc.Client) LinkSource { return clientLinks{c} }

func (l clientLinks) Link(ctx context.Context, prev [32]byte, height uint64) (*merkle.Receipt, error) {
	q, err := l.c.Query(ctx, protocol.DnUrl().JoinPath(protocol.AnchorPool), &api.ChainQuery{
		Name: "anchor(directory)-root", Entry: prev[:], IncludeReceipt: &api.ReceiptOptions{ForHeight: height}})
	if err != nil {
		if strings.Contains(err.Error(), "cannot satisfy target height") {
			return nil, fmt.Errorf("%w: %v", ErrLinkNotAnchored, err)
		}
		return nil, err
	}
	ce, ok := q.(*api.ChainEntryRecord[api.Record])
	if !ok || ce.Receipt == nil {
		return nil, fmt.Errorf("got %T without a receipt", q)
	}
	r := ce.Receipt.Receipt
	return &r, nil
}

// servedRun is a minor-root record as the Directory served it (with its root proof) and whether the walk applied an update in it.
type servedRun struct {
	rec     *api.MinorRootRecord
	applied bool
}

func hexOf32(b [32]byte) string { return hex.EncodeToString(b[:]) }

// anchorRuns turns the served runs of one sequence (certify, or the set check's hops) into the anchored form. start is the root chain
// anchor the walk stands at before the first run. A run is kept when it applied an update or is the last; a kept run is anchored (its root
// proof dropped, its link taken from src) unless the link is unavailable only because the previous root is not yet anchored at the run's
// height, in which case the runs from the previous emitted one up to it are emitted continuous. The height of a link is the run's
// RootChainIndex (V-E A9: it equals the end of the run's root proof, which the behavioural test pins on every live fixture).
func anchorRuns(ctx context.Context, runs []servedRun, start [32]byte, src LinkSource) (items, links []string, err error) {
	prev, prevIdx := start, -1
	emit := func(r *api.MinorRootRecord) error {
		b, err := r.MarshalBinary()
		if err != nil {
			return err
		}
		items = append(items, hex.EncodeToString(b))
		return nil
	}
	for i, run := range runs {
		if !run.applied && i != len(runs)-1 {
			continue
		}
		body, err := checkDirectorySelfAnchor(run.rec.Anchor)
		if err != nil {
			return nil, nil, err
		}
		link, lerr := src.Link(ctx, prev, body.RootChainIndex)
		switch {
		case lerr == nil:
			if !stepsPresent(link) || !bytesEq(link.Start, prev[:]) || !bytesEq(link.Anchor, body.RootChainAnchor[:]) || !link.Validate(nil) {
				return nil, nil, fmt.Errorf("%w: the served receipt does not join %s to %s", certifyState(StateCertifyLinkUnavailable, hexOf32(prev), strconv.FormatUint(body.RootChainIndex, 10)), hexOf32(prev), hexOf32(body.RootChainAnchor))
			}
			lb, err := link.MarshalBinary()
			if err != nil {
				return nil, nil, err
			}
			anchored := *run.rec
			anchored.RootProof = nil
			if err := emit(&anchored); err != nil {
				return nil, nil, err
			}
			links = append(links, hex.EncodeToString(lb))
		case errors.Is(lerr, ErrLinkNotAnchored):
			for k := prevIdx + 1; k <= i; k++ {
				if runs[k].rec.RootProof == nil {
					return nil, nil, fmt.Errorf("%w: %v", certifyState(StateCertifyLinkUnavailable, hexOf32(prev), strconv.FormatUint(body.RootChainIndex, 10)), lerr)
				}
				if err := emit(runs[k].rec); err != nil {
					return nil, nil, err
				}
			}
		default:
			return nil, nil, fmt.Errorf("%w: %v", certifyState(StateCertifyLinkUnavailable, hexOf32(prev), strconv.FormatUint(body.RootChainIndex, 10)), lerr)
		}
		prev, prevIdx = body.RootChainAnchor, i
	}
	return items, links, nil
}

func bytesEq(a, b []byte) bool { return string(a) == string(b) }

// rangeUnavailable is the named state of a minor-root range the Directory does not serve (retryable), with the cause kept.
func rangeUnavailable(since, until uint64, cause error) error {
	return fmt.Errorf("%w: %w", certifyState(StateCertifyRangeUnavailable, strconv.FormatUint(since, 10), strconv.FormatUint(until, 10)), cause)
}

// spinesAt returns the spine after each requested number of major blocks (0: the genesis spine) walked from the incarnation's genesis.
func spinesAt(ar *Archive, in proof.IncarnationInputs, counts ...uint64) (map[uint64]*Spine, error) {
	g, err := genesisValues(in.NetworkRecord, in.GlobalsRecord)
	if err != nil {
		return nil, err
	}
	sp, err := NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	want := map[uint64]bool{}
	var need uint64
	for _, c := range counts {
		want[c] = true
		need = max(need, c)
	}
	if need > uint64(len(ar.Majors)) {
		return nil, fmt.Errorf("evidence builds on %d major blocks; the archive has %d", need, len(ar.Majors))
	}
	at := map[uint64]*Spine{}
	if want[0] {
		at[0] = sp.Clone()
	}
	for i := uint64(0); i < need; i++ {
		if err := sp.Advance(ar.Majors[i]); err != nil {
			return nil, fmt.Errorf("spine: %w", err)
		}
		if want[i+1] {
			at[i+1] = sp.Clone()
		}
	}
	return at, nil
}

// walkServed advances a clone of sp through continuous records (hex), keeping each record with whether it applied an update.
func walkServed(sp *Spine, hexRuns []string) ([]servedRun, error) {
	w := sp.Clone()
	w.refuseReplay = true
	var out []servedRun
	for i, h := range hexRuns {
		mr, err := decodeMinorRoot(h)
		if err != nil {
			return nil, fmt.Errorf("run %d: %w", i, err)
		}
		n := len(w.Applied)
		if err := w.AdvanceEpoch(mr); err != nil {
			return nil, fmt.Errorf("run %d: %w", i, err)
		}
		out = append(out, servedRun{rec: mr, applied: len(w.Applied) > n})
	}
	return out, nil
}

// AnchorEvidence re-expresses a continuous evidence 2.1 document in the anchored form: the same facts, certify and set-check hops reduced
// to the runs that apply an update and the last, each joined by a link from src. The input is not changed. The caller verifies the result
// (Verify21FromGenesis); both forms give the same report. A document that is already anchored, or is not 2.1, is refused.
func AnchorEvidence(ctx context.Context, ev *Evidence, ar *Archive, in proof.IncarnationInputs, src LinkSource) (*Evidence, error) {
	if ev == nil || ev.Version != Version21 {
		return nil, fmt.Errorf("only evidence 2.1 has the anchored form")
	}
	if len(ev.Links) != 0 {
		return nil, fmt.Errorf("the document is already anchored")
	}
	at, err := spinesAt(ar, in, ev.Majors, ev.Check.Majors)
	if err != nil {
		return nil, err
	}
	certRuns, err := walkServed(at[ev.Majors], ev.Certify)
	if err != nil {
		return nil, fmt.Errorf("certify: %w", err)
	}
	out := *ev
	var links []string
	if out.Certify, links, err = anchorRuns(ctx, certRuns, at[ev.Majors].RootChainAnchor, src); err != nil {
		return nil, err
	}
	if len(ev.Check.Hops) > 0 {
		hopRuns, err := walkServed(at[ev.Check.Majors], ev.Check.Hops)
		if err != nil {
			return nil, fmt.Errorf("set check: %w", err)
		}
		var hl []string
		if out.Check.Hops, hl, err = anchorRuns(ctx, hopRuns, at[ev.Check.Majors].RootChainAnchor, src); err != nil {
			return nil, err
		}
		links = append(links, hl...)
	}
	out.Links = links
	// The chain identity (V-E A1b, F-VE-2): every evidence 2.1 document carries the receipt from the pinned incarnation's genesis root chain
	// anchor to the certified root, asked of the same account chain (entry 0, the genesis root, at the certified anchor's height) - one with no
	// link of its own (every run had to be emitted continuous) included, because the offline walk requires it of the continuous form too (RB9-F6).
	if out.GenesisLink, err = genesisLinkOf(ctx, src, in.GenesisRootChainAnchor, out.Certify[len(out.Certify)-1]); err != nil {
		return nil, err
	}
	return &out, nil
}

// MajorRootChainAnchor is the root chain anchor of the closing anchor of major block m (1-based) of the archive: the root a certification
// that builds on m major blocks starts from.
func MajorRootChainAnchor(ar *Archive, m uint64) ([32]byte, error) {
	if m < 1 || m > uint64(len(ar.Majors)) {
		return [32]byte{}, fmt.Errorf("major block %d: the archive holds %d", m, len(ar.Majors))
	}
	body, err := checkDirectorySelfAnchor(ar.Majors[m-1].Anchor)
	if err != nil {
		return [32]byte{}, err
	}
	return body.RootChainAnchor, nil
}

// RunAnchor is the RootChainIndex and RootChainAnchor of the anchor of a minor-root record given as hex.
func RunAnchor(run string) (index uint64, root [32]byte, err error) {
	mr, err := decodeMinorRoot(run)
	if err != nil {
		return 0, root, err
	}
	body, err := checkDirectorySelfAnchor(mr.Anchor)
	if err != nil {
		return 0, root, err
	}
	return body.RootChainIndex, body.RootChainAnchor, nil
}

// RunRootProofEnd is the root chain height a record's root proof ends at (MerkleState.Count + len(Elements) - 1), the quantity the
// builder used before it took the height from the anchor's RootChainIndex (V-E A9 pins that they are equal on every live record).
func RunRootProofEnd(run string) (uint64, error) {
	mr, err := decodeMinorRoot(run)
	if err != nil {
		return 0, err
	}
	if mr.RootProof == nil || mr.RootProof.MerkleState == nil {
		return 0, fmt.Errorf("the record carries no root proof")
	}
	return uint64(mr.RootProof.MerkleState.Count) + uint64(len(mr.RootProof.Elements)) - 1, nil
}

// genesisLinkOf asks src for the chain identity of an anchored document (V-E A1b): the receipt from the pinned incarnation's genesis root chain
// anchor (entry 0 of the account chain) to the root chain anchor of lastRun, the last run of certify (hex), at that run's RootChainIndex.
func genesisLinkOf(ctx context.Context, src LinkSource, genesis [32]byte, lastRun string) (string, error) {
	height, root, err := RunAnchor(lastRun)
	if err != nil {
		return "", err
	}
	gl, lerr := src.Link(ctx, genesis, height)
	if lerr != nil {
		return "", fmt.Errorf("%w: %v", certifyState(StateCertifyLinkUnavailable, hexOf32(genesis), strconv.FormatUint(height, 10)), lerr)
	}
	if !stepsPresent(gl) || !bytesEq(gl.Start, genesis[:]) || !bytesEq(gl.Anchor, root[:]) || !gl.Validate(nil) {
		return "", fmt.Errorf("%w: the served receipt does not join the genesis root %s to the certified root %s", certifyState(StateCertifyLinkUnavailable, hexOf32(genesis), strconv.FormatUint(height, 10)), hexOf32(genesis), hexOf32(root))
	}
	gb, err := gl.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(gb), nil
}

// addGenesisLink gives an evidence 2.1 document the chain identity, asked of the live Directory: the receipt from genesis (the pinned incarnation's
// genesis root chain anchor) to the certified root.
func (b *Builder) addGenesisLink(ctx context.Context, ev *Evidence, genesis [32]byte) error {
	var err error
	ev.GenesisLink, err = genesisLinkOf(ctx, NewClientLinks(b.C), genesis, ev.Certify[len(ev.Certify)-1])
	return err
}
