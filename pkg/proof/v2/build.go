// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// ErrNotYetCertified means the Directory has not yet emitted an anchor at or after the block the proof needs
// certified; on a quiet network that can take minutes. Retry Build later with the same captured pages.
var ErrNotYetCertified = errors.New("the Directory has not yet emitted an anchor certifying this block")

// noSignaturesYet matches exactly the quorum failure of a minor-root record that carries NO validator signature: verifyQuorum counts
// the distinct, verified, active Directory validators that signed and reports "quorum not met: <count> of <threshold> validator
// signatures", and a signature that is invalid or from a non-validator is refused by its own error before the count. A count of zero
// is therefore a record with no signature at all.
var noSignaturesYet = regexp.MustCompile(`quorum not met: 0 of [0-9]+ validator signatures`)

// certifyError is the error of advancing the walk over a freshly served minor-root record (RB9-C1b-2-B1). The Directory serves the
// record before its validator signatures arrive, so "quorum not met: 0 of N" is a record that is not yet certified, not a refusal: it
// is ErrNotYetCertified (the callers retry it under the bound they already use for that error), with the original text kept. A record
// with some signatures but too few, an invalid signature or any other failure is a hard failure exactly as before. Only the BUILDER
// maps: the verifiers (Verify, Verify21FromGenesis, VerifyFromSpine) are untouched, so no verdict on any document changes.
func certifyError(what string, err error) error {
	if noSignaturesYet.MatchString(err.Error()) {
		return fmt.Errorf("%s: %w: %w", what, ErrNotYetCertified, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// Builder builds v2 Accumulate evidence from a live network.
type Builder struct {
	C *jsonrpc.Client
	Q proof.AccumulateQuerier

	inc   [32]byte
	incEv *proof.IncarnationEvidence

	// mu guards ar and majors, which Refresh appends to while builds read them: a build works on a view (view).
	mu      sync.RWMutex
	refresh sync.Mutex
	ar      *Archive
	majors  []*Spine // majors[i] is the spine after major block i+1
}

// view returns the spines and records of the first max major blocks walked (all of them for max 0). Both only ever
// grow, so a view stays valid while Refresh appends.
func (b *Builder) view(max uint64) ([]*Spine, *Archive) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := len(b.majors)
	if max > 0 && max < uint64(n) {
		n = int(max)
	}
	return b.majors[:n:n], &Archive{Majors: b.ar.Majors[:n:n]}
}

// NewBuilder walks the spine from the pinned incarnation's genesis once; every Build extends a copy of it. The
// incarnation evidence must re-derive the pinned identity.
func NewBuilder(ctx context.Context, c *jsonrpc.Client, q proof.AccumulateQuerier, inc *proof.IncarnationEvidence, pinned [32]byte) (*Builder, error) {
	ir, err := inc.Verify()
	if err != nil {
		return nil, fmt.Errorf("incarnation evidence: %w", err)
	}
	if ir.Incarnation != pinned {
		return nil, fmt.Errorf("incarnation evidence is for %x, not the pinned %x", ir.Incarnation, pinned)
	}
	g, err := genesisValues(ir.Inputs.NetworkRecord, ir.Inputs.GlobalsRecord)
	if err != nil {
		return nil, err
	}
	b := &Builder{C: c, Q: q, inc: pinned, incEv: inc, ar: &Archive{}}
	sp, err := NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	if err := b.extend(ctx, sp); err != nil {
		return nil, err
	}
	return b, nil
}

// NewBuilderFromArchive is NewBuilder that walks the given major records instead of fetching them, and then follows
// the network through c as NewBuilder's does. The records are verified by the walk, as fetched ones are.
func NewBuilderFromArchive(c *jsonrpc.Client, q proof.AccumulateQuerier, inc *proof.IncarnationEvidence, pinned [32]byte, ar *Archive) (*Builder, error) {
	ir, err := inc.Verify()
	if err != nil {
		return nil, fmt.Errorf("incarnation evidence: %w", err)
	}
	if ir.Incarnation != pinned {
		return nil, fmt.Errorf("incarnation evidence is for %x, not the pinned %x", ir.Incarnation, pinned)
	}
	g, err := genesisValues(ir.Inputs.NetworkRecord, ir.Inputs.GlobalsRecord)
	if err != nil {
		return nil, err
	}
	sp, err := NewSpine(g, 1)
	if err != nil {
		return nil, err
	}
	b := &Builder{C: c, Q: q, inc: pinned, incEv: inc, ar: &Archive{}}
	for _, r := range ar.Majors {
		if err := sp.Advance(r); err != nil {
			return nil, fmt.Errorf("spine: %w", err)
		}
		b.ar.Majors = append(b.ar.Majors, r)
		b.majors = append(b.majors, sp.Clone())
	}
	if len(b.majors) == 0 {
		return nil, fmt.Errorf("the archive holds no major block")
	}
	return b, nil
}

// Archive returns the major records walked so far.
func (b *Builder) Archive() *Archive {
	_, ar := b.view(0)
	return ar
}

// Refresh walks any major blocks closed since the last walk. Concurrent refreshes would walk the same blocks twice, so
// they are serialised.
func (b *Builder) Refresh(ctx context.Context) error {
	b.refresh.Lock()
	defer b.refresh.Unlock()
	majors, _ := b.view(0)
	return b.extend(ctx, majors[len(majors)-1].Clone())
}

func (b *Builder) extend(ctx context.Context, sp *Spine) error {
	for {
		recs, err := b.C.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor + 99})
		if err != nil {
			// A range past the newest major block is refused whole; ask for one at a time to reach the end.
			recs, err = b.C.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor})
			if err != nil {
				if majors, _ := b.view(0); len(majors) == 0 {
					return fmt.Errorf("spine: no major block could be read: %w", err)
				}
				return nil
			}
		}
		for _, r := range recs {
			if err := sp.Advance(r); err != nil {
				return fmt.Errorf("spine: %w", err)
			}
			b.mu.Lock()
			b.ar.Majors = append(b.ar.Majors, r)
			b.majors = append(b.majors, sp.Clone())
			b.mu.Unlock()
		}
	}
}

// lastMajorBefore returns the number of major blocks whose closing anchor precedes block, and the spine after them.
func lastMajorBefore(majors []*Spine, block uint64) (uint64, *Spine, error) {
	for i := len(majors) - 1; i >= 0; i-- {
		if majors[i].LastMinorBlock < block {
			return uint64(i + 1), majors[i].Clone(), nil
		}
	}
	return 0, nil, fmt.Errorf("DN block %d precedes the first major block", block)
}

// Build proves one transaction (S1-S2), its partition anchor, the captured pages (G1(a)) and the validator set in
// force (the set check). Pages are captured with CapturePage at discovery, while their block is inside retention.
func (b *Builder) Build(ctx context.Context, account, txHash, bvn string, pages ...*PageState) (*Evidence, error) {
	return b.BuildBounded(ctx, 0, account, txHash, bvn, pages...)
}

// BuildBounded is Build on no more than the first maxMajors major blocks (0: all walked). A proof judged in consensus
// must start at a checkpoint the chain has verified, so a proposer bounds it by the consensus spine's height; the
// proof's own minor-root runs cover the blocks past it.
func (b *Builder) BuildBounded(ctx context.Context, maxMajors uint64, account, txHash, bvn string, pages ...*PageState) (*Evidence, error) {
	ev, _, err := b.buildBounded(ctx, maxMajors, account, txHash, bvn, nil, pages...)
	return ev, err
}

// Build21 proves one transaction and assembles evidence 2.1 from a capture (docs/proof/G1_CROSS_PARTITION.md; RB9 Phase C1b-2): the
// transaction's own proof as Build does it, the captured pages of every partition each trimmed to its own partition's state root,
// the anchor of every partition proven into the same certified root (AnchorAt), the votes with their receipts, arrival proofs and
// production, the carried transaction, and the routing table proven beside the validator set. The producer verifies its own
// document with Verify21FromGenesis; the report is returned with it.
func (b *Builder) Build21(ctx context.Context, maxMajors uint64, account, txHash, bvn string, a *Assembly) (*Evidence, *Report, error) {
	if a == nil || len(a.Pages) == 0 {
		return nil, nil, &NamedState{Code: StateCompletenessUnproven, Detail: "evidence 2.1 needs the captured pages"}
	}
	return b.buildBounded(ctx, maxMajors, account, txHash, bvn, a)
}

func (b *Builder) buildBounded(ctx context.Context, maxMajors uint64, account, txHash, bvn string, x *Assembly, pages ...*PageState) (*Evidence, *Report, error) {
	majors, ar := b.view(maxMajors)
	if len(majors) == 0 {
		return nil, nil, fmt.Errorf("no major block has been walked")
	}
	cp, err := chained_proof.NewProofBuilder(b.C, false).BuildProof(ctx, chained_proof.ProofInput{Account: account, TxHash: txHash, BVN: bvn})
	if err != nil {
		return nil, nil, fmt.Errorf("account and partition legs: %w", err)
	}
	r1, err := toMerkle(cp.Layer1.Receipt)
	if err != nil {
		return nil, nil, err
	}
	r2, err := toMerkle(cp.Layer2.RootReceipt)
	if err != nil {
		return nil, nil, err
	}

	// Certify the Directory block the Directory leg reached, from the last major block before it.
	n, cert, err := lastMajorBefore(majors, cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex)
	if err != nil {
		return nil, nil, err
	}
	// A minor-root run is bounded, so a long range can take several; walk until the run covers the target block.
	target := cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex
	anchored := x != nil // evidence 2.1 keeps only the runs that apply an update and the last, joined by links (build_anchored.go)
	mr, runs, links, err := b.CertifyRuns(ctx, cert, target, anchored)
	if err != nil {
		return nil, nil, err
	}

	// The Directory leg, asked to end at exactly the certified root: ForHeight on a chain-entry receipt is a root
	// chain height. The height is the certified anchor's RootChainIndex, which equals the end of its root proof (V-E A9, pinned on every
	// live fixture) and stays readable when the proof is not carried.
	certBody, err := checkDirectorySelfAnchor(mr.Anchor)
	if err != nil {
		return nil, nil, err
	}
	height := int64(certBody.RootChainIndex)
	q, err := b.C.Query(ctx, protocol.DnUrl().JoinPath(protocol.AnchorPool), &api.ChainQuery{
		Name: "anchor(directory)-root", Entry: r2.Anchor, IncludeReceipt: &api.ReceiptOptions{ForHeight: uint64(height)}})
	if err != nil {
		return nil, nil, fmt.Errorf("directory leg at root height %d: %w", height, err)
	}
	ce, ok := q.(*api.ChainEntryRecord[api.Record])
	if !ok || ce.Receipt == nil {
		return nil, nil, fmt.Errorf("directory leg: got %T without a receipt", q)
	}
	cont, err := r1.Combine(r2, &ce.Receipt.Receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("combine: %w", err)
	}

	// The partition anchor for the transaction's block, proven into the same certified root.
	l4 := cp.Layer4BVN
	if l4 == nil {
		return nil, nil, fmt.Errorf("no partition anchor leg for the transaction's block")
	}
	pool, err := url.Parse(l4.AnchorPool)
	if err != nil {
		return nil, nil, err
	}
	idx := l4.AnchorIndex
	aq, err := b.C.Query(ctx, pool, &api.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &api.ReceiptOptions{ForHeight: uint64(height)}})
	if err != nil {
		return nil, nil, fmt.Errorf("partition anchor at root height %d: %w", height, err)
	}
	ace, ok := aq.(*api.ChainEntryRecord[api.Record])
	if !ok || ace.Receipt == nil {
		return nil, nil, fmt.Errorf("partition anchor: got %T without a receipt", aq)
	}
	arb, err := ace.Receipt.Receipt.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	stateRoot, err := hex.DecodeString(l4.StateTreeAnchor)
	if err != nil {
		return nil, nil, err
	}
	var trimmed []PageState
	xSource := ""
	if x != nil {
		_, seq, _, aerr := anchorBody(l4.SequencedMessage)
		if aerr != nil {
			return nil, nil, aerr
		}
		xSource = seq.Source.String()
		pages = x.Pages
	}
	for _, p := range pages {
		root := stateRoot
		if x != nil {
			if strings.EqualFold(p.Partition, xSource) {
				root = stateRoot
			} else if r, ok := x.Roots[p.Partition]; ok {
				root = r[:]
			} else {
				return nil, nil, &NamedState{Code: StatePartitionAnchorUnavailable, Partition: p.Partition, Detail: fmt.Sprintf("%s: no state root is captured for its partition", p.URL)}
			}
		}
		t, err := trimPage(p, root)
		if err != nil {
			return nil, nil, err
		}
		trimmed = append(trimmed, *t)
	}

	set, chk, hopLinks, err := b.buildSetCheckAt(ctx, majors, n, cert, anchored)
	if err != nil {
		return nil, nil, err
	}

	rb, err := cont.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	ev := &Evidence{
		Version: Version, Account: account, TxHash: txHash,
		Receipt: hex.EncodeToString(rb), Majors: n, Certify: runs,
		Anchor: PartitionAnchor{Message: l4.SequencedMessage, Receipt: hex.EncodeToString(arb)},
		Pages:  trimmed,
		Check:  *set,
		Links:  append(links, hopLinks...),
	}

	if x != nil {
		return b.assemble21(ctx, ev, x, ar, height, chk)
	}

	// The producer verifies its own output, so a malformed proof never reaches storage.
	if _, err := Verify(ev, ar, b.incEv, b.inc); err != nil {
		return nil, nil, fmt.Errorf("built evidence that does not verify: %w", err)
	}
	return ev, nil, nil
}

// assemble21 turns the 2.0 document built from the transaction's proof into evidence 2.1: the anchors of the other partitions, the
// votes, the transaction and the routing proof, then verifies it.
func (b *Builder) assemble21(ctx context.Context, ev *Evidence, x *Assembly, ar *Archive, rootHeight int64, chk *Spine) (*Evidence, *Report, error) {
	_, seq, _, err := anchorBody(ev.Anchor.Message)
	if err != nil {
		return nil, nil, err
	}
	ev.Version = Version21
	if len(ev.Links) > 0 { // the chain identity of an anchored document (V-E A1b)
		if err := b.addGenesisLink(ctx, ev); err != nil {
			return nil, nil, err
		}
	}
	ev.Anchors = map[string]PartitionAnchor{seq.Source.String(): ev.Anchor}
	for _, pb := range x.Foreign {
		pa, _, err := AnchorAt(ctx, b.C, pb, uint64(rootHeight))
		if err != nil {
			return nil, nil, fmt.Errorf("anchor of %s block %d: %w", pb.Partition, pb.Block, err)
		}
		ev.Anchors[protocol.PartitionUrl(pb.Partition).String()] = pa
	}
	if ev.Votes, err = x.ProveMembers(ctx, ev.Account); err != nil {
		return nil, nil, err
	}
	if len(x.Votes) == 0 {
		ev.Votes = nil
	}
	ev.Transaction = x.Transaction
	if ev.Check.Routing, err = proof.BuildRoutingProofAt(ctx, b.Q, chk.LastMinorBlock, chk.StateTreeAnchor); err != nil {
		return nil, nil, fmt.Errorf("routing proof: %w", err)
	}
	ir, err := b.incEv.Verify()
	if err != nil {
		return nil, nil, fmt.Errorf("incarnation evidence: %w", err)
	}
	rep, err := Verify21FromGenesis(ev, ar, ir.Inputs, b.inc)
	if err != nil {
		return nil, nil, fmt.Errorf("built evidence 2.1 that does not verify: %w", err)
	}
	// Before anything is signed: the whole certificate must fit the transaction path (certificate_budget{size,limit} with tx_too_large), and
	// the update windows (one link each) at this validator count must be inside the k x V bound (xbudget.go).
	if err := checkAssembledBudget(ev, rep.Validators, seq.Source.String(), rep.AnchorBlock); err != nil {
		return nil, nil, err
	}
	return ev, rep, nil
}

// buildSetCheckAt proves the validator set at the certified block itself, reusing the certification: no runs of its
// own, which keeps the evidence small enough for a consensus block. The certified block is recent when a proof is built
// promptly, so its state is inside the node's retention; when it is not (a proof built later), the set is proven at
// the newest certified block instead (buildSetCheck). Both are the same guarantee: the set proven at a certified block
// at or after the certified one.
func (b *Builder) buildSetCheckAt(ctx context.Context, majors []*Spine, n uint64, cert *Spine, anchored bool) (*SetCheck, *Spine, []string, error) {
	set, err := proof.BuildValidatorSetProofAt(ctx, b.Q, b.inc, cert.LastMinorBlock, cert.StateTreeAnchor)
	if err != nil {
		if strings.Contains(err.Error(), "retained") {
			return b.buildSetCheck(ctx, majors, cert.LastMinorBlock, anchored)
		}
		return nil, nil, nil, fmt.Errorf("set check: %w", err)
	}
	return &SetCheck{Majors: n, Set: *set}, cert, nil, nil
}

// buildSetCheck walks a copy of the spine from the last major block to the newest certified block, keeping every
// minor-root run (anchored: the runs that apply an update and the last, with their links), and proves the validator set there. The
// newest certified block is inside the public node's retention, and its state receipt passes through the state root the anchor
// certifies whatever later root it ends at.
func (b *Builder) buildSetCheck(ctx context.Context, majors []*Spine, atLeast uint64, anchored bool) (*SetCheck, *Spine, []string, error) {
	n := uint64(len(majors))
	chk := majors[n-1].Clone()
	startRoot := chk.RootChainAnchor
	var hops []string
	var served []servedRun
	for {
		mr, err := b.C.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: chk.LastMinorBlock})
		if err != nil {
			break
		}
		applied := len(chk.Applied)
		if err := chk.AdvanceEpoch(mr); err != nil {
			return nil, nil, nil, certifyError("set check", err)
		}
		served = append(served, servedRun{rec: mr, applied: len(chk.Applied) > applied})
		hb, err := mr.MarshalBinary()
		if err != nil {
			return nil, nil, nil, err
		}
		hops = append(hops, hex.EncodeToString(hb))
	}
	if len(hops) == 0 || chk.LastMinorBlock < atLeast {
		return nil, nil, nil, fmt.Errorf("set check: the walk reached DN %d, not the certified DN %d", chk.LastMinorBlock, atLeast)
	}
	var links []string
	if anchored {
		var err error
		if hops, links, err = anchorRuns(ctx, served, startRoot, NewClientLinks(b.C)); err != nil {
			return nil, nil, nil, err
		}
	}
	set, err := proof.BuildValidatorSetProofAt(ctx, b.Q, b.inc, chk.LastMinorBlock, chk.StateTreeAnchor)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("set check: %w", err)
	}
	return &SetCheck{Majors: n, Hops: hops, Set: *set}, chk, links, nil
}

func toMerkle(r chained_proof.Receipt) (*merkle.Receipt, error) {
	out := new(merkle.Receipt)
	var err error
	if out.Start, err = hex.DecodeString(r.Start); err != nil {
		return nil, err
	}
	if out.Anchor, err = hex.DecodeString(r.Anchor); err != nil {
		return nil, err
	}
	for _, e := range r.Entries {
		h, err := hex.DecodeString(e.Hash)
		if err != nil {
			return nil, err
		}
		out.Entries = append(out.Entries, &merkle.ReceiptEntry{Hash: h, Right: e.Right})
	}
	return out, nil
}

// CertifyRuns walks cert (the spine after the last major block before target) through the Directory's minor-root runs until one covers
// the block target, and returns them as certify members: every run continuous (anchored false: evidence 2.0), or the runs that apply an
// update and the last, anchored, with their links (anchored true: evidence 2.1). last is the run that certifies target. cert is advanced.
// A range the Directory does not serve is certify_range_unavailable{since,until}; a link that cannot be had is certify_link_unavailable.
func (b *Builder) CertifyRuns(ctx context.Context, cert *Spine, target uint64, anchored bool) (last *api.MinorRootRecord, runs, links []string, err error) {
	startRoot := cert.RootChainAnchor
	var served []servedRun
	for cert.LastMinorBlock < target {
		since := cert.LastMinorBlock
		mr, err := b.C.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: since, Until: target})
		if err != nil {
			if strings.Contains(err.Error(), "no anchor at or after") {
				return nil, nil, nil, fmt.Errorf("DN %d: %w", target, ErrNotYetCertified)
			}
			return nil, nil, nil, fmt.Errorf("certify DN %d: %w", target, rangeUnavailable(since, target, err))
		}
		applied := len(cert.Applied)
		if err := cert.AdvanceEpoch(mr); err != nil {
			return nil, nil, nil, certifyError("certify", err)
		}
		served = append(served, servedRun{rec: mr, applied: len(cert.Applied) > applied})
		rb, err := mr.MarshalBinary()
		if err != nil {
			return nil, nil, nil, err
		}
		runs = append(runs, hex.EncodeToString(rb))
		last = mr
	}
	if last == nil {
		return nil, nil, nil, fmt.Errorf("certify DN %d: the spine already stands at DN %d", target, cert.LastMinorBlock)
	}
	if anchored {
		if runs, links, err = anchorRuns(ctx, served, startRoot, NewClientLinks(b.C)); err != nil {
			return nil, nil, nil, err
		}
	}
	return last, runs, links, nil
}
