// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
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
	majors, ar := b.view(maxMajors)
	if len(majors) == 0 {
		return nil, fmt.Errorf("no major block has been walked")
	}
	cp, err := chained_proof.NewProofBuilder(b.C, false).BuildProof(ctx, chained_proof.ProofInput{Account: account, TxHash: txHash, BVN: bvn})
	if err != nil {
		return nil, fmt.Errorf("account and partition legs: %w", err)
	}
	r1, err := toMerkle(cp.Layer1.Receipt)
	if err != nil {
		return nil, err
	}
	r2, err := toMerkle(cp.Layer2.RootReceipt)
	if err != nil {
		return nil, err
	}

	// Certify the Directory block the Directory leg reached, from the last major block before it.
	n, cert, err := lastMajorBefore(majors, cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex)
	if err != nil {
		return nil, err
	}
	// A minor-root run is bounded, so a long range can take several; walk until the run covers the target block.
	target := cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex
	var mr *api.MinorRootRecord
	var runs []string
	for cert.LastMinorBlock < target {
		mr, err = b.C.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: cert.LastMinorBlock, Until: target})
		if err != nil {
			if strings.Contains(err.Error(), "no anchor at or after") {
				return nil, fmt.Errorf("DN %d: %w", target, ErrNotYetCertified)
			}
			return nil, fmt.Errorf("certify DN %d: %w", target, err)
		}
		if err := cert.AdvanceEpoch(mr); err != nil {
			return nil, fmt.Errorf("certify: %w", err)
		}
		rb, err := mr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		runs = append(runs, hex.EncodeToString(rb))
	}

	// The Directory leg, asked to end at exactly the certified root: ForHeight on a chain-entry receipt is a root
	// chain height, and the certified anchor's root covers the root chain to the end of its RootProof.
	height := mr.RootProof.MerkleState.Count + int64(len(mr.RootProof.Elements)) - 1
	q, err := b.C.Query(ctx, protocol.DnUrl().JoinPath(protocol.AnchorPool), &api.ChainQuery{
		Name: "anchor(directory)-root", Entry: r2.Anchor, IncludeReceipt: &api.ReceiptOptions{ForHeight: uint64(height)}})
	if err != nil {
		return nil, fmt.Errorf("directory leg at root height %d: %w", height, err)
	}
	ce, ok := q.(*api.ChainEntryRecord[api.Record])
	if !ok || ce.Receipt == nil {
		return nil, fmt.Errorf("directory leg: got %T without a receipt", q)
	}
	cont, err := r1.Combine(r2, &ce.Receipt.Receipt)
	if err != nil {
		return nil, fmt.Errorf("combine: %w", err)
	}

	// The partition anchor for the transaction's block, proven into the same certified root.
	l4 := cp.Layer4BVN
	if l4 == nil {
		return nil, fmt.Errorf("no partition anchor leg for the transaction's block")
	}
	pool, err := url.Parse(l4.AnchorPool)
	if err != nil {
		return nil, err
	}
	idx := l4.AnchorIndex
	aq, err := b.C.Query(ctx, pool, &api.ChainQuery{Name: "main", Index: &idx, IncludeReceipt: &api.ReceiptOptions{ForHeight: uint64(height)}})
	if err != nil {
		return nil, fmt.Errorf("partition anchor at root height %d: %w", height, err)
	}
	ace, ok := aq.(*api.ChainEntryRecord[api.Record])
	if !ok || ace.Receipt == nil {
		return nil, fmt.Errorf("partition anchor: got %T without a receipt", aq)
	}
	arb, err := ace.Receipt.Receipt.MarshalBinary()
	if err != nil {
		return nil, err
	}
	stateRoot, err := hex.DecodeString(l4.StateTreeAnchor)
	if err != nil {
		return nil, err
	}
	var trimmed []PageState
	for _, p := range pages {
		t, err := trimPage(p, stateRoot)
		if err != nil {
			return nil, err
		}
		trimmed = append(trimmed, *t)
	}

	set, err := b.buildSetCheckAt(ctx, majors, n, cert)
	if err != nil {
		return nil, err
	}

	rb, err := cont.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ev := &Evidence{
		Version: Version, Account: account, TxHash: txHash,
		Receipt: hex.EncodeToString(rb), Majors: n, Certify: runs,
		Anchor: PartitionAnchor{Message: l4.SequencedMessage, Receipt: hex.EncodeToString(arb)},
		Pages:  trimmed,
		Check:  *set,
	}

	// The producer verifies its own output, so a malformed proof never reaches storage.
	if _, err := Verify(ev, ar, b.incEv, b.inc); err != nil {
		return nil, fmt.Errorf("built evidence that does not verify: %w", err)
	}
	return ev, nil
}

// buildSetCheckAt proves the validator set at the certified block itself, reusing the certification: no runs of its
// own, which keeps the evidence small enough for a consensus block. The certified block is recent when a proof is built
// promptly, so its state is inside the node's retention; when it is not (a proof built later), the set is proven at
// the newest certified block instead (buildSetCheck). Both are the same guarantee: the set proven at a certified block
// at or after the certified one.
func (b *Builder) buildSetCheckAt(ctx context.Context, majors []*Spine, n uint64, cert *Spine) (*SetCheck, error) {
	set, err := proof.BuildValidatorSetProofAt(ctx, b.Q, b.inc, cert.LastMinorBlock, cert.StateTreeAnchor)
	if err != nil {
		if strings.Contains(err.Error(), "retained") {
			return b.buildSetCheck(ctx, majors, cert.LastMinorBlock)
		}
		return nil, fmt.Errorf("set check: %w", err)
	}
	return &SetCheck{Majors: n, Set: *set}, nil
}

// buildSetCheck walks a copy of the spine from the last major block to the newest certified block, keeping every
// minor-root run, and proves the validator set there. The newest certified block is inside the public node's
// retention, and its state receipt passes through the state root the anchor certifies whatever later root it ends at.
func (b *Builder) buildSetCheck(ctx context.Context, majors []*Spine, atLeast uint64) (*SetCheck, error) {
	n := uint64(len(majors))
	chk := majors[n-1].Clone()
	var hops []string
	for {
		mr, err := b.C.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: chk.LastMinorBlock})
		if err != nil {
			break
		}
		if err := chk.AdvanceEpoch(mr); err != nil {
			return nil, fmt.Errorf("set check: %w", err)
		}
		hb, err := mr.MarshalBinary()
		if err != nil {
			return nil, err
		}
		hops = append(hops, hex.EncodeToString(hb))
	}
	if len(hops) == 0 || chk.LastMinorBlock < atLeast {
		return nil, fmt.Errorf("set check: the walk reached DN %d, not the certified DN %d", chk.LastMinorBlock, atLeast)
	}
	set, err := proof.BuildValidatorSetProofAt(ctx, b.Q, b.inc, chk.LastMinorBlock, chk.StateTreeAnchor)
	if err != nil {
		return nil, fmt.Errorf("set check: %w", err)
	}
	return &SetCheck{Majors: n, Hops: hops, Set: *set}, nil
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
