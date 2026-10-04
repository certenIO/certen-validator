// Copyright 2026 Certen Protocol

package proofv2

import (
	"context"
	"encoding/hex"
	"fmt"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/proof"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// Builder builds v2 Accumulate evidence from a live network.
type Builder struct {
	C *jsonrpc.Client
	Q proof.AccumulateQuerier

	inc    [32]byte
	incEv  *proof.IncarnationEvidence
	ar     *Archive
	majors []*Spine // majors[i] is the spine after major block i+1
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
func (b *Builder) Archive() *Archive { return b.ar }

// Refresh walks any major blocks closed since the last walk.
func (b *Builder) Refresh(ctx context.Context) error {
	return b.extend(ctx, b.majors[len(b.majors)-1].Clone())
}

func (b *Builder) extend(ctx context.Context, sp *Spine) error {
	for {
		recs, err := b.C.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor + 99})
		if err != nil {
			// A range past the newest major block is refused whole; ask for one at a time to reach the end.
			recs, err = b.C.MajorHeaderRange(ctx, api.MajorHeaderRangeOptions{Partition: protocol.Directory, Start: sp.NextMajor, End: sp.NextMajor})
			if err != nil {
				if len(b.majors) == 0 {
					return fmt.Errorf("spine: no major block could be read: %w", err)
				}
				return nil
			}
		}
		for _, r := range recs {
			if err := sp.Advance(r); err != nil {
				return fmt.Errorf("spine: %w", err)
			}
			b.ar.Majors = append(b.ar.Majors, r)
			b.majors = append(b.majors, sp.Clone())
		}
	}
}

// lastMajorBefore returns the number of major blocks whose closing anchor precedes block, and the spine after them.
func (b *Builder) lastMajorBefore(block uint64) (uint64, *Spine, error) {
	for i := len(b.majors) - 1; i >= 0; i-- {
		if b.majors[i].LastMinorBlock < block {
			return uint64(i + 1), b.majors[i].Clone(), nil
		}
	}
	return 0, nil, fmt.Errorf("DN block %d precedes the first major block", block)
}

// Build proves one transaction (S1-S2) and the validator set in force (the set check).
func (b *Builder) Build(ctx context.Context, account, txHash, bvn string) (*Evidence, error) {
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
	n, cert, err := b.lastMajorBefore(cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex)
	if err != nil {
		return nil, err
	}
	mr, err := b.C.MinorRootRange(ctx, api.MinorRootRangeOptions{Partition: protocol.Directory, Since: cert.LastMinorBlock, Until: cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex})
	if err != nil {
		return nil, fmt.Errorf("certify DN %d: %w", cp.Layer3.DNSelfAnchorRecordedAtMinorBlockIndex, err)
	}
	if err := cert.AdvanceEpoch(mr); err != nil {
		return nil, fmt.Errorf("certify: %w", err)
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

	set, err := b.buildSetCheck(ctx, cert.LastMinorBlock)
	if err != nil {
		return nil, err
	}

	rb, err := cont.MarshalBinary()
	if err != nil {
		return nil, err
	}
	cb, err := mr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ev := &Evidence{
		Version: Version, Account: account, TxHash: txHash,
		Receipt: hex.EncodeToString(rb), Majors: n, Certify: hex.EncodeToString(cb),
		Check: *set,
	}

	// The producer verifies its own output, so a malformed proof never reaches storage.
	if _, err := Verify(ev, b.ar, b.incEv, b.inc); err != nil {
		return nil, fmt.Errorf("built evidence that does not verify: %w", err)
	}
	return ev, nil
}

// buildSetCheck walks a copy of the spine from the last major block to the newest certified block, keeping every
// minor-root run, and proves the validator set there. The newest certified block is inside the public node's
// retention, and its state receipt passes through the state root the anchor certifies whatever later root it ends at.
func (b *Builder) buildSetCheck(ctx context.Context, atLeast uint64) (*SetCheck, error) {
	n := uint64(len(b.majors))
	chk := b.majors[n-1].Clone()
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
