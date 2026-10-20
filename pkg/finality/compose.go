// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"encoding/json"
)

// SectionSource is what the portable composition reads for one proof: the leg (the chain its bundle's execution proof settled
// on), the leg's L6 evidence and the stored addendum chain. pkg/database.FinalityAddendaRepository implements it.
type SectionSource interface {
	LegRef(ctx context.Context, proofID string) (LegRef, error)
	LegSettlement(ctx context.Context, ref LegRef) (Settlement, error)
	Chain(ctx context.Context, proofID string) ([]Addendum, error)
}

// ComposeSection builds the spec-2.5 member of a proof's portable document,
//
//	{"format":"certen-finality-addenda/1","leg":{"chain","blockNumber","blockHash"},"addenda":[...]}
//
// at request time, from the repository, exactly as the proof service composes `majors` and `govRootV3Inputs`: the member is not
// stored inside the document and nothing in the chain depends on how the rest of the document is composed. The leg is the
// block DERIVED from the proof's verified L6 evidence (DeriveIncluded), never a stored claim, and the stored chain is recomputed
// under D0 = LegBinding of that block before it is served: a chain that does not verify is not composed (the named
// finality_chain_broken, so the caller can show the state instead of a section a verifier will refuse).
//
// A proof with no addenda has no section: the result is nil and the document is byte-for-byte what it was (the member is
// absent, not empty). A proof whose bundle carries no settlement evidence has no leg to attach to: the named
// finality_included_unavailable state.
func ComposeSection(ctx context.Context, src SectionSource, proofID string) (*Section, error) {
	if _, err := ParseProofID(proofID); err != nil {
		return nil, err
	}
	chain, err := src.Chain(ctx, proofID)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, nil
	}
	ref, err := src.LegRef(ctx, proofID)
	if err != nil {
		return nil, err
	}
	settlement, err := src.LegSettlement(ctx, ref)
	if err != nil {
		return nil, err
	}
	block, err := DeriveIncluded(ref.Chain, settlement.Included)
	if err != nil {
		return nil, err
	}
	if err := CheckLegChain(block, block, chain); err != nil {
		return nil, err
	}
	s := NewSection(block, chain)
	return &s, nil
}

// ComposeSectionJSON is ComposeSection rendered as the JSON value of the document's `finality` member (nil when the proof has
// no addenda).
func ComposeSectionJSON(ctx context.Context, src SectionSource, proofID string) (json.RawMessage, error) {
	s, err := ComposeSection(ctx, src, proofID)
	if err != nil || s == nil {
		return nil, err
	}
	return json.Marshal(s)
}
