// Copyright 2026 Certen Protocol

package finality

import (
	"errors"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// AppendRequest asks a store to extend one leg's addendum chain (V2_SPEC_S7 2.4). It carries NO chain link: the sequence
// number, previous hash and own hash are formed by the store under its lock from the chain it reads, so two upgraders that
// race on the same leg never hold a stale link. It carries no D0 either: the store derives the leg binding from Settlement
// (S6 verified here, the block number read positionally from the header), never from a file or from a caller.
type AppendRequest struct {
	ProofID    [16]byte
	Chain      uint64
	Settlement *ethproof.Settlement // the leg's L6 evidence; verified by DeriveIncluded inside the append
	Level      Level
	Kind       string
	Evidence   []byte    // the CFE1 container
	Registry   *Registry // the registered Kind verifiers: the evidence is judged by them or it is not stored
	Pins       *Pins
}

// errAppendIncomplete is a defect of the caller (a missing registry), not a state of any leg.
var errAppendIncomplete = errors.New("finality: an append request needs a registry (the evidence is judged before it is stored)")

// PlanAppend is the pure core of Append: given the chain the store has just read under its lock, it either returns the
// addendum to insert or the named state that refuses it. In order:
//
//  1. the leg block and D0 are derived from the request's Settlement (DeriveIncluded; D0 = LegBinding of that block);
//  2. the stored chain is recomputed under that D0 (CheckLegChain: chain supported, VerifyChain), so a chain forged under another
//     binding is refused as finality_chain_broken{own_hash} and nothing is appended to it; the chain must be about req.Chain;
//  3. the cheap checks: (chain, level, kind) is a table row and the chain holds no addendum at the level (level_already_present);
//  4. the registered Kind judges the evidence (Registry.JudgeAddendum: the container decodes strictly, its header names the
//     addendum's kind, chain and level and the leg block, and the Kind accepts it at exactly the row's level);
//  5. only then is the link formed (NewAddendum) and the addendum returned.
//
// The returned BlockRef is the derived leg block.
func PlanAppend(req AppendRequest, stored []Addendum) (Addendum, BlockRef, error) {
	if req.Registry == nil {
		return Addendum{}, BlockRef{}, errAppendIncomplete
	}
	block, err := DeriveIncluded(req.Chain, req.Settlement)
	if err != nil {
		return Addendum{}, BlockRef{}, err
	}
	if err := CheckLegChain(block, block, stored); err != nil {
		return Addendum{}, block, err
	}
	if len(stored) > 0 && stored[0].Chain != req.Chain {
		return Addendum{}, block, ChainBroken(1, CheckKind, "stored", stored[0].Chain, "settled_on", req.Chain)
	}
	if !IsRow(req.Chain, req.Level, req.Kind) {
		return Addendum{}, block, ChainBroken(uint64(len(stored)+1), CheckKind, "chain", req.Chain, "level", req.Level, "kind", req.Kind)
	}
	if LevelsOf(stored).Has(req.Level) {
		return Addendum{}, block, NewState(CodeLevelAlreadyPresent, "chain", req.Chain, "level", req.Level)
	}
	// the Kind judges the evidence of (chain, level, kind) about the leg block; the link (seq, prev, own hash) is formed after it
	candidate := Addendum{ProofID: req.ProofID, Level: req.Level, Chain: req.Chain, Kind: req.Kind, Evidence: req.Evidence}
	if _, err := req.Registry.JudgeAddendum(block, candidate, req.Pins); err != nil {
		return Addendum{}, block, err
	}
	a, err := NewAddendum(LegBindingOf(block), req.ProofID, stored, req.Chain, req.Level, req.Kind, req.Evidence)
	if err != nil {
		return Addendum{}, block, err
	}
	return a, block, nil
}
