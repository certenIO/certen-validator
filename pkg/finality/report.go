// Copyright 2026 Certen Protocol

package finality

import (
	"github.com/certen/independant-validator/pkg/ethproof"
)

// Status of one level in a Report (R2).
type Status string

const (
	StatusVerified      Status = "verified"
	StatusNotApplicable Status = "level_not_applicable"
	StatusPending       Status = "pending"
	StatusRefused       Status = "refused"
)

// LevelStatus is one level's outcome: verified (with the Kind's Verdict), level_not_applicable (the table's reason),
// pending (finality_pending, always with the level reached) or refused{code} (evidence present, predicate false).
type LevelStatus struct {
	Status  Status
	Verdict *Verdict
	State   *StateError // not-applicable, pending or refusal state; nil when verified
}

// FinalizedBlock is the leg's own block as S7 finalized it, for S8 (R6).
type FinalizedBlock struct {
	Number    uint64
	Hash      [32]byte
	StateRoot [32]byte
}

// Report is the S7 outcome for ONE leg: the pair (Settlement block, addenda) it judged.
type Report struct {
	Block BlockRef
	// Unsupported is finality_chain_unsupported when the chain is not a row of the table (R5): no S7 statement at all.
	Unsupported *StateError
	// Included is level 1, derived from the Settlement (R1); Levels[LevelIncluded] mirrors it.
	Levels map[Level]LevelStatus
	// Headline is the highest verified level (LevelNone if the Settlement itself did not verify).
	Headline Level
	// Broken is finality_chain_broken when the addendum chain, or the carried leg, does not verify: it voids every addendum
	// (R3), the headline is included.
	Broken *StateError
	// FinalizedBlock is exposed when finalized is verified (R6).
	FinalizedBlock *FinalizedBlock
	// FinalizedBlockState is the named state raised when finalized is verified and the leg block still cannot be exposed (the
	// BlockRef has no header, or its header is unreadable): R6 is never silently omitted.
	FinalizedBlockState *StateError
	// PinsSHA256 and PinsSource name the pins judged against (4.1).
	PinsSHA256 string
	PinsSource string
}

// Verify is the pure S7 judgement of one leg: the Settlement is verified (S6, level 1 derived, R1), the carried leg is
// compared with the verified Settlement's triple, the chain is verified against D0 recomputed from that triple, and each
// addendum is judged alone. The addenda never supply D0.
func (r *Registry) Verify(chain uint64, s *ethproof.Settlement, carried BlockRef, adds []Addendum, p *Pins) Report {
	b, err := DeriveIncluded(chain, s)
	if err != nil {
		st, _ := AsNamed(err)
		rep := Report{Block: BlockRef{Chain: chain}, Levels: map[Level]LevelStatus{LevelIncluded: {Status: StatusRefused, State: st}}}
		rep.PinsSHA256, rep.PinsSource = p.Identity()
		return rep
	}
	return r.VerifyLeg(b, carried, adds, p)
}

// Verify is Registry.Verify over the Default registry.
func Verify(chain uint64, s *ethproof.Settlement, carried BlockRef, adds []Addendum, p *Pins) Report {
	return Default.Verify(chain, s, carried, adds, p)
}

// VerifyLeg judges addenda against an already verified leg block b (the triple of a verified Settlement). Rules:
//
//	R1 included is derived, never stored.            R2 levels are independent; the headline is the highest verified.
//	R3 a broken chain voids all addenda.             R4 an absent level is finality_pending{no_evidence_in_file}.
//	R5 not-applicable comes from the table.          R6 finalized exposes finalized_block.
func (r *Registry) VerifyLeg(b BlockRef, carried BlockRef, adds []Addendum, p *Pins) Report {
	rep := Report{Block: b, Levels: map[Level]LevelStatus{}}
	rep.PinsSHA256, rep.PinsSource = p.Identity()
	if !ChainSupported(b.Chain) {
		rep.Unsupported = ChainUnsupported(b.Chain)
		return rep
	}
	rep.Levels[LevelIncluded] = LevelStatus{Status: StatusVerified}
	rep.Headline = LevelIncluded

	voided := func(st *StateError) {
		rep.Broken = st
		for _, l := range []Level{LevelL1Posted, LevelFinalized} {
			rep.Levels[l] = r.absentOrNA(b.Chain, l, LevelIncluded, &LevelStatus{Status: StatusRefused, State: st})
		}
	}
	if err := CheckLegChain(b, carried, adds); err != nil {
		st, _ := AsNamed(err)
		voided(st)
		return rep
	}
	byLevel := map[Level]Addendum{}
	for _, a := range adds {
		byLevel[a.Level] = a
	}
	// independent judgement per level (R2); the headline is the highest verified
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		a, present := byLevel[l]
		if !present {
			continue
		}
		v, err := r.JudgeAddendum(b, a, p)
		if err != nil {
			st, _ := AsNamed(err)
			if st == nil {
				st = NewState(CodeVerifierFailed, "chain", b.Chain, "kind", a.Kind, "cause", err.Error())
			}
			rep.Levels[l] = LevelStatus{Status: StatusRefused, State: st}
			continue
		}
		vv := v
		rep.Levels[l] = LevelStatus{Status: StatusVerified, Verdict: &vv}
		if l > rep.Headline {
			rep.Headline = l
		}
	}
	for _, l := range []Level{LevelL1Posted, LevelFinalized} {
		if _, done := rep.Levels[l]; done {
			continue
		}
		rep.Levels[l] = r.absentOrNA(b.Chain, l, rep.Headline, nil)
	}
	if st := rep.Levels[LevelFinalized]; st.Status == StatusVerified {
		switch {
		case len(b.HeaderRLP) == 0:
			rep.FinalizedBlockState = FinalizedBlockUnavailable(b.Chain, b.Number, FinalizedBlockNoHeader)
		default:
			h, err := ReadHeader(b.HeaderRLP)
			if err != nil {
				kv := []any{}
				if hs, ok := AsNamed(err); ok {
					if idx, has := hs.Fields["index"]; has {
						kv = append(kv, "index", idx)
					}
				}
				rep.FinalizedBlockState = FinalizedBlockUnavailable(b.Chain, b.Number, FinalizedBlockHeaderUnreadable, kv...)
			} else {
				rep.FinalizedBlock = &FinalizedBlock{Number: b.Number, Hash: b.Hash, StateRoot: h.StateRoot}
			}
		}
	}
	return rep
}

// absentOrNA is the status of a level with no addendum: level_not_applicable from the table (never from the file), else
// finality_pending{no_evidence_in_file} (R4) - or `fallback` when the chain is broken and the level is offered.
func (r *Registry) absentOrNA(chain uint64, l, reached Level, fallback *LevelStatus) LevelStatus {
	if _, err := KindFor(chain, l); err != nil {
		if st, ok := AsNamed(err); ok && st.Code == CodeNotApplicable {
			return LevelStatus{Status: StatusNotApplicable, State: st}
		}
	}
	if fallback != nil {
		return *fallback
	}
	return LevelStatus{Status: StatusPending, State: NoEvidenceInFile(chain, reached, l).State()}
}
