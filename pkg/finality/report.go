// Copyright 2026 Certen Protocol

package finality

import (
	"encoding/json"
	"strconv"
)

// Verdict is the outcome of judging one leg's addendum chain.
type Verdict string

const (
	// VerdictVerified: the chain verifies and every addendum's evidence verifies to exactly its level.
	VerdictVerified Verdict = "verified"
	// VerdictSummaryOnly: nothing is wrong, but some addendum could not be judged here (no verifier registered for its kind,
	// a pin this verifier does not hold, an unrecognised container version). The levels below it are reported; it is not.
	VerdictSummaryOnly Verdict = "summary_only"
	// VerdictFailed: the chain or an addendum's evidence is present and does not check out.
	VerdictFailed Verdict = "failed"
)

// AddendumVerdict is the judgement of one addendum.
type AddendumVerdict struct {
	Seq      uint64
	Level    Level
	Kind     string
	Verified bool
	// Err is the named state when not verified.
	Err error
	// Unjudged is true when Err means "this verifier cannot judge it" rather than "it is wrong".
	Unjudged bool
}

// LegReport is the per-statement S7 report of one leg: the level reached and why not further.
type LegReport struct {
	ProofID string
	Chain   uint64
	Subject Subject
	Digest  [32]byte
	Verdict Verdict
	// Reached is the highest level whose addendum, and every addendum before it, verified. LevelNone if none.
	Reached Level
	// Top is the chain's top level; Next the lowest offered level above Reached (LevelNone when Reached is the top).
	Top  Level
	Next Level
	// NotApplicable lists the levels this chain does not have, with reasons.
	NotApplicable []*NotApplicable
	// ChainErr is VerifyChain's refusal (nothing in a broken chain is reported as reached).
	ChainErr error
	Addenda  []AddendumVerdict
}

// unjudgedCodes are the named states that say "this verifier cannot judge", not "the evidence is wrong".
var unjudgedCodes = map[string]bool{
	CodeKindUnknown: true, CodePinMissing: true, CodeChainUnsupported: true, CodeEvidenceUnrecognised: true,
}

func isUnjudged(err error) bool {
	n, ok := AsNamed(err)
	return ok && unjudgedCodes[n.Code()]
}

// VerifyLeg judges one leg's chain against its original digest: VerifyChain first (a broken chain reports nothing as
// reached), then each addendum through VerifyAddendum, stopping the reached level at the first addendum that does not verify.
func (r *Registry) VerifyLeg(digest [32]byte, chain []Addendum, pins *Pins) LegReport {
	rep := LegReport{Digest: digest, Verdict: VerdictVerified}
	if len(chain) > 0 {
		rep.ProofID, rep.Chain = chain[0].ProofID, chain[0].Chain
		if subject, err := ChainSubject(chain); err == nil {
			rep.Subject = subject
		}
	}
	if profile, err := r.Profile(rep.Chain); err == nil {
		rep.Top = profile.Top()
		for _, l := range Levels {
			if na, ok := profile.NotApplicableFor(l); ok {
				rep.NotApplicable = append(rep.NotApplicable, na)
			}
		}
	}
	if err := VerifyChain(digest, chain); err != nil {
		rep.Verdict, rep.ChainErr = VerdictFailed, err
		return rep
	}
	stopped := false
	for _, a := range chain {
		v := AddendumVerdict{Seq: a.Seq, Level: a.Level, Kind: a.Kind}
		if stopped {
			v.Err = NewState(CodeVerifierFailed, "reason", "an earlier addendum did not verify", "seq", a.Seq)
			v.Unjudged = true
			rep.Addenda = append(rep.Addenda, v)
			continue
		}
		level, err := r.VerifyAddendum(a, pins)
		if err != nil {
			v.Err, v.Unjudged = err, isUnjudged(err)
			stopped = true
			if v.Unjudged {
				if rep.Verdict == VerdictVerified {
					rep.Verdict = VerdictSummaryOnly
				}
			} else {
				rep.Verdict = VerdictFailed
			}
		} else {
			v.Verified = true
			rep.Reached = level
		}
		rep.Addenda = append(rep.Addenda, v)
	}
	if profile, err := r.Profile(rep.Chain); err == nil {
		rep.Next = profile.Next(rep.Reached)
	}
	return rep
}

// PendingState returns the finality_pending state the report implies: the level reached is proven and the next is not yet
// evidenced. It is nil when the chain is at its top, or when the chain is broken or unjudged (those are not pending).
func (l LegReport) PendingState() *Pending {
	if l.Verdict != VerdictVerified || l.Next == LevelNone || l.Reached == LevelNone {
		return nil
	}
	return &Pending{Chain: l.Chain, LevelReached: l.Reached, NextLevel: l.Next, Reason: "no addendum for the next level yet",
		Judged: map[string]string{"block": strconv.FormatUint(l.Subject.BlockNumber, 10)}}
}

// DocumentSection is the value of a portable document's `finality` field for a proof: its addenda as JSON, each carrying the
// original digest it commits to. The field sits beside the document's hashed content and never inside it (PROOF_V2 10.3).
func DocumentSection(digest [32]byte, chain []Addendum) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(chain))
	for _, a := range chain {
		a.OriginalDigest = digest
		raw, err := json.Marshal(a)
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// VerifyDocumentSection judges the `finality` field of a portable document with no database: it groups the addenda by proof
// id (in document order), takes each group's original digest from its addenda (which must agree, and which the chain hash
// recomputes), and verifies every group as VerifyLeg does. A document with no finality section yields no legs.
func (r *Registry) VerifyDocumentSection(raw []json.RawMessage, pins *Pins) ([]LegReport, error) {
	groups := map[string][]Addendum{}
	var order []string
	for i, j := range raw {
		var a Addendum
		if err := json.Unmarshal(j, &a); err != nil {
			return nil, err
		}
		if a.OriginalDigest == ([32]byte{}) {
			return nil, NewState(CodeAddendumMalformed, "field", "originalDigest", "reason", "a document's addendum must carry the digest it commits to", "index", i)
		}
		if _, seen := groups[a.ProofID]; !seen {
			order = append(order, a.ProofID)
		}
		groups[a.ProofID] = append(groups[a.ProofID], a)
	}
	var reports []LegReport
	for _, id := range order {
		chain := groups[id]
		digest := chain[0].OriginalDigest
		bad := false
		for _, a := range chain {
			if a.OriginalDigest != digest {
				bad = true
			}
		}
		if bad {
			reports = append(reports, LegReport{
				ProofID: id, Chain: chain[0].Chain, Digest: digest, Verdict: VerdictFailed,
				ChainErr: NewState(CodeChainBroken, "check", "original_digest", "reason", "the addenda of one proof state different original digests"),
			})
			continue
		}
		rep := r.VerifyLeg(digest, chain, pins)
		reports = append(reports, rep)
	}
	return reports, nil
}
