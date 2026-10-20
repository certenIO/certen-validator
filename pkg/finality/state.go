// Copyright 2026 Certen Protocol

package finality

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Named is every answer this package gives that is not a level: a named state with its data. Nothing is returned as a
// bare string, a boolean or a weaker level (00_STANDARD.md section 3, "No fallback").
type Named interface {
	error
	// Code is the state's published name, e.g. "finality_kind_unknown".
	Code() string
	// Fields are the values the state was judged at (chain, level, block, ...), as text.
	Fields() map[string]string
}

// AsNamed returns the named state in err's chain, if any.
func AsNamed(err error) (Named, bool) {
	var n Named
	if errors.As(err, &n) {
		return n, true
	}
	return nil, false
}

// Codes of the states the framework itself names. Chain packages add their own (finality_participation_insufficient,
// game_challenger_wins, ...) as State values with their own codes.
const (
	CodeChainUnsupported       = "finality_chain_unsupported"
	CodeKindUnknown            = "finality_kind_unknown"
	CodeEvidenceMalformed      = "finality_evidence_malformed"
	CodeEvidenceUnrecognised   = "finality_evidence_unrecognised"
	CodeSubjectMismatch        = "finality_subject_mismatch"
	CodeLevelExceedsEvidence   = "finality_level_exceeds_evidence"
	CodeLevelNotOffered        = "finality_level_not_offered"
	CodeLevelMismatch          = "finality_level_mismatch"
	CodeVerifierFailed         = "finality_verifier_failed"
	CodeChainBroken            = "finality_addendum_chain_broken"
	CodeAddendumMalformed      = "finality_addendum_malformed"
	CodePinMissing             = "finality_pin_unknown"
	CodeIncludedUnavailable    = "finality_included_unavailable"
	CodeIncludedInvalid        = "finality_included_invalid"
	CodeAppendConflict         = "finality_append_conflict"
	CodePanic                  = "finality_prover_panicked"
	CodeBuildTimeout           = "finality_build_timeout"
	CodeUpgraderDisabled       = "finality_upgrader_disabled"
	CodeNotApplicable          = "level_not_applicable"
	CodePending                = "finality_pending"
	CodeDocumentDigestMismatch = "finality_document_digest_mismatch"
)

// State is a refusal or an unavailability, named, with the values it was judged at.
type State struct {
	StateCode string
	Detail    map[string]string
}

// NewState builds a State from alternating key, value pairs.
func NewState(code string, kv ...any) *State {
	s := &State{StateCode: code, Detail: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Detail[fmt.Sprint(kv[i])] = fmt.Sprint(kv[i+1])
	}
	return s
}

func (s *State) Code() string { return s.StateCode }

func (s *State) Fields() map[string]string { return copyFields(s.Detail) }

func (s *State) Error() string { return render(s.StateCode, s.Detail) }

// NotApplicable is the typed non-level for a level the chain does not have (Adiri and Sepolia have no l1_posted). It is
// complete as an answer: a chain whose only missing levels are not applicable has reached its top.
type NotApplicable struct {
	Chain  uint64
	Level  Level
	Reason string
}

func (n *NotApplicable) Code() string { return CodeNotApplicable }

func (n *NotApplicable) Fields() map[string]string {
	return map[string]string{"chain": fmt.Sprint(n.Chain), "level": n.Level.String(), "reason": n.Reason}
}

func (n *NotApplicable) Error() string { return render(CodeNotApplicable, n.Fields()) }

// Pending is the typed non-level for a level that is not yet buildable: it names the level reached (which is proven), the
// next level, an estimate of when it can be built, and why not yet. It is not a failure and carries no weaker evidence.
type Pending struct {
	Chain        uint64
	LevelReached Level
	NextLevel    Level
	// ETA is the earliest time the next level can be built (zero if unknown). It is an estimate, never evidence.
	ETA    time.Time
	Reason string
	// Judged are the values the pending judgement was made at (block, slot, epoch, ...).
	Judged map[string]string
}

func (p *Pending) Code() string { return CodePending }

func (p *Pending) Fields() map[string]string {
	f := copyFields(p.Judged)
	f["chain"] = fmt.Sprint(p.Chain)
	f["level_reached"] = p.LevelReached.String()
	f["next_level"] = p.NextLevel.String()
	f["reason"] = p.Reason
	if !p.ETA.IsZero() {
		f["eta"] = p.ETA.UTC().Format(time.RFC3339)
	}
	return f
}

func (p *Pending) Error() string { return render(CodePending, p.Fields()) }

func copyFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+5)
	for k, v := range in {
		out[k] = v
	}
	return out
}

func render(code string, f map[string]string) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(code)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(f[k])
	}
	b.WriteByte('}')
	return b.String()
}
