// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/ethrpc"
)

// BuilderStatusFormat is the format string of a builder status document (the jsonb `state` column of proof_finality_status).
const BuilderStatusFormat = "certen-finality-status/1"

// BuilderClass is what kind of answer the builder holds for one (leg, target level). It is builder-side bookkeeping for the
// gateway (V2_SPEC_S7 2.7), outside the addendum chain and never read by a verifier.
type BuilderClass string

const (
	// BuilderPending: the level cannot be built yet (finality_pending: level reached, next level, reason, eta).
	BuilderPending BuilderClass = "pending"
	// BuilderUnavailable: the builder could not obtain what it needs (a provider window, a source, a timeout, a panic): class U.
	BuilderUnavailable BuilderClass = "unavailable"
	// BuilderRefused: evidence was built and the registered Kind refused it (class R); nothing was stored.
	BuilderRefused BuilderClass = "refused"
	// BuilderNotApplicable: the chain has no such level (level_not_applicable).
	BuilderNotApplicable BuilderClass = "not_applicable"
	// BuilderVerified: the level is stored (the addendum exists; the row says which seq).
	BuilderVerified BuilderClass = "verified"
)

// Status is one builder status row. State is nil only for BuilderVerified. NextLevel is the level the builder is working
// towards (the row's target level for every class but verified).
type BuilderStatus struct {
	ProofID      string
	Chain        uint64
	TargetLevel  Level
	Class        BuilderClass
	LevelReached Level
	NextLevel    Level
	ETA          time.Time // zero = no eta stated
	Seq          uint64    // the addendum's seq, BuilderVerified only
	State        *StateError
	JudgedAt     time.Time
}

// statusDoc is the stored form. Members are written in this fixed order; the named state is its Canonical form.
type statusDoc struct {
	Format       string          `json:"format"`
	Class        BuilderClass    `json:"class"`
	LevelReached string          `json:"levelReached"`
	NextLevel    string          `json:"nextLevel"`
	ETA          string          `json:"eta,omitempty"`
	Seq          uint64          `json:"seq,omitempty"`
	State        json.RawMessage `json:"state,omitempty"`
}

// Document renders the jsonb `state` of the row.
func (s BuilderStatus) Document() ([]byte, error) {
	if !s.TargetLevel.Stored() {
		return nil, fmt.Errorf("finality: a status row targets l1_posted or finalized, not %s", s.TargetLevel)
	}
	d := statusDoc{Format: BuilderStatusFormat, Class: s.Class, LevelReached: s.LevelReached.String(), NextLevel: s.NextLevel.String(), Seq: s.Seq}
	if !s.ETA.IsZero() {
		d.ETA = s.ETA.UTC().Format(time.RFC3339)
	}
	switch s.Class {
	case BuilderVerified:
		if s.State != nil {
			return nil, fmt.Errorf("finality: a verified status carries no state")
		}
	case BuilderPending, BuilderUnavailable, BuilderRefused, BuilderNotApplicable:
		if s.State == nil {
			return nil, fmt.Errorf("finality: a %s status names its state", s.Class)
		}
		d.State = s.State.Canonical()
	default:
		return nil, fmt.Errorf("finality: unknown status class %q", s.Class)
	}
	return json.Marshal(d)
}

// ParseBuilderStatusDocument is the inverse of Document for the fields a reader shows. The state is returned as the stored canonical
// JSON (code and fields), not re-materialised into a StateError.
func ParseBuilderStatusDocument(raw []byte) (BuilderStatusView, error) {
	var d statusDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return BuilderStatusView{}, fmt.Errorf("finality: status document: %w", err)
	}
	if d.Format != BuilderStatusFormat {
		return BuilderStatusView{}, fmt.Errorf("finality: status document format %q", d.Format)
	}
	v := BuilderStatusView{Class: d.Class, Seq: d.Seq, State: d.State}
	var err error
	if v.LevelReached, err = ParseLevelOrNone(d.LevelReached); err != nil {
		return BuilderStatusView{}, err
	}
	if v.NextLevel, err = ParseLevelOrNone(d.NextLevel); err != nil {
		return BuilderStatusView{}, err
	}
	if d.ETA != "" {
		if v.ETA, err = time.Parse(time.RFC3339, d.ETA); err != nil {
			return BuilderStatusView{}, fmt.Errorf("finality: status eta: %w", err)
		}
	}
	return v, nil
}

// ParseLevelOrNone reads a level name or "none".
func ParseLevelOrNone(s string) (Level, error) {
	if s == LevelNone.String() {
		return LevelNone, nil
	}
	return ParseLevel(s)
}

// BuilderStatusView is a status row as a reader (the gateway, proofverify --db) sees it.
type BuilderStatusView struct {
	ProofID      string
	Chain        uint64
	TargetLevel  Level
	Class        BuilderClass
	LevelReached Level
	NextLevel    Level
	ETA          time.Time
	Seq          uint64
	State        json.RawMessage // {"code":...,"fields":{...}} canonical, nil for verified
	JudgedAt     time.Time
}

// BuilderStatusStore holds the builder status rows: mutable, a later pass replaces the row of the same (proof, target level).
type BuilderStatusStore interface {
	UpsertStatus(ctx context.Context, s BuilderStatus) error
	// GetStatus returns the row, or ok=false when the builder has judged nothing for that (proof, level).
	GetStatus(ctx context.Context, proofID string, target Level) (BuilderStatusView, bool, error)
}

// BuilderStatusOf classifies a builder-side state for the status row. pd is the pending the prover returned (class pending);
// otherwise err is the named state it failed with: level_not_applicable is not_applicable, a refusal of built evidence
// (refused=true) is refused, anything else is unavailable. reached is the highest stored level the leg holds and target the
// level the builder was working towards.
func BuilderStatusOf(proofID string, chain uint64, target, reached Level, pd *PendingState, err error, refused bool, at time.Time) BuilderStatus {
	s := BuilderStatus{ProofID: proofID, Chain: chain, TargetLevel: target, LevelReached: reached, NextLevel: target, JudgedAt: at}
	if pd != nil {
		s.Class, s.State, s.ETA = BuilderPending, pd.State(), pd.ETA
		return s
	}
	st, named := AsNamed(err)
	if !named {
		st = NewState(CodeVerifierFailed, "chain", chain, "kind", "unnamed", "cause", fmt.Sprint(err))
	}
	switch {
	case st.Code == CodeNotApplicable:
		s.Class = BuilderNotApplicable
	case refused:
		s.Class = BuilderRefused
	default:
		s.Class = BuilderUnavailable
	}
	s.State = redactedState(st)
	return s
}

// redactedState is st with every text field (a string or an error value) passed through the one
// sanitiser of provider text, pkg/ethrpc RedactText, before it is stored in a status row: the row is read by the gateway and
// must never carry a credential from a provider URL or response. Numbers, bytes and levels are left as they are.
func redactedState(st *StateError) *StateError {
	out := NewState(st.Code)
	for k, v := range st.Fields {
		switch x := v.(type) {
		case string:
			out.Fields[k] = ethrpc.RedactText(x)
		case error:
			out.Fields[k] = ethrpc.RedactText(x.Error())
		default:
			out.Fields[k] = v
		}
	}
	return out
}

// VerifiedBuilderStatus is the row of a level that is stored.
func VerifiedBuilderStatus(proofID string, chain uint64, level Level, seq uint64, at time.Time) BuilderStatus {
	return BuilderStatus{ProofID: proofID, Chain: chain, TargetLevel: level, Class: BuilderVerified, LevelReached: level, NextLevel: level, Seq: seq, JudgedAt: at}
}
