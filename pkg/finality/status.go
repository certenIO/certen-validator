// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
	// BuilderRefused: evidence was built and its APPEND was refused; nothing was stored. Who refused is the state's code, exactly: the
	// registered Kind's verifier (its own named state: class R proper), the store's chain checks (finality_chain_broken, or
	// finality_block_mismatch{leg}) or the table's guard (finality_guard_refused). The class names the event (a built addendum was not
	// stored), never the reason; the reason is the code.
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
	// PinsSHA256 is the hash of the pins the builder judged under (hex, 64 lowercase characters; Pins.Identity). It is recorded in the
	// document as pinsSha256 so that a consumer, who verifies under the pins IT trusts, can see whether the builder's pins differ from
	// its own. Empty = not recorded (a row written before the member existed, or by a writer that holds no pins).
	PinsSHA256 string
}

// WithPins is the status with the identity of the pins the builder judged under (a nil Pins records nothing).
func (s BuilderStatus) WithPins(p *Pins) BuilderStatus {
	h, _ := p.Identity()
	s.PinsSHA256 = h
	return s
}

// checkPinsSHA256 accepts an absent identity or 64 lowercase hex characters.
func checkPinsSHA256(h string) error {
	if h == "" {
		return nil
	}
	if len(h) != 64 {
		return fmt.Errorf("finality: status pinsSha256 %q is not 64 lowercase hex characters", h)
	}
	for i := 0; i < len(h); i++ {
		if c := h[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("finality: status pinsSha256 %q is not 64 lowercase hex characters", h)
		}
	}
	return nil
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
	// PinsSHA256 is additive (RB12-DBFIX): last, omitted when not recorded, so a document without it is what it always was.
	PinsSHA256 string `json:"pinsSha256,omitempty"`
}

// Document renders the jsonb `state` of the row.
func (s BuilderStatus) Document() ([]byte, error) {
	if !s.TargetLevel.Stored() {
		return nil, fmt.Errorf("finality: a status row targets l1_posted or finalized, not %s", s.TargetLevel)
	}
	if err := checkPinsSHA256(s.PinsSHA256); err != nil {
		return nil, err
	}
	d := statusDoc{Format: BuilderStatusFormat, Class: s.Class, LevelReached: s.LevelReached.String(), NextLevel: s.NextLevel.String(), Seq: s.Seq, PinsSHA256: s.PinsSHA256}
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
		// the last gate: the state is redacted here as well, whatever built it (BuilderStatusOf redacts too, and redaction is idempotent)
		d.State = redactedState(s.State).Canonical()
	default:
		return nil, fmt.Errorf("finality: unknown status class %q", s.Class)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	// and the whole document once more: a credential that survived in any member (a field name, a pattern the structural pass cannot see)
	// is removed from the text, and the result must still be the same document shape (a redaction that breaks the JSON is refused)
	if red := ethrpc.RedactText(string(raw)); red != string(raw) {
		if !json.Valid([]byte(red)) {
			return nil, fmt.Errorf("finality: the status document of %s cannot be redacted into a valid document", s.ProofID)
		}
		raw = []byte(red)
	}
	return raw, nil
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
	if err := checkPinsSHA256(d.PinsSHA256); err != nil {
		return BuilderStatusView{}, err
	}
	v := BuilderStatusView{Class: d.Class, Seq: d.Seq, State: d.State, PinsSHA256: d.PinsSHA256}
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
	PinsSHA256   string // the pins the builder judged under (see BuilderStatus.PinsSHA256); empty = not recorded
}

// BuilderStatusStore holds the builder status rows: mutable, a later pass replaces the row of the same (proof, target level).
type BuilderStatusStore interface {
	UpsertStatus(ctx context.Context, s BuilderStatus) error
	// GetStatus returns the row, or ok=false when the builder has judged nothing for that (proof, level).
	GetStatus(ctx context.Context, proofID string, target Level) (BuilderStatusView, bool, error)
}

// BuilderStatusOf classifies a builder-side state for the status row. pd is the pending the prover returned (class pending);
// otherwise err is the named state it failed with: level_not_applicable is not_applicable, a refusal of the append of built evidence
// (refused=true: the Kind, the chain checks or the guard refused it; the state's code says which) is refused, anything else is unavailable. reached is the highest stored level the leg holds and target the
// level the builder was working towards.
func BuilderStatusOf(proofID string, chain uint64, target, reached Level, pd *PendingState, err error, refused bool, at time.Time) BuilderStatus {
	s := BuilderStatus{ProofID: proofID, Chain: chain, TargetLevel: target, LevelReached: reached, NextLevel: target, JudgedAt: at}
	if pd != nil {
		s.Class, s.State, s.ETA = BuilderPending, redactedState(pd.State()), pd.ETA
		return s
	}
	st, named := AsNamed(err)
	if !named {
		st = builderErrorState(chain, err)
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

// CodeBuilderError is the named state of an error that carries no name of its own: a capture row that vanished, a database error, a
// provider error, any plain error a prover or the addendum store returns. It is class unavailable and says WHERE it came from (stage) and
// what it said (cause, redacted). finality_verifier_failed is NOT used for it: that code means evidence was built and failed
// verification, which none of these is (RB12-P0LIVE-FIX D4).
const CodeBuilderError = "finality_builder_error"

// The stages of a builder error: the prover building the evidence, and the store appending what was built.
const (
	StageBuild  = "build"
	StageAppend = "append"
)

// stagedError marks an unnamed error with the stage that raised it.
type stagedError struct {
	stage string
	err   error
}

func (e *stagedError) Error() string { return e.err.Error() }
func (e *stagedError) Unwrap() error { return e.err }

// AtStage marks an unnamed error with the stage (StageBuild, StageAppend) it came from; BuilderStatusOf reads it. An error that already
// has a name is returned as it is.
func AtStage(stage string, err error) error {
	if err == nil {
		return nil
	}
	if _, named := AsNamed(err); named {
		return err
	}
	return &stagedError{stage: stage, err: err}
}

// builderErrorState is the named state of an unnamed builder error (the stage is StageBuild unless the error was marked by AtStage).
func builderErrorState(chain uint64, err error) *StateError {
	stage := StageBuild
	var se *stagedError
	if errors.As(err, &se) {
		stage = se.stage
	}
	return NewState(CodeBuilderError, "chain", chain, "stage", stage, "cause", fmt.Sprint(err))
}

// Field names a failed builder status adds to its named state (RB12-F1): how many consecutive asks of this (leg, level) have failed
// and when the builder asks again. They are fields of the state, not members of the status document, so the document format and
// every reader of it are unchanged.
const (
	FieldAttempt       = "attempt"
	FieldNextAttemptAt = "next_attempt_at"
)

// noteAttempt records on a failure status the ordinal of the failed ask and the time of the next one (RFC 3339, UTC, whole
// seconds). The state is copied, so a shared state value is never changed.
func (s *BuilderStatus) noteAttempt(attempt int, next time.Time) {
	if s.State == nil {
		return
	}
	st := copyState(s.State)
	st.Fields[FieldAttempt] = uint64(attempt)
	st.Fields[FieldNextAttemptAt] = next.UTC().Format(time.RFC3339)
	s.State = st
}

// noteRetry records on a held status when the builder asks again: the eta of the pending row and the next_attempt_at field of its
// state. A hold is no failed ask, so it carries no attempt ordinal.
func (s *BuilderStatus) noteRetry(next time.Time) {
	if s.State == nil {
		return
	}
	st := copyState(s.State)
	st.Fields[FieldNextAttemptAt] = next.UTC().Format(time.RFC3339)
	s.State, s.ETA = st, next
}

// noteNextAttempt records on the row of a leg held by the environment (a state of ClassEnvironment that is not itself a pending row, such
// as l1_capture_gap) when the builder asks again: the next_attempt_at field of its state. It carries no attempt ordinal (a hold is no
// failed ask) and no eta (the row's class says what the leg is; the field says when it is asked next).
func (s *BuilderStatus) noteNextAttempt(next time.Time) {
	if s.State == nil {
		return
	}
	st := copyState(s.State)
	st.Fields[FieldNextAttemptAt] = next.UTC().Format(time.RFC3339)
	s.State = st
}

func copyState(s *StateError) *StateError {
	st := NewState(s.Code)
	for k, v := range s.Fields {
		st.Fields[k] = v
	}
	return st
}

// HeldBuilderStatus is the row of a level whose build the process memory budget held back (CodeMemoryBudget, even after waiting for a
// release): the leg is pending, not failed. The row names the state; the upgrader adds the time of the next ask.
func HeldBuilderStatus(proofID string, chain uint64, target, reached Level, st *StateError, at time.Time) BuilderStatus {
	return BuilderStatus{ProofID: proofID, Chain: chain, TargetLevel: target, Class: BuilderPending, LevelReached: reached, NextLevel: target, State: redactedState(st), JudgedAt: at}
}

// redactedState is st with every text in it passed through the one sanitiser of provider text, pkg/ethrpc RedactText, before it is
// stored in a status row: the row is read by the gateway and must never carry a credential from a provider URL or response. The
// redaction is recursive (redactValue): a string, an error, a fmt.Stringer, the elements of a slice, the values of a map and the
// exported fields of a nested struct are each sanitised, whatever their depth. Numbers, bytes, levels and times are left as they are.
func redactedState(st *StateError) *StateError {
	out := NewState(st.Code)
	for k, v := range st.Fields {
		out.Fields[k] = redactValue(v, 0)
	}
	return out
}

// maxRedactDepth bounds the recursion into nested values; a value nested deeper is rendered as text and that text is redacted,
// so nothing below the bound is stored as it was.
const maxRedactDepth = 8

// redactValue returns v with every text in it redacted. The result keeps the canonical rendering of v (canonValue): a string stays a
// string, a []string a []string, a map a map, a Level a Level, an integer an integer, bytes bytes; an error, a fmt.Stringer, a
// pointer, a struct and any other composite is replaced by redacted text or by the map of its redacted exported fields.
func redactValue(v any, depth int) any {
	if depth > maxRedactDepth {
		return ethrpc.RedactText(fmt.Sprint(v))
	}
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		return ethrpc.RedactText(x)
	case error:
		return ethrpc.RedactText(x.Error())
	case bool, Level, uint8, uint16, uint32, uint64, uint, int, int16, int32, int64, [32]byte, [4]byte, []byte, time.Time, time.Duration, []uint64:
		return v
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = ethrpc.RedactText(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[ethrpc.RedactText(k)] = redactValue(e, depth+1)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[ethrpc.RedactText(k)] = ethrpc.RedactText(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactValue(e, depth+1)
		}
		return out
	case fmt.Stringer:
		return ethrpc.RedactText(x.String())
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return redactValue(rv.Elem().Interface(), depth+1)
	case reflect.Struct:
		out := map[string]any{}
		for i := 0; i < rv.NumField(); i++ {
			if f := rv.Type().Field(i); f.IsExported() {
				out[f.Name] = redactValue(rv.Field(i).Interface(), depth+1)
			}
		}
		return out
	case reflect.Map:
		out := map[string]any{}
		for _, k := range rv.MapKeys() {
			out[ethrpc.RedactText(fmt.Sprint(k.Interface()))] = redactValue(rv.MapIndex(k).Interface(), depth+1)
		}
		return out
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return v // a byte string: rendered as hex by canonValue, no text
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = redactValue(rv.Index(i).Interface(), depth+1)
		}
		return out
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uintptr, reflect.Bool, reflect.Float32, reflect.Float64:
		return v
	case reflect.String:
		return ethrpc.RedactText(rv.String())
	}
	return ethrpc.RedactText(fmt.Sprint(v))
}

// VerifiedBuilderStatus is the row of a level that is stored.
func VerifiedBuilderStatus(proofID string, chain uint64, level Level, seq uint64, at time.Time) BuilderStatus {
	return BuilderStatus{ProofID: proofID, Chain: chain, TargetLevel: level, Class: BuilderVerified, LevelReached: level, NextLevel: level, Seq: seq, JudgedAt: at}
}
