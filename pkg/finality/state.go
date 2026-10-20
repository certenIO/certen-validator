// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// StateError is every answer this package gives that is not a level: a named state with the values it was judged at.
// Nothing is returned as a bare string, a boolean or a weaker level (00_STANDARD.md section 3, "No fallback").
//
// The machine registry of the codes and their field names is testdata/finality/states.json (V2_SPEC_S7 section 7); a code
// that is not in it, or a state that lacks a required field, fails the conformance test. The canonical form (Canonical) is
// what the Go and TypeScript verifiers compare on every vector: JSON with sorted keys, no whitespace, every unsigned
// integer as a decimal string, byte strings as lowercase hex without a prefix.
type StateError struct {
	Code   string
	Fields map[string]any
}

// State is the former name of StateError, kept so existing references compile.
type State = StateError

// Named is implemented by *StateError; it exists so a caller can hold "an error that is a named state".
type Named interface {
	error
	State() *StateError
}

// State returns the receiver (Named).
func (s *StateError) State() *StateError { return s }

// AsNamed returns the named state in err's chain, if any.
func AsNamed(err error) (*StateError, bool) {
	var s *StateError
	if errors.As(err, &s) && s != nil {
		return s, true
	}
	return nil, false
}

// Codes the framework itself raises. Chain packages add their own (section 7) with their own constants.
const (
	CodeChainUnsupported     = "finality_chain_unsupported"
	CodeChainBroken          = "finality_chain_broken"
	CodeEvidenceMalformed    = "finality_evidence_malformed"
	CodeEvidenceUnrecognised = "finality_evidence_unrecognised"
	CodeEvidenceTooLarge     = "finality_evidence_too_large"
	CodeBlockMismatch        = "finality_block_mismatch"
	CodePinsCorrupt          = "finality_pins_corrupt"
	CodePinUnknown           = "finality_pin_unknown"
	CodePinMissing           = CodePinUnknown // former name
	CodeLedgerExtensionBad   = "finality_ledger_extension_invalid"
	CodeNotApplicable        = "level_not_applicable"
	CodePending              = "finality_pending"
	CodeLevelAlreadyPresent  = "level_already_present"

	// Operational states of this Go implementation that V2_SPEC_S7 section 7 does not list (registry scope "go_operational").
	CodeAddendumMalformed   = "finality_addendum_malformed"
	CodeVerifierFailed      = "finality_verifier_failed"
	CodeIncludedUnavailable = "finality_included_unavailable"
	CodeIncludedInvalid     = "finality_included_invalid"
	CodeAppendConflict      = "finality_append_conflict"
	CodePanic               = "finality_prover_panicked"
	CodeBuildTimeout        = "finality_build_timeout"
	CodeUpgraderDisabled    = "finality_upgrader_disabled"
)

// The check names of finality_chain_broken (section 2.3), exactly.
const (
	CheckSeqGap         = "seq_gap"
	CheckPrevHash       = "prev_hash"
	CheckOwnHash        = "own_hash"
	CheckLevelDuplicate = "level_duplicate"
	CheckKind           = "kind"
	CheckLegBinding     = "leg_binding"
)

// NewState builds a StateError from alternating key, value pairs.
func NewState(code string, kv ...any) *StateError {
	s := &StateError{Code: code, Fields: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Fields[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return s
}

func (s *StateError) Error() string {
	keys := make([]string, 0, len(s.Fields))
	for k := range s.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(s.Code)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.Write(canonValue(s.Fields[k]))
	}
	b.WriteByte('}')
	return b.String()
}

// Canonical is the cross-language form: {"code":...,"fields":{...}} with sorted keys and no whitespace.
func (s *StateError) Canonical() []byte {
	var b bytes.Buffer
	b.WriteString(`{"code":`)
	b.Write(canonString(s.Code))
	b.WriteString(`,"fields":`)
	b.Write(canonValue(s.Fields))
	b.WriteByte('}')
	return b.Bytes()
}

func canonString(s string) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// canonValue renders v canonically: maps with sorted keys, unsigned and signed integers as decimal strings, byte arrays and
// slices as lowercase hex strings, a Level by name, booleans and nil as JSON literals, a time as RFC 3339 UTC.
func canonValue(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte("null")
	case string:
		return canonString(x)
	case bool:
		return []byte(strconv.FormatBool(x))
	case Level:
		return canonString(x.String())
	case uint8:
		return canonString(strconv.FormatUint(uint64(x), 10))
	case uint16:
		return canonString(strconv.FormatUint(uint64(x), 10))
	case uint32:
		return canonString(strconv.FormatUint(uint64(x), 10))
	case uint64:
		return canonString(strconv.FormatUint(x, 10))
	case uint:
		return canonString(strconv.FormatUint(uint64(x), 10))
	case int:
		return canonString(strconv.FormatInt(int64(x), 10))
	case int16:
		return canonString(strconv.FormatInt(int64(x), 10))
	case int32:
		return canonString(strconv.FormatInt(int64(x), 10))
	case int64:
		return canonString(strconv.FormatInt(x, 10))
	case [32]byte:
		return canonString(hexLower(x[:]))
	case []byte:
		return canonString(hexLower(x))
	case time.Time:
		return canonString(x.UTC().Format(time.RFC3339))
	case time.Duration:
		return canonString(strconv.FormatInt(int64(x), 10))
	case []string:
		parts := make([][]byte, len(x))
		for i, e := range x {
			parts[i] = canonString(e)
		}
		return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
	case []uint64:
		parts := make([][]byte, len(x))
		for i, e := range x {
			parts[i] = canonString(strconv.FormatUint(e, 10))
		}
		return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b bytes.Buffer
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(canonString(k))
			b.WriteByte(':')
			b.Write(canonValue(x[k]))
		}
		b.WriteByte('}')
		return b.Bytes()
	case fmt.Stringer:
		return canonString(x.String())
	}
	return canonString(fmt.Sprint(v))
}

// ---- constructors of the framework states (section 7, Framework R and N) ----

// Malformed is finality_evidence_malformed for a part; got and want are byte or element counts (0 when not meaningful).
func Malformed(part, reason string, got, want int) *StateError {
	return NewState(CodeEvidenceMalformed, "part", part, "reason", reason, "got_len", uint64(maxInt(got, 0)), "want_len", uint64(maxInt(want, 0)))
}

// MalformedAt is Malformed for element index of a list or item of a header.
func MalformedAt(part string, index int, reason string, got, want int) *StateError {
	s := Malformed(part, reason, got, want)
	s.Fields["index"] = uint64(index)
	return s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// EvidenceTooLarge is finality_evidence_too_large{part,count,limit}.
func EvidenceTooLarge(part string, count, limit uint64) *StateError {
	return NewState(CodeEvidenceTooLarge, "part", part, "count", count, "limit", limit)
}

// EvidenceUnrecognised is finality_evidence_unrecognised{kind,version}.
func EvidenceUnrecognised(kind, version string) *StateError {
	return NewState(CodeEvidenceUnrecognised, "kind", kind, "version", version)
}

// ChainUnsupported is finality_chain_unsupported{chain}.
func ChainUnsupported(chain uint64) *StateError {
	return NewState(CodeChainUnsupported, "chain", chain)
}

// ChainBroken is finality_chain_broken{seq,check}.
func ChainBroken(seq uint64, check string, kv ...any) *StateError {
	return NewState(CodeChainBroken, append([]any{"seq", seq, "check", check}, kv...)...)
}

// BlockMismatch is finality_block_mismatch{field,want,got}.
func BlockMismatch(field string, want, got any) *StateError {
	return NewState(CodeBlockMismatch, "field", field, "want", want, "got", got)
}

// PinsCorrupt is finality_pins_corrupt.
func PinsCorrupt(reason string, kv ...any) *StateError {
	return NewState(CodePinsCorrupt, append([]any{"reason", reason}, kv...)...)
}

// NotApplicableState is level_not_applicable{chain,level,reason}: complete as an answer; a chain whose only missing levels
// are not applicable has reached its top.
func NotApplicableState(chain uint64, level Level, reason string) *StateError {
	return NewState(CodeNotApplicable, "chain", chain, "level", level, "reason", reason)
}

// PendingState is the builder-side (and offline) "not yet" of a level: the level reached (proven), the next level, the
// reason from the closed set of states.json, an optional ETA and the reason's own fields. It is not a failure and never
// carries weaker evidence.
type PendingState struct {
	Chain        uint64
	LevelReached Level
	NextLevel    Level
	Reason       string
	ETA          time.Time
	Judged       map[string]any
}

// State renders the single code finality_pending{chain, level_reached, next_level, reason, eta?, ...}.
func (p *PendingState) State() *StateError {
	s := NewState(CodePending, "chain", p.Chain, "level_reached", p.LevelReached, "next_level", p.NextLevel, "reason", p.Reason)
	if !p.ETA.IsZero() {
		s.Fields["eta"] = p.ETA.UTC()
	}
	for k, v := range p.Judged {
		s.Fields[k] = v
	}
	return s
}

func (p *PendingState) Error() string { return p.State().Error() }

// NoEvidenceInFile is the offline verifier's pending for a level without an addendum (R4).
func NoEvidenceInFile(chain uint64, reached, next Level) *PendingState {
	return &PendingState{Chain: chain, LevelReached: reached, NextLevel: next, Reason: "no_evidence_in_file"}
}
