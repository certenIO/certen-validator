// Copyright 2026 Certen Protocol

package finality

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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
// what the Go and TypeScript verifiers compare on every vector: JSON with sorted keys, no whitespace, EVERY integer field of
// ANY width and signedness (int, int8..int64, uint, uint8..uint64, uintptr and every named integer type that is not a Level)
// as a decimal string, EVERY byte string and fixed byte array ([]byte, [4]byte, [32]byte, any [N]byte) as 0x-prefixed lower-case hex ("0x" for the empty string), a named string type as its string.
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
	CodeAddendumMalformed         = "finality_addendum_malformed"
	CodeVerifierFailed            = "finality_verifier_failed"
	CodeIncludedUnavailable       = "finality_included_unavailable"
	CodeIncludedInvalid           = "finality_included_invalid"
	CodeAppendConflict            = "finality_append_conflict"
	CodePanic                     = "finality_prover_panicked"
	CodeBuildTimeout              = "finality_build_timeout"
	CodeUpgraderDisabled          = "finality_upgrader_disabled"
	CodeFinalizedBlockUnavailable = "finality_finalized_block_unavailable"
	CodeGuardRefused              = "finality_guard_refused"
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

// ---- the closed reason sets ----
//
// Every `reason` of a state is a member of a CLOSED set recorded in testdata/finality/states.json (`enums.reason` of the
// state), so a TypeScript port reproduces a token, never a Go sentence. The constructors below take the typed token, and
// the conformance tests assert (1) the typed constants of each set equal the registry's set, (2) every literal reason in
// the package's own sources, in pkg/database and in cmd/* is a member, (3) every state built by a constructor conforms.
// Free text that helps a human (a Go error message) goes in a `cause` field of a go_operational state, never in a reason.

// EvidenceReason is the reason of finality_evidence_malformed.
type EvidenceReason string

const (
	ReasonTruncated               EvidenceReason = "truncated"
	ReasonLengthExceedsRemaining  EvidenceReason = "length_exceeds_remaining"
	ReasonStrNotASCIIOrNUL        EvidenceReason = "str_not_ascii_or_nul"
	ReasonCountExceedsRemaining   EvidenceReason = "count_exceeds_remaining"
	ReasonNodesNotAscendingUnique EvidenceReason = "nodes_not_ascending_unique"
	ReasonTrailingBytes           EvidenceReason = "trailing_bytes"
	ReasonLevelNotStored          EvidenceReason = "level_not_stored"
	ReasonDiffersFromAddendum     EvidenceReason = "differs_from_addendum"
	ReasonHeaderNotRLPList        EvidenceReason = "header_not_rlp_list"
	ReasonHeaderTrailingBytes     EvidenceReason = "header_trailing_bytes"
	ReasonHeaderBadItem           EvidenceReason = "header_bad_item"
	ReasonHeaderTooFewItems       EvidenceReason = "header_too_few_items"
	ReasonHeaderItemNot32Bytes    EvidenceReason = "header_item_not_32_bytes"
	ReasonHeaderItemNotCanonUint  EvidenceReason = "header_item_not_canonical_uint"
	ReasonHeaderItemIsList        EvidenceReason = "header_item_is_list"

	// The compact Adiri committee chain (pkg/finality/adiri, RB11-F1): the container body of adiri/finalized/v1.
	ReasonCFA1BadMagic             EvidenceReason = "cfa1_bad_magic"
	ReasonCFA1KeyLength            EvidenceReason = "cfa1_key_length"
	ReasonCFA1NoRecords            EvidenceReason = "cfa1_no_records"
	ReasonCFA1NoTables             EvidenceReason = "cfa1_no_tables"
	ReasonCFA1SignersTooMany       EvidenceReason = "cfa1_signers_too_many"
	ReasonCFA1TableEmpty           EvidenceReason = "cfa1_table_empty"
	ReasonCFA1TableIndexOutOfRange EvidenceReason = "cfa1_table_index_out_of_range"
	ReasonCFA1TableSize            EvidenceReason = "cfa1_table_size"
	ReasonCFA1TooLargeToEncode     EvidenceReason = "cfa1_too_large_to_encode"
	ReasonLevelNotFinalized        EvidenceReason = "level_not_finalized"
	ReasonLinkKind2AtSeal          EvidenceReason = "link_kind_2_at_seal"
	ReasonLinkKindUnknown          EvidenceReason = "link_kind_unknown"
	ReasonSpineEmpty               EvidenceReason = "spine_empty"
	ReasonBadEnumValue             EvidenceReason = "bad_enum_value"

	// The Sepolia L1-finality kind (pkg/finality/ethsepolia, RB11-C2): the framing reasons of the light-client part, as pkg/finality/ethl1
	// names them, and the spine that does not end at the leg block.
	ReasonAttestedOffset        EvidenceReason = "attested_offset"
	ReasonEmpty                 EvidenceReason = "empty"
	ReasonExecutionOffset       EvidenceReason = "execution_offset"
	ReasonExtraDataLength       EvidenceReason = "extra_data_length"
	ReasonExtraDataOffset       EvidenceReason = "extra_data_offset"
	ReasonFinalizedOffset       EvidenceReason = "finalized_offset"
	ReasonHeaderLength          EvidenceReason = "header_length"
	ReasonHeaderOffset          EvidenceReason = "header_offset"
	ReasonLayoutByteNotZero     EvidenceReason = "layout_byte_not_zero"
	ReasonLayoutByteUnknown     EvidenceReason = "layout_byte_unknown"
	ReasonLayoutByteZero        EvidenceReason = "layout_byte_zero"
	ReasonLength                EvidenceReason = "length"
	ReasonSpineNotEndingAtBlock EvidenceReason = "spine_not_ending_at_block"
	ReasonUnknownKind           EvidenceReason = "unknown_kind"
	ReasonUnsupportedProfile    EvidenceReason = "unsupported_profile"
)

// AddendumReason is the reason of finality_addendum_malformed (the JSON form of an addendum, a section and a proof id).
type AddendumReason string

const (
	AddendumNotJSON        AddendumReason = "not_json"
	AddendumUnknownKey     AddendumReason = "unknown_key"
	AddendumDuplicateKey   AddendumReason = "duplicate_key"
	AddendumMissingKey     AddendumReason = "missing_key"
	AddendumBadValue       AddendumReason = "bad_value"
	AddendumLevelNotStored AddendumReason = "level_not_stored"
	AddendumUnknownLevel   AddendumReason = "unknown_level"
	AddendumNotLowerHex    AddendumReason = "not_lowercase_hex"
	AddendumNot32Bytes     AddendumReason = "not_32_bytes"
	AddendumNotUUID        AddendumReason = "not_canonical_uuid"
	AddendumWrongFormat    AddendumReason = "wrong_format"
)

// PinsReason is the reason of finality_pins_corrupt.
type PinsReason string

const (
	PinsSHA256Mismatch           PinsReason = "sha256_mismatch"
	PinsSHA256ConstantMalformed  PinsReason = "sha256_constant_malformed"
	PinsNotUTF8                  PinsReason = "not_utf8"
	PinsContainsCR               PinsReason = "contains_cr"
	PinsByteOrderMark            PinsReason = "byte_order_mark"
	PinsKeysUnsorted             PinsReason = "keys_unsorted"
	PinsDuplicateKey             PinsReason = "duplicate_key"
	PinsUnknownKey               PinsReason = "unknown_key"
	PinsNotJSON                  PinsReason = "not_json"
	PinsBadValue                 PinsReason = "bad_value"
	PinsWrongFormat              PinsReason = "wrong_format"
	PinsPublishedUTCEmpty        PinsReason = "published_utc_empty"
	PinsChainIDMismatch          PinsReason = "chain_id_mismatch"
	PinsGenesisRootMalformed     PinsReason = "genesis_validators_root_malformed"
	PinsParticipationFloor       PinsReason = "participation_floor_invalid"
	PinsBoundMissing             PinsReason = "bound_missing"
	PinsForksEmpty               PinsReason = "forks_empty"
	PinsForkMalformed            PinsReason = "fork_malformed"
	PinsForkEpochNotAscending    PinsReason = "fork_epoch_not_ascending"
	PinsForkLayoutUnknown        PinsReason = "fork_layout_unknown"
	PinsFirstForkNotEpochZero    PinsReason = "first_fork_not_epoch_zero"
	PinsAnchorMalformed          PinsReason = "anchor_malformed"
	PinsAnchorPeriodDuplicate    PinsReason = "anchor_period_duplicate"
	PinsAnchorPeriodNotAscending PinsReason = "anchor_period_not_ascending"
	PinsAnchorWspBelow256        PinsReason = "anchor_wsp_epochs_below_256"
	PinsAnchorDerivedByEmpty     PinsReason = "anchor_derived_by_empty"
)

// IncludedReason is the reason of finality_included_unavailable.
type IncludedReason string

const (
	IncludedNoSettlement        IncludedReason = "no_settlement"
	IncludedNoExecutionProof    IncludedReason = "no_execution_proof_component"
	IncludedSettlementNotJudged IncludedReason = "no_settlement_to_recompute_d0"
)

// FinalizedBlockReason is the reason of finality_finalized_block_unavailable: a verified finalized level whose leg block cannot
// be exposed for S8 (R6) because the BlockRef carries no header, or the header cannot be read.
type FinalizedBlockReason string

const (
	FinalizedBlockNoHeader         FinalizedBlockReason = "no_header"
	FinalizedBlockHeaderUnreadable FinalizedBlockReason = "header_unreadable"
)

// NotApplicableReason is the reason of level_not_applicable: the two cells of the section 1 table, verbatim.
type NotApplicableReason string

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
		return canonString("0x" + hexLower(x[:]))
	case [4]byte:
		return canonString("0x" + hexLower(x[:]))
	case []byte:
		return canonString("0x" + hexLower(x))
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
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return canonString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return canonString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.String:
		return canonString(rv.String())
	case reflect.Array, reflect.Slice:
		if rv.Type().Elem().Kind() == reflect.Uint8 { // every fixed byte array and every named byte slice
			b := make([]byte, rv.Len())
			reflect.Copy(reflect.ValueOf(b), rv)
			return canonString("0x" + hexLower(b))
		}
	}
	return canonString(fmt.Sprint(v))
}

// ---- constructors of the framework states (section 7, Framework R and N) ----

// Malformed is finality_evidence_malformed for a part; got and want are byte or element counts (0 when not meaningful).
func Malformed(part string, reason EvidenceReason, got, want int) *StateError {
	return NewState(CodeEvidenceMalformed, "part", part, "reason", reason, "got_len", uint64(maxInt(got, 0)), "want_len", uint64(maxInt(want, 0)))
}

// MalformedAt is Malformed for element index of a list or item of a header.
func MalformedAt(part string, index int, reason EvidenceReason, got, want int) *StateError {
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

// PinsCorrupt is finality_pins_corrupt{reason, ...}.
func PinsCorrupt(reason PinsReason, kv ...any) *StateError {
	return NewState(CodePinsCorrupt, append([]any{"reason", reason}, kv...)...)
}

// NotApplicableState is level_not_applicable{chain,level,reason}: complete as an answer; a chain whose only missing levels
// are not applicable has reached its top.
func NotApplicableState(chain uint64, level Level, reason NotApplicableReason) *StateError {
	return NewState(CodeNotApplicable, "chain", chain, "level", level, "reason", reason)
}

// AddendumMalformed is finality_addendum_malformed{field, reason}: the JSON form of an addendum, a section or a proof id was
// refused. field names the member (or the object, for a key refusal) and key the offending key.
func AddendumMalformed(field string, reason AddendumReason, kv ...any) *StateError {
	return NewState(CodeAddendumMalformed, append([]any{"field", field, "reason", reason}, kv...)...)
}

// IncludedUnavailable is finality_included_unavailable{reason}: level 1 cannot be derived because a leg has no Settlement.
func IncludedUnavailable(reason IncludedReason, kv ...any) *StateError {
	return NewState(CodeIncludedUnavailable, append([]any{"reason", reason}, kv...)...)
}

// FinalizedBlockUnavailable is finality_finalized_block_unavailable{chain, number, reason[, index]}.
func FinalizedBlockUnavailable(chain, number uint64, reason FinalizedBlockReason, kv ...any) *StateError {
	return NewState(CodeFinalizedBlockUnavailable, append([]any{"chain", chain, "number", number, "reason", reason}, kv...)...)
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
