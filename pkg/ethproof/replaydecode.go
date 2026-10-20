// Copyright 2026 Certen Protocol

package ethproof

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// =============================================================================
// The S6 evidence wire format (certen:s6-replay:v1) and its strict decoding
// =============================================================================
//
// DecodeReplayGuardEvidence is the one entry point a verifier reads evidence bytes through. It is strict, so that the Go
// and TypeScript verifiers (testdata/s6replay1/SPEC.md) accept exactly the same byte strings: a document is refused,
// with a named reason, unless it is at most MaxReplayEvidenceBytes long, one JSON value with no duplicate key, every object holds only the keys of its
// schema and every required one, every value has its schema's type and lexical form, exactly one of proof and state is
// carried, and every version is ReplayGuardDomain. Each refusal is s6_replay_unproven{reason}.

// Reasons of a strict-decoding refusal.
const (
	ReasonMalformedJSON = "malformed_json"
	ReasonUnknownField  = "unknown_field"
	ReasonMissingField  = "missing_field"
	ReasonWrongType     = "wrong_type"
	// ReasonEvidenceTooLarge: the document is longer than MaxReplayEvidenceBytes. It is refused before anything is read, so
	// it is never malformed_json, however the document is made.
	ReasonEvidenceTooLarge = "evidence_too_large"
)

// MaxReplayEvidenceBytes is the largest evidence document, in bytes, that DecodeReplayGuardEvidence reads (4 MiB). Honest
// evidence is far smaller (at most 512 headers of about 1.2 KB of hex, and the proofs: under 1 MiB). The reader has no
// depth limit, so its memory is bounded only by its input, which is therefore bounded here, before anything is parsed.
const MaxReplayEvidenceBytes = 4 << 20

// MaxReplayJSONInteger is the largest integer the wire format carries (2^53-1): every JSON number is exact in both
// verifiers.
const MaxReplayJSONInteger = 1<<53 - 1

type wireKind int

const (
	wireString wireKind = iota
	wireBool
	wireUint
	wireHash
	wireAddress
	wireBytes
	wireBytesList
	wireObject
	wireObjectList
)

type wireField struct {
	key      string
	kind     wireKind
	required bool
	schema   []wireField
}

var (
	wireBlockRef = []wireField{{"number", wireUint, true, nil}, {"hash", wireHash, true, nil}}
	wireSlot     = []wireField{{"key", wireHash, true, nil}, {"base", wireUint, true, nil}, {"derivation", wireString, true, nil},
		{"slot", wireHash, true, nil}}
	wireSlotProof = []wireField{{"accountAbsent", wireBool, false, nil}, {"accountProof", wireBytesList, true, nil},
		{"storageHash", wireHash, true, nil}, {"codeHash", wireHash, true, nil}, {"storageProof", wireBytesList, true, nil},
		{"value", wireHash, true, nil}}
	wireProviderFailure   = []wireField{{"host", wireString, true, nil}, {"error", wireString, true, nil}}
	wireBefore            = []wireField{{"parentHeader", wireBytes, true, nil}, {"proof", wireObject, true, wireSlotProof}}
	wireBeforeUnavailable = []wireField{{"reason", wireString, true, nil}, {"providers", wireObjectList, false, wireProviderFailure}}
	wireProof             = []wireField{{"version", wireString, true, nil}, {"chainId", wireUint, true, nil},
		{"generation", wireString, true, nil}, {"contract", wireAddress, true, nil}, {"slot", wireObject, true, wireSlot},
		{"settlementBlock", wireObject, true, wireBlockRef}, {"provenAt", wireObject, true, wireBlockRef},
		{"headers", wireBytesList, true, nil}, {"after", wireObject, true, wireSlotProof},
		{"before", wireObject, false, wireBefore}, {"beforeUnavailable", wireObject, false, wireBeforeUnavailable}}
	wireNamedState = []wireField{{"state", wireString, true, nil}, {"reason", wireString, true, nil},
		{"chainId", wireUint, true, nil}, {"txHash", wireHash, true, nil}, {"blockNumber", wireUint, true, nil},
		{"blockHash", wireHash, true, nil}, {"contract", wireAddress, true, nil},
		{"providers", wireObjectList, false, wireProviderFailure}, {"detail", wireString, false, nil},
		{"before", wireObject, false, wireBefore}}
	wireEvidence = []wireField{{"version", wireString, true, nil}, {"proof", wireObject, false, wireProof},
		{"state", wireObject, false, wireNamedState}}
)

var (
	wireUintRe    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	wireHashRe    = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
	wireAddressRe = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	wireBytesRe   = regexp.MustCompile(`^0x([0-9a-fA-F]{2})*$`)
)

// jsonValue is a parsed JSON value that keeps object keys in document order.
type jsonValue struct {
	kind byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' bool, 'z' null
	keys []string
	vals map[string]*jsonValue
	arr  []*jsonValue
	str  string // the string, or the number's literal text
}

// parseJSONValue reads one JSON value with an explicit stack of the containers that are open, never by recursion: the
// recursion this replaced was bounded by Go's goroutine stack, whose overflow is a fatal runtime error, so a hostile
// document of a few million nested arrays (a 12 MB file) could kill the process of any verifier reading it. The reading
// is otherwise the recursive reader's, step for step: the same json.Decoder calls in the same order (so a syntax error
// carries the same text), an object's key is checked for a duplicate when it is read, before its value, and keys and
// values are kept in document order. A pending object key is the last element of its object's keys, its value being
// stored when the value is complete.
func parseJSONValue(dec *json.Decoder) (*jsonValue, error) {
	var open []*jsonValue // the containers opened and not yet closed, outermost first
	for {
		// the first token of a value: a scalar is a complete value, a delimiter opens a container
		var done *jsonValue
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				open = append(open, &jsonValue{kind: 'o', vals: map[string]*jsonValue{}})
			case '[':
				open = append(open, &jsonValue{kind: 'a', arr: []*jsonValue{}})
			default:
				return nil, fmt.Errorf("unexpected %v", t)
			}
		case string:
			done = &jsonValue{kind: 's', str: t}
		case json.Number:
			done = &jsonValue{kind: 'n', str: t.String()}
		case bool:
			if t {
				done = &jsonValue{kind: 'b', str: "true"}
			} else {
				done = &jsonValue{kind: 'b', str: "false"}
			}
		case nil:
			done = &jsonValue{kind: 'z'}
		default:
			return nil, fmt.Errorf("unexpected token %v", tok)
		}
		// advance: hand a complete value to the container it sits in, then either read that container's next element
		// (back to the outer loop for its first token) or close it, which completes it in turn
		for {
			if done != nil {
				if len(open) == 0 {
					return done, nil
				}
				top := open[len(open)-1]
				if top.kind == 'o' {
					top.vals[top.keys[len(top.keys)-1]] = done
				} else {
					top.arr = append(top.arr, done)
				}
				done = nil
			}
			top := open[len(open)-1]
			if dec.More() {
				if top.kind == 'o' {
					kt, err := dec.Token()
					if err != nil {
						return nil, err
					}
					k, ok := kt.(string)
					if !ok {
						return nil, fmt.Errorf("object key is not a string")
					}
					if _, dup := top.vals[k]; dup {
						return nil, fmt.Errorf("duplicate key %q", k)
					}
					top.keys = append(top.keys, k)
					top.vals[k] = nil // the value is stored when it is complete
				}
				break
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			open[len(open)-1] = nil
			open = open[:len(open)-1]
			done = top
		}
	}
}

func parseStrictJSON(raw []byte) (*jsonValue, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("data after the JSON value")
	}
	return v, nil
}

func wireTypeError(path, want string) error {
	return unproven(ReasonWrongType, "%s is not %s", path, want)
}

func checkWireValue(path string, v *jsonValue, f wireField) error {
	switch f.kind {
	case wireString:
		if v.kind != 's' {
			return wireTypeError(path, "a string")
		}
	case wireBool:
		if v.kind != 'b' {
			return wireTypeError(path, "a boolean")
		}
	case wireUint:
		if v.kind != 'n' || !wireUintRe.MatchString(v.str) {
			return wireTypeError(path, "a non-negative integer without sign, fraction or exponent")
		}
		if n, err := strconv.ParseUint(v.str, 10, 64); err != nil || n > MaxReplayJSONInteger {
			return wireTypeError(path, "an integer at most 2^53-1")
		}
	case wireHash:
		if v.kind != 's' || !wireHashRe.MatchString(v.str) {
			return wireTypeError(path, "0x and 64 hex digits")
		}
	case wireAddress:
		if v.kind != 's' || !wireAddressRe.MatchString(v.str) {
			return wireTypeError(path, "0x and 40 hex digits")
		}
	case wireBytes:
		if v.kind != 's' || !wireBytesRe.MatchString(v.str) {
			return wireTypeError(path, "0x and an even number of hex digits")
		}
	case wireBytesList:
		if v.kind != 'a' {
			return wireTypeError(path, "an array")
		}
		for i, e := range v.arr {
			if err := checkWireValue(fmt.Sprintf("%s[%d]", path, i), e, wireField{kind: wireBytes}); err != nil {
				return err
			}
		}
	case wireObject:
		return checkWireObject(path, v, f.schema)
	case wireObjectList:
		if v.kind != 'a' {
			return wireTypeError(path, "an array")
		}
		for i, e := range v.arr {
			if err := checkWireObject(fmt.Sprintf("%s[%d]", path, i), e, f.schema); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkWireObject: the value is an object; then its keys in document order, each known to the schema; then the schema's
// fields in order, each required one present, each present one of its type (null is no type of any field).
func checkWireObject(path string, v *jsonValue, schema []wireField) error {
	if v.kind != 'o' {
		return wireTypeError(path, "an object")
	}
	for _, k := range v.keys {
		known := false
		for _, f := range schema {
			if f.key == k {
				known = true
				break
			}
		}
		if !known {
			return unproven(ReasonUnknownField, "%s.%s is no field of the format", path, k)
		}
	}
	for _, f := range schema {
		child, ok := v.vals[f.key]
		if !ok {
			if f.required {
				return unproven(ReasonMissingField, "%s.%s is required", path, f.key)
			}
			continue
		}
		if err := checkWireValue(path+"."+f.key, child, f); err != nil {
			return err
		}
	}
	return nil
}

// DecodeReplayGuardEvidence decodes S6 evidence strictly (see the top of this file and testdata/s6replay1/SPEC.md):
//
//  0. at most MaxReplayEvidenceBytes long - else evidence_too_large, before anything is read (testdata/s6replay5/SPEC.md);
//  1. one JSON value, no duplicate key, nothing after it - else malformed_json;
//  2. the schema, depth first in schema order - unknown_field, missing_field, wrong_type;
//  3. exactly one of proof and state - else no_evidence_or_state;
//  4. the evidence's version, then the proof's, is ReplayGuardDomain - else unknown_version.
func DecodeReplayGuardEvidence(raw []byte) (*ReplayGuardEvidence, error) {
	if len(raw) > MaxReplayEvidenceBytes {
		return nil, unproven(ReasonEvidenceTooLarge, "the evidence is %d bytes, more than the %d bytes the format allows", len(raw), MaxReplayEvidenceBytes)
	}
	return decodeReplayEvidence(raw)
}

// decodeReplayEvidence is steps 1-4 of DecodeReplayGuardEvidence, for a document within the size bound. Its reader has no
// depth limit and no recursion, so a document of any depth that fits in memory is read (RB10-B12); the tests call it
// directly to hold the reader itself to that, independent of the size bound.
func decodeReplayEvidence(raw []byte) (*ReplayGuardEvidence, error) {
	doc, err := parseStrictJSON(raw)
	if err != nil {
		return nil, unproven(ReasonMalformedJSON, "%v", err)
	}
	if err := checkWireObject("$", doc, wireEvidence); err != nil {
		return nil, err
	}
	var ev ReplayGuardEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, unproven(ReasonWrongType, "%v", err)
	}
	if (ev.Proof == nil) == (ev.State == nil) {
		return nil, unproven(ReasonEmptyEvidence, "the evidence carries exactly one of a proof and a named state")
	}
	if ev.Version != ReplayGuardDomain {
		return nil, unproven(ReasonVersion, "version %q is not %s", ev.Version, ReplayGuardDomain)
	}
	if ev.Proof != nil && ev.Proof.Version != ReplayGuardDomain {
		return nil, unproven(ReasonVersion, "the proof's version %q is not %s", ev.Proof.Version, ReplayGuardDomain)
	}
	return &ev, nil
}
