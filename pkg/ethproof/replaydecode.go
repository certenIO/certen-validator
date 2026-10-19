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
// with a named reason, unless it is one JSON value with no duplicate key, every object holds only the keys of its
// schema and every required one, every value has its schema's type and lexical form, exactly one of proof and state is
// carried, and every version is ReplayGuardDomain. Each refusal is s6_replay_unproven{reason}.

// Reasons of a strict-decoding refusal.
const (
	ReasonMalformedJSON = "malformed_json"
	ReasonUnknownField  = "unknown_field"
	ReasonMissingField  = "missing_field"
	ReasonWrongType     = "wrong_type"
)

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

func parseJSONValue(dec *json.Decoder) (*jsonValue, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v := &jsonValue{kind: 'o', vals: map[string]*jsonValue{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not a string")
				}
				if _, dup := v.vals[k]; dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				child, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				v.keys = append(v.keys, k)
				v.vals[k] = child
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		case '[':
			v := &jsonValue{kind: 'a', arr: []*jsonValue{}}
			for dec.More() {
				child, err := parseJSONValue(dec)
				if err != nil {
					return nil, err
				}
				v.arr = append(v.arr, child)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return v, nil
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case string:
		return &jsonValue{kind: 's', str: t}, nil
	case json.Number:
		return &jsonValue{kind: 'n', str: t.String()}, nil
	case bool:
		if t {
			return &jsonValue{kind: 'b', str: "true"}, nil
		}
		return &jsonValue{kind: 'b', str: "false"}, nil
	case nil:
		return &jsonValue{kind: 'z'}, nil
	}
	return nil, fmt.Errorf("unexpected token %v", tok)
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
//  1. one JSON value, no duplicate key, nothing after it - else malformed_json;
//  2. the schema, depth first in schema order - unknown_field, missing_field, wrong_type;
//  3. exactly one of proof and state - else no_evidence_or_state;
//  4. the evidence's version, then the proof's, is ReplayGuardDomain - else unknown_version.
func DecodeReplayGuardEvidence(raw []byte) (*ReplayGuardEvidence, error) {
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
