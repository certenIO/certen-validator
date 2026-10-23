// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

// Prefix is on every code of the registry in states.json and in every report (the tables of the specification omit it).
const Prefix = "contract_identity_"

// statesJSON is testdata/contractidentity/states.json, lifted from Freeze inventory item 3 by design/vectors/s8/lift.mjs: one row per
// (code, reason). names_gen.go holds the constants of the same table; states_test.go fails when they differ.
//
//go:embed testdata/contractidentity/states.json
var statesJSON []byte

// Row is one row of the named-state registry.
type Row struct {
	Code      string              `json:"code"`
	Row       string              `json:"row"`    // the "reason / sub-code" cell of the specification, verbatim ("-" for none)
	Part      string              `json:"part"`   // the part a not_checked row is about (the cell reads "<part> / <reason>")
	Reason    string              `json:"reason"` // the reason constant of the row ("" for the cell "-" and the wrapper row)
	Class     string              `json:"class"`
	Fields    []string            `json:"fields"`   // every field the state may carry (reason included when the row has one)
	Optional  []string            `json:"optional"` // the fields of Fields that may be absent
	Step      string              `json:"step"`
	Effect    string              `json:"effect"`
	ReasonSet string              `json:"reason_set"` // family row: the state's reason is a member of this vocabulary set (the cell names the family)
	Variants  map[string][]string `json:"variants"`   // family row: the fields required with each reason (besides reason itself)

	fieldSet map[string]bool
	optSet   map[string]bool
}

// Registry is the machine registry of every state the S8 verifier can answer with.
type Registry struct {
	Format       string   `json:"format"`
	Prefix       string   `json:"prefix"`
	CommonFields []string `json:"common_fields"`
	Rows         []Row    `json:"rows"`

	index map[string]*Row // code + "|" + row cell
	vocab *Vocabulary
}

var knownClasses = map[string]bool{"FR": true, "JR": true, "U": true, "OPEN": true, "PEND": true, "VER": true, "NA": true, "WRAP": true}

// LoadRegistry parses a states.json strictly and checks it against the vocabulary (every reason_set exists).
func LoadRegistry(raw []byte, vocab *Vocabulary) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var g struct {
		Registry
		Spec    json.RawMessage   `json:"spec"`
		Classes map[string]string `json:"classes"`
		Effects []string          `json:"effects"`
	}
	if err := dec.Decode(&g); err != nil {
		return nil, fmt.Errorf("contractidentity: states.json: %w", err)
	}
	r := g.Registry
	if r.Format != "certen-contract-identity-states/1" || r.Prefix != Prefix {
		return nil, fmt.Errorf("contractidentity: states.json: format %q prefix %q", r.Format, r.Prefix)
	}
	r.index = map[string]*Row{}
	r.vocab = vocab
	effects := map[string]bool{}
	for _, e := range g.Effects {
		effects[e] = true
	}
	for i := range r.Rows {
		row := &r.Rows[i]
		if !strings.HasPrefix(row.Code, Prefix) {
			return nil, fmt.Errorf("contractidentity: states.json: code %q has no %s prefix", row.Code, Prefix)
		}
		if !knownClasses[row.Class] {
			return nil, fmt.Errorf("contractidentity: states.json: row %s|%s: class %q", row.Code, row.Row, row.Class)
		}
		eff := strings.SplitN(row.Effect, " ", 2)[0]
		if !effects[eff] {
			return nil, fmt.Errorf("contractidentity: states.json: row %s|%s: effect %q", row.Code, row.Row, row.Effect)
		}
		k := row.Code + "|" + row.Row
		if r.index[k] != nil {
			return nil, fmt.Errorf("contractidentity: states.json: duplicate row %s", k)
		}
		r.index[k] = row
		row.fieldSet = map[string]bool{}
		for _, f := range row.Fields {
			row.fieldSet[f] = true
		}
		row.optSet = map[string]bool{}
		for _, f := range row.Optional {
			if !row.fieldSet[f] {
				return nil, fmt.Errorf("contractidentity: states.json: row %s: optional %q is not a field", k, f)
			}
			row.optSet[f] = true
		}
		if row.ReasonSet != "" {
			if vocab == nil || vocab.Sets[row.ReasonSet] == nil {
				return nil, fmt.Errorf("contractidentity: states.json: row %s: reason_set %q is not a vocabulary", k, row.ReasonSet)
			}
			for reason, extra := range row.Variants {
				if !vocab.Check(row.ReasonSet, reason) {
					return nil, fmt.Errorf("contractidentity: states.json: row %s: variant %q is not in %s", k, reason, row.ReasonSet)
				}
				for _, f := range extra {
					if !row.fieldSet[f] {
						return nil, fmt.Errorf("contractidentity: states.json: row %s: variant %q field %q is not a field", k, reason, f)
					}
				}
			}
		}
	}
	return &r, nil
}

var (
	defaultRegOnce sync.Once
	defaultReg     *Registry
	defaultRegErr  error
)

// DefaultRegistry is the embedded states.json checked against the embedded vocabulary.
func DefaultRegistry() (*Registry, error) {
	defaultRegOnce.Do(func() {
		v, err := DefaultVocabulary()
		if err != nil {
			defaultRegErr = err
			return
		}
		defaultReg, defaultRegErr = LoadRegistry(statesJSON, v)
	})
	return defaultReg, defaultRegErr
}

// Lookup returns the registry row of (code, row cell). The cell "" means "-".
func (g *Registry) Lookup(code, row string) (*Row, bool) {
	if row == "" {
		row = "-"
	}
	r, ok := g.index[code+"|"+row]
	return r, ok
}

// RowsOf returns every row of a code in registry order.
func (g *Registry) RowsOf(code string) []*Row {
	var out []*Row
	for i := range g.Rows {
		if g.Rows[i].Code == code {
			out = append(out, &g.Rows[i])
		}
	}
	return out
}

// Codes are the distinct codes in registry order.
func (g *Registry) Codes() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range g.Rows {
		if !seen[r.Code] {
			seen[r.Code] = true
			out = append(out, r.Code)
		}
	}
	return out
}

// StateError is every answer the S8 verifier gives that is not a verified fact: a named state with the values it was judged at
// (00_STANDARD.md section 3, "No fallback"). It is built only by New/Must (or the typed helpers below), which refuse an unregistered
// (code, row) and a missing or extra field. Reason is the value of the "reason" field when the state has one ("" otherwise).
type StateError struct {
	Code   string
	Reason string
	Fields map[string]any

	cause error // the Go error that led to the state (a parse detail); never part of the state, its canonical form or a comparison
}

// Unwrap returns the underlying cause, if any, for errors.Is / errors.As and for diagnostics.
func (s *StateError) Unwrap() error { return s.cause }

// WithCause attaches the underlying cause to a copy of the state. The cause is a diagnostic only: Canonical, Validate and every comparison
// ignore it.
func (s *StateError) WithCause(err error) *StateError {
	c := *s
	c.cause = err
	return &c
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
		c, err := Canonical(s.Fields[k])
		if err != nil {
			b.WriteString("?")
		} else {
			b.Write(c)
		}
	}
	b.WriteByte('}')
	return b.String()
}

// Canonical is the cross-language form {"code":...,"fields":{...}}: sorted keys, no whitespace, integers as decimal strings, bytes as 0x
// hex (the form that Go and TypeScript compare on every vector, expected state = code + fields).
func (s *StateError) Canonical() []byte {
	c, err := Canonical(map[string]any{"code": s.Code, "fields": s.Fields})
	if err != nil {
		// New refuses a state whose fields have no canonical form; reaching this means the fields were edited after construction.
		return []byte(`{"code":` + string(mustJSONString(s.Code)) + `,"fields":null}`)
	}
	return c
}

func mustJSONString(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}

// AsState returns the *StateError in err's chain.
func AsState(err error) (*StateError, bool) {
	var s *StateError
	if errors.As(err, &s) && s != nil {
		return s, true
	}
	return nil, false
}

func (g *Registry) fieldString(v any) (string, bool) {
	rv := reflect.ValueOf(v)
	if rv.IsValid() && rv.Kind() == reflect.String {
		return rv.String(), true
	}
	return "", false
}

// New builds the state of registry row (code, row) with exactly the given fields. row is the row cell of the registry ("" or "-" for
// a code with one unnamed row). The discriminants of the row (a not_checked row's part and reason, a plain U row's reason, pending's and
// not_applicable's reason) are filled in when absent and must equal the row's when present; a family row (authority_level_unproven,
// settlement_path_unsupported) takes its reason from the field, which must be a member of the family's vocabulary and fixes the other
// required fields. A missing required field, a field the row does not list, a value outside a bound closed vocabulary and a value with no
// canonical form are all refusals; the returned error then names the row and the field.
func (g *Registry) New(code, row string, fields map[string]any) (*StateError, error) {
	rr, ok := g.Lookup(code, row)
	if !ok {
		return nil, fmt.Errorf("contractidentity: unregistered state %s (row %q)", code, row)
	}
	f := make(map[string]any, len(fields)+2)
	for k, v := range fields {
		f[k] = v
	}
	set := func(k, want string) error {
		if have, present := f[k]; present {
			s, isStr := g.fieldString(have)
			if !isStr || s != want {
				return fmt.Errorf("contractidentity: state %s|%s: field %s is %v, the row fixes %q", code, rr.Row, k, have, want)
			}
			return nil
		}
		f[k] = want
		return nil
	}
	if rr.Part != "" {
		if err := set("part", rr.Part); err != nil {
			return nil, err
		}
	}
	if rr.Reason != "" && rr.ReasonSet == "" {
		if err := set("reason", rr.Reason); err != nil {
			return nil, err
		}
	}
	required := map[string]bool{}
	allowed := rr.fieldSet
	if rr.ReasonSet != "" {
		rv, present := f["reason"]
		if !present {
			return nil, fmt.Errorf("contractidentity: state %s|%s: the reason is required (a member of %s)", code, rr.Row, rr.ReasonSet)
		}
		rs, isStr := g.fieldString(rv)
		if !isStr || !g.vocab.Check(rr.ReasonSet, rs) {
			return nil, fmt.Errorf("contractidentity: state %s|%s: reason %v is not in %s", code, rr.Row, rv, rr.ReasonSet)
		}
		extra, hasVariant := rr.Variants[rs]
		if rr.Variants != nil && !hasVariant {
			return nil, fmt.Errorf("contractidentity: state %s|%s: reason %q has no field variant", code, rr.Row, rs)
		}
		allowed = map[string]bool{"reason": true}
		required["reason"] = true
		for _, x := range rr.Fields {
			if rr.fieldSet[x] && !rr.optSet[x] {
				required[x] = true
				allowed[x] = true
			}
		}
		for _, x := range extra {
			required[x] = true
			allowed[x] = true
		}
	} else {
		for _, x := range rr.Fields {
			if !rr.optSet[x] {
				required[x] = true
			}
		}
	}
	for k := range f {
		if !allowed[k] {
			return nil, fmt.Errorf("contractidentity: state %s|%s: field %q is not a field of the row", code, rr.Row, k)
		}
	}
	var missing []string
	for k := range required {
		if _, present := f[k]; !present {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("contractidentity: state %s|%s: missing field(s) %s", code, rr.Row, strings.Join(missing, ","))
	}
	short := strings.TrimPrefix(code, Prefix)
	for k, v := range f {
		id := g.vocab.SetFor(short, k, rr.Row)
		if id == "" {
			continue
		}
		s, isStr := g.fieldString(v)
		if !isStr || !g.vocab.Check(id, s) {
			return nil, fmt.Errorf("contractidentity: state %s|%s: field %s = %v is outside the closed vocabulary %s", code, rr.Row, k, v, id)
		}
	}
	if _, err := Canonical(f); err != nil {
		return nil, fmt.Errorf("contractidentity: state %s|%s: %w", code, rr.Row, err)
	}
	st := &StateError{Code: code, Fields: f}
	if r, ok := f["reason"]; ok {
		st.Reason, _ = g.fieldString(r)
	}
	return st, nil
}

// Validate checks an existing state against the registry: it finds the state's row (by its code and, where the code has several rows,
// by its reason and part) and re-applies every rule of New to its fields.
func (g *Registry) Validate(s *StateError) error {
	if s == nil {
		return errors.New("contractidentity: nil state")
	}
	rows := g.RowsOf(s.Code)
	if len(rows) == 0 {
		return fmt.Errorf("contractidentity: unregistered code %s", s.Code)
	}
	reasonStr := ""
	if r, ok := s.Fields["reason"]; ok {
		reasonStr, _ = g.fieldString(r)
	}
	partStr := ""
	if p, ok := s.Fields["part"]; ok {
		partStr, _ = g.fieldString(p)
	}
	var pick *Row
	for _, r := range rows {
		switch {
		case len(rows) == 1:
			pick = r
		case r.ReasonSet != "":
			if reasonStr != "" && g.vocab.Check(r.ReasonSet, reasonStr) {
				pick = r
			}
		case r.Part != "":
			if reasonStr == r.Reason && partStr == r.Part {
				pick = r
			}
		case r.Reason != "":
			if reasonStr == r.Reason {
				pick = r
			}
		case r.Row == "(wrapper)":
			if _, has := s.Fields["reason"]; !has {
				pick = r
			}
		}
		if pick != nil {
			break
		}
	}
	if pick == nil {
		return fmt.Errorf("contractidentity: state %s(reason %q, part %q) matches no registry row", s.Code, reasonStr, partStr)
	}
	if _, err := g.New(s.Code, pick.Row, s.Fields); err != nil {
		return err
	}
	if s.Reason != reasonStr {
		return fmt.Errorf("contractidentity: state %s: Reason %q differs from the reason field %q", s.Code, s.Reason, reasonStr)
	}
	return nil
}

// New is Registry.New on the embedded registry.
func New(code, row string, fields map[string]any) (*StateError, error) {
	g, err := DefaultRegistry()
	if err != nil {
		return nil, err
	}
	return g.New(code, row, fields)
}

// Must is New for call sites whose arguments are constants of the registry (a typed helper below, a verifier step raising a fixed row).
// An invalid construction there is a programming error that the registry walk tests of every package using it exist to catch before
// release; Must then panics rather than answer with a state the registry does not define.
func Must(code, row string, fields map[string]any) *StateError {
	s, err := New(code, row, fields)
	if err != nil {
		panic(err)
	}
	return s
}

// Validate is Registry.Validate on the embedded registry.
func Validate(s *StateError) error {
	g, err := DefaultRegistry()
	if err != nil {
		return err
	}
	return g.Validate(s)
}

// Context is the common data that every state of a report carries (registry common_fields). It is kept beside the fields of a state, not
// in them: several rows have fields of their own named chain or block (manifest_unknown, state_changed_in_block, record_created_in_block),
// and the common block is the settlement block while theirs is the attestation block.
type Context struct {
	Chain          uint64
	Block          uint64
	BlockHash      [32]byte
	JudgedAtLevel  string
	ManifestSHA256 [32]byte
	ManifestSource string
}

// Map renders the context with the registry's common field names.
func (c Context) Map() (map[string]any, error) {
	v, err := DefaultVocabulary()
	if err != nil {
		return nil, err
	}
	if !v.Check("manifest_source", c.ManifestSource) {
		return nil, fmt.Errorf("contractidentity: manifest_source %q is outside the closed vocabulary", c.ManifestSource)
	}
	return map[string]any{
		"chain": c.Chain, "block": c.Block, "block_hash": c.BlockHash, "judged_at_level": c.JudgedAtLevel,
		"manifest_sha256": c.ManifestSHA256, "manifest_source": c.ManifestSource,
	}, nil
}

// CanonicalWithContext is the report form {"code":...,"context":{...},"fields":{...}}.
func (s *StateError) CanonicalWithContext(c Context) ([]byte, error) {
	m, err := c.Map()
	if err != nil {
		return nil, err
	}
	return Canonical(map[string]any{"code": s.Code, "context": m, "fields": s.Fields})
}

// ---- typed helpers for the states the codec and the manifest loader raise ----
//
// Each builds its state through Must, so a field list or a vocabulary that drifts from the registry is caught by the registry walk test
// (TestTypedHelpersConform) and never reaches a verifier.

// Malformed is evidence_malformed{part,index,reason,got_len,want_len} (step 1, 22b). index is a byte offset for the reasons that stop a
// read and an element index for the ordering reasons (FORMAT.md, "Decode error fields"); gotLen and wantLen are 0 when not meaningful.
func Malformed(part, reason string, index, gotLen, wantLen int) *StateError {
	return Must(CodeEvidenceMalformed, "", map[string]any{
		"part": part, "index": uint64(maxInt(index, 0)), "reason": reason, "got_len": uint64(maxInt(gotLen, 0)), "want_len": uint64(maxInt(wantLen, 0)),
	})
}

// TooLarge is evidence_too_large{part,count,limit}.
func TooLarge(part string, count, limit uint64) *StateError {
	return Must(CodeEvidenceTooLarge, "", map[string]any{"part": part, "count": count, "limit": limit})
}

// Unrecognised is evidence_unrecognised{kind,version}; version is the "/vN" suffix of the kind, as for S7.
func Unrecognised(kind string) *StateError {
	version := ""
	if i := strings.LastIndex(kind, "/"); i >= 0 {
		version = kind[i+1:]
	}
	return Must(CodeEvidenceUnrecognised, "", map[string]any{"kind": kind, "version": version})
}

// ManifestCorrupt is manifest_corrupt (refuse to start).
func ManifestCorrupt() *StateError { return Must(CodeManifestCorrupt, "", map[string]any{}) }

// ManifestUnknown is manifest_unknown{chain}.
func ManifestUnknown(chain uint64) *StateError {
	return Must(CodeManifestUnknown, "", map[string]any{"chain": chain})
}

// ManifestShadow is manifest_shadow{table,key}.
func ManifestShadow(table, key string) *StateError {
	return Must(CodeManifestShadow, "", map[string]any{"table": table, "key": key})
}

// BlockMismatch is block_mismatch{field,want,got}; want and got are the numbers or hashes compared (any canonical value).
func BlockMismatch(field string, want, got any) *StateError {
	return Must(CodeBlockMismatch, "", map[string]any{"field": field, "want": want, "got": got})
}

// ContextIncomplete is context_incomplete{missing:[...]}; missing is sorted into the order of Freeze item 2a.
func ContextIncomplete(missing []string) *StateError {
	m := append([]string(nil), missing...)
	return Must(CodeContextIncomplete, "", map[string]any{"missing": m})
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
