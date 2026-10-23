// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// This file is the loader contract of the PUBLISHED vector sets (testdata/contractidentity/vectors/FORMAT.md): what a set directory
// holds, how it is hash-checked, which mutation operations are legal, and how a vector is run through a Verifier. The synthetic world
// itself (H0: headers, node sets, code blobs, leaves) and the application of the mutations are supplied by a WorldBuilder; this package
// defines the contract and the runner, and a vector can never pass without a Verifier having judged it.

// Vector index statuses.
const (
	VectorSpecOnly   = "spec_only"
	VectorPublished  = "published"
	VectorSuperseded = "superseded"
)

// Outcomes of running a vector.
const (
	OutcomePass   = "pass"
	OutcomeFail   = "fail"
	OutcomeNotRun = "not_run"
)

// MutationOps is the CLOSED vocabulary of mutation operations a vector may use (FORMAT.md lists the same set).
var MutationOps = []string{"set_byte", "replace_hex", "truncate", "append_hex", "drop_node", "add_node", "reorder", "set_field", "unset_field"}

// MutationTargets are the artifacts a mutation can address.
var MutationTargets = []string{"container", "context", "manifest", "extension", "world"}

// reorderLists are the lists `reorder` can reverse in the decoded container.
var reorderLists = []string{"codes", "nodes", "hopHeaders", "spine", "blockTxs"}

// IndexVector is one entry of vectors/MANIFEST.json: a row of Freeze item 5.
type IndexVector struct {
	ID           string          `json:"id"`
	Step         string          `json:"step"`
	Mutation     string          `json:"mutation"`
	ExpectedText string          `json:"expectedText"`
	Expected     []IndexExpected `json:"expected"`
	OtherTokens  []string        `json:"other_tokens"`
	Set          *string         `json:"set"`
	Status       string          `json:"status"`
}

// IndexExpected is a registry state named by the expectation text of a row.
type IndexExpected struct {
	Code   string  `json:"code"`
	Reason *string `json:"reason"`
	Fields *string `json:"fields"`
}

// VectorIndex is vectors/MANIFEST.json.
type VectorIndex struct {
	Format  string        `json:"format"`
	Note    string        `json:"note"`
	Vectors []IndexVector `json:"vectors"`
}

var vectorIDRe = regexp.MustCompile(`^VS8-\d{3}$`)

// LoadVectorIndex parses vectors/MANIFEST.json strictly and checks it against the registry: ids unique and ascending, every expected code a
// registry code, every status in the vocabulary, a published or superseded vector naming its set.
func LoadVectorIndex(raw []byte, reg *Registry) (*VectorIndex, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var x struct {
		VectorIndex
		Spec json.RawMessage `json:"spec"`
	}
	if err := dec.Decode(&x); err != nil {
		return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %w", err)
	}
	idx := &x.VectorIndex
	if idx.Format != "certen-contract-identity-vectors/1" {
		return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: format %q", idx.Format)
	}
	codes := map[string]bool{}
	for _, c := range reg.Codes() {
		codes[c] = true
	}
	prev := ""
	for _, v := range idx.Vectors {
		if !vectorIDRe.MatchString(v.ID) || v.ID <= prev {
			return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: id %q is malformed, repeated or out of order", v.ID)
		}
		prev = v.ID
		if v.Step == "" || v.Mutation == "" || v.ExpectedText == "" {
			return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %s has an empty cell", v.ID)
		}
		for _, e := range v.Expected {
			if !codes[e.Code] {
				return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %s expects %q, which is not a registry code", v.ID, e.Code)
			}
		}
		switch v.Status {
		case VectorSpecOnly:
			if v.Set != nil {
				return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %s is spec_only but names the set %q", v.ID, *v.Set)
			}
		case VectorPublished, VectorSuperseded:
			if v.Set == nil || *v.Set == "" {
				return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %s is %s without a set", v.ID, v.Status)
			}
		default:
			return nil, fmt.Errorf("contractidentity: vectors/MANIFEST.json: %s has status %q", v.ID, v.Status)
		}
	}
	return idx, nil
}

// Mutation is one step of a vector's mutation list. Which of the optional members each operation uses is fixed in FORMAT.md and checked
// by Validate.
type Mutation struct {
	Op     string          `json:"op"`
	Target string          `json:"target,omitempty"`
	Path   string          `json:"path,omitempty"`
	Offset *int            `json:"offset,omitempty"`
	Index  *int            `json:"index,omitempty"`
	Length *int            `json:"length,omitempty"`
	List   string          `json:"list,omitempty"`
	Old    string          `json:"old,omitempty"`
	New    string          `json:"new,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
}

// Validate checks that the operation is in the closed vocabulary, addresses a legal target and carries exactly the members it needs.
func (m Mutation) Validate() error {
	known := false
	for _, op := range MutationOps {
		if m.Op == op {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("mutation op %q is outside the closed vocabulary %v", m.Op, MutationOps)
	}
	isHex := func(s string) bool { _, err := hex.DecodeString(s); return err == nil && s != "" }
	targetOK := func(allowed ...string) error {
		for _, a := range allowed {
			if m.Target == a {
				return nil
			}
		}
		return fmt.Errorf("mutation %s: target %q is not one of %v", m.Op, m.Target, allowed)
	}
	var unused []string
	if m.Offset != nil && m.Op != "set_byte" && m.Op != "replace_hex" {
		unused = append(unused, "offset")
	}
	if m.Index != nil && m.Op != "drop_node" {
		unused = append(unused, "index")
	}
	if m.Length != nil && m.Op != "truncate" {
		unused = append(unused, "length")
	}
	if m.List != "" && m.Op != "reorder" {
		unused = append(unused, "list")
	}
	if (m.Old != "" || m.New != "") && m.Op != "replace_hex" {
		unused = append(unused, "old/new")
	}
	if m.Path != "" && m.Op != "set_field" && m.Op != "unset_field" {
		unused = append(unused, "path")
	}
	if len(m.Value) > 0 && m.Op != "set_byte" && m.Op != "append_hex" && m.Op != "add_node" && m.Op != "set_field" {
		unused = append(unused, "value")
	}
	if len(unused) > 0 {
		return fmt.Errorf("mutation %s carries members it does not use: %v", m.Op, unused)
	}
	var hexValue string
	if len(m.Value) > 0 {
		_ = json.Unmarshal(m.Value, &hexValue)
	}
	switch m.Op {
	case "set_byte":
		if err := targetOK("container"); err != nil {
			return err
		}
		if m.Offset == nil || *m.Offset < 0 || len(hexValue) != 2 || !isHex(hexValue) {
			return fmt.Errorf("mutation set_byte needs offset >= 0 and a one-byte hex value")
		}
	case "replace_hex":
		if err := targetOK("container"); err != nil {
			return err
		}
		if m.Offset == nil || *m.Offset < 0 || !isHex(m.Old) || !isHex(m.New) {
			return fmt.Errorf("mutation replace_hex needs offset >= 0 and hex old and new")
		}
	case "truncate":
		if err := targetOK("container"); err != nil {
			return err
		}
		if m.Length == nil || *m.Length < 0 {
			return fmt.Errorf("mutation truncate needs length >= 0")
		}
	case "append_hex":
		if err := targetOK("container"); err != nil {
			return err
		}
		if !isHex(hexValue) {
			return fmt.Errorf("mutation append_hex needs a hex value")
		}
	case "drop_node":
		if err := targetOK("container"); err != nil {
			return err
		}
		if m.Index == nil || *m.Index < 0 {
			return fmt.Errorf("mutation drop_node needs index >= 0")
		}
	case "add_node":
		if err := targetOK("container"); err != nil {
			return err
		}
		if !isHex(hexValue) {
			return fmt.Errorf("mutation add_node needs a hex value")
		}
	case "reorder":
		if err := targetOK("container"); err != nil {
			return err
		}
		ok := false
		for _, l := range reorderLists {
			ok = ok || m.List == l
		}
		if !ok {
			return fmt.Errorf("mutation reorder: list %q is not one of %v", m.List, reorderLists)
		}
	case "set_field", "unset_field":
		if err := targetOK("container", "context", "manifest", "extension", "world"); err != nil {
			return err
		}
		if m.Path == "" || (m.Op == "set_field") != (len(m.Value) > 0) {
			return fmt.Errorf("mutation %s needs a path (and a value for set_field only)", m.Op)
		}
	}
	return nil
}

// ExpectedState is a state a vector requires, by the part that carries it (or "first" for the first refusal of a refused headline).
type ExpectedState struct {
	Part   string          `json:"part"`
	Code   string          `json:"code"`
	Fields json.RawMessage `json:"fields"`
}

// ExpectedOpen is an Open entry a vector requires.
type ExpectedOpen struct {
	Part   string          `json:"part"`
	Kind   string          `json:"kind"`
	Code   string          `json:"code"`
	Fields json.RawMessage `json:"fields"`
}

// Expected is what a vector requires of the Report. Absent members are unconstrained; present ones are compared exactly (states and Open
// entries by canonical JSON).
type Expected struct {
	Headline string            `json:"headline"`
	Parts    map[string]string `json:"parts,omitempty"`
	States   []ExpectedState   `json:"states,omitempty"`
	Open     []ExpectedOpen    `json:"open,omitempty"`
}

// Vector is one file `<id>.json` of a set.
type Vector struct {
	ID        string     `json:"id"`
	Base      string     `json:"base"`
	Mutations []Mutation `json:"mutations"`
	Expected  Expected   `json:"expected"`
}

// SpecID is the Freeze item 5 row a vector belongs to: the id up to the first dot (VS8-012.03 -> VS8-012).
func (v Vector) SpecID() string { return strings.SplitN(v.ID, ".", 2)[0] }

// Validate checks the vector's shape.
func (v Vector) Validate() error {
	if !regexp.MustCompile(`^VS8-\d{3}(\.[A-Za-z0-9_-]+)?$`).MatchString(v.ID) {
		return fmt.Errorf("vector id %q", v.ID)
	}
	if v.Base != "H0" {
		return fmt.Errorf("vector %s: base %q (the only base world is H0)", v.ID, v.Base)
	}
	for i, m := range v.Mutations {
		if err := m.Validate(); err != nil {
			return fmt.Errorf("vector %s mutation %d: %w", v.ID, i, err)
		}
	}
	if !Check("headline", v.Expected.Headline) {
		return fmt.Errorf("vector %s: expected headline %q", v.ID, v.Expected.Headline)
	}
	for part := range v.Expected.Parts {
		if partIndex(part) < 0 {
			return fmt.Errorf("vector %s: expected part %q", v.ID, part)
		}
	}
	for _, s := range v.Expected.States {
		if (s.Part != "first" && partIndex(s.Part) < 0) || !strings.HasPrefix(s.Code, Prefix) {
			return fmt.Errorf("vector %s: expected state %+v", v.ID, s)
		}
	}
	return nil
}

// VectorSet is a loaded, hash-checked published set.
type VectorSet struct {
	Name       string
	Dir        string
	World      json.RawMessage
	Vectors    []Vector
	Containers map[string][]byte // id -> container bytes where the file exists
	Superseded bool
}

var manifestLineRe = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$`)

// LoadVectorSet reads a set directory: MANIFEST (sha256 of every other file, sorted by file name, `<hex>  <name>` lines), world.json,
// one <id>.json per vector and <id>.container.hex where the container bytes change; a SUPERSEDED.md marks the set superseded. Every file
// in the directory must be listed in MANIFEST and hash to its entry, every listed file must exist: published sets are never edited.
func LoadVectorSet(dir string) (*VectorSet, error) {
	manifest, err := os.ReadFile(filepath.Join(dir, "MANIFEST"))
	if err != nil {
		return nil, fmt.Errorf("contractidentity: vector set %s: %w", dir, err)
	}
	listed := map[string]string{}
	lastName := ""
	for _, line := range strings.Split(strings.TrimRight(string(manifest), "\n"), "\n") {
		m := manifestLineRe.FindStringSubmatch(line)
		if m == nil || m[2] <= lastName || m[2] == "MANIFEST" {
			return nil, fmt.Errorf("contractidentity: vector set %s: MANIFEST line %q is malformed or out of order", dir, line)
		}
		lastName = m[2]
		listed[m[2]] = m[1]
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	set := &VectorSet{Name: filepath.Base(dir), Dir: dir, Containers: map[string][]byte{}}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("contractidentity: vector set %s: unexpected directory %s", dir, e.Name())
		}
		if e.Name() == "MANIFEST" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		want, ok := listed[e.Name()]
		if !ok {
			return nil, fmt.Errorf("contractidentity: vector set %s: file %s is not listed in MANIFEST", dir, e.Name())
		}
		if hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("contractidentity: vector set %s: file %s differs from its MANIFEST hash (published sets are never edited)", dir, e.Name())
		}
		files[e.Name()] = b
	}
	for name := range listed {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("contractidentity: vector set %s: MANIFEST lists the missing file %s", dir, name)
		}
	}
	world, ok := files["world.json"]
	if !ok || !json.Valid(world) {
		return nil, fmt.Errorf("contractidentity: vector set %s: world.json missing or not JSON", dir)
	}
	set.World = world
	_, set.Superseded = files["SUPERSEDED.md"]
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		switch {
		case n == "world.json" || n == "SUPERSEDED.md":
		case strings.HasSuffix(n, ".container.hex"):
			id := strings.TrimSuffix(n, ".container.hex")
			b, err := hex.DecodeString(strings.TrimSpace(string(files[n])))
			if err != nil {
				return nil, fmt.Errorf("contractidentity: vector set %s: %s: %w", dir, n, err)
			}
			if _, ok := files[id+".json"]; !ok {
				return nil, fmt.Errorf("contractidentity: vector set %s: %s has no %s.json", dir, n, id)
			}
			set.Containers[id] = b
		case strings.HasSuffix(n, ".json"):
			dec := json.NewDecoder(bytes.NewReader(files[n]))
			dec.DisallowUnknownFields()
			var v Vector
			if err := dec.Decode(&v); err != nil {
				return nil, fmt.Errorf("contractidentity: vector set %s: %s: %w", dir, n, err)
			}
			if v.ID+".json" != n {
				return nil, fmt.Errorf("contractidentity: vector set %s: %s carries the id %s", dir, n, v.ID)
			}
			if err := v.Validate(); err != nil {
				return nil, fmt.Errorf("contractidentity: vector set %s: %w", dir, err)
			}
			set.Vectors = append(set.Vectors, v)
		default:
			return nil, fmt.Errorf("contractidentity: vector set %s: unexpected file %s", dir, n)
		}
	}
	return set, nil
}

// Inputs are what a Verifier is run on.
type Inputs struct {
	Ctx       LegContext
	Container []byte
	Manifest  *Manifest
}

// WorldBuilder turns a set's world.json and a vector (its base H0 and its mutations; the container file where there is one) into the
// inputs of a Verifier. It is supplied by the world package of the verify work packages; this package never builds a world.
type WorldBuilder interface {
	Build(world json.RawMessage, v Vector, container []byte) (Inputs, error)
}

// VectorResult is the outcome of running one vector.
type VectorResult struct {
	ID      string
	Outcome string // pass | fail | not_run
	Detail  string
}

// RunSet runs every vector of a set. With no WorldBuilder or no Verifier a vector is `not_run`; it is `pass` only when a Verifier judged
// the inputs and its Report satisfies the expectation exactly. A Verifier error, a world that cannot be built and a Report that does not
// match are `fail`.
func RunSet(set *VectorSet, wb WorldBuilder, ver Verifier) []VectorResult {
	out := make([]VectorResult, 0, len(set.Vectors))
	for _, v := range set.Vectors {
		switch {
		case wb == nil:
			out = append(out, VectorResult{v.ID, OutcomeNotRun, "no world builder"})
			continue
		case ver == nil:
			out = append(out, VectorResult{v.ID, OutcomeNotRun, "no verifier"})
			continue
		}
		in, err := wb.Build(set.World, v, set.Containers[v.ID])
		if err != nil {
			out = append(out, VectorResult{v.ID, OutcomeFail, "world: " + err.Error()})
			continue
		}
		rep, err := ver.Verify(in.Ctx, in.Container, in.Manifest)
		if err != nil {
			out = append(out, VectorResult{v.ID, OutcomeFail, "verifier error: " + err.Error()})
			continue
		}
		if err := MatchExpected(v.Expected, rep); err != nil {
			out = append(out, VectorResult{v.ID, OutcomeFail, err.Error()})
			continue
		}
		out = append(out, VectorResult{v.ID, OutcomePass, ""})
	}
	return out
}

// MatchExpected compares a Report with an expectation: the headline kind, the part statuses, the part states (canonical JSON, exact), the
// first refusal and the Open entries (exact set). A Report that is not even valid (its headline is of no kind) never matches.
func MatchExpected(e Expected, r Report) error {
	if r.Headline.Kind == "" {
		return fmt.Errorf("the report has no headline")
	}
	if r.Headline.Kind != e.Headline {
		return fmt.Errorf("headline %s, expected %s", r.Headline.Kind, e.Headline)
	}
	byPart := map[string]PartResult{}
	for _, p := range r.Parts {
		byPart[p.Part] = p
	}
	for part, want := range e.Parts {
		if got, ok := byPart[part]; !ok || string(got.Status) != want {
			return fmt.Errorf("part %s is %q, expected %s", part, byPart[part].Status, want)
		}
	}
	for _, s := range e.States {
		var got *StateError
		if s.Part == "first" {
			got = r.Headline.First
		} else if p, ok := byPart[s.Part]; ok {
			got = p.State
		}
		if got == nil {
			return fmt.Errorf("part %s carries no state, expected %s", s.Part, s.Code)
		}
		want := map[string]any{}
		if len(s.Fields) > 0 {
			if err := json.Unmarshal(s.Fields, &want); err != nil {
				return fmt.Errorf("expected fields of %s: %w", s.Part, err)
			}
		}
		if got.Code != s.Code || !canonicalJSONEqual(got.Fields, want) {
			return fmt.Errorf("part %s state %s, expected %s%s", s.Part, got.Canonical(), s.Code, s.Fields)
		}
	}
	if e.Open != nil {
		open := r.OpenEntries()
		if len(open) != len(e.Open) {
			return fmt.Errorf("%d Open entries, expected %d", len(open), len(e.Open))
		}
		for i, o := range open {
			w := e.Open[i]
			want := map[string]any{}
			if len(w.Fields) > 0 {
				_ = json.Unmarshal(w.Fields, &want)
			}
			if o.Part != w.Part || o.Kind != w.Kind || o.State.Code != w.Code || !canonicalJSONEqual(o.State.Fields, want) {
				return fmt.Errorf("Open entry %d is %s:%s %s, expected %s:%s %s", i, o.Part, o.Kind, o.State.Canonical(), w.Part, w.Kind, w.Code)
			}
		}
	}
	return nil
}

// canonicalJSONEqual compares a state's fields with the expectation's fields by their canonical forms. The expectation is written in the
// canonical form already (integers as decimal strings, bytes as 0x hex), so a JSON number in it (which has no canonical form) never matches.
func canonicalJSONEqual(have map[string]any, want map[string]any) bool {
	a, err := Canonical(have)
	if err != nil {
		return false
	}
	b, err := Canonical(want)
	if err != nil {
		return false
	}
	return bytes.Equal(a, b)
}
