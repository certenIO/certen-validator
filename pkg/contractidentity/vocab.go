// Copyright 2026 Certen Protocol

package contractidentity

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// vocabJSON is testdata/contractidentity/vocab.json, lifted from Freeze inventory item 4 by design/vectors/s8/lift.mjs.
//
//go:embed testdata/contractidentity/vocab.json
var vocabJSON []byte

// VocabSet is one closed vocabulary of Freeze inventory item 4: a list of values, patterns (for the open-ended spellings: hop:<i>, an AUTH
// row id with an optional key, override:<sha256>, a tx type), or free text that the producer states verbatim (S6State).
type VocabSet struct {
	Title    string         `json:"title"`
	Values   []string       `json:"values"`
	Patterns []string       `json:"patterns"`
	Free     string         `json:"free"`
	Numbers  map[string]int `json:"numbers"`

	compiled []*regexp.Regexp
	member   map[string]bool
}

// Vocabulary is the set of closed vocabularies and the binding of each (state code, field) to the set that its value must belong to.
type Vocabulary struct {
	Format   string               `json:"format"`
	Sets     map[string]*VocabSet `json:"sets"`
	Bindings map[string]string    `json:"bindings"`
}

// LoadVocabulary parses a vocab.json strictly and compiles its patterns.
func LoadVocabulary(raw []byte) (*Vocabulary, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var v struct {
		Format string               `json:"format"`
		Spec   json.RawMessage      `json:"spec"`
		Sets   map[string]*VocabSet `json:"sets"`
		Bind   map[string]string    `json:"bindings"`
	}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("contractidentity: vocab.json: %w", err)
	}
	if v.Format != "certen-contract-identity-vocab/1" {
		return nil, fmt.Errorf("contractidentity: vocab.json: format %q", v.Format)
	}
	out := &Vocabulary{Format: v.Format, Sets: v.Sets, Bindings: v.Bind}
	for id, s := range out.Sets {
		s.member = map[string]bool{}
		for _, x := range s.Values {
			if s.member[x] {
				return nil, fmt.Errorf("contractidentity: vocab.json: set %s repeats %q", id, x)
			}
			s.member[x] = true
		}
		for _, p := range s.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("contractidentity: vocab.json: set %s pattern %q: %w", id, p, err)
			}
			s.compiled = append(s.compiled, re)
		}
		if len(s.Values) == 0 && len(s.Patterns) == 0 && s.Free == "" {
			return nil, fmt.Errorf("contractidentity: vocab.json: set %s is empty", id)
		}
	}
	for k, id := range out.Bindings {
		if out.Sets[id] == nil {
			return nil, fmt.Errorf("contractidentity: vocab.json: binding %s names the missing set %s", k, id)
		}
	}
	return out, nil
}

var (
	defaultVocabOnce sync.Once
	defaultVocab     *Vocabulary
	defaultVocabErr  error
)

// DefaultVocabulary is the embedded vocab.json.
func DefaultVocabulary() (*Vocabulary, error) {
	defaultVocabOnce.Do(func() { defaultVocab, defaultVocabErr = LoadVocabulary(vocabJSON) })
	return defaultVocab, defaultVocabErr
}

// Check reports whether value is a member of the closed vocabulary name (the set ids of vocab.json: part_malformed, malformed_reason, ...).
// An unknown name is false: nothing is accepted by default.
func (v *Vocabulary) Check(name, value string) bool {
	s := v.Sets[name]
	if s == nil {
		return false
	}
	if s.Free != "" {
		return value != ""
	}
	if s.member[value] {
		return true
	}
	for _, re := range s.compiled {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// Check is Vocabulary.Check on the embedded vocabulary. A broken embed makes every check false (and TestVocabularyEmbedLoads fail).
func Check(name, value string) bool {
	v, err := DefaultVocabulary()
	if err != nil {
		return false
	}
	return v.Check(name, value)
}

// Values returns the enumerated values of a set in specification order (nil for a pattern-only or free set).
func (v *Vocabulary) Values(name string) []string {
	if s := v.Sets[name]; s != nil {
		return append([]string(nil), s.Values...)
	}
	return nil
}

// Names are the set ids in sorted order.
func (v *Vocabulary) Names() []string {
	out := make([]string, 0, len(v.Sets))
	for k := range v.Sets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SetFor is the set that the field of a state must take its value from ("" when the field is unbound). code is without the prefix;
// row is the registry row cell ("" for the code's only row), used for bindings that are restricted to one row (key field@row).
func (v *Vocabulary) SetFor(code, field, row string) string {
	code = strings.TrimPrefix(code, Prefix)
	if row != "" {
		if id, ok := v.Bindings[code+"."+field+"@"+row]; ok {
			return id
		}
	}
	return v.Bindings[code+"."+field]
}

// LevelNumber is the number of an authority level name (NONE 0 ... ROOT 4); ok is false for a name outside the vocabulary.
func (v *Vocabulary) LevelNumber(name string) (int, bool) {
	s := v.Sets["authority_level"]
	if s == nil {
		return 0, false
	}
	n, ok := s.Numbers[name]
	return n, ok
}
