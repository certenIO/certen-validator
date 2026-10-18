// Copyright 2026 Certen Protocol

// Package jsonmutate is the instrument of RB9-L's robustness tests: a deterministic mutation engine over a JSON document. For every
// member of a document (every object path, recursively, every array element) it builds the document with that member removed, set to
// null, set to the wrong type, set to an empty string, object or array, and - for a member that holds hex - with the binary cut short, its
// leading nibble flipped, its bytes zeroed and, when the bytes are a transaction, sequenced message, signature or account, with each field
// of the decoded value in turn absent (HollowVariants). Each mutated document is judged by the function under test, which must return,
// never panic; Run records every panic with the frames of the repository's code that raised it.
//
// It is test infrastructure (pkg/proof/v2 and pkg/consensus tests import it); nothing in a production binary does.
package jsonmutate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
)

// Path addresses one member of a document: a string for an object member, an int for an array element.
type Path []any

func (p Path) String() string {
	parts := make([]string, len(p))
	for i, e := range p {
		parts[i] = fmt.Sprint(e)
	}
	return strings.Join(parts, "/")
}

// Shape is the path with every array index replaced by "*": the member's place in the document's schema.
func (p Path) Shape() string {
	parts := make([]string, len(p))
	for i, e := range p {
		if _, isIndex := e.(int); isIndex {
			parts[i] = "*"
		} else {
			parts[i] = fmt.Sprint(e)
		}
	}
	return strings.Join(parts, "/")
}

// ParseTree reads a document keeping every number exactly as written.
func ParseTree(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Clone deep-copies a tree.
func Clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = Clone(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Clone(e)
		}
		return out
	}
	return v
}

// WalkSpec bounds which members are visited. The zero value visits every member.
type WalkSpec struct {
	// Keep, when set, is asked about every member; a member it refuses is not visited and nothing below it is.
	Keep func(Path) bool
	// Covered, when set, is asked about every member with its value; a member it reports covered is not visited and nothing below it is
	// (the representative run mutates a subtree that earlier documents carry identically once).
	Covered func(Path, any) bool
	// ArrayLimit, when set, visits of an array longer than it only the first, the middle and the last element. The documents it is set for
	// (the real ones) carry arrays of hundreds of elements that one code path handles alike; the synthetic documents are walked in full.
	ArrayLimit int
}

func (w WalkSpec) indices(n int) []int {
	if w.ArrayLimit > 0 && n > w.ArrayLimit {
		return []int{0, n / 2, n - 1}
	}
	all := make([]int, n)
	for i := range all {
		all[i] = i
	}
	return all
}

// Walk calls visit for every member below the root (depth first, object members in key order), with the path and the value.
func Walk(v any, w WalkSpec, visit func(Path, any)) { walk(v, nil, w, visit) }

func walk(v any, path Path, w WalkSpec, visit func(Path, any)) {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := append(append(Path{}, path...), k)
			if w.Keep != nil && !w.Keep(p) {
				continue
			}
			if w.Covered != nil && w.Covered(p, t[k]) {
				continue
			}
			visit(p, t[k])
			walk(t[k], p, w, visit)
		}
	case []any:
		for _, i := range w.indices(len(t)) {
			p := append(append(Path{}, path...), i)
			if w.Keep != nil && !w.Keep(p) {
				continue
			}
			if w.Covered != nil && w.Covered(p, t[i]) {
				continue
			}
			visit(p, t[i])
			walk(t[i], p, w, visit)
		}
	}
}

// Mutation is one change to one member.
type Mutation struct {
	Path Path
	Kind string
	Val  any // the replacement; ignored for "remove"
}

func (m Mutation) String() string { return m.Path.String() + " <- " + m.Kind }

// KindOf names the JSON type of a decoded value.
func KindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case json.Number, float64:
		return "number"
	case bool:
		return "bool"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	}
	return "?"
}

func isHexMember(s string) bool {
	if len(s) < 4 || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// MutationsOf lists the mutations of one member, in a fixed order.
func MutationsOf(p Path, v any) []Mutation {
	var out []Mutation
	add := func(kind string, val any) { out = append(out, Mutation{Path: p, Kind: kind, Val: val}) }
	add("remove", nil)
	k := KindOf(v)
	if k != "null" {
		add("null", nil)
	}
	if s, ok := v.(string); !ok || s != "" {
		add("empty-string", "")
	}
	if m, ok := v.(map[string]any); !ok || len(m) != 0 {
		add("empty-object", map[string]any{})
	}
	if a, ok := v.([]any); !ok || len(a) != 0 {
		add("empty-array", []any{})
	}
	switch k {
	case "string":
		add("wrong-type-number", json.Number("7"))
		add("wrong-type-bool", true)
	case "number":
		add("wrong-type-string", "7")
		add("wrong-type-bool", true)
	case "bool":
		add("wrong-type-string", "x")
		add("wrong-type-number", json.Number("7"))
	case "object", "array":
		add("wrong-type-string", "x")
		add("wrong-type-number", json.Number("7"))
	case "null":
		add("wrong-type-string", "x")
		add("wrong-type-number", json.Number("7"))
		add("wrong-type-bool", true)
	}
	if s, ok := v.(string); ok && isHexMember(s) {
		add("hex-cut-one-byte", s[:len(s)-2])
		first := "0"
		if s[0] == '0' {
			first = "f"
		}
		add("hex-flip-leading-nibble", first+s[1:])
		add("hex-zeroed", strings.Repeat("0", len(s)))
		for _, hv := range cachedHollowVariants(s) {
			add("hollow-"+hv.Name, hv.Hex)
		}
	}
	return out
}

// WholeDocument lists the mutations that make the document itself something else.
func WholeDocument() []Mutation {
	var out []Mutation
	for _, w := range []struct {
		kind string
		v    any
	}{{"null", nil}, {"empty-object", map[string]any{}}, {"empty-array", []any{}}, {"wrong-type-string", "x"}, {"wrong-type-number", json.Number("7")}} {
		out = append(out, Mutation{Path: Path{}, Kind: w.kind, Val: w.v})
	}
	return out
}

// Apply sets the mutation in tree and returns the function that undoes it, and the document's root (which differs from tree only for a
// mutation of the whole document).
func (m Mutation) Apply(tree any) (undo func(), root any) {
	if len(m.Path) == 0 {
		return func() {}, m.Val
	}
	parent := tree
	for _, e := range m.Path[:len(m.Path)-1] {
		switch t := parent.(type) {
		case map[string]any:
			parent = t[e.(string)]
		case []any:
			parent = t[e.(int)]
		}
	}
	last := m.Path[len(m.Path)-1]
	switch t := parent.(type) {
	case map[string]any:
		key := last.(string)
		old, had := t[key]
		if m.Kind == "remove" {
			delete(t, key)
		} else {
			t[key] = m.Val
		}
		return func() {
			if had {
				t[key] = old
			} else {
				delete(t, key)
			}
		}, tree
	case []any:
		i := last.(int)
		if m.Kind == "remove" {
			return removeElement(tree, m.Path, i)
		}
		old := t[i]
		t[i] = m.Val
		return func() { t[i] = old }, tree
	}
	return func() {}, tree
}

// removeElement removes element i of the array at path[:len-1] by replacing that array in its own parent.
func removeElement(tree any, path Path, i int) (func(), any) {
	arrPath := path[:len(path)-1]
	if len(arrPath) == 0 {
		old := tree.([]any)
		return func() {}, append(append([]any{}, old[:i]...), old[i+1:]...)
	}
	holder := tree
	for _, e := range arrPath[:len(arrPath)-1] {
		switch t := holder.(type) {
		case map[string]any:
			holder = t[e.(string)]
		case []any:
			holder = t[e.(int)]
		}
	}
	switch h := holder.(type) {
	case map[string]any:
		key := arrPath[len(arrPath)-1].(string)
		old := h[key].([]any)
		h[key] = append(append([]any{}, old[:i]...), old[i+1:]...)
		return func() { h[key] = old }, tree
	case []any:
		idx := arrPath[len(arrPath)-1].(int)
		old := h[idx].([]any)
		h[idx] = append(append([]any{}, old[:i]...), old[i+1:]...)
		return func() { h[idx] = old }, tree
	}
	return func() {}, tree
}

// Verdict is what the function under test did with one mutated document.
type Verdict struct {
	Panicked string // the panic value and the frames in this repository, when the function panicked
	Refused  bool   // an error was returned (decode errors included)
	Err      string // the error text, for a refusal
	Report   string // the canonical report, for a verified document
	// Unproven are the codes of the named states a verified report lists as not established (a verified report with any is not a
	// verified claim of everything: the consensus binding refuses it).
	Unproven []string
	// Noop is set by a judge that can tell the mutated document is, to the verifier, the very input of the original (the member was
	// already null, empty or absent; the same value spelt another way).
	Noop bool
}

// Judge judges document bytes. It need not recover: Run does.
type Judge func(raw []byte) Verdict

// repoFrames reduces a stack to the first three frames of non-runtime code, innermost first.
func repoFrames(stack []byte) string {
	var frames []string
	lines := strings.Split(string(stack), "\n")
	for i := 0; i+1 < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		loc := strings.TrimSpace(lines[i+1])
		if !strings.Contains(loc, "/") && !strings.Contains(loc, ":\\") {
			continue
		}
		if strings.Contains(l, "runtime/debug.Stack") || strings.HasPrefix(l, "panic(") || strings.HasPrefix(l, "runtime.") ||
			strings.Contains(l, "jsonmutate.") {
			continue
		}
		fn := l
		if j := strings.Index(fn, "("); j > 0 {
			fn = fn[:j]
		}
		if k := strings.LastIndex(loc, "/"); k >= 0 {
			loc = loc[k+1:]
		}
		if sp := strings.Index(loc, " +0x"); sp > 0 {
			loc = loc[:sp]
		}
		frames = append(frames, fn[strings.LastIndex(fn, "/")+1:]+" "+loc)
		if len(frames) == 3 {
			break
		}
	}
	return strings.Join(frames, " < ")
}

// Guard runs f and converts a panic into a recorded verdict.
func Guard(f func() Verdict) (v Verdict) {
	defer func() {
		if r := recover(); r != nil {
			var msg string
			if re, ok := r.(runtime.Error); ok {
				msg = re.Error()
			} else {
				msg = fmt.Sprint(r)
			}
			v = Verdict{Panicked: msg + " @ " + repoFrames(debug.Stack())}
		}
	}()
	return f()
}

// Outcome is one mutation and what became of it.
type Outcome struct {
	M Mutation
	V Verdict
}

// Run applies every mutation to a pristine copy of the document and judges the result, spreading the work over workers while keeping the
// results in the order of the mutations.
func Run(tree any, muts []Mutation, judge Judge, workers int) []Outcome {
	out := make([]Outcome, len(muts))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mine := Clone(tree)
			for i := range jobs {
				undo, root := muts[i].Apply(mine)
				raw, err := json.Marshal(root)
				undo()
				if err != nil {
					out[i] = Outcome{M: muts[i], V: Verdict{Refused: true, Err: "harness: " + err.Error()}}
					continue
				}
				out[i] = Outcome{M: muts[i], V: Guard(func() Verdict { return judge(raw) })}
			}
		}()
	}
	for i := range muts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}
