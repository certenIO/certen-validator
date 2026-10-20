// Copyright 2026 Certen Protocol

package ethproof

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// =============================================================================
// RB10-B12: the iterative S6 evidence reader is the recursive one, verdict for verdict
// =============================================================================
//
// The functions below are the reader as it stood at b372a7a (pkg/ethproof/replaydecode.go:97-171 and
// DecodeReplayGuardEvidence at :269-291), copied verbatim except for their names (old... prefix, so that the recursive
// call goes to the copy). They are the reference: the differential test judges a generated corpus with the reference and
// with the reader in replaydecode.go and requires the parsed tree, the error text and the decoded evidence to be
// identical for every document. The recursion is bounded by Go's goroutine stack, so the reference is only fed documents
// that are far under that bound (depth 9000 at most).

func oldParseJSONValue(dec *json.Decoder) (*jsonValue, error) {
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
				child, err := oldParseJSONValue(dec)
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
				child, err := oldParseJSONValue(dec)
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

func oldParseStrictJSON(raw []byte) (*jsonValue, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := oldParseJSONValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("data after the JSON value")
	}
	return v, nil
}

func oldDecodeReplayGuardEvidence(raw []byte) (*ReplayGuardEvidence, error) {
	doc, err := oldParseStrictJSON(raw)
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

// ---- the corpus ----

// corpusSeeds: every evidence document the four committed sets carry: the valid and refused vectors' evidence, the
// 1,937 mutations of s6replay1-3, and the 30 deep documents of s6replay4.
func corpusSeeds(t *testing.T) [][]byte {
	t.Helper()
	var seeds [][]byte
	for _, set := range []string{"s6replay1", "s6replay2", "s6replay3"} {
		files, err := filepath.Glob(filepath.Join("testdata", set, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Evidence string `json:"evidence"`
			}
			if err := json.Unmarshal(raw, &v); err != nil || v.Evidence == "" {
				continue // manifest.json
			}
			seeds = append(seeds, []byte(v.Evidence))
		}
		gz, err := os.ReadFile(filepath.Join("testdata", set, "mutations.json.gz"))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatal(err)
		}
		mraw, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		var muts []struct {
			Evidence string `json:"evidence"`
		}
		if err := json.Unmarshal(mraw, &muts); err != nil {
			t.Fatal(err)
		}
		for _, m := range muts {
			seeds = append(seeds, []byte(m.Evidence))
		}
	}
	deep, err := filepath.Glob(filepath.Join("testdata", "s6replay4", "*.evidence.gz"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range deep {
		gz, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		seeds = append(seeds, ev)
	}
	return seeds
}

var (
	corpusKeys = []string{`"a"`, `"b"`, `"c"`, `"version"`, `"proof"`, `"state"`, `"headers"`, `"zzz"`, `"chainId"`, `"contract"`,
		`"slot"`, `"before"`, `"after"`, `"a"`, `"é"`, `""`, `"k\"q"`, `"a b"`}
	corpusStrings = []string{`""`, `"x"`, `"0x00"`, `"0x"`, `"é"`, `"a\"b"`, `"\n\t\\\/"`, `"certen:s6-replay:v1"`,
		`"0x0000000000000000000000000000000000000000000000000000000000000001"`,
		`"0x00000000000000000000000000000000000000ab"`, `"CertenAccountV7_3"`, `"😀"`, `"\ud83d"`}
	corpusNumbers = []string{`0`, `1`, `-1`, `1.5`, `1e3`, `1E-2`, `123456789012345678901234567890`, `0.0`, `-0`, `9007199254740991`,
		`9007199254740992`, `84532`, `4`, `01`, `1.`, `.5`, `+1`, `0x10`}
	corpusWS = []string{"", "", "", " ", "\n", "\t ", "\r\n  "}
)

type docGen struct {
	r      *rand.Rand
	sb     strings.Builder
	budget int // containers a document may still open off its spine: bounds the size, which is otherwise exponential in the depth
}

func (g *docGen) ws() { g.sb.WriteString(corpusWS[g.r.Intn(len(corpusWS))]) }

func (g *docGen) scalar() {
	switch g.r.Intn(6) {
	case 0, 1:
		g.sb.WriteString(corpusStrings[g.r.Intn(len(corpusStrings))])
	case 2, 3:
		g.sb.WriteString(corpusNumbers[g.r.Intn(len(corpusNumbers))])
	case 4:
		g.sb.WriteString([]string{"true", "false"}[g.r.Intn(2)])
	default:
		g.sb.WriteString("null")
	}
}

// value writes a random JSON value of nesting depth at most max below it; spine forces the first child to nest further
// until max is reached, so that the corpus really has documents of the stated depth.
func (g *docGen) value(max int, spine bool) {
	g.ws()
	if max <= 0 || (!spine && (g.budget <= 0 || g.r.Intn(4) == 0)) {
		g.scalar()
		g.ws()
		return
	}
	g.budget--
	n := g.r.Intn(4)
	if spine && n == 0 {
		n = 1
	}
	if g.r.Intn(2) == 0 {
		g.sb.WriteByte('{')
		for i := 0; i < n; i++ {
			if i > 0 {
				g.sb.WriteByte(',')
			}
			g.ws()
			g.sb.WriteString(corpusKeys[g.r.Intn(len(corpusKeys))])
			g.ws()
			g.sb.WriteByte(':')
			g.value(max-1, spine && i == 0)
		}
		g.sb.WriteByte('}')
	} else {
		g.sb.WriteByte('[')
		for i := 0; i < n; i++ {
			if i > 0 {
				g.sb.WriteByte(',')
			}
			g.value(max-1, spine && i == 0)
		}
		g.sb.WriteByte(']')
	}
	g.ws()
}

func (g *docGen) tree(max int) []byte {
	g.sb.Reset()
	g.budget = 20 + g.r.Intn(40)
	g.value(max, g.r.Intn(2) == 0)
	return append([]byte(nil), g.sb.String()...)
}

var (
	corpusPunct   = []byte(`{}[],:"\ 0x-.eEtfnu`)
	corpusTrail   = []string{" ", "x", "{}", "]", "}", ",", " 1", "\n\n", "[]", `"a"`, "\x00", "\xff", "null"}
	corpusInserts = []string{`"version":"certen:s6-replay:v1",`, `"a":1,`, `"proof":{},`, `"state":{},`, `"headers":[],`, `"zzz":0,`,
		`"a":0,"a":0,`, `,"version":"x"`, `,"a":[]`, `{`, `[`, `]`, `}`, `,`}
)

// mutate returns raw changed by one random byte-level operation.
func mutate(r *rand.Rand, raw []byte) []byte {
	if len(raw) == 0 {
		return []byte(corpusTrail[r.Intn(len(corpusTrail))])
	}
	out := append([]byte(nil), raw...)
	switch r.Intn(7) {
	case 0: // truncate
		return out[:r.Intn(len(out))]
	case 1: // replace one byte by a punctuation byte
		out[r.Intn(len(out))] = corpusPunct[r.Intn(len(corpusPunct))]
	case 2: // replace one byte by any byte
		out[r.Intn(len(out))] = byte(r.Intn(256))
	case 3: // delete one byte
		i := r.Intn(len(out))
		out = append(out[:i], out[i+1:]...)
	case 4: // trailing garbage
		out = append(out, corpusTrail[r.Intn(len(corpusTrail))]...)
	case 5: // insert a fragment (a duplicate key, a child, a stray bracket) at a random place
		i := r.Intn(len(out) + 1)
		ins := corpusInserts[r.Intn(len(corpusInserts))]
		out = append(out[:i], append([]byte(ins), out[i:]...)...)
	default: // insert a fragment right after a random opening brace: the place a duplicate key lands in an object
		var opens []int
		for i, c := range out {
			if c == '{' {
				opens = append(opens, i)
			}
		}
		if len(opens) == 0 {
			return out[:r.Intn(len(out))]
		}
		i := opens[r.Intn(len(opens))] + 1
		ins := corpusInserts[r.Intn(len(corpusInserts)-5)]
		out = append(out[:i], append([]byte(ins), out[i:]...)...)
	}
	return out
}

// deepDoc writes a structured deep document: shape picks the nesting (arrays, objects, alternating), where picks the place
// it sits in (the whole document, an unknown field of an evidence, the version of an evidence, after a valid prefix), and
// tail picks how it ends (closed, truncated, closed then trailing garbage, closed then a duplicate key).
func deepDoc(r *rand.Rand, base []byte) []byte {
	n := 100 + r.Intn(8901)
	var open, core, closeS string
	switch r.Intn(3) {
	case 0:
		open, core, closeS = "[", "0", "]"
	case 1:
		open, core, closeS = `{"a":`, `"x"`, "}"
	default:
		open, core, closeS = `[{"a":`, "null", "}]"
	}
	if r.Intn(4) == 0 {
		core = "[]"
	}
	deep := strings.Repeat(open, n) + core + strings.Repeat(closeS, n)
	switch r.Intn(6) {
	case 0:
		return []byte(deep)
	case 1:
		return []byte(`{"version":"certen:s6-replay:v1","zzz":` + deep + `}`)
	case 2:
		return []byte(`{"version":"certen:s6-replay:v1","zzz":` + strings.Repeat(open, n) + core)
	case 3:
		return []byte(`{"version":"certen:s6-replay:v1","zzz":` + deep + `,"version":"x"}`)
	case 4:
		return []byte(`{"version":"certen:s6-replay:v1","zzz":` + deep + `}` + corpusTrail[r.Intn(len(corpusTrail))])
	}
	// deep value in place of the first value of a valid evidence (version) or after its first brace
	s := string(base)
	if i := strings.Index(s, `"certen:s6-replay:v1"`); i >= 0 && r.Intn(2) == 0 {
		return []byte(s[:i] + deep + s[i+len(`"certen:s6-replay:v1"`):])
	}
	if i := strings.IndexByte(s, '{'); i >= 0 {
		return []byte(s[:i+1] + `"zzz":` + deep + `,` + s[i+1:])
	}
	return []byte(deep)
}

// outcome names a decode result for the corpus census.
func outcome(ev *ReplayGuardEvidence, err error) string {
	if err == nil {
		if ev == nil {
			return "nil-nil"
		}
		return "decoded"
	}
	if re, ok := err.(*ReplayError); ok {
		return re.State + "/" + re.Reason
	}
	return "other-error"
}

// TestReplayDecodeIterativeDifferential: the reader in replaydecode.go and the verbatim recursive reference agree on
// every document of a generated corpus: the parsed tree (keys in document order, values, numbers' text), the read error's
// text, the decoded evidence and the refusal (state, reason and detail). A document is only counted when both readers
// returned.
func TestReplayDecodeIterativeDifferential(t *testing.T) {
	seeds := corpusSeeds(t)
	if len(seeds) < 1900 {
		t.Fatalf("only %d seed documents", len(seeds))
	}
	r := rand.New(rand.NewSource(20261019))
	g := &docGen{r: r}
	var corpus [][]byte
	class := map[string]int{}
	add := func(kind string, d []byte) {
		corpus = append(corpus, d)
		class[kind]++
	}
	valid := 0
	for _, s := range seeds {
		add("seed", s)
		if bytes.Contains(s, []byte(`"proof"`)) {
			valid++
		}
	}
	if valid < 1000 {
		t.Fatalf("only %d seed documents carry a proof", valid)
	}
	// random trees to depth 40, whole and mutated
	for i := 0; i < 6000; i++ {
		add("random-tree", g.tree(1+r.Intn(40)))
	}
	var trees [][]byte
	for i := 0; i < 2000; i++ {
		trees = append(trees, g.tree(1+r.Intn(40)))
	}
	for i := 0; i < 5000; i++ {
		add("mutated-tree", mutate(r, trees[r.Intn(len(trees))]))
	}
	// mutated evidence: truncated, byte-flipped, duplicate keys, trailing garbage, stray brackets, two mutations
	for i := 0; i < 9000; i++ {
		d := mutate(r, seeds[r.Intn(len(seeds))])
		if r.Intn(4) == 0 {
			d = mutate(r, d)
		}
		add("mutated-evidence", d)
	}
	// structured deep documents (depth 100-9000) in every position, and mutated
	for i := 0; i < 700; i++ {
		add("deep", deepDoc(r, seeds[r.Intn(len(seeds))]))
	}
	for i := 0; i < 200; i++ {
		add("deep-mutated", mutate(r, deepDoc(r, seeds[r.Intn(len(seeds))])))
	}
	if len(corpus) < 20000 {
		t.Fatalf("the corpus has %d documents, at least 20000 required", len(corpus))
	}

	census := map[string]int{}
	for i, raw := range corpus {
		oldTree, oldErr := oldParseStrictJSON(raw)
		newTree, newErr := parseStrictJSON(raw)
		if (oldErr == nil) != (newErr == nil) || (oldErr != nil && oldErr.Error() != newErr.Error()) {
			t.Fatalf("document %d (%d bytes): read error %v, the iterative reader says %v\n%.200s", i, len(raw), oldErr, newErr, raw)
		}
		if !reflect.DeepEqual(oldTree, newTree) {
			t.Fatalf("document %d (%d bytes): the iterative reader read another tree\n%.200s", i, len(raw), raw)
		}
		oldEv, oldDecErr := oldDecodeReplayGuardEvidence(raw)
		newEv, newDecErr := DecodeReplayGuardEvidence(raw)
		if (oldDecErr == nil) != (newDecErr == nil) || (oldDecErr != nil && !reflect.DeepEqual(oldDecErr, newDecErr)) {
			t.Fatalf("document %d (%d bytes): decode says %v, the iterative reader says %v\n%.200s", i, len(raw), oldDecErr, newDecErr, raw)
		}
		if !reflect.DeepEqual(oldEv, newEv) {
			t.Fatalf("document %d (%d bytes): decoded evidence differs\n%.200s", i, len(raw), raw)
		}
		census[outcome(newEv, newDecErr)]++
	}
	t.Logf("%d documents identical (tree, read error, decoded evidence, refusal): %v", len(corpus), class)
	t.Logf("outcomes: %v", census)
	// the corpus has teeth: every refusal the decoder names, and decoded evidence, occur many times
	for _, want := range []string{"decoded", "s6_replay_unproven/" + ReasonMalformedJSON, "s6_replay_unproven/" + ReasonUnknownField,
		"s6_replay_unproven/" + ReasonMissingField, "s6_replay_unproven/" + ReasonWrongType} {
		if census[want] < 100 {
			t.Errorf("outcome %q occurs %d times in the corpus (census %v)", want, census[want], census)
		}
	}
}
