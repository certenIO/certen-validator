// Copyright 2026 Certen Protocol

// Package s6replay4 is the fourth conformance set of the S6 replay-guard evidence (the same wire format and domain tag,
// certen:s6-replay:v1), written by RB10-B9 from review V-R10C2: it pins what Go's strict decoder does with a deeply
// nested JSON document. Go reads the document with json.Decoder.Token() (no depth limit), then checks the schema; the
// 10000-container limit belongs to json.Unmarshal, which sees only documents that passed the schema, so a deep document
// is refused by the schema check (unknown_field, wrong_type) or the duplicate-key / syntax check (malformed_json), never
// by a depth limit. The set records what Go does; it changes no verdict. `go run ./cmd/s6replayvectors -set s6replay4`
// writes it to pkg/ethproof/testdata/s6replay4; the TypeScript verifier consumes byte-identical copies.
//
// Each vector's evidence is stored gzipped (a deep document is ~2N bytes of brackets) and is also given as a recipe in
// manifest.json: evidence = prefix + open x count + core + close x count + suffix (SPEC.md §2).
package s6replay4

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
)

// Generator is the command line that writes this set.
const Generator = "cmd/s6replayvectors -set s6replay4"

// JSONMaxNestingDepth is encoding/json's scanner limit (maxNestingDepth in go1.25), applied by json.Unmarshal and
// json.Valid but not by json.Decoder.Token.
const JSONMaxNestingDepth = 10000

// Recipe rebuilds a vector's evidence: Prefix, then Open repeated Count times, Core, Close repeated Count times, Suffix.
type Recipe struct {
	Prefix string `json:"prefix"`
	Open   string `json:"open"`
	Core   string `json:"core"`
	Close  string `json:"close"`
	Count  int    `json:"count"`
	Suffix string `json:"suffix"`
}

// Bytes is the evidence the recipe describes.
func (r Recipe) Bytes() []byte {
	var b strings.Builder
	b.WriteString(r.Prefix)
	b.WriteString(strings.Repeat(r.Open, r.Count))
	b.WriteString(r.Core)
	b.WriteString(strings.Repeat(r.Close, r.Count))
	b.WriteString(r.Suffix)
	return []byte(b.String())
}

// Vector is one vector file: the settlement, the file holding the evidence (gzip), and Go's verdict.
type Vector struct {
	Name         string               `json:"name"`
	Description  string               `json:"description"`
	Settlement   s6replay1.Settlement `json:"settlement"`
	EvidenceFile string               `json:"evidenceFile"`
	Expect       s6replay1.Expect     `json:"expect"`
}

// Entry is a vector's line in manifest.json.
type Entry struct {
	File           string `json:"file"`
	Sha256         string `json:"sha256"`
	EvidenceFile   string `json:"evidenceFile"`
	EvidenceGzSha  string `json:"evidenceGzSha256"`
	EvidenceSha256 string `json:"evidenceSha256"`
	EvidenceLength int    `json:"evidenceLength"`
	MaxDepth       int    `json:"maxDepth"`
	Recipe         Recipe `json:"recipe"`
}

// Case is a vector with its evidence bytes and recipe.
type Case struct {
	Vector   Vector
	Evidence []byte
	Recipe   Recipe
}

// MaxDepth is the deepest nesting of containers ({ and [ outside strings) in a JSON text.
func MaxDepth(raw []byte) int {
	depth, max := 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			depth--
		}
	}
	return max
}

// panicTB is the builder's TB outside a test.
type panicTB struct{}

func (panicTB) Helper()                   {}
func (panicTB) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

// DepthsAroundTheLimit are the nesting counts of the arrays vectors: below, at (the object plus 9999 arrays is depth
// 10000), and above json.Unmarshal's limit.
var DepthsAroundTheLimit = []int{5000, 9999, 10000, 10001, 20000}

const head = `{"version":"certen:s6-replay:v1","zzz":`

type builder struct {
	cases []Case
	s     s6replay1.Settlement
}

func (b *builder) add(name, desc string, r Recipe) {
	ev := r.Bytes()
	n := fmt.Sprintf("%03d_%s", len(b.cases)+1, name)
	b.cases = append(b.cases, Case{
		Vector:   Vector{Name: n, Description: desc, Settlement: b.s, EvidenceFile: n + ".evidence.gz", Expect: s6replay1.Judge(b.s, ev)},
		Evidence: ev, Recipe: r})
}

// splice returns the evidence cut at the single occurrence of at: prefix (through at) and suffix (after the replaced text).
func splice(evidence, at, replaced string) (prefix, suffix string) {
	if strings.Count(evidence, at+replaced) != 1 {
		panic(fmt.Sprintf("s6replay4: %q is not exactly once in the base evidence", at+replaced))
	}
	i := strings.Index(evidence, at+replaced)
	return evidence[:i+len(at)], evidence[i+len(at)+len(replaced):]
}

// BuildCases builds every vector with its evidence, in order. The settlement is s6replay1's vector 001 (the base world).
func BuildCases() []Case {
	tb := panicTB{}
	base := replayworld.New(tb, replayworld.Opts{})
	b := &builder{s: s6replay1.SettlementOf(base)}
	evBase := string(s6replay1.ProofEvidence(base.Proof))
	st := &ethproof.ReplayNamedState{State: ethproof.ReplayUnproven, Reason: ethproof.ReasonStateUnavailable, ChainID: replayworld.ChainID,
		TxHash: base.Tx.Hash(), BlockNumber: replayworld.N, BlockHash: base.HeaderN.Hash(), Contract: base.Contract}
	evState := string(s6replay1.StateEvidence(st))
	arr := func(prefix, suffix string, n int) Recipe {
		return Recipe{Prefix: prefix, Open: "[", Close: "]", Count: n, Suffix: suffix}
	}
	obj := func(prefix, suffix string, n int) Recipe {
		return Recipe{Prefix: prefix, Open: `{"a":`, Core: "0", Close: "}", Count: n, Suffix: suffix}
	}

	// (f) the schema-valid document itself.
	b.add("valid_vector_001_itself", "s6replay1 vector 001's evidence, byte for byte: a schema-valid document (depth 4) is still proven",
		Recipe{Prefix: evBase})

	// (a) an unknown field holding N nested arrays: Go reads the whole document, then refuses the unknown field.
	for _, n := range DepthsAroundTheLimit {
		b.add(fmt.Sprintf("unknown_field_arrays_%d", n),
			fmt.Sprintf("an unknown field holding %d nested arrays (document depth %d): refused unknown_field by the schema check, at any depth", n, n+1),
			arr(head, "}", n))
	}
	// (b) headers replaced by N nested arrays: the first element of headers is not a string.
	hp, hs := splice(evBase, `"headers":`, `[]`)
	for _, n := range DepthsAroundTheLimit {
		b.add(fmt.Sprintf("headers_arrays_%d", n),
			fmt.Sprintf("headers replaced by %d nested arrays (depth %d): refused wrong_type at headers[0]", n, n+2),
			arr(hp, hs, n))
	}
	// (c) objects instead of arrays.
	for _, n := range DepthsAroundTheLimit {
		b.add(fmt.Sprintf("unknown_field_objects_%d", n),
			fmt.Sprintf("an unknown field holding %d nested objects {\"a\":{\"a\":...0}} (document depth %d): refused unknown_field", n, n+1),
			obj(head, "}", n))
	}
	b.add("object_duplicate_key_at_depth_10001", "10001 nested objects whose innermost object repeats its key \"a\": refused malformed_json (duplicate key)",
		Recipe{Prefix: head, Open: `{"a":`, Core: `0,"a":0`, Close: "}", Count: 10001, Suffix: "}"})
	// (d) a deep unknown field, then a duplicate key of the document's first object.
	for _, n := range []int{5000, 10001, 20000} {
		b.add(fmt.Sprintf("deep_then_duplicate_version_%d", n),
			fmt.Sprintf("an unknown field holding %d nested arrays followed by a second \"version\" key: refused malformed_json (duplicate key, found at any depth before the schema check)", n),
			arr(head, `,"version":"certen:s6-replay:v1"}`, n))
	}
	// (e) deep nesting where a string- or integer-typed field of the valid document belongs.
	gp, gs := splice(evBase, `"generation":`, `"CertenAccountV7_3"`)
	for _, n := range []int{10001, 20000} {
		b.add(fmt.Sprintf("generation_arrays_%d", n),
			fmt.Sprintf("the proof's string-typed generation replaced by %d nested arrays, the document valid up to it: refused wrong_type", n), arr(gp, gs, n))
	}
	cp, cs := splice(evBase, `"chainId":`, fmt.Sprint(replayworld.ChainID))
	b.add("chainid_arrays_10001", "the proof's integer-typed chainId replaced by 10001 nested arrays: refused wrong_type", arr(cp, cs, 10001))
	const verText = `{"version":"certen:s6-replay:v1"`
	if !strings.HasPrefix(evBase, verText) {
		panic("s6replay4: the base evidence does not start with its version")
	}
	b.add("version_arrays_10001", "the evidence's string-typed version replaced by 10001 nested arrays: refused wrong_type",
		arr(`{"version":`, evBase[len(verText):], 10001))
	// (g) named-state evidence.
	b.add("state_valid", "a schema-valid named state (state_unavailable of the settlement's chain and contract) is still stated", Recipe{Prefix: evState})
	sp, ss := splice(evState, `"state":{`, `"state":"s6_replay_unproven"`)
	for _, n := range []int{10001, 20000} {
		b.add(fmt.Sprintf("state_unknown_field_arrays_%d", n),
			fmt.Sprintf("a named state with an unknown field holding %d nested arrays: refused unknown_field at $.state.zzz", n),
			arr(sp+`"zzz":`, `,"state":"s6_replay_unproven"`+ss, n))
	}
	rp, rs := splice(evState, `"reason":`, `"state_unavailable"`)
	b.add("state_reason_arrays_10001", "a named state whose string-typed reason is 10001 nested arrays: refused wrong_type", arr(rp, rs, 10001))
	// Documents that are not an object, and one that ends inside the nesting.
	b.add("top_level_arrays_10001", "the whole document is 10001 nested arrays: parsed, then refused wrong_type (the document is not an object)", arr("", "", 10001))
	b.add("truncated_arrays_10001", "an unknown field holding 10001 opened and never closed arrays: refused malformed_json (end of input inside the value)",
		Recipe{Prefix: head, Open: "[", Count: 10001})
	return b.cases
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func gz(b []byte) []byte {
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err := zw.Write(b); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

// Files are the set's files by name: per vector its JSON and its gzipped evidence, then manifest.json and MANIFEST.
func Files() map[string][]byte {
	files := map[string][]byte{}
	manifest := struct {
		Domain              string  `json:"domain"`
		Generator           string  `json:"generator"`
		Spec                string  `json:"spec"`
		JSONMaxNestingDepth int     `json:"jsonMaxNestingDepth"`
		Vectors             []Entry `json:"vectors"`
	}{Domain: ethproof.ReplayGuardDomain, Generator: Generator, Spec: "SPEC.md", JSONMaxNestingDepth: JSONMaxNestingDepth}
	for _, c := range BuildCases() {
		enc, err := json.MarshalIndent(c.Vector, "", "  ")
		if err != nil {
			panic(err)
		}
		enc = append(enc, '\n')
		name := c.Vector.Name + ".json"
		gzb := gz(c.Evidence)
		files[name] = enc
		files[c.Vector.EvidenceFile] = gzb
		manifest.Vectors = append(manifest.Vectors, Entry{File: name, Sha256: sum(enc), EvidenceFile: c.Vector.EvidenceFile,
			EvidenceGzSha: sum(gzb), EvidenceSha256: sum(c.Evidence), EvidenceLength: len(c.Evidence), MaxDepth: MaxDepth(c.Evidence), Recipe: c.Recipe})
	}
	var mb bytes.Buffer
	enc := json.NewEncoder(&mb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		panic(err)
	}
	files["manifest.json"] = mb.Bytes()
	files["MANIFEST"] = []byte(sum(mb.Bytes()) + "  manifest.json\n")
	return files
}
