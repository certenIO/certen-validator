// Copyright 2026 Certen Protocol

// Package s6replay5 is the fifth conformance set of the S6 replay-guard evidence (the same wire format and domain tag,
// certen:s6-replay:v1), written by RB10-B12 from review V-R10C3: it pins the size bound of the evidence document. The
// strict reader has no depth limit (s6replay4), so its memory is bounded only by its input; honest evidence is under
// 1 MiB, and DecodeReplayGuardEvidence refuses a document longer than MaxReplayEvidenceBytes (4 MiB) as
// s6_replay_unproven{evidence_too_large} before it reads a byte. The set pins the boundary exactly (4194304 bytes are
// read, 4194305 are refused) and the documents a hostile producer would send. It changes no verdict of a document of at
// most 4 MiB, so s6replay1-4 stay byte-identical. `go run ./cmd/s6replayvectors -set s6replay5` writes it to
// pkg/ethproof/testdata/s6replay5; the TypeScript verifier consumes byte-identical copies.
//
// Each vector's evidence is stored gzipped and is also given as a recipe in manifest.json (the s6replay4 recipe):
// evidence = prefix + open x count + core + close x count + suffix (SPEC.md §2).
package s6replay5

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
	"github.com/certen/independant-validator/pkg/ethproof/s6replay4"
)

// Generator is the command line that writes this set.
const Generator = "cmd/s6replayvectors -set s6replay5"

// Cap is the size bound the set pins: 4 MiB, ethproof.MaxReplayEvidenceBytes (a test requires them equal). It is a
// literal here so that the set states the number it is about.
const Cap = 4194304

// Recipe, Vector, Entry and MaxDepth are s6replay4's: the same files, the same recipe.
type (
	Recipe = s6replay4.Recipe
	Vector = s6replay4.Vector
	Entry  = s6replay4.Entry
)

// Case is a vector with its evidence bytes and recipe.
type Case struct {
	Vector   Vector
	Evidence []byte
	Recipe   Recipe
}

type panicTB struct{}

func (panicTB) Helper()                   {}
func (panicTB) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

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

// BuildCases builds every vector with its evidence, in order. The settlement is s6replay1's vector 001 (the base world).
func BuildCases() []Case {
	tb := panicTB{}
	base := replayworld.New(tb, replayworld.Opts{})
	b := &builder{s: s6replay1.SettlementOf(base)}
	evBase := string(s6replay1.ProofEvidence(base.Proof))
	if !strings.HasPrefix(evBase, "{") {
		panic("s6replay5: the base evidence is not an object")
	}

	// padded: vector 001's evidence with an unknown first key holding a string of 'a' of the length that makes the whole
	// document n bytes. The document is valid JSON; it is refused unknown_field when read, evidence_too_large when longer
	// than the cap.
	padPrefix, padSuffix := `{"zzz":"`, `",`+evBase[1:]
	padded := func(n int) Recipe {
		return Recipe{Prefix: padPrefix, Open: "a", Count: n - len(padPrefix) - len(padSuffix), Suffix: padSuffix}
	}
	// closed arrays: an unknown field holding as many nested arrays as fit in n bytes, the remainder (0 or 1) as a space
	// after the closing brace.
	closed := func(n int) Recipe {
		k := (n - len(head) - 1) / 2
		return Recipe{Prefix: head, Open: "[", Close: "]", Count: k, Suffix: "}" + strings.Repeat(" ", n-len(head)-1-2*k)}
	}

	b.add("valid_vector_001_itself", fmt.Sprintf("s6replay1 vector 001's evidence, byte for byte (%d bytes): the bound changes nothing for it", len(evBase)), Recipe{Prefix: evBase})
	b.add("padded_cap_minus_1", "vector 001's evidence behind an unknown first key holding a string, the document 4194303 bytes: read, refused unknown_field",
		padded(Cap-1))
	b.add("padded_cap", "the same, the document exactly 4194304 bytes (the cap): read, refused unknown_field", padded(Cap))
	b.add("padded_cap_plus_1", "the same, the document 4194305 bytes: refused evidence_too_large without being read", padded(Cap+1))
	b.add("arrays_closed_cap", "an unknown field holding as many nested arrays as fit, the document exactly 4194304 bytes (about 2.1 million levels deep): "+
		"read to the end, refused unknown_field", closed(Cap))
	b.add("arrays_closed_cap_plus_1", "the same, 4194305 bytes: refused evidence_too_large without being read", closed(Cap+1))
	b.add("arrays_open_cap_plus_1", "an unknown field holding nested arrays opened and never closed, 4194305 bytes: refused evidence_too_large, "+
		"not malformed_json (it is not read)", Recipe{Prefix: head, Open: "[", Count: Cap + 1 - len(head)})
	b.add("arrays_six_million", fmt.Sprintf("an unknown field holding 6000000 nested arrays, closed (%d bytes): refused evidence_too_large "+
		"(the document that killed the recursive reader at 6000000 levels)", len(head)+2*6_000_000+1), Recipe{Prefix: head, Open: "[", Close: "]", Count: 6_000_000, Suffix: "}"})
	b.add("whitespace_cap", "4194304 spaces: read, refused malformed_json (the input ends before a value)", Recipe{Open: " ", Count: Cap})
	b.add("whitespace_cap_plus_1", "4194305 spaces: refused evidence_too_large", Recipe{Open: " ", Count: Cap + 1})
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
		Domain           string  `json:"domain"`
		Generator        string  `json:"generator"`
		Spec             string  `json:"spec"`
		MaxEvidenceBytes int     `json:"maxEvidenceBytes"`
		Vectors          []Entry `json:"vectors"`
	}{Domain: ethproof.ReplayGuardDomain, Generator: Generator, Spec: "SPEC.md", MaxEvidenceBytes: Cap}
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
			EvidenceGzSha: sum(gzb), EvidenceSha256: sum(c.Evidence), EvidenceLength: len(c.Evidence), MaxDepth: s6replay4.MaxDepth(c.Evidence),
			Recipe: c.Recipe})
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
