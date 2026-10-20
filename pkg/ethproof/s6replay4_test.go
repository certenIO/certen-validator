// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay4"
)

const s6Dir4 = "testdata/s6replay4"

func s6Read4(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s6Dir4, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type s6Manifest4 struct {
	Domain              string            `json:"domain"`
	Generator           string            `json:"generator"`
	JSONMaxNestingDepth int               `json:"jsonMaxNestingDepth"`
	Vectors             []s6replay4.Entry `json:"vectors"`
}

// s6Want4 is what the set states, by vector: Go's verdict on every deep document. Depth never decides it.
var s6Want4 = map[string]string{
	"001_valid_vector_001_itself":             "proven ",
	"002_unknown_field_arrays_5000":           "refused unknown_field",
	"003_unknown_field_arrays_9999":           "refused unknown_field",
	"004_unknown_field_arrays_10000":          "refused unknown_field",
	"005_unknown_field_arrays_10001":          "refused unknown_field",
	"006_unknown_field_arrays_20000":          "refused unknown_field",
	"007_headers_arrays_5000":                 "refused wrong_type",
	"008_headers_arrays_9999":                 "refused wrong_type",
	"009_headers_arrays_10000":                "refused wrong_type",
	"010_headers_arrays_10001":                "refused wrong_type",
	"011_headers_arrays_20000":                "refused wrong_type",
	"012_unknown_field_objects_5000":          "refused unknown_field",
	"013_unknown_field_objects_9999":          "refused unknown_field",
	"014_unknown_field_objects_10000":         "refused unknown_field",
	"015_unknown_field_objects_10001":         "refused unknown_field",
	"016_unknown_field_objects_20000":         "refused unknown_field",
	"017_object_duplicate_key_at_depth_10001": "refused malformed_json",
	"018_deep_then_duplicate_version_5000":    "refused malformed_json",
	"019_deep_then_duplicate_version_10001":   "refused malformed_json",
	"020_deep_then_duplicate_version_20000":   "refused malformed_json",
	"021_generation_arrays_10001":             "refused wrong_type",
	"022_generation_arrays_20000":             "refused wrong_type",
	"023_chainid_arrays_10001":                "refused wrong_type",
	"024_version_arrays_10001":                "refused wrong_type",
	"025_state_valid":                         "stated state_unavailable",
	"026_state_unknown_field_arrays_10001":    "refused unknown_field",
	"027_state_unknown_field_arrays_20000":    "refused unknown_field",
	"028_state_reason_arrays_10001":           "refused wrong_type",
	"029_top_level_arrays_10001":              "refused wrong_type",
	"030_truncated_arrays_10001":              "refused malformed_json",
}

// TestS6Replay4Vectors judges every vector of the RB10-B9 set through the manifest MANIFEST pins, exactly as each states:
// the evidence file is the manifest's recipe, byte for byte, and Go's verdict on it is the recorded one; the depth claims
// of SPEC.md are checked against encoding/json itself.
func TestS6Replay4Vectors(t *testing.T) {
	mraw := s6Read4(t, "manifest.json")
	if want := s6Sum(mraw) + "  manifest.json\n"; string(s6Read4(t, "MANIFEST")) != want {
		t.Fatalf("MANIFEST is not the sha256 of manifest.json (%s)", want)
	}
	var m s6Manifest4
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Generator != s6replay4.Generator || m.Domain != ethproof.ReplayGuardDomain || m.JSONMaxNestingDepth != 10000 {
		t.Fatalf("manifest header %+v", m)
	}
	if len(m.Vectors) != len(s6Want4) {
		t.Fatalf("%d vectors, the set states %d", len(m.Vectors), len(s6Want4))
	}
	var v1 s6replay1.Vector
	if err := json.Unmarshal(s6Read(t, "001_valid_at_settlement_block.json"), &v1); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	deepRefused := 0
	for _, e := range m.Vectors {
		raw := s6Read4(t, e.File)
		if s6Sum(raw) != e.Sha256 {
			t.Fatalf("%s is not the file the manifest hashes", e.File)
		}
		var v s6replay4.Vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v.Name+".json" != e.File || v.EvidenceFile != e.EvidenceFile || seen[v.Name] {
			t.Fatalf("%s: the vector and its manifest entry name different files", e.File)
		}
		seen[v.Name] = true
		// The evidence file: gzip of the evidence bytes, which are what the manifest hashes and the recipe rebuilds.
		gzb := s6Read4(t, v.EvidenceFile)
		if s6Sum(gzb) != e.EvidenceGzSha {
			t.Fatalf("%s is not the file the manifest hashes", v.EvidenceFile)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gzb))
		if err != nil {
			t.Fatal(err)
		}
		ev, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		if s6Sum(ev) != e.EvidenceSha256 || len(ev) != e.EvidenceLength {
			t.Fatalf("%s: the evidence is not what the manifest hashes (%d bytes)", v.Name, len(ev))
		}
		if !bytes.Equal(e.Recipe.Bytes(), ev) {
			t.Errorf("%s: the manifest's recipe does not rebuild the evidence bytes", v.Name)
		}
		if !reflect.DeepEqual(v.Settlement, v1.Settlement) {
			t.Errorf("%s: the settlement is not s6replay1 vector 001's", v.Name)
		}
		// Go's verdict is the recorded one.
		if got := s6replay1.Judge(v.Settlement, ev); !reflect.DeepEqual(got, v.Expect) {
			t.Errorf("%s: judged %+v, the vector expects %+v", v.Name, got, v.Expect)
		}
		if w, ok := s6Want4[v.Name]; !ok || w != v.Expect.Result+" "+v.Expect.Reason {
			t.Errorf("%s records %q, the set states %q", v.Name, v.Expect.Result+" "+v.Expect.Reason, w)
		}
		// Depth: the manifest's maxDepth is the nesting of the bytes; json.Unmarshal's scanner refuses exactly what is
		// deeper than 10000 (and an unterminated document), while Go's strict decoder judged the same bytes by schema.
		depth := s6replay4.MaxDepth(ev)
		if depth != e.MaxDepth {
			t.Errorf("%s: nesting depth %d, the manifest states %d", v.Name, depth, e.MaxDepth)
		}
		unmarshalErr := json.Unmarshal(ev, &struct{}{})
		wantErr := depth > 10000 || strings.Contains(v.Name, "truncated")
		if (unmarshalErr != nil) != wantErr {
			t.Errorf("%s: depth %d, json.Unmarshal says %v", v.Name, depth, unmarshalErr)
		}
		if depth > 10000 && !strings.Contains(v.Name, "truncated") {
			deepRefused++
			// The refusal is the schema check's (its detail names a $ path), not json.Unmarshal's depth error.
			_, err := ethproof.DecodeReplayGuardEvidence(ev)
			var re *ethproof.ReplayError
			switch {
			case v.Expect.Reason == ethproof.ReasonMalformedJSON:
				// duplicate key, found by the document read before any schema check
			case !errors.As(err, &re) || !strings.HasPrefix(re.Detail, "$"):
				t.Errorf("%s: a document deeper than 10000 is refused by %v, not by the schema check", v.Name, err)
			}
		}
		if (e.Recipe.Count > 0) == (e.Recipe.Open == "") {
			t.Errorf("%s: recipe count %d with open %q", v.Name, e.Recipe.Count, e.Recipe.Open)
		}
	}
	if deepRefused < 20 {
		t.Errorf("%d vectors deeper than json.Unmarshal's limit", deepRefused)
	}
	// Vector 001 is s6replay1 vector 001's evidence, byte for byte.
	if got := s6replay4.BuildCases()[0].Evidence; string(got) != v1.Evidence {
		t.Error("vector 001 is not s6replay1 vector 001's evidence")
	}
}

// TestS6Replay4SchemaValidIsShallow pins the other half of the depth statement: the deepest schema-valid evidence in every
// committed set (a proof or named state that is proven or stated) nests five containers, far under json.Unmarshal's 10000,
// so the limit cannot be reached after the schema check.
func TestS6Replay4SchemaValidIsShallow(t *testing.T) {
	deepest, valid := 0, 0
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
			var v s6replay1.Vector
			if err := json.Unmarshal(raw, &v); err != nil || v.Name == "" {
				continue // manifest.json
			}
			if v.Expect.Result != s6replay1.ResultProven && v.Expect.Result != s6replay1.ResultStated {
				continue
			}
			valid++
			if d := s6replay4.MaxDepth([]byte(v.Evidence)); d > deepest {
				deepest = d
			}
		}
	}
	if valid < 25 || deepest != 5 {
		t.Fatalf("%d schema-valid vectors, deepest nesting %d (the set states 5)", valid, deepest)
	}
}

// TestS6Replay4Deterministic regenerates the set and requires it byte-identical to the committed files, and twice in a
// row identical to itself.
func TestS6Replay4Deterministic(t *testing.T) {
	files := s6replay4.Files()
	again := s6replay4.Files()
	if len(files) != len(again) {
		t.Fatalf("two runs generate %d and %d files", len(files), len(again))
	}
	for name, b := range files {
		if !bytes.Equal(b, again[name]) {
			t.Errorf("%s: two runs generate other bytes", name)
		}
	}
	entries, err := os.ReadDir(s6Dir4)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.Name() == "SPEC.md" || e.Name() == ".gitattributes" {
			continue
		}
		onDisk[e.Name()] = true
		if _, ok := files[e.Name()]; !ok {
			t.Errorf("%s is committed but not generated", e.Name())
		}
	}
	for name, want := range files {
		if !onDisk[name] {
			t.Errorf("%s is generated but not committed", name)
			continue
		}
		if !bytes.Equal(s6Read4(t, name), want) {
			t.Errorf("%s: regenerating gives other bytes (go run ./cmd/s6replayvectors -set s6replay4)", name)
		}
	}
}
