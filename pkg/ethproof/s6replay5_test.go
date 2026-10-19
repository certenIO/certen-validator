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
	"github.com/certen/independant-validator/pkg/ethproof/s6replay5"
)

const s6Dir5 = "testdata/s6replay5"

func s6Read5(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s6Dir5, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type s6Manifest5 struct {
	Domain           string            `json:"domain"`
	Generator        string            `json:"generator"`
	MaxEvidenceBytes int               `json:"maxEvidenceBytes"`
	Vectors          []s6replay5.Entry `json:"vectors"`
}

// s6Want5 is what the set states, by vector: the size bound decides by length alone.
var s6Want5 = map[string]string{
	"001_valid_vector_001_itself":  "proven ",
	"002_padded_cap_minus_1":       "refused unknown_field",
	"003_padded_cap":               "refused unknown_field",
	"004_padded_cap_plus_1":        "refused evidence_too_large",
	"005_arrays_closed_cap":        "refused unknown_field",
	"006_arrays_closed_cap_plus_1": "refused evidence_too_large",
	"007_arrays_open_cap_plus_1":   "refused evidence_too_large",
	"008_arrays_six_million":       "refused evidence_too_large",
	"009_whitespace_cap":           "refused malformed_json",
	"010_whitespace_cap_plus_1":    "refused evidence_too_large",
}

// TestS6Replay5Vectors judges every vector of the RB10-B12 set through the manifest MANIFEST pins, exactly as each states:
// the evidence file is the manifest's recipe, byte for byte, Go's verdict on it is the recorded one, and the size bound
// is exact (every document of at most the cap is read, every longer one is refused evidence_too_large, whatever it is).
func TestS6Replay5Vectors(t *testing.T) {
	mraw := s6Read5(t, "manifest.json")
	if want := s6Sum(mraw) + "  manifest.json\n"; string(s6Read5(t, "MANIFEST")) != want {
		t.Fatalf("MANIFEST is not the sha256 of manifest.json (%s)", want)
	}
	var m s6Manifest5
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	// The set's cap, the package constant and the number the SPEC states are one value: a compile-time check, so the
	// comparisons below are against a single number.
	const _ = uint(s6replay5.Cap-ethproof.MaxReplayEvidenceBytes) + uint(ethproof.MaxReplayEvidenceBytes-s6replay5.Cap)
	if m.Generator != s6replay5.Generator || m.Domain != ethproof.ReplayGuardDomain {
		t.Fatalf("manifest header %+v", m)
	}
	if m.MaxEvidenceBytes != s6replay5.Cap {
		t.Fatalf("manifest maxEvidenceBytes %d, the set pins %d", m.MaxEvidenceBytes, s6replay5.Cap)
	}
	if len(m.Vectors) != len(s6Want5) {
		t.Fatalf("%d vectors, the set states %d", len(m.Vectors), len(s6Want5))
	}
	var v1 s6replay1.Vector
	if err := json.Unmarshal(s6Read(t, "001_valid_at_settlement_block.json"), &v1); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	total, tooLarge := 0, 0
	for _, e := range m.Vectors {
		raw := s6Read5(t, e.File)
		total += len(raw)
		if s6Sum(raw) != e.Sha256 {
			t.Fatalf("%s is not the file the manifest hashes", e.File)
		}
		var v s6replay5.Vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v.Name+".json" != e.File || v.EvidenceFile != e.EvidenceFile || seen[v.Name] {
			t.Fatalf("%s: the vector and its manifest entry name different files", e.File)
		}
		seen[v.Name] = true
		gzb := s6Read5(t, v.EvidenceFile)
		total += len(gzb)
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
		if got := s6replay1.Judge(v.Settlement, ev); !reflect.DeepEqual(got, v.Expect) {
			t.Errorf("%s: judged %+v, the vector expects %+v", v.Name, got, v.Expect)
		}
		if w, ok := s6Want5[v.Name]; !ok || w != v.Expect.Result+" "+v.Expect.Reason {
			t.Errorf("%s records %q, the set states %q", v.Name, v.Expect.Result+" "+v.Expect.Reason, w)
		}
		// The bound is exact and decides by length alone.
		if big := len(ev) > ethproof.MaxReplayEvidenceBytes; big != (v.Expect.Reason == ethproof.ReasonEvidenceTooLarge) {
			t.Errorf("%s: %d bytes, the cap is %d, and the vector says %q", v.Name, len(ev), ethproof.MaxReplayEvidenceBytes, v.Expect.Reason)
		} else if big {
			tooLarge++
		}
		if (e.Recipe.Count > 0) == (e.Recipe.Open == "") {
			t.Errorf("%s: recipe count %d with open %q", v.Name, e.Recipe.Count, e.Recipe.Open)
		}
	}
	if tooLarge != 5 {
		t.Errorf("%d vectors over the cap, the set states 5", tooLarge)
	}
	if total > 150*1024 {
		t.Errorf("the set's vector and evidence files are %d bytes, at most 150 KB", total)
	}
	// Vector 001 is s6replay1 vector 001's evidence, byte for byte.
	if got := s6replay5.BuildCases()[0].Evidence; string(got) != v1.Evidence {
		t.Error("vector 001 is not s6replay1 vector 001's evidence")
	}
}

// TestReplayEvidenceCapIsExact: DecodeReplayGuardEvidence reads a document of exactly MaxReplayEvidenceBytes and refuses
// one byte more, before parsing it; the refusal's detail names the length; and the boundary holds for a document that is
// not even JSON (the length is judged first, so it is never malformed_json).
func TestReplayEvidenceCapIsExact(t *testing.T) {
	if ethproof.MaxReplayEvidenceBytes != 4194304 || ethproof.ReasonEvidenceTooLarge != "evidence_too_large" {
		t.Fatalf("cap %d reason %q", ethproof.MaxReplayEvidenceBytes, ethproof.ReasonEvidenceTooLarge)
	}
	for _, filler := range []string{" ", "x", "[", "\x00"} {
		for _, c := range []struct {
			n      int
			reason string
		}{
			{ethproof.MaxReplayEvidenceBytes - 1, ethproof.ReasonMalformedJSON},
			{ethproof.MaxReplayEvidenceBytes, ethproof.ReasonMalformedJSON},
			{ethproof.MaxReplayEvidenceBytes + 1, ethproof.ReasonEvidenceTooLarge},
			{ethproof.MaxReplayEvidenceBytes * 2, ethproof.ReasonEvidenceTooLarge},
		} {
			_, err := ethproof.DecodeReplayGuardEvidence([]byte(strings.Repeat(filler, c.n)))
			var re *ethproof.ReplayError
			if !errors.As(err, &re) || re.State != ethproof.ReplayUnproven || re.Reason != c.reason {
				t.Errorf("%q x %d: %v, want s6_replay_unproven{%s}", filler, c.n, err, c.reason)
			}
		}
	}
	// The error for a document over the cap names its length and the cap.
	_, err := ethproof.DecodeReplayGuardEvidence(make([]byte, ethproof.MaxReplayEvidenceBytes+1))
	var re *ethproof.ReplayError
	if !errors.As(err, &re) || !strings.Contains(re.Detail, "4194305 bytes") || !strings.Contains(re.Detail, "4194304") {
		t.Errorf("detail %v", err)
	}
}

// TestS6Replay5Deterministic regenerates the set and requires it byte-identical to the committed files, and twice in a
// row identical to itself.
func TestS6Replay5Deterministic(t *testing.T) {
	files := s6replay5.Files()
	again := s6replay5.Files()
	if len(files) != len(again) {
		t.Fatalf("two runs generate %d and %d files", len(files), len(again))
	}
	for name, b := range files {
		if !bytes.Equal(b, again[name]) {
			t.Errorf("%s: two runs generate other bytes", name)
		}
	}
	entries, err := os.ReadDir(s6Dir5)
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
		if !bytes.Equal(s6Read5(t, name), want) {
			t.Errorf("%s: regenerating gives other bytes (go run ./cmd/s6replayvectors -set s6replay5)", name)
		}
	}
}
