// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay3"
)

const s6Dir3 = "testdata/s6replay3"

func s6Read3(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s6Dir3, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestS6Replay3Vectors judges every vector and mutation of the RB10-B7 set through the manifest MANIFEST pins, exactly as
// each states, and pins the statements the set exists for by name.
func TestS6Replay3Vectors(t *testing.T) {
	mraw := s6Read3(t, "manifest.json")
	if want := s6Sum(mraw) + "  manifest.json\n"; string(s6Read3(t, "MANIFEST")) != want {
		t.Fatalf("MANIFEST is not the sha256 of manifest.json (%s)", want)
	}
	var m s6Manifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Vectors) == 0 || m.MutationCount == 0 || m.MutationCount > s6replay1.MaxMutations {
		t.Fatalf("%d vectors, %d mutations", len(m.Vectors), m.MutationCount)
	}
	byName := map[string]s6replay1.Vector{}
	for _, e := range m.Vectors {
		raw := s6Read3(t, e.File)
		if s6Sum(raw) != e.Sha256 {
			t.Fatalf("%s is not the file the manifest hashes", e.File)
		}
		var v s6replay1.Vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		byName[v.Name] = v
		if got := s6replay1.Judge(v.Settlement, []byte(v.Evidence)); !reflect.DeepEqual(got, v.Expect) {
			t.Errorf("%s: judged %+v, the vector expects %+v", v.Name, got, v.Expect)
		}
	}
	// The statements this set exists for, pinned by name.
	want := map[string]string{
		"002_state_of_another_chain": "refused contract_mismatch", "003_state_of_another_contract": "refused contract_mismatch",
		"004_state_receipt_unavailable_no_contract": "stated receipt_unavailable", "005_state_unavailable_no_contract": "refused contract_mismatch",
		"006_refuted_with_verified_before": "stated slot_set_at_parent", "007_refuted_without_before": "refused proof_does_not_verify",
		"008_refuted_with_another_parent": "refused parent_header_unproven", "010_header_non_canonical_rlp": "refused proof_does_not_verify",
		"013_envelope_legacy_pre_eip155": "proven ", "014_envelope_legacy_eip155": "proven ", "015_envelope_legacy_eip155_other_chain": "refused contract_mismatch",
		"016_envelope_type1_access_list": "proven ", "018_envelope_type3_blob_canonical": "proven ", "019_envelope_type3_blob_sidecar_v0": "proven ",
		"020_envelope_type3_blob_sidecar_v1": "proven ", "021_envelope_type4_set_code": "proven ", "023_escaped_hex_proof_contract": "refused wrong_type",
		"035_escaped_hex_state_txhash": "refused wrong_type", "039_escaped_hex_order_after_schema": "refused unknown_field",
		"040_escaped_hex_order_before_version": "refused wrong_type", "041_escaped_hex_order_before_one_of": "refused wrong_type",
		"042_escaped_string_control": "proven ",
	}
	for name, w := range want {
		v, ok := byName[name]
		if !ok {
			t.Errorf("no vector %s", name)
			continue
		}
		if got := v.Expect.Result + " " + v.Expect.Reason; got != w {
			t.Errorf("%s records %q, the set states %q", name, got, w)
		}
	}
	if !byName["006_refuted_with_verified_before"].Expect.BeforeVerified {
		t.Error("the refutation with its Before does not record the Before verified")
	}

	gz := s6Read3(t, m.Mutations.File)
	if s6Sum(gz) != m.Mutations.Sha256 {
		t.Fatal("mutations.json.gz is not the file the manifest hashes")
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	mj, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if s6Sum(mj) != m.MutationsJSON {
		t.Fatal("the mutations' JSON is not what the manifest hashes")
	}
	var muts []s6replay1.Mutation
	if err := json.Unmarshal(mj, &muts); err != nil {
		t.Fatal(err)
	}
	if len(muts) != m.MutationCount {
		t.Fatalf("%d mutations, the manifest counts %d", len(muts), m.MutationCount)
	}
	for _, mu := range muts {
		base, ok := byName[mu.Base]
		if !ok {
			t.Fatalf("%s: no base vector %s", mu.Name, mu.Base)
		}
		if mu.Evidence == base.Evidence {
			t.Fatalf("%s mutates nothing", mu.Name)
		}
		if got := s6replay1.Judge(base.Settlement, []byte(mu.Evidence)); !reflect.DeepEqual(got, mu.Expect) {
			t.Errorf("%s: judged %+v, the corpus expects %+v", mu.Name, got, mu.Expect)
		}
		if strings.Contains(mu.Name, "/escape_") && (mu.Expect.Result != s6replay1.ResultRefused || mu.Expect.Reason != ethproof.ReasonWrongType) {
			t.Errorf("%s: an escaped hex value is judged %+v, not refused wrong_type", mu.Name, mu.Expect)
		}
		if mu.Expect.Result == s6replay1.ResultProven && !strings.Contains(mu.Name, "beforeUnavailable.providers") {
			t.Errorf("%s is proven: a mutation of what the verifier checks must not verify", mu.Name)
		}
	}
}

// TestS6Replay3Deterministic regenerates the set and requires it byte-identical to the committed files.
func TestS6Replay3Deterministic(t *testing.T) {
	files := s6replay3.Files()
	entries, err := os.ReadDir(s6Dir3)
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
		if !bytes.Equal(s6Read3(t, name), want) {
			t.Errorf("%s: regenerating gives other bytes (go run ./cmd/s6replayvectors -set s6replay3)", name)
		}
	}
}
