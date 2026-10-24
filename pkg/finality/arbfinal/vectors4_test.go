// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// vectorDir4 is the fourth published set (RB12-OPS-A1, BETA finding B-ARB-2): which L1 header the framework header reader judges. Sets 1, 2, 3
// and the force set are untouched; nothing in this set supersedes one of their verdicts.
const vectorDir4 = "testdata/finality_arb_final4"

func TestSet4ManifestHashesEveryVectorFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir4, "MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	want, err := os.ReadFile(filepath.Join(vectorDir4, "MANIFEST.json.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(want)) != hex.EncodeToString(sum[:]) {
		t.Fatalf("MANIFEST.json hashes to %x, MANIFEST.json.sha256 says %s", sum, want)
	}
	var m struct {
		Format string            `json:"format"`
		Files  map[string]string `json:"files"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Format != "finality_arb_final4/manifest/1" {
		t.Fatalf("manifest format %q", m.Format)
	}
	if _, ok := m.Files["README.md"]; ok {
		t.Fatal("README.md must stay outside the manifest")
	}
	// 8 evidence files, 1 pins file, vectors.json: nothing else is in the directory either
	if len(m.Files) != 10 {
		t.Fatalf("manifest lists %d files, want 10", len(m.Files))
	}
	onDisk := 0
	_ = filepath.Walk(vectorDir4, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			onDisk++
		}
		return nil
	})
	if onDisk != 10+3 { // + README.md, MANIFEST.json, MANIFEST.json.sha256
		t.Fatalf("%d files on disk, want 13", onDisk)
	}
	for p, h := range m.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir4, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != h {
			t.Errorf("%s hashes to %x, manifest says %s", p, s, h)
		}
	}
	vraw, err := os.ReadFile(filepath.Join(vectorDir4, "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vf struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(vraw, &vf); err != nil || vf.Format != "finality_arb_final4/1" {
		t.Fatalf("vectors.json format %q (%v)", vf.Format, err)
	}
}

// The documented verdict of each world, written here independently of the literals of vectors.json: an odd header at K cannot be read
// by the framework reader, so K is not found (finality_block_not_covered); an odd header anywhere else is not judged and the leg is finalized.
// K is block 11999995 and the finalized head 12000000 in every world.
func TestSet4EveryVectorGivesTheDocumentedVerdict(t *testing.T) {
	f := loadSet(t, vectorDir4)
	if len(f.Vectors) != 8 {
		t.Fatalf("%d vectors, want 8", len(f.Vectors))
	}
	notCovered := `{"code":"finality_block_not_covered","fields":{"block_number":"11999995","finalized_exec_number":"12000000"}}`
	documented := map[string]string{ // vector -> "finalized" or the literal refusal
		"l1_headers_other_than_k_have_a_31_byte_transactions_root":    "finalized",
		"l1_headers_other_than_k_have_a_33_byte_receipts_root":        "finalized",
		"l1_headers_other_than_k_have_a_list_in_the_withdrawals_slot": "finalized",
		"l1_header_at_s_has_a_31_byte_transactions_root":              "finalized",
		"l1_head_has_a_31_byte_transactions_root":                     "finalized",
		"l1_header_at_k_has_a_31_byte_transactions_root":              notCovered,
		"l1_header_at_k_has_a_33_byte_receipts_root":                  notCovered,
		"l1_header_at_k_has_a_list_in_the_withdrawals_slot":           notCovered,
	}
	finalized, refused := 0, 0
	for _, v := range f.Vectors {
		want, ok := documented[v.Name]
		if !ok {
			t.Errorf("vector %s is not documented", v.Name)
			continue
		}
		got := outcome(arbfinal.New().Verify(pinsOf(t, f, v), legOf(t, v), evidenceOf(t, f, v)))
		if got != v.Expect {
			t.Errorf("%s:\n got:  %s\n want: %s", v.Name, got, v.Expect)
		}
		if want == "finalized" {
			finalized++
			if !strings.HasPrefix(got, `{"code":"finalized",`) {
				t.Errorf("%s: documented as finalized, got %s", v.Name, got)
			}
		} else {
			refused++
			if got != want {
				t.Errorf("%s: documented as %s, got %s", v.Name, want, got)
			}
		}
		if v.Group != "synthetic" {
			t.Errorf("%s: group %q", v.Name, v.Group)
		}
	}
	if finalized != 5 || refused != 3 {
		t.Fatalf("%d finalized and %d refused, want 5 and 3", finalized, refused)
	}
}

// The only state the set reaches besides finalized is a registered one with exactly its registered fields.
func TestSet4StatesConformToTheRegistry(t *testing.T) {
	reg := loadRegistry(t)
	f := loadSet(t, vectorDir4)
	for _, v := range f.Vectors {
		var st struct {
			Code   string            `json:"code"`
			Fields map[string]string `json:"fields"`
		}
		if err := json.Unmarshal([]byte(v.Expect), &st); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if st.Code == "finalized" {
			continue
		}
		r, ok := reg[st.Code]
		if !ok {
			t.Errorf("%s: code %q is not in states.json", v.Name, st.Code)
			continue
		}
		for _, req := range r.Required {
			if _, ok := st.Fields[req]; !ok {
				t.Errorf("%s: %s lacks required field %q", v.Name, st.Code, req)
			}
		}
		for k := range st.Fields {
			if !has(r.Required, k) && !has(r.Optional, k) {
				t.Errorf("%s: %s carries unregistered field %q", v.Name, st.Code, k)
			}
		}
	}
}
