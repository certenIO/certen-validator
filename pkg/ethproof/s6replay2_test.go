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
	"github.com/certen/independant-validator/pkg/ethproof/s6replay2"
)

const s6Dir2 = "testdata/s6replay2"

func s6Read2(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s6Dir2, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestS6Replay2Vectors judges every vector and mutation of the CertenAccountV7_2 set through the manifest MANIFEST pins,
// exactly as each states, and requires V7_2 settlements proven through both entry points.
func TestS6Replay2Vectors(t *testing.T) {
	mraw := s6Read2(t, "manifest.json")
	if want := s6Sum(mraw) + "  manifest.json\n"; string(s6Read2(t, "MANIFEST")) != want {
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
	provenV72 := map[string]bool{}
	for _, e := range m.Vectors {
		raw := s6Read2(t, e.File)
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
		if v.Expect.Result == s6replay1.ResultProven {
			if len(v.Expect.Established) == 0 || !strings.Contains(v.Expect.Established[0], ethproof.AccountGenerationV7_2+" _consumedLeaf[leaf]") {
				t.Errorf("%s: a proven V7_2 vector names its generation: %v", v.Name, v.Expect.Established)
			}
			_, tx, _, _, err := s6replay1.DecodeSettlement(v.Settlement)
			if err != nil {
				t.Fatal(err)
			}
			provenV72[string(tx.Data()[:4])] = true
		}
	}
	for _, sel := range [][]byte{{0x57, 0xf8, 0x56, 0x7d}, {0xb7, 0xda, 0xa9, 0x01}} {
		if !provenV72[string(sel)] {
			t.Errorf("no vector proves a V7_2 settlement through selector %x", sel)
		}
	}
	for _, want := range []string{"005_v7_2_proof_of_a_v7_3_call", "006_v7_3_proof_of_a_v7_2_call", "010_generation_unpinned"} {
		if v, ok := byName[want]; !ok || v.Expect.Reason != ethproof.ReasonAccountGeneration {
			t.Errorf("%s is not refused as account_generation: %+v", want, v.Expect)
		}
	}
	// Every s6replay1 vector the superseded list names exists there.
	for name := range s6Replay1Superseded {
		if _, err := os.Stat(filepath.Join(s6Dir, name+".json")); err != nil {
			t.Errorf("the superseded list names %s, which s6replay1 does not hold: %v", name, err)
		}
	}

	gz := s6Read2(t, m.Mutations.File)
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
		if mu.Expect.Result == s6replay1.ResultProven && !strings.Contains(mu.Name, "beforeUnavailable.providers") {
			t.Errorf("%s is proven: a mutation of what the verifier checks must not verify", mu.Name)
		}
	}
}

// TestS6Replay2Deterministic regenerates the set and requires it byte-identical to the committed files.
func TestS6Replay2Deterministic(t *testing.T) {
	files := s6replay2.Files()
	entries, err := os.ReadDir(s6Dir2)
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
		if !bytes.Equal(s6Read2(t, name), want) {
			t.Errorf("%s: regenerating gives other bytes (go run ./cmd/s6replayvectors -set s6replay2)", name)
		}
	}
}
