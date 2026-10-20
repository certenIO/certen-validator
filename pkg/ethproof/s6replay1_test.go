// Copyright 2026 Certen Protocol

package ethproof_test

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
)

const s6Dir = "testdata/s6replay1"

// s6Replay1Superseded are the s6replay1 vectors testdata/s6replay1/SUPERSEDED.md names (RB10-F3: CertenAccountV7_2's
// layout is pinned): the expectation each file records, the verdict the code gives now, and the s6replay2 vectors that
// state what holds instead. The files are never edited.
var s6Replay1Superseded = map[string]struct {
	recorded, now s6replay1.Expect
	by            []string
	set           string // the set holding by (default s6replay2)
}{
	"029_generation_v7_2_unpinned": {
		recorded: s6replay1.Expect{Result: s6replay1.ResultRefused, State: ethproof.ReplayUnproven, Reason: ethproof.ReasonAccountGeneration, Established: []string{}},
		now:      s6replay1.Expect{Result: s6replay1.ResultRefused, State: ethproof.ReplayUnproven, Reason: ethproof.ReasonAccountGeneration, Established: []string{}},
		by:       []string{"005_v7_2_proof_of_a_v7_3_call", "001_v7_2_valid_execute"},
	},
	"047_state_unproven_account_generation": {
		recorded: s6replay1.Expect{Result: s6replay1.ResultStated, State: ethproof.ReplayUnproven, Reason: ethproof.ReasonAccountGeneration, Established: []string{}},
		now:      s6replay1.Expect{Result: s6replay1.ResultStated, State: ethproof.ReplayUnproven, Reason: ethproof.ReasonAccountGeneration, Established: []string{}},
		by:       []string{"001_v7_2_valid_execute", "002_v7_2_valid_batch"},
	},
	// RB10-B7: a refutation is stated only with its verified Before; this vector carries another world's parent.
	"049_state_refuted_slot_set_at_parent": {
		recorded: s6replay1.Expect{Result: s6replay1.ResultStated, State: ethproof.ReplayRefuted, Reason: ethproof.ReasonSlotSetAtParent, Established: []string{}},
		now:      s6replay1.Expect{Result: s6replay1.ResultRefused, State: ethproof.ReplayUnproven, Reason: ethproof.ReasonParentHeaderUnproven, Established: []string{}},
		by:       []string{"006_refuted_with_verified_before", "007_refuted_without_before", "008_refuted_with_another_parent"},
		set:      s6Dir3,
	},
}

type s6Manifest struct {
	Vectors []struct {
		File   string `json:"file"`
		Sha256 string `json:"sha256"`
	} `json:"vectors"`
	Mutations struct {
		File   string `json:"file"`
		Sha256 string `json:"sha256"`
	} `json:"mutations"`
	MutationCount int    `json:"mutationCount"`
	MutationsJSON string `json:"mutationsJsonSha256"`
}

func s6Sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func s6Read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s6Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestS6Replay1Vectors judges every vector and every mutation of the committed suite, through the manifest whose hash
// MANIFEST pins, exactly as each states.
func TestS6Replay1Vectors(t *testing.T) {
	mraw := s6Read(t, "manifest.json")
	if want := s6Sum(mraw) + "  manifest.json\n"; string(s6Read(t, "MANIFEST")) != want {
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
	seen := map[string]bool{}
	for _, e := range m.Vectors {
		raw := s6Read(t, e.File)
		if s6Sum(raw) != e.Sha256 {
			t.Fatalf("%s is not the file the manifest hashes", e.File)
		}
		var v s6replay1.Vector
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		byName[v.Name] = v
		if sup, ok := s6Replay1Superseded[v.Name]; ok {
			// A superseded vector (SUPERSEDED.md) is judged only through the list: its recorded expectation, and the
			// verdict the code gives now, both stated there.
			if !reflect.DeepEqual(v.Expect, sup.recorded) {
				t.Errorf("%s: the file records %+v, the superseded list %+v", v.Name, v.Expect, sup.recorded)
			}
			if got := s6replay1.Judge(v.Settlement, []byte(v.Evidence)); !reflect.DeepEqual(got, sup.now) {
				t.Errorf("%s (superseded): judged %+v, the superseded list states %+v now", v.Name, got, sup.now)
			}
			dir := s6Dir2
			if sup.set != "" {
				dir = sup.set
			}
			for _, by := range sup.by {
				if _, err := os.Stat(filepath.Join(dir, by+".json")); err != nil {
					t.Errorf("%s is superseded by %s %s, which is not committed: %v", v.Name, dir, by, err)
				}
			}
		} else if got := s6replay1.Judge(v.Settlement, []byte(v.Evidence)); !reflect.DeepEqual(got, v.Expect) {
			t.Errorf("%s: judged %+v, the vector expects %+v", v.Name, got, v.Expect)
		}
		seen[v.Expect.Result+" "+v.Expect.State+" "+v.Expect.Reason] = true
	}
	// Every named state and reason the verifier can reach is a vector.
	for _, want := range []string{
		"proven proven ", "stated s6_replay_unproven state_unavailable", "stated s6_event_missing no_leaf_consumed_event",
		"stated s6_replay_refuted slot_set_at_parent", "stated s6_replay_refuted slot_unset_at_block",
		"refused s6_replay_refuted slot_set_at_parent", "refused s6_replay_refuted slot_unset_at_block",
		"refused s6_event_missing no_leaf_consumed_event",
	} {
		if !seen[want] {
			t.Errorf("no vector is judged %q", want)
		}
	}
	for _, reason := range []string{ethproof.ReasonProofDoesNotVerify, ethproof.ReasonParentHeaderUnproven, ethproof.ReasonHeaderChainBroken,
		ethproof.ReasonHeaderChainTooLong, ethproof.ReasonAccountGeneration, ethproof.ReasonSlotMismatch, ethproof.ReasonContractMismatch,
		ethproof.ReasonSettlementUnproven, ethproof.ReasonSettlementNotExecuted, ethproof.ReasonBlockMismatch, ethproof.ReasonBeforeUndisclosed,
		ethproof.ReasonVersion, ethproof.ReasonEmptyEvidence, ethproof.ReasonMalformedJSON, ethproof.ReasonUnknownField,
		ethproof.ReasonMissingField, ethproof.ReasonWrongType} {
		if !seen["refused "+ethproof.ReplayUnproven+" "+reason] {
			t.Errorf("no vector is refused as s6_replay_unproven{%s}", reason)
		}
	}

	gz := s6Read(t, m.Mutations.File)
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
		// A mutation of proof bytes, a key, a slot, a contract or a block is never proven.
		if mu.Expect.Result == s6replay1.ResultProven && !strings.Contains(mu.Name, "beforeUnavailable.providers") {
			t.Errorf("%s is proven: a mutation of what the verifier checks must not verify", mu.Name)
		}
	}
}

// TestS6Replay1Deterministic regenerates the suite and requires it byte-identical to the committed files.
func TestS6Replay1Deterministic(t *testing.T) {
	files := s6replay1.Files()
	entries, err := os.ReadDir(s6Dir)
	if err != nil {
		t.Fatal(err)
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.Name() == "SPEC.md" || e.Name() == ".gitattributes" || e.Name() == "SUPERSEDED.md" {
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
		if !bytes.Equal(s6Read(t, name), want) {
			t.Errorf("%s: regenerating gives other bytes (go run ./cmd/s6replayvectors)", name)
		}
	}
}

// TestDecodeReplayGuardEvidence_Strict: the wire format is camelCase and the decoder refuses what it does not define.
func TestDecodeReplayGuardEvidence_Strict(t *testing.T) {
	w := newWorld(t, worldOpts{})
	enc, err := json.Marshal(&ethproof.ReplayGuardEvidence{Version: ethproof.ReplayGuardDomain, Proof: w.proof})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"chainId":`, `"settlementBlock":`, `"provenAt":`, `"accountProof":`, `"storageProof":`, `"parentHeader":`} {
		if !bytes.Contains(enc, []byte(key)) {
			t.Fatalf("the wire format has no %s: %s", key, enc[:120])
		}
	}
	ev, err := ethproof.DecodeReplayGuardEvidence(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Verify(w.settlement); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, from, to, reason string }{
		{"unknown field", `{"version":`, `{"extra":1,"version":`, ethproof.ReasonUnknownField},
		{"case-variant key", `"chainId":`, `"ChainId":`, ethproof.ReasonUnknownField},
		{"duplicate key", `{"version":`, `{"version":"x","version":`, ethproof.ReasonMalformedJSON},
		{"number as string", `"chainId":84532`, `"chainId":"84532"`, ethproof.ReasonWrongType},
		{"wrong version", `"certen:s6-replay:v1"`, `"certen:s6-replay:v2"`, ethproof.ReasonVersion},
	} {
		_, err := ethproof.DecodeReplayGuardEvidence(bytes.Replace(enc, []byte(c.from), []byte(c.to), 1))
		refusedAs(t, c.name, err, ethproof.ReplayUnproven, c.reason)
	}
}

// TestReplayGuard_AbsentAccountDeclaresZeroHashes: an exclusion proof that declares a storage or code hash is refused.
func TestReplayGuard_AbsentAccountDeclaresZeroHashes(t *testing.T) {
	w := newWorld(t, worldOpts{noBeforeAcc: true})
	p := w.clone()
	p.Before.Proof.CodeHash[0] ^= 1
	_, err := p.Verify(w.settlement)
	refusedAs(t, "absent account with a code hash", err, ethproof.ReplayUnproven, ethproof.ReasonProofDoesNotVerify)
}
