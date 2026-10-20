// Copyright 2026 Certen Protocol

package finality

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- helpers shared by the package tests ----

func fill(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func mustHex32(t testing.TB, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("not 32 bytes of hex: %q", s)
	}
	return [32]byte(raw)
}

func stateOf(t testing.TB, err error) *StateError {
	t.Helper()
	st, ok := AsNamed(err)
	if !ok {
		t.Fatalf("not a named state: %v", err)
	}
	return st
}

// testBase is the Base Sepolia leg the package tests chain addenda to.
func testBase() BlockRef {
	return BlockRef{Chain: ChainBaseSepolia, Number: 47368146, Hash: fill(0x33)}
}

func containerFor(t testing.TB, kind string, b BlockRef, level Level, body string) []byte {
	t.Helper()
	enc, err := Container{Header: ContainerHeader{Kind: kind, Chain: b.Chain, Level: level, BlockNumber: b.Number, BlockHash: b.Hash}, Body: []byte(body)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

const (
	kBaseL1  = "base-sepolia/l1_posted/v1"
	kBaseFin = "base-sepolia/finalized/v1"
	kSepFin  = "eth-sepolia/finalized/v1"
)

var testProofID = [16]byte{1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 10, 11, 12, 13, 14, 15, 16}

// buildChain makes a valid chain for leg b through NewAddendum, in the given level order.
func buildChain(t testing.TB, b BlockRef, levels ...Level) []Addendum {
	t.Helper()
	kinds := map[Level]string{LevelL1Posted: kBaseL1, LevelFinalized: kBaseFin}
	var chain []Addendum
	for _, l := range levels {
		a, err := NewAddendum(LegBindingOf(b), testProofID, chain, b.Chain, l, kinds[l], containerFor(t, kinds[l], b, l, "body"))
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, a)
	}
	return chain
}

func readVectors(t testing.TB, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "finality_chain1", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- golden G0 and G1 (V2_SPEC_S7 2.2), computed independently with Python hashlib and node crypto ----

const (
	g0OwnHash = "0fa894743892da569d5278c87a2b5a2068e0ffef9ba524ca245e4004b4749539"
	g1D0      = "1cea0a369d4a4167f9f3b9be09de1670dfb5718a866bbf7d2a6519b540643445"
	g1OwnHash = "27b59e3b7779b06113e9230f73df87a437166871b293f17ffbfc98913725cdc7"
)

func g0Addendum() Addendum {
	return Addendum{Seq: 1, Level: LevelFinalized, Chain: ChainSepolia, Kind: kSepFin, Evidence: []byte("CFE1-test-vector")}
}

func TestGoldenG0OwnHashOverTheIndependent187BytePreimage(t *testing.T) {
	d0 := fill(0x11)
	a := g0Addendum()
	if n := len(OwnHashPreimage(d0, a)); n != 187 {
		t.Fatalf("preimage is %d bytes, the golden has 187", n)
	}
	if got := OwnHash(d0, a); hex.EncodeToString(got[:]) != g0OwnHash {
		t.Fatalf("G0 ownHash %x, golden %s", got, g0OwnHash)
	}
	if sum := sha256.Sum256(a.Evidence); hex.EncodeToString(sum[:]) != "da4b922562e3e456ffc9b66393eb4b96e77a6271376b628ed68e241c18a06ec9" {
		t.Fatalf("sha256(evidence) %x", sum)
	}
}

func TestGoldenG1LegBindingAndOwnHashUnderIt(t *testing.T) {
	leg := BlockRef{Chain: ChainSepolia, Number: 11845679, Hash: fill(0x22)}
	if n := len(LegBindingPreimage(leg.Chain, leg.Number, leg.Hash)); n != 85 {
		t.Fatalf("D0 preimage is %d bytes, the golden has 85", n)
	}
	d0 := LegBindingOf(leg)
	if hex.EncodeToString(d0[:]) != g1D0 {
		t.Fatalf("G1 D0 %x, golden %s", d0, g1D0)
	}
	if got := OwnHash(d0, g0Addendum()); hex.EncodeToString(got[:]) != g1OwnHash {
		t.Fatalf("G1 ownHash %x, golden %s", got, g1OwnHash)
	}
}

func TestGoldensArePinnedInTheVectorSetToo(t *testing.T) {
	var g struct {
		G0 struct {
			OwnHash     string `json:"ownHash"`
			PreimageLen int    `json:"preimageLen"`
		} `json:"g0"`
		G1 struct {
			D0            string `json:"d0"`
			OwnHash       string `json:"ownHash"`
			D0PreimageLen int    `json:"d0PreimageLen"`
		} `json:"g1"`
	}
	if err := json.Unmarshal(readVectors(t, "goldens.json"), &g); err != nil {
		t.Fatal(err)
	}
	if g.G0.OwnHash != g0OwnHash || g.G0.PreimageLen != 187 || g.G1.D0 != g1D0 || g.G1.OwnHash != g1OwnHash || g.G1.D0PreimageLen != 85 {
		t.Fatalf("goldens.json disagrees with the pinned goldens: %+v", g)
	}
}

// The old golden file (never merged) is kept and superseded: its preimage layout still reproduces its ownHash values when
// the "original digest" is read as D0, but it stores level 1 and takes its digest from the file, which V2_SPEC_S7 forbids
// (testdata/SUPERSEDED.md). This test pins that the OwnHash formula is unchanged, not that the old chain is valid.
func TestSupersededGoldenStillReproducesUnderTheUnchangedPreimageLayout(t *testing.T) {
	raw, err := os.ReadFile("testdata/addendum_v1.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		OriginalDigest string `json:"originalDigest"`
		Addenda        []struct {
			Seq      uint64 `json:"seq"`
			Level    string `json:"level"`
			Chain    uint64 `json:"chain"`
			Kind     string `json:"kind"`
			Evidence string `json:"evidence"`
			PrevHash string `json:"prevHash"`
			OwnHash  string `json:"ownHash"`
		} `json:"addenda"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	d0 := mustHex32(t, g.OriginalDigest)
	for _, e := range g.Addenda {
		level, err := ParseLevel(e.Level)
		if err != nil {
			t.Fatal(err)
		}
		ev, _ := hex.DecodeString(e.Evidence)
		a := Addendum{Seq: e.Seq, Level: level, Chain: e.Chain, Kind: e.Kind, Evidence: ev, PrevHash: mustHex32(t, e.PrevHash)}
		if got := OwnHash(d0, a); hex.EncodeToString(got[:]) != e.OwnHash {
			t.Fatalf("addendum %d: OwnHash %x, old golden %s", e.Seq, got, e.OwnHash)
		}
	}
	if _, err := ParseStoredLevel("included"); err == nil {
		t.Fatal("level included parsed as a stored level")
	}
}

// ---- the vector set finality_chain1 ----

func canonOf(err error) string {
	if err == nil {
		return "ok"
	}
	if st, ok := AsNamed(err); ok {
		return string(st.Canonical())
	}
	return "NOT A NAMED STATE: " + err.Error()
}

func TestChainVectorsGiveTheExpectedVerdicts(t *testing.T) {
	raw := readVectors(t, "chains.json")
	// json tags on the embedded legs are on the type; decode by hand for the two named members
	var shell struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &shell); err != nil {
		t.Fatal(err)
	}
	if len(shell.Vectors) < 17 {
		t.Fatalf("only %d chain vectors", len(shell.Vectors))
	}
	seen := map[string]bool{}
	for _, v := range shell.Vectors {
		var name, expect string
		var leg, carried CarriedLeg
		var addenda []json.RawMessage
		for k, dst := range map[string]any{"name": &name, "expect": &expect, "leg": &leg, "carried": &carried, "addenda": &addenda} {
			if err := json.Unmarshal(v[k], dst); err != nil {
				t.Fatalf("%s: %v", k, err)
			}
		}
		seen[name] = true
		t.Run(name, func(t *testing.T) {
			legRef, err := leg.Ref()
			if err != nil {
				t.Fatal(err)
			}
			carriedRef, err := carried.Ref()
			if err != nil {
				t.Fatal(err)
			}
			var adds []Addendum
			var parseErr error
			for _, r := range addenda {
				var a Addendum
				if err := json.Unmarshal(r, &a); err != nil {
					parseErr = err
					break
				}
				adds = append(adds, a)
			}
			got := ""
			if parseErr != nil {
				got = canonOf(parseErr)
			} else {
				got = canonOf(CheckLegChain(legRef, carriedRef, adds))
			}
			if got != supersededExpect(expect) {
				t.Fatalf("verdict\n got  %s\n want %s", got, supersededExpect(expect))
			}
		})
	}
	// every check of 2.3 and the leg binding has a vector
	for _, want := range []string{"tamper_seq_gap", "tamper_prev_hash", "tamper_own_hash", "tamper_level_duplicate", "tamper_kind_unregistered_version",
		"leg_binding_altered_leg_member", "wrong_d0_with_matching_leg", "chain_unsupported", "kind_level1_refused",
		"valid_base_l1_posted_then_finalized", "valid_base_finalized_then_l1_posted", "valid_sepolia_finalized"} {
		if !seen[want] {
			t.Errorf("vector %q is missing", want)
		}
	}
}

func TestTableVectorsGiveTheExpectedAnswers(t *testing.T) {
	var set struct {
		Queries []struct {
			Chain  uint64 `json:"chain"`
			Level  uint8  `json:"level"`
			Expect string `json:"expect"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(readVectors(t, "table.json"), &set); err != nil {
		t.Fatal(err)
	}
	for _, q := range set.Queries {
		kind, err := KindFor(q.Chain, Level(q.Level))
		got := "kind:" + kind
		if err != nil {
			got = canonOf(err)
		}
		if got != supersededExpect(q.Expect) {
			t.Errorf("chain %d level %d: got %s, want %s", q.Chain, q.Level, got, supersededExpect(q.Expect))
		}
	}
}

func TestManifestPinsEveryFileAndItself(t *testing.T) {
	manifestRaw := readVectors(t, "MANIFEST.json")
	var m struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(manifestRaw, &m); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"goldens.json", "chains.json", "containers.json", "codec_probe.json", "table.json"} {
		sum := sha256.Sum256(readVectors(t, f))
		if m.Files[f] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: manifest says %s, file hashes to %x", f, m.Files[f], sum)
		}
	}
	ms := sha256.Sum256(manifestRaw)
	if got := strings.TrimSpace(string(readVectors(t, "MANIFEST.json.sha256"))); got != hex.EncodeToString(ms[:]) {
		t.Errorf("MANIFEST.json.sha256 %s, manifest hashes to %x", got, ms)
	}
}

// ---- chain behaviours not tied to a vector ----

func TestLevelOrderIsFreeAndEachLevelAppearsOnce(t *testing.T) {
	b := testBase()
	for _, order := range [][]Level{{LevelL1Posted, LevelFinalized}, {LevelFinalized, LevelL1Posted}, {LevelFinalized}, {LevelL1Posted}} {
		if err := CheckLegChain(b, b, buildChain(t, b, order...)); err != nil {
			t.Errorf("order %v: %v", order, err)
		}
	}
	chain := buildChain(t, b, LevelFinalized)
	if _, err := NewAddendum(LegBindingOf(b), testProofID, chain, b.Chain, LevelFinalized, kBaseFin, containerFor(t, kBaseFin, b, LevelFinalized, "again")); err == nil || stateOf(t, err).Code != CodeLevelAlreadyPresent {
		t.Fatalf("a second finalized addendum was built: %v", err)
	}
}

func TestLevelOneIsNeverBuiltStoredOrParsed(t *testing.T) {
	b := testBase()
	if _, err := NewAddendum(LegBindingOf(b), testProofID, nil, b.Chain, LevelIncluded, "included.eth-mpt/v1", []byte("x")); err == nil || stateOf(t, err).Fields["check"] != CheckKind {
		t.Fatalf("NewAddendum accepted level 1: %v", err)
	}
	if _, err := (Container{Header: ContainerHeader{Kind: kBaseFin, Chain: b.Chain, Level: LevelIncluded}}).Encode(); err == nil {
		t.Fatal("a container with level 1 encoded")
	}
	a := buildChain(t, b, LevelFinalized)[0]
	a.Level = LevelIncluded
	a.OwnHash = OwnHash(LegBindingOf(b), a)
	if err := VerifyChain(LegBindingOf(b), []Addendum{a}); err == nil || stateOf(t, err).Fields["check"] != CheckKind {
		t.Fatalf("VerifyChain accepted a rehashed level 1 addendum: %v", err)
	}
	raw, _ := json.Marshal(a)
	var back Addendum
	if err := json.Unmarshal(raw, &back); err == nil || stateOf(t, err).Code != CodeAddendumMalformed {
		t.Fatalf("JSON level included parsed: %v", err)
	}
}

func TestDIsRecomputedFromTheLegNeverReadFromTheFile(t *testing.T) {
	// a chain forged by someone who controls the file and invents a digest for it (the RB11-B-GAP defect)
	forged := testBase()
	forged.Number++ // an arbitrary other binding
	adds := buildChain(t, forged, LevelL1Posted, LevelFinalized)
	// the verifier holds the real Settlement block: the forged chain cannot verify under it, whatever the file claims
	real := testBase()
	err := CheckLegChain(real, real, adds)
	if err == nil {
		t.Fatal("a chain forged for another block verified")
	}
	if st := stateOf(t, err); st.Fields["check"] != CheckOwnHash || st.Fields["seq"] != uint64(1) {
		t.Fatalf("want own_hash at seq 1: %v", err)
	}
	// the leg's own chain verifies; the only input the verifier took from the file was the carried triple, compared first
	if err := CheckLegChain(real, real, buildChain(t, real, LevelL1Posted, LevelFinalized)); err != nil {
		t.Fatal(err)
	}
}

func TestAddendumJSONIsStrictAndRoundTrips(t *testing.T) {
	b := testBase()
	chain := buildChain(t, b, LevelL1Posted)
	raw, err := json.Marshal(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	var back Addendum
	if err := json.Unmarshal(raw, &back); err != nil || back.OwnHash != chain[0].OwnHash || back.Level != LevelL1Posted || back.ProofID != testProofID {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field": func(s string) string { return strings.Replace(s, `"seq"`, `"extra":1,"seq"`, 1) },
		"level":         func(s string) string { return strings.Replace(s, `"l1_posted"`, `"almost"`, 1) },
		"level 1":       func(s string) string { return strings.Replace(s, `"l1_posted"`, `"included"`, 1) },
		"short hash":    func(s string) string { return strings.Replace(s, `"ownHash":"`, `"ownHash":"00`, 1) },
		"evidence hex":  func(s string) string { return strings.Replace(s, `"evidence":"`, `"evidence":"zz`, 1) },
		"proof id":      func(s string) string { return strings.Replace(s, `"proofId":"`, `"proofId":"zz`, 1) },
	} {
		var a Addendum
		if err := json.Unmarshal([]byte(edit(string(raw))), &a); err == nil {
			t.Fatalf("%s: accepted", name)
		} else if st := stateOf(t, err); st.Code != CodeAddendumMalformed {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSectionIsStrict(t *testing.T) {
	b := testBase()
	sec := NewSection(b, buildChain(t, b, LevelFinalized))
	raw, _ := json.Marshal(sec)
	back, err := ParseSection(raw)
	if err != nil || back.Leg != sec.Leg || len(back.Addenda) != 1 {
		t.Fatalf("%v %+v", err, back)
	}
	for name, edit := range map[string]func(string) string{
		"format":  func(s string) string { return strings.Replace(s, SectionFormat, "certen-finality-addenda/2", 1) },
		"unknown": func(s string) string { return strings.Replace(s, `"leg"`, `"originalProofDigest":"00","leg"`, 1) },
	} {
		if _, err := ParseSection([]byte(edit(string(raw)))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProofIDsAreUUIDs(t *testing.T) {
	id, err := ParseProofID("01020304-0506-4708-8909-0a0b0c0d0e0f")
	if err != nil || id != [16]byte{1, 2, 3, 4, 5, 6, 0x47, 8, 0x89, 9, 10, 11, 12, 13, 14, 15} {
		t.Fatalf("%v %x", err, id)
	}
	if ProofIDString(id) != "01020304-0506-4708-8909-0a0b0c0d0e0f" {
		t.Fatal(ProofIDString(id))
	}
	for _, bad := range []string{"", "not-a-uuid", "0102030405064708890909a0b0c0d0e0f0", "0102030g-0506-4708-8909-0a0b0c0d0e0f"} {
		if _, err := ParseProofID(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
