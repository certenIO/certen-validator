// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const vectorDir = "testdata/finality_ethl1_v1"

type vPins struct {
	ChainID string `json:"chain_id"`
	GVR     string `json:"genesis_validators_root"`
	Forks   []struct {
		Name    string `json:"name"`
		Epoch   string `json:"epoch"`
		Version string `json:"version"`
		Layout  int    `json:"layout"`
	} `json:"forks"`
	Anchors []struct {
		Period        string  `json:"period"`
		CommitteeRoot string  `json:"committee_root"`
		BlockRoot     *string `json:"block_root"`
		WSPEpochs     string  `json:"wsp_epochs"`
	} `json:"anchors"`
	MinParticipants int `json:"min_participants"`
	MaxLinks        int `json:"max_links"`
	MaxSpine        int `json:"max_spine_headers"`
}

type vCase struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Description string          `json:"description"`
	Pins        string          `json:"pins"`
	LC          string          `json:"lc"`
	ExecHash    string          `json:"exec_hash"`
	Spine       []string        `json:"spine"`
	Max         int             `json:"max"`
	BlockNumber string          `json:"block_number"`
	Expect      json.RawMessage `json:"expect"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func h32of(t *testing.T, s string) (a [32]byte) {
	t.Helper()
	b := mustHex(t, s)
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	copy(a[:], b)
	return
}

func loadPins(t *testing.T, name string) Pins {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var vp vPins
	if err := json.Unmarshal(raw, &vp); err != nil {
		t.Fatal(err)
	}
	var p Pins
	p.Network.ChainID, _ = strconv.ParseUint(vp.ChainID, 10, 64)
	p.Network.GenesisValidatorsRoot = h32of(t, vp.GVR)
	for _, f := range vp.Forks {
		var fk Fork
		fk.Name = f.Name
		fk.Epoch, _ = strconv.ParseUint(f.Epoch, 10, 64)
		copy(fk.Version[:], mustHex(t, f.Version))
		fk.Layout = Layout(f.Layout)
		p.Network.Forks = append(p.Network.Forks, fk)
	}
	for _, a := range vp.Anchors {
		var an Anchor
		an.Period, _ = strconv.ParseUint(a.Period, 10, 64)
		an.CommitteeRoot = h32of(t, a.CommitteeRoot)
		if a.BlockRoot != nil {
			br := h32of(t, *a.BlockRoot)
			an.BlockRoot = &br
		}
		an.WSPEpochs, _ = strconv.ParseUint(a.WSPEpochs, 10, 64)
		p.Anchors = append(p.Anchors, an)
	}
	p.MinParticipants, p.MaxLinks, p.MaxSpineHeaders = vp.MinParticipants, vp.MaxLinks, vp.MaxSpine
	return p
}

func loadCases(t *testing.T) []vCase {
	t.Helper()
	var man struct {
		Cases []string `json:"cases"`
	}
	raw, err := os.ReadFile(filepath.Join(vectorDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	var out []vCase
	for _, id := range man.Cases {
		b, err := os.ReadFile(filepath.Join(vectorDir, "cases", id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var c vCase
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func loadLC(t *testing.T, c vCase) LC {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, c.LC))
	if err != nil {
		t.Fatal(err)
	}
	lc, err := DecodeLC(b, 1<<16)
	if err != nil {
		t.Fatalf("%s: DecodeLC: %v", c.ID, err)
	}
	if !bytes.Equal(EncodeLC(lc), b) {
		t.Fatalf("%s: encode(decode(lc)) differs from the file", c.ID)
	}
	return lc
}

// canonicalExpect turns an expect object into the canonical bytes the verifier's output must equal.
func canonicalExpect(t *testing.T, expect json.RawMessage) []byte {
	t.Helper()
	var e struct {
		Result string            `json:"result"`
		Code   string            `json:"code"`
		Fields map[string]any    `json:"fields"`
		Head   map[string]string `json:"finalized_head"`
		Blocks []map[string]string
	}
	if err := json.Unmarshal(expect, &e); err != nil {
		t.Fatal(err)
	}
	switch e.Result {
	case "fault":
		b, _ := json.Marshal(map[string]any{"code": e.Code, "fields": e.Fields})
		return b
	case "ok":
		var any map[string]any
		_ = json.Unmarshal(expect, &any)
		b, _ := json.Marshal(any["finalized_head"])
		if e.Head == nil {
			b, _ = json.Marshal(any["blocks"])
		}
		return b
	}
	t.Fatalf("bad expect %s", expect)
	return nil
}

func headOutput(h FinalizedHead, err error) []byte {
	if err != nil {
		return err.(*Fault).CanonicalJSON()
	}
	b, _ := json.Marshal(map[string]string{
		"slot": strconv.FormatUint(h.Slot, 10), "epoch": strconv.FormatUint(h.Epoch, 10), "beacon_root": "0x" + hex.EncodeToString(h.BeaconRoot[:]),
		"exec_hash": "0x" + hex.EncodeToString(h.ExecHash[:]), "participants": strconv.Itoa(h.Participants), "periods_crossed": strconv.FormatUint(h.PeriodsCrossed, 10),
	})
	return b
}

func coversOutput(t *testing.T, c vCase) []byte {
	t.Helper()
	var spine [][]byte
	for _, s := range c.Spine {
		spine = append(spine, mustHex(t, s))
	}
	head := FinalizedHead{ExecHash: h32of(t, c.ExecHash)}
	bl, err := head.Covers(spine, c.Max)
	if err == nil && c.BlockNumber != "" {
		n, _ := strconv.ParseUint(c.BlockNumber, 10, 64)
		_, err = BlockAt(bl, n)
	}
	if err != nil {
		return err.(*Fault).CanonicalJSON()
	}
	out := []map[string]string{}
	for _, b := range bl {
		out = append(out, map[string]string{"hash": "0x" + hex.EncodeToString(b.Hash[:]), "number": strconv.FormatUint(b.Number, 10), "state_root": "0x" + hex.EncodeToString(b.StateRoot[:]), "timestamp": strconv.FormatUint(b.Timestamp, 10)})
	}
	b, _ := json.Marshal(out)
	return b
}

// TestManifestPinsEveryFile: the published set is exactly the files the manifest hashes, and the manifest hash file is its hash.
func TestManifestPinsEveryFile(t *testing.T) {
	mraw, err := os.ReadFile(filepath.Join(vectorDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	ms := sha256.Sum256(mraw)
	want, err := os.ReadFile(filepath.Join(vectorDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ms[:]) + "  manifest.json\n"; got != string(want) {
		t.Fatalf("MANIFEST.sha256 = %q, manifest.json hashes to %q", want, got)
	}
	var man struct {
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int    `json:"bytes"`
		} `json:"files"`
	}
	if err := json.Unmarshal(mraw, &man); err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, f := range man.Files {
		b, err := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != f.SHA256 || len(b) != f.Bytes {
			t.Errorf("%s: sha256/size differs from the manifest", f.Path)
		}
		listed[f.Path] = true
	}
	var onDisk []string
	_ = filepath.Walk(vectorDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(vectorDir, p)
			rel = filepath.ToSlash(rel)
			if rel != "manifest.json" && rel != "MANIFEST.sha256" {
				onDisk = append(onDisk, rel)
			}
		}
		return nil
	})
	sort.Strings(onDisk)
	for _, p := range onDisk {
		if !listed[p] {
			t.Errorf("%s is in the vector directory but not in the manifest", p)
		}
	}
}

// TestHeadVectors runs every published L1-head case through the exported verifier and compares the canonical bytes of the
// verdict with the recorded expectation, exactly as the TypeScript port does.
func TestHeadVectors(t *testing.T) {
	have := map[string]bool{}
	for _, c := range loadCases(t) {
		if c.Kind != "head" {
			continue
		}
		have[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			h, err := VerifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c))
			if got, want := headOutput(h, err), canonicalExpect(t, c.Expect); !bytes.Equal(got, want) {
				t.Fatalf("verdict\n got %s\nwant %s", got, want)
			}
		})
	}
	// every adversarial class of R11-sepolia [ADV] and of the work package must be present in the published set
	for _, id := range requiredHeadCases {
		if !have[id] {
			t.Errorf("required case %s is missing from the set", id)
		}
	}
}

var requiredHeadCases = []string{
	"valid_k1_k0", "valid_k2_k0", "valid_k1_short", "valid_k1_chain",
	"adv_zero_participation", "adv_participation_341", "adv_342_bits_506_signature", "adv_flipped_signature_bit", "adv_attested_slot_plus_one",
	"adv_attested_state_root_altered", "adv_fulu_version_at_gloas_slot", "adv_wrong_genesis_validators_root", "adv_forged_finality_branch_node",
	"adv_forged_finalized_exec_hash", "adv_forged_finalized_exec_branch_node", "adv_finalized_slot_after_attested", "adv_signature_slot_equals_attested",
	"adv_period_skip_first_link_missing", "adv_period_gap_final", "adv_links_out_of_order", "adv_bootstrap_header_not_pin", "adv_bootstrap_committee_branch_forged",
	"adv_learned_committee_not_ledger", "adv_anchor_root_disagrees_with_committee", "adv_committee_body_not_ledger", "adv_bootstrap_committee_not_ledger",
	"adv_window_exceeded", "adv_pin_unknown_period", "adv_ledger_behind", "adv_too_many_links", "electra_link_real_fulu_update",
	"synth_valid_342_exact", "adv_synth_341_valid_signature", "synth_valid_fork_boundary_domain", "adv_synth_domain_from_attested_epoch",
	"synth_valid_electra_era_finalized_header", "adv_synth_electra_era_nonzero_extra_node", "adv_synth_finalized_header_in_unsupported_fork", "adv_synth_identity_signature",
}

func TestCoversVectors(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range loadCases(t) {
		if c.Kind != "covers" {
			continue
		}
		seen[c.ID] = true
		t.Run(c.ID, func(t *testing.T) {
			if got, want := coversOutput(t, c), canonicalExpect(t, c.Expect); !bytes.Equal(got, want) {
				t.Fatalf("verdict\n got %s\nwant %s", got, want)
			}
		})
	}
	for _, id := range []string{"spine_valid_20", "adv_spine_forged_link", "spine_block_above_head", "spine_head_with_unknown_trailing_items", "adv_spine_number_mismatch", "adv_spine_header_not_rlp"} {
		if !seen[id] {
			t.Errorf("required covers case %s is missing from the set", id)
		}
	}
}

// TestMutationChecks sets one deliberately wrong verifier variant at a time and requires the vector that exists for that
// rule to change verdict: the vector really exercises the rule, and the rule is really implemented.
func TestMutationChecks(t *testing.T) {
	cases := map[string]vCase{}
	for _, c := range loadCases(t) {
		cases[c.ID] = c
	}
	run := func(id string, q quirks) (FinalizedHead, *Fault) {
		c := cases[id]
		return verifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c), q)
	}
	muts := []struct {
		name  string
		q     quirks
		cases []string
	}{
		{"drop the 342 floor", quirks{dropFloor: true}, []string{"adv_participation_341", "adv_link_participation_341", "adv_synth_341_valid_signature"}},
		{"take the signing-domain fork version from the attested epoch", quirks{attestedEpochDomain: true}, []string{"synth_valid_fork_boundary_domain"}},
		{"skip the per-period ledger rule", quirks{skipLedgerLearned: true}, []string{"adv_learned_committee_not_ledger"}},
		{"skip the window rule", quirks{skipWindow: true}, []string{"adv_window_exceeded"}},
		{"skip the finality branch", quirks{skipFinalityBranch: true}, []string{"adv_forged_finality_branch_node", "adv_attested_state_root_altered"}},
		{"skip the next-committee branch", quirks{skipNextBranch: true}, []string{"adv_link_next_committee_branch_forged", "adv_link_next_committee_forged"}},
	}
	for _, m := range muts {
		for _, id := range m.cases {
			_, f := run(id, m.q)
			var want struct {
				Code string `json:"code"`
			}
			_ = json.Unmarshal(cases[id].Expect, &want)
			got := "ok"
			if f != nil {
				got = f.Code
			}
			t.Logf("MUTATION %q on %s: expected %q, mutated verifier returns %q", m.name, id, want.Code, got)
			if (f == nil && want.Code == "") || (f != nil && f.Code == want.Code) {
				t.Errorf("mutation %q: vector %s still returns its expected verdict; the vector does not exercise the rule", m.name, id)
			}
		}
	}
	// the unmutated verifier still returns the expected code for each of them
	for _, id := range []string{"adv_participation_341", "adv_learned_committee_not_ledger", "adv_window_exceeded", "adv_forged_finality_branch_node", "adv_synth_341_valid_signature"} {
		_, f := run(id, quirks{})
		var want struct{ Code string }
		_ = json.Unmarshal(cases[id].Expect, &want)
		if f == nil || f.Code != want.Code {
			t.Errorf("%s: unmutated verifier returned %v, want %s", id, f, want.Code)
		}
	}
}

// TestDecodeLCStrict: the container codec refuses trailing bytes, truncation, an over-bound link count, and round-trips.
func TestDecodeLCStrict(t *testing.T) {
	c := cases(t)["valid_k1_short"]
	b, err := os.ReadFile(filepath.Join(vectorDir, c.LC))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeLC(append(append([]byte(nil), b...), 0), 64); err == nil || err.(*Fault).Code != CodeEvidenceMalformed {
		t.Errorf("trailing byte: %v", err)
	}
	if _, err := DecodeLC(b[:len(b)-1], 64); err == nil || err.(*Fault).Code != CodeEvidenceMalformed {
		t.Errorf("truncated: %v", err)
	}
	if _, err := DecodeLC(b, 1); err == nil || err.(*Fault).Code != CodeEvidenceTooLarge {
		t.Errorf("link count over the bound: %v", err)
	}
}

func cases(t *testing.T) map[string]vCase {
	m := map[string]vCase{}
	for _, c := range loadCases(t) {
		m[c.ID] = c
	}
	return m
}

func TestFaultCanonicalJSON(t *testing.T) {
	f := PinMismatch(1390, [32]byte{1}, [32]byte{2})
	want := `{"code":"finality_pin_mismatch","fields":{"got_root":"0x0200000000000000000000000000000000000000000000000000000000000000","period":"1390","want_root":"0x0100000000000000000000000000000000000000000000000000000000000000"}}`
	if string(f.CanonicalJSON()) != want {
		t.Fatalf("got %s", f.CanonicalJSON())
	}
	g := LinkInvalid(3, "x\"<y>", 18446744073709551615, 2, 7)
	if !strings.Contains(string(g.CanonicalJSON()), `"attested_slot":"18446744073709551615"`) || !strings.Contains(string(g.CanonicalJSON()), `"check":"x\"<y>"`) {
		t.Fatalf("u64 or escaping: %s", g.CanonicalJSON())
	}
	if len(AllCodes()) != 15 {
		t.Fatalf("expected the 15 L1-head codes of spec section 7, have %d", len(AllCodes()))
	}
}

func TestNormalizedBranchRejectsNonZeroExtra(t *testing.T) {
	// a 3-node branch at gindex 4 (depth 2): the extra leading node must be zero
	leaf := [32]byte{9}
	n1, n2, extra := [32]byte{1}, [32]byte{2}, [32]byte{3}
	// gindex 4 = 0b100: index 0, depth 2: v = H(H(leaf,n1),n2)
	root := sha2(func() []byte { v := sha2(leaf[:], n1[:]); return v[:] }(), n2[:])
	if !IsValidNormalizedMerkleBranch(leaf, [][32]byte{{}, n1, n2}, 4, root) {
		t.Fatal("zero-extended branch rejected")
	}
	if IsValidNormalizedMerkleBranch(leaf, [][32]byte{extra, n1, n2}, 4, root) {
		t.Fatal("non-zero extra node accepted")
	}
	if IsValidNormalizedMerkleBranch(leaf, [][32]byte{n1}, 4, root) {
		t.Fatal("branch shorter than the depth accepted")
	}
}

func TestContainerSizes(t *testing.T) {
	for k, n := range map[string]int{"BeaconBlockHeader": 112, "LightClientHeader": 496, "SyncCommittee": 24624, "LightClientBootstrap": 25472, "LightClientUpdate": 26424, "LightClientFinalityUpdate": 1448} {
		if err := ValidateContainer(k, make([]byte, n)); err != nil {
			t.Errorf("%s at %d: %v", k, n, err)
		}
		if err := ValidateContainer(k, make([]byte, n+1)); err == nil {
			t.Errorf("%s at %d accepted", k, n+1)
		}
	}
}

// TestTimingRecorded verifies the published chain and logs the wall time of one final update and of the 11-link chain.
func TestTimingRecorded(t *testing.T) {
	c := cases(t)
	for _, id := range []string{"valid_k1_k0", "valid_k1_chain"} {
		pins, lc := loadPins(t, c[id].Pins), loadLC(t, c[id])
		start := time.Now()
		h, err := VerifyFinalizedHead(pins, lc)
		d := time.Since(start)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		t.Logf("TIMING %s: %d links, %d participants, %v", id, len(lc.Links), h.Participants, d)
	}
}

// TestHashTreeRootsAgainstLiveRoots pins the SSZ merkleization to roots the live chain committed to: the captured bootstrap's
// BeaconBlockHeader hashes to the checkpoint block root the beacon API named, and its SyncCommittee hashes to the root the
// chain of links derived independently.
func TestHashTreeRootsAgainstLiveRoots(t *testing.T) {
	var capt struct {
		BootRoot string `json:"bootstrap_block_root"`
	}
	raw, err := os.ReadFile(filepath.Join(vectorDir, "raw", "capture.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &capt); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile(filepath.Join(vectorDir, "raw", "bootstrap.ssz"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateContainer("LightClientBootstrap", boot); err != nil {
		t.Fatal(err)
	}
	got, err := HashTreeRootBeaconBlockHeader(boot[:BeaconBlockHeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if want := h32of(t, capt.BootRoot); got != want {
		t.Fatalf("hash_tree_root(BeaconBlockHeader) = %x, the beacon API named checkpoint root %x", got, want)
	}
	pins := loadPins(t, "pins/main.json")
	last := pins.Anchors[len(pins.Anchors)-1]
	if r := HashTreeRootSyncCommittee(boot[LightClientHeaderSize : LightClientHeaderSize+SyncCommitteeBytes]); r != last.CommitteeRoot {
		t.Fatalf("hash_tree_root(SyncCommittee) of the bootstrap = %x, the link chain derived %x", r, last.CommitteeRoot)
	}
}
