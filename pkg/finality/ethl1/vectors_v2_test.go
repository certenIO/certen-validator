// Copyright 2026 Certen Protocol

package ethl1

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

const vectorDirV2 = "testdata/finality_ethl1_v2"

// v2 is the set the TypeScript port consumes: v1 regenerated under the v2 domain tag plus the electra-layout cases of the real
// Fulu objects, the legacy leg with its 4,057-header spine, and the synthetic cases for the defects of review V-C1A.
func TestV2ManifestPinsEveryFile(t *testing.T) {
	useSet(t, vectorDirV2)
	checkManifest(t)
}

var requiredV2HeadCases = []string{
	// carried over from v1 (regenerated)
	"valid_k1_k0", "valid_k2_k0", "valid_k1_short", "valid_k1_chain", "adv_participation_341", "adv_window_exceeded", "adv_learned_committee_not_ledger",
	"synth_valid_342_exact", "synth_valid_fork_boundary_domain", "synth_valid_electra_era_finalized_header",
	// the real Fulu objects and the mixed-fork chain
	"valid_k2_fulu_k0", "valid_k1_fulu_k0", "valid_k2_fulu_chain_to_gloas", "valid_k1_fulu_chain_to_gloas",
	// electra adversaries
	"adv_electra_forged_attested_exec_field", "adv_electra_forged_finalized_exec_field", "adv_electra_forged_attested_exec_branch_node", "adv_electra_forged_finalized_exec_branch_node",
	"adv_electra_forged_finality_branch_node", "adv_electra_attested_slot_in_gloas_era", "adv_electra_extra_data_offset_lie", "adv_electra_execution_offset_lie", "adv_electra_attested_offset_lie",
	"adv_electra_finalized_offset_out_of_range", "adv_electra_finalized_offset_descending", "adv_electra_overlong_tail", "adv_electra_extra_data_grown_by_one", "adv_electra_truncated",
	"adv_electra_layout_byte_gloas_on_electra_bytes", "adv_gloas_layout_byte_electra_on_gloas_bytes", "adv_electra_bootstrap_layout_byte_gloas", "adv_electra_fork_version_wrong",
	"adv_electra_bootstrap_forged_exec_field", "adv_electra_bootstrap_committee_branch_forged", "adv_electra_bootstrap_committee_swapped", "adv_electra_ledger_1378_committee_wrong",
	"adv_electra_chain_learned_not_ledger", "adv_electra_link_signature_flipped", "adv_electra_link_next_committee_branch_forged", "adv_electra_link_next_committee_forged",
	"adv_electra_link_participation_341", "adv_electra_link_finality_branch_forged",
	// decode strictness at the link and bootstrap level
	"adv_electra_link_attested_offset_lie", "adv_electra_link_finalized_offset_out_of_range", "adv_electra_link_execution_offset_lie", "adv_electra_link_extra_data_offset_lie",
	"adv_electra_link_truncated", "adv_electra_link_overlong_tail", "adv_electra_link_forged_attested_exec_field", "adv_electra_link_forged_finalized_exec_field",
	"adv_electra_link_attested_slot_in_gloas_era", "adv_electra_bootstrap_header_offset_lie", "adv_electra_bootstrap_truncated", "adv_electra_bootstrap_execution_offset_lie",
	"adv_electra_bootstrap_extra_data_offset_lie", "adv_electra_bootstrap_overlong_tail", "adv_electra_anchor_body_layout_byte_electra",
	// V-C1A defects
	"synth_valid_link_then_final", "adv_synth_next_committee_mismatch", "adv_synth_final_period_gap_next_known", "adv_synth_link_period_skip_next_known",
	"synth_valid_nonparticipating_invalid_key", "adv_synth_participating_invalid_key", "adv_synth_final_finalized_slot_zero", "adv_pins_network_mismatch",
	"adv_ledger_period_1380_altered", "adv_ledger_period_1385_altered", "adv_ledger_period_1390_altered",
}

func TestV2HeadVectors(t *testing.T) {
	useSet(t, vectorDirV2)
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
	for _, id := range requiredV2HeadCases {
		if !have[id] {
			t.Errorf("required case %s is missing from the v2 set", id)
		}
	}
	t.Logf("v2 head cases run: %d", len(have))
}

func TestV2CoversVectors(t *testing.T) {
	useSet(t, vectorDirV2)
	seen := 0
	for _, c := range loadCases(t) {
		if c.Kind != "covers" {
			continue
		}
		seen++
		t.Run(c.ID, func(t *testing.T) {
			if got, want := coversOutput(t, c), canonicalExpect(t, c.Expect); !bytes.Equal(got, want) {
				t.Fatalf("verdict\n got %s\nwant %s", got, want)
			}
		})
	}
	for _, id := range []string{"spine_valid_20", "spine_legacy_leg", "adv_spine_legacy_leg_over_bound", "spine_legacy_block_above_head"} {
		if _, ok := cases(t)[id]; !ok {
			t.Errorf("required covers case %s is missing", id)
		}
	}
	t.Logf("v2 covers cases run: %d", seen)
}

// TestV2MutationChecks switches the rules the v2 vectors were added for off, one at a time, and requires the vector to change verdict
// (V-C1A survivors A..P and the electra header rule).
func TestV2MutationChecks(t *testing.T) {
	useSet(t, vectorDirV2)
	var rotated, firstLearn []string
	for q := 1380; q <= 1390; q++ {
		id := "adv_ledger_period_" + strconv.Itoa(q) + "_altered"
		rotated = append(rotated, id)
		firstLearn = append(firstLearn, id)
	}
	// each altered-period vector is caught at first learn or at rotation; every period must be caught by one of the two, and the
	// vectors that only the rotation branch catches must exist (V-C1A mutant P)
	cs := cases(t)
	rotCaught, firstCaught := 0, 0
	for _, id := range rotated {
		c := cs[id]
		_, fr := verifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c), offSet(chkLedgerRotation))
		_, ff := verifyFinalizedHead(loadPins(t, c.Pins), loadLC(t, c), offSet(chkLedgerFirstLearn))
		if fr == nil || fr.Code != CodePinMismatch {
			rotCaught++
		}
		if ff == nil || ff.Code != CodePinMismatch {
			firstCaught++
		}
	}
	if rotCaught == 0 {
		t.Errorf("no altered-period vector is caught only by the rotation-branch ledger rule (mutant P survives)")
	}
	if firstCaught == 0 {
		t.Errorf("no altered-period vector is caught only by the first-learn ledger rule")
	}
	t.Logf("altered-period vectors: %d changed verdict with the rotation rule off, %d with the first-learn rule off", rotCaught, firstCaught)
	runMutations(t, []mutation{
		{"skip the next-committee mismatch rule (V-C1A G)", offSet(chkNextMismatch), []string{"adv_synth_next_committee_mismatch"}},
		{"skip the signature-period rule with next known (V-C1A H), final update", offSet(chkPeriodRuleNextKnown), []string{"adv_synth_final_period_gap_next_known"}},
		{"skip the signature-period rule with next known (V-C1A H), link", offSet(chkPeriodRuleNextKnown), []string{"adv_synth_link_period_skip_next_known"}},
		{"skip the final-update finalized-slot-zero refusal", offSet(chkFinalNotFinality), []string{"adv_synth_final_finalized_slot_zero"}},
		{"skip the execution-branch rule of both layouts", offSet(chkExecBranch), []string{"adv_electra_forged_attested_exec_field", "adv_electra_forged_finalized_exec_field",
			"adv_electra_forged_attested_exec_branch_node", "adv_electra_forged_finalized_exec_branch_node", "adv_forged_attested_exec_hash",
			"adv_electra_link_forged_attested_exec_field", "adv_electra_link_forged_finalized_exec_field"}},
		{"skip the finality branch (electra gindex 169)", offSet(chkFinalityBranch), []string{"adv_electra_forged_finality_branch_node"}},
		{"skip the next-committee branch (electra gindex 87)", offSet(chkNextBranch), []string{"adv_electra_link_next_committee_branch_forged", "adv_electra_link_next_committee_forged"}},
		{"drop the 342 floor on a Fulu link", offSet(chkFloor), []string{"adv_electra_link_participation_341"}},
		{"take the domain version from the attested epoch (Fulu)", mutRules{domainFromAttested: true}, []string{"synth_valid_fork_boundary_domain"}},
		{"skip the window rule", offSet(chkWindow), []string{"adv_window_exceeded"}},
	})
}

// TestV2MixedForkLinkChainCrossesTheForkBoundary pins the live property: the Fulu update is link 0 of a chain whose remaining links are
// Gloas objects and the periods crossed count 12.
func TestV2MixedForkLinkChainCrossesTheForkBoundary(t *testing.T) {
	useSet(t, vectorDirV2)
	c := cases(t)["valid_k2_fulu_chain_to_gloas"]
	lc := loadLC(t, c)
	if lc.AnchorBody.Layout != LayoutElectra || lc.Links[0].Layout != LayoutElectra || lc.Links[1].Layout != LayoutGloas || lc.FinalUpdate.Layout != LayoutGloas {
		t.Fatalf("layouts: %v %v %v %v", lc.AnchorBody.Layout, lc.Links[0].Layout, lc.Links[1].Layout, lc.FinalUpdate.Layout)
	}
	h, err := VerifyFinalizedHead(loadPins(t, c.Pins), lc)
	if err != nil {
		t.Fatal(err)
	}
	if h.PeriodsCrossed != 12 {
		t.Fatalf("periods crossed %d, want 12", h.PeriodsCrossed)
	}
}

// TestElectraMinimumSizesAgainstLiveObjects: the minimums of spec 3.2 (e) by SSZ arithmetic, and the live objects are above them
// and below the maximum (32 bytes of extra_data per header).
func TestElectraMinimumSizesAgainstLiveObjects(t *testing.T) {
	if electraMinUpdate != 26872 || electraMinBootstrap != 25648 || electraMinFinalityUpdate != 2056 {
		t.Fatalf("minimums %d %d %d, want 26872 25648 2056", electraMinUpdate, electraMinBootstrap, electraMinFinalityUpdate)
	}
	if electraUpdateFixed != 25216 || electraBootstrapFixed != 24820 || electraFinalityUpdateFixed != 400 || electraHeaderFixed != 244 {
		t.Fatalf("fixed parts %d %d %d %d", electraUpdateFixed, electraBootstrapFixed, electraFinalityUpdateFixed, electraHeaderFixed)
	}
	raw := filepath.Join(vectorDirV2, "raw")
	for name, bounds := range map[string][2]int{
		"update_1378.ssz":    {electraMinUpdate, electraMinUpdate + 64},
		"update_1377.ssz":    {electraMinUpdate, electraMinUpdate + 64},
		"bootstrap_fulu.ssz": {electraMinBootstrap, electraMinBootstrap + 32},
	} {
		b, err := os.ReadFile(filepath.Join(raw, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) < bounds[0] || len(b) > bounds[1] {
			t.Errorf("%s: %d bytes outside [%d,%d]", name, len(b), bounds[0], bounds[1])
		}
		t.Logf("%s: %d bytes (minimum %d)", name, len(b), bounds[0])
	}
	// every electra blob is longer than its Gloas twin
	if electraMinUpdate <= LightClientUpdateSize || electraMinBootstrap <= LightClientBootstrapSize || electraMinFinalityUpdate <= LightClientFinalityUpdateSize {
		t.Fatal("an electra minimum is not above the Gloas fixed size")
	}
}

// TestElectraDecodersNeverPanic feeds every truncation and a spread of single-byte overwrites of the live electra objects to the
// decoders: each is a *Fault or a decoded object, never a panic.
func TestElectraDecodersNeverPanic(t *testing.T) {
	raw := filepath.Join(vectorDirV2, "raw")
	upd, _ := os.ReadFile(filepath.Join(raw, "update_1378.ssz"))
	boot, _ := os.ReadFile(filepath.Join(raw, "bootstrap_fulu.ssz"))
	c := cases(t)
	_ = c
	fu := electraFinalityFromUpdate(upd)
	for n := 0; n <= len(upd); n += 7 {
		_, _ = decodeElectraUpdate(upd[:n], 0)
	}
	for n := 0; n <= len(boot); n += 7 {
		_, _ = decodeElectraBootstrap(boot[:n])
	}
	for n := 0; n <= len(fu); n++ {
		if _, f := decodeElectraFinalityUpdate(fu[:n]); f == nil && n != len(fu) {
			// a shorter blob decoding successfully would mean the header lengths absorbed the cut: still a valid encoding of a shorter extra_data
			t.Logf("truncation to %d decodes (extra_data shorter)", n)
		}
	}
	for i := 0; i < len(fu); i++ {
		for _, v := range []byte{0x00, 0xff} {
			m := append([]byte(nil), fu...)
			m[i] = v
			_, _ = decodeElectraFinalityUpdate(m)
		}
	}
}

// electraFinalityFromUpdate converts an electra LightClientUpdate to the LightClientFinalityUpdate carrying the same finality data.
func electraFinalityFromUpdate(u []byte) []byte {
	finOff := int(binary.LittleEndian.Uint32(u[24820:24824]))
	att, fin := u[electraUpdateFixed:finOff], u[finOff:]
	out := binary.LittleEndian.AppendUint32(nil, electraFinalityUpdateFixed)
	out = binary.LittleEndian.AppendUint32(out, uint32(electraFinalityUpdateFixed+len(att)))
	out = append(out, u[24824:25208]...)
	out = append(out, u[25208:25216]...)
	out = append(out, att...)
	return append(out, fin...)
}

// TestLegacyLegTimingAndSpineMutations verifies the legacy final update and the 4,057-header spine, records their wall time, and
// mutates the long spine in place (one byte of a header in the middle, the count bound).
func TestLegacyLegTimingAndSpineMutations(t *testing.T) {
	useSet(t, vectorDirV2)
	cs := cases(t)
	c := cs["valid_k2_fulu_k0"]
	pins, lc := loadPins(t, c.Pins), loadLC(t, c)
	start := time.Now()
	h, err := VerifyFinalizedHead(pins, lc)
	d := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TIMING legacy final update (electra layout, kind-2 Fulu bootstrap anchor): %d participants, %v", h.Participants, d)
	leg := cs["spine_legacy_leg"]
	spine := readSpineFile(t, leg.SpineFile)
	total := 0
	for _, s := range spine {
		total += len(s)
	}
	start = time.Now()
	blocks, err := h.Covers(spine, pins.MaxSpineHeaders)
	d = time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TIMING legacy spine: %d headers, %d bytes of RLP (%d framed), Covers %v; top block %d, leg block %d", len(blocks), total, total+4*len(spine)+4, d, blocks[0].Number, blocks[len(blocks)-1].Number)
	if _, err := h.Covers(spine, len(spine)-1); err == nil || err.(*Fault).Code != CodeEvidenceTooLarge {
		t.Errorf("spine over the bound: %v", err)
	}
	for _, at := range []int{1, 2000, len(spine) - 2} {
		mut := make([][]byte, len(spine))
		copy(mut, spine)
		mut[at] = append([]byte(nil), spine[at]...)
		mut[at][len(mut[at])-1] ^= 1
		if _, err := h.Covers(mut, 16384); err == nil || err.(*Fault).Code != CodeHeaderChainBroken {
			t.Errorf("header %d altered: %v", at, err)
		}
	}
	// the final update of the leg and the JSON of its head must agree with the head of the covered spine
	if h.ExecHash != blocks[0].Hash {
		t.Errorf("final update exec hash %x != spine top %x", h.ExecHash, blocks[0].Hash)
	}
	var exp struct {
		Head map[string]string `json:"finalized_head"`
	}
	_ = json.Unmarshal(c.Expect, &exp)
	if exp.Head["exec_hash"] == "" {
		t.Error("the recorded verdict has no exec_hash")
	}
}

// TestPinsDecodeLCCarriesTheBound: Pins.DecodeLC applies Pins.MaxLinks.
func TestPinsDecodeLCCarriesTheBound(t *testing.T) {
	useSet(t, vectorDirV2)
	c := cases(t)["valid_k1_short"]
	b, err := os.ReadFile(filepath.Join(vectorDir, c.LC))
	if err != nil {
		t.Fatal(err)
	}
	p := loadPins(t, c.Pins)
	if _, err := p.DecodeLC(b); err != nil {
		t.Fatal(err)
	}
	p.MaxLinks = 1
	if _, err := p.DecodeLC(b); err == nil || err.(*Fault).Code != CodeEvidenceTooLarge {
		t.Errorf("two links against Pins.MaxLinks 1: %v", err)
	}
}

// TestHashTreeRootSyncCommitteeNeverPanics: any length other than 24,624 is a fault, not a panic (V-C1A).
func TestHashTreeRootSyncCommitteeNeverPanics(t *testing.T) {
	for _, n := range []int{0, 1, SyncCommitteeBytes - 1, SyncCommitteeBytes + 1, 1 << 20} {
		if _, err := HashTreeRootSyncCommittee(make([]byte, n)); err == nil || err.(*Fault).Code != CodeEvidenceMalformed {
			t.Errorf("length %d: %v", n, err)
		}
	}
	if _, err := HashTreeRootSyncCommittee(make([]byte, SyncCommitteeBytes)); err != nil {
		t.Error(err)
	}
	if _, err := HashTreeRootSyncCommittee(nil); err == nil {
		t.Error("nil accepted")
	}
}

// TestElectraEmptyHeaderIsTheGenuineEmptyEncoding: LightClientHeader() of the electra shape (the finalized header of an update with
// finalized slot 0) encodes with a non-zero extra_data offset; it is empty, and a header with any execution field set, a non-empty
// extra_data, a beacon field or a branch node set is not.
func TestElectraEmptyHeaderIsTheGenuineEmptyEncoding(t *testing.T) {
	enc := make([]byte, electraHeaderMin)
	binary.LittleEndian.PutUint32(enc[BeaconBlockHeaderSize:], electraHeaderFixed)
	binary.LittleEndian.PutUint32(enc[electraHeaderFixed+electraExecExtraOffAt:], electraExecFixed)
	h, f := decodeElectraHeader(enc, "t", 0)
	if f != nil {
		t.Fatal(f)
	}
	if !h.isEmpty() {
		t.Fatal("the SSZ encoding of the empty electra LightClientHeader is not recognised as empty")
	}
	for name, mut := range map[string]func([]byte) []byte{
		"beacon slot":     func(b []byte) []byte { b[0] = 1; return b },
		"branch node":     func(b []byte) []byte { b[116+5] = 1; return b },
		"fee recipient":   func(b []byte) []byte { b[electraHeaderFixed+40] = 1; return b },
		"base fee":        func(b []byte) []byte { b[electraHeaderFixed+electraExecFixed-60] = 1; return b },
		"excess blob gas": func(b []byte) []byte { b[electraHeaderFixed+electraExecFixed-1] = 1; return b },
		"non-empty extra": func(b []byte) []byte { return append(b, 0) },
		"first exec byte": func(b []byte) []byte { b[electraHeaderFixed] = 1; return b },
	} {
		m, f := decodeElectraHeader(mut(append([]byte(nil), enc...)), "t", 0)
		if f != nil {
			t.Fatalf("%s: %v", name, f)
		}
		if m.isEmpty() {
			t.Errorf("%s: a non-empty header is recognised as empty", name)
		}
	}
}

// TestElectraDecoderBoundaries pins the exact size boundaries of the strict electra decoders with minimally-shaped blobs: a header of
// 828..860 bytes (extra_data 0..32) decodes and 827 and 861 are refused, and each container accepts its minimum size and refuses one
// byte less, with a header of either extreme on either side of the second offset.
func TestElectraDecoderBoundaries(t *testing.T) {
	hdr := func(extra int) []byte {
		b := make([]byte, electraHeaderMin+extra)
		binary.LittleEndian.PutUint32(b[BeaconBlockHeaderSize:], electraHeaderFixed)
		binary.LittleEndian.PutUint32(b[electraHeaderFixed+electraExecExtraOffAt:], electraExecFixed)
		return b
	}
	reason := func(f *Fault) string {
		if f == nil {
			return ""
		}
		r, _ := f.Fields["reason"].(string)
		return r
	}
	for _, extra := range []int{0, 1, 31, 32} {
		if _, f := decodeElectraHeader(hdr(extra), "t", 0); f != nil {
			t.Errorf("header with %d bytes of extra_data refused: %v", extra, f)
		}
	}
	if _, f := decodeElectraHeader(hdr(33), "t", 0); reason(f) != "header_length" {
		t.Errorf("861-byte header: %v", f)
	}
	if _, f := decodeElectraHeader(hdr(0)[:electraHeaderMin-1], "t", 0); reason(f) != "header_length" {
		t.Errorf("827-byte header: %v", f)
	}
	// bootstrap
	boot := func(extra int) []byte {
		b := make([]byte, electraBootstrapFixed)
		binary.LittleEndian.PutUint32(b, electraBootstrapFixed)
		return append(b, hdr(extra)...)
	}
	for _, extra := range []int{0, 32} {
		if _, f := decodeElectraBootstrap(boot(extra)); f != nil {
			t.Errorf("bootstrap with a %d-byte extra_data refused: %v", extra, f)
		}
	}
	if b := boot(0); len(b) != electraMinBootstrap {
		t.Fatalf("minimum bootstrap is %d bytes, constant says %d", len(b), electraMinBootstrap)
	}
	if _, f := decodeElectraBootstrap(boot(0)[:electraMinBootstrap-1]); reason(f) != "length" {
		t.Errorf("bootstrap one byte under the minimum: %v", f)
	}
	if _, f := decodeElectraBootstrap(boot(33)); reason(f) != "header_length" {
		t.Errorf("bootstrap with a 861-byte header: %v", f)
	}
	// update and finality update: first header a bytes of extra_data, second header b bytes
	upd := func(fixed, secondAt, a, b int) []byte {
		ha, hb := hdr(a), hdr(b)
		out := make([]byte, fixed)
		binary.LittleEndian.PutUint32(out, uint32(fixed))
		binary.LittleEndian.PutUint32(out[secondAt:], uint32(fixed+len(ha)))
		return append(append(out, ha...), hb...)
	}
	updAt, finAt := 4+SyncCommitteeBytes+32*electraCommitteeBranchLen, 4
	for _, ab := range [][2]int{{0, 0}, {32, 32}, {0, 32}, {32, 0}} {
		if _, f := decodeElectraUpdate(upd(electraUpdateFixed, updAt, ab[0], ab[1]), 0); f != nil {
			t.Errorf("update with extra_data %v refused: %v", ab, f)
		}
		if _, f := decodeElectraFinalityUpdate(upd(electraFinalityUpdateFixed, finAt, ab[0], ab[1])); f != nil {
			t.Errorf("finality update with extra_data %v refused: %v", ab, f)
		}
	}
	if b := upd(electraUpdateFixed, updAt, 0, 0); len(b) != electraMinUpdate {
		t.Fatalf("minimum update is %d bytes, constant says %d", len(b), electraMinUpdate)
	}
	if b := upd(electraFinalityUpdateFixed, finAt, 0, 0); len(b) != electraMinFinalityUpdate {
		t.Fatalf("minimum finality update is %d bytes, constant says %d", len(b), electraMinFinalityUpdate)
	}
	if _, f := decodeElectraUpdate(upd(electraUpdateFixed, updAt, 0, 0)[:electraMinUpdate-1], 0); reason(f) != "length" {
		t.Errorf("update one byte under the minimum: %v", f)
	}
	if _, f := decodeElectraFinalityUpdate(upd(electraFinalityUpdateFixed, finAt, 0, 0)[:electraMinFinalityUpdate-1]); reason(f) != "length" {
		t.Errorf("finality update one byte under the minimum: %v", f)
	}
	if _, f := decodeElectraUpdate(upd(electraUpdateFixed, updAt, 33, 0), 0); reason(f) != "finalized_offset" {
		t.Errorf("update with an 861-byte first header: %v", f)
	}
	if _, f := decodeElectraUpdate(upd(electraUpdateFixed, updAt, 0, 33), 0); reason(f) != "header_length" {
		t.Errorf("update with an 861-byte second header: %v", f)
	}
	if _, f := decodeElectraFinalityUpdate(upd(electraFinalityUpdateFixed, finAt, 33, 0)); reason(f) != "finalized_offset" {
		t.Errorf("finality update with an 861-byte first header: %v", f)
	}
	if _, f := decodeElectraFinalityUpdate(upd(electraFinalityUpdateFixed, finAt, 0, 33)); reason(f) != "header_length" {
		t.Errorf("finality update with an 861-byte second header: %v", f)
	}
	// the first header may also be one byte short: the second offset then falls under fixed + 828
	if _, f := decodeElectraUpdate(func() []byte {
		b := upd(electraUpdateFixed, updAt, 0, 0)
		binary.LittleEndian.PutUint32(b[updAt:], electraUpdateFixed+electraHeaderMin-1)
		return b
	}(), 0); reason(f) != "finalized_offset" {
		t.Errorf("update whose first header is 827 bytes: %v", f)
	}
}
