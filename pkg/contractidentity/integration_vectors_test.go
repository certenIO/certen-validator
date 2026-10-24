// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// The vector set s8_int_1 (V2_SPEC_S8 r3.2 + F14-F17 + [r3.3:FORMAT-R2]) belongs to no single verifier package: it needs the facts of the whole
// composition. VS8-076 (drift of the attestation words and of a validator record after the attestation, end to end), VS8-190 (step 24: S7
// finalized for another block / refused / chain not in the S7 table), VS8-162 (the registry object and expected_subset_count), and the
// printed rules_not_judged of step 23 (VS8-180). Expectations are written from the specification rows; the set is run by the REAL composed
// verifier (NewDefaultVerifier) from its materialised inputs.

const vectorSetInt = "s8_int_1"

type authorInt struct {
	t *testing.T
	f *fixture
}

func (a *authorInt) stationWord(station string, who common.Address, slot common.Hash) common.Hash {
	acct := a.f.spec.Stations[station].Accounts[strings.ToLower(who.Hex())]
	return common.HexToHash(acct.Storage[strings.ToLower(slot.Hex())])
}

func (a *authorInt) vectors() []ci.Vector {
	f := a.f
	sp := f.spec
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		if muts == nil {
			muts = []ci.Mutation{}
		}
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	anchor := hexAddr(sp.Roles.Anchor)
	vc := func(open ...ci.ExpectedOpen) ci.Expected {
		e := exp(ci.HeadlineVerifiedCore, map[string]string{ci.JudgedAuthorizationAttest: "verified", ci.JudgedRegistryLink: "verified", ci.JudgedStateAtSettlement: "open"})
		e.Open = open
		return e
	}
	drift := func(field string, attest, settle common.Hash) ci.ExpectedOpen {
		return ci.ExpectedOpen{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenDrift, Code: ci.Prefix + "drift", Fields: cf(map[string]any{"field": field, "attest": attest, "settle": settle})}
	}

	// VS8-076 (step 13): a legitimate rotation AFTER the attestation is a drift (Open), never a refusal: the word is read at B_v post and at N
	pkc := common.HexToHash(sp.Attestation.Blob[13])
	a05 := ci.MappingSlotAt(ci.KeyBytes32(pkc), 4)
	for _, c := range []struct {
		id   string
		slot common.Hash
		to   func(common.Hash) common.Hash
	}{
		{"A05", a05, func(common.Hash) common.Hash { return common.Hash{} }},
		{"A07", ci.SlotIndex(5), func(w common.Hash) common.Hash { return common.BigToHash(new(big.Int).Add(w.Big(), big.NewInt(1))) }},
		{"A11", ci.SlotIndex(14), func(w common.Hash) common.Hash { return common.BigToHash(new(big.Int).Add(w.Big(), big.NewInt(1))) }},
	} {
		was := a.stationWord(world.StationPost, anchor, c.slot)
		now := c.to(was)
		opens := []ci.ExpectedOpen{drift(c.id, was, now)}
		if c.id == "A11" { // [r3.4:H3] the total word no longer equals the sum of the listed powers at N
			opens = append([]ci.ExpectedOpen{{Part: ci.JudgedStateAtSettlement, Kind: ci.OpenAlert, Code: ci.Prefix + "alert", Fields: cf(map[string]any{"field": "total_power", "at": "settle", "onchain": now, "want": was})}}, opens...)
		}
		add("VS8-076.drift_"+c.id, vc(opens...), world.SetStorage(world.StationSettle, anchor, c.slot, now))
	}
	// VS8-152: a key rotated between B_v and N is a drift: the BLS key bytes of one listed validator change at N (the set root does not commit to keys)
	m0 := sp.Context.Registry9.Members[0]
	v0 := hexAddr(m0.Address)
	oldKey, err := hex.DecodeString(strings.TrimPrefix(m0.BLSKey, "0x"))
	if err != nil {
		a.t.Fatal(err)
	}
	newKey := append([]byte(nil), oldKey...)
	newKey[0] ^= 1
	base := ci.MappingSlotAt(ci.KeyAddress(v0), 12)
	dataSlot := crypto.Keccak256Hash(ci.MemberSlot(base, 2).Bytes())
	was := a.stationWord(world.StationSettle, anchor, dataSlot)
	if was != common.BytesToHash(oldKey[:32]) {
		a.t.Fatalf("the key of validator 0 is not stored at keccak256(slot): %x vs %x", was, oldKey[:32])
	}
	key := "A09:" + strings.ToLower(v0.Hex())
	add("VS8-152.key_rotated_after_attestation", vc(drift(key+":key", crypto.Keccak256Hash(oldKey), crypto.Keccak256Hash(newKey))),
		world.SetStorage(world.StationSettle, anchor, dataSlot, common.BytesToHash(newKey[:32])))

	// VS8-190 (step 24, [r3.1:D2]): a state root that S7 did not authenticate for THIS block is pending; an unsupported chain is unproven
	pending := func(status string) ci.Expected {
		e := exp(ci.HeadlinePending, nil)
		e.S7FinalizedStatus = status
		return e
	}
	s7set := func(path, v string) ci.Mutation {
		b, _ := json.Marshal(v)
		return ci.Mutation{Op: "set_field", Target: "s7", Path: path, Value: b}
	}
	add("VS8-190.finalized_other_block", pending("verified_other_block"), s7set("finalized_block.hash", "0x"+strings.Repeat("11", 32)))
	add("VS8-190.finalized_refused", pending("refused:finality_chain_broken"), s7set("finalized.status", "refused"), s7set("finalized.state", "finality_chain_broken"))
	unsupported := exp(ci.HeadlineUnproven, map[string]string{}, est(ci.JudgedAuthorizationAttest, "unproven", map[string]any{"part": "all", "reason": "s7_chain_unsupported", "chain": sp.Chain}))
	for _, p := range ci.JudgedParts {
		unsupported.Parts[p] = "unproven"
	}
	unsupported.S7FinalizedStatus = "refused:finality_chain_unsupported"
	add("VS8-190.chain_not_in_the_s7_table", unsupported, s7set("unsupported", "finality_chain_unsupported"))

	// VS8-162 (step 21a): the registry object as proven at B_v, n = 7 listed validators with equal power at 2/3: expected_subset_count 29
	reg := json.RawMessage(`{"count":"7","totalVotingPower":"70","threshold":{"num":"2","den":"3"},"binding":true,"authorizedCommitments":{"expected_subset_count":"29"}}`)
	e162 := exp(ci.HeadlineVerified, nil)
	e162.Registry = reg
	add("VS8-162.registry_object", e162)
	k2 := strings.ToUpper(strings.TrimPrefix(sp.Context.Registry9.Members[2].BLSKey, "0x"))
	// [r3.3:S1] E-g fixes the form of a Registry9 key (lowercase hex, no 0x): another spelling is not a mismatch of the key (the compare is on the
	// decoded bytes) but a context that is not a Registry9, context_incomplete{missing:[registry9]}
	noncanon := exp(ci.HeadlineRefused, nil, est("first", "context_incomplete", map[string]any{"missing": []any{"registry9"}}))
	add("VS8-020.registry9_key_0x_prefix", noncanon, ctxSet("registry9.members.2.bls_key", "0x"+strings.ToLower(k2)))
	add("VS8-020.registry9_key_upper_case", noncanon, ctxSet("registry9.members.2.bls_key", k2))
	add("VS8-020.s7_absent", exp(ci.HeadlineRefused, nil, est("first", "context_incomplete", map[string]any{"missing": []any{"s7"}})), ci.Mutation{Op: "unset_field", Target: "context", Path: "s7"})

	// VS8-184 (step 23): every outcome prints rules_not_judged, with the reason (the four rows of the "Not judged" paragraph of Policy rules)
	rnj := []ci.ExpectedRuleNotJudged{
		{Row: "A21", Reason: "minimumGovernanceLevelForValueOps is read only by executeWithGovernance (CertenAnchorV8_2.sol:1398), not on the attestation path; reported in registry"},
		{Row: "A09:3", Reason: "registeredAt is informational; no acceptance decision reads it"},
		{Row: "slot19:usedNonces", Reason: "restrict-only: its single reader is nonceValid = !usedNonces[...] (CertenAnchorV8_2.sol:2002) and its single writer assigns the literal true (:1352)"},
		{Row: "slot28:operators", Reason: "not read by the attestation path"},
	}
	outcome := func(headline string, muts ...ci.Mutation) {
		e := exp(headline, nil)
		e.RulesNotJudged = rnj
		add("VS8-184."+headline, e, muts...)
	}
	outcome(ci.HeadlineVerified)
	outcome(ci.HeadlinePending, s7set("finalized_block.hash", "0x"+strings.Repeat("11", 32)))
	outcome(ci.HeadlineUnproven, s7set("unsupported", "finality_chain_unsupported"))
	outcome(ci.HeadlineRefused, world.SetStorage(world.StationPre, anchor, ci.SlotIndex(6), common.Hash{}), world.SetStorage(world.StationPost, anchor, ci.SlotIndex(6), common.Hash{}))
	return out
}

func TestVectorSetIntIsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &authorInt{t, f}
	vectors := a.vectors()
	if _, err := os.Stat(setDir(vectorSetInt)); err != nil && os.Getenv("CERTEN_WRITE_S8_INT") == "1" {
		if err := world.WriteSet(setDir(vectorSetInt), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSetInt))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSetInt, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ci.RunSet(set, nil, ver) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	checkPublishedBytes(t, f, vectorSetInt, vectors)
}

// ---- s8_int_2: the framework rows (steps 0, 1, 1b, 22b) and the headline rows of step 23 that need S7 and a refusal together ----

const vectorSetInt2 = "s8_int_2"

func (a *authorInt) vectors2() []ci.Vector {
	f := a.f
	sp := f.spec
	var out []ci.Vector
	add := func(id string, e ci.Expected, muts ...ci.Mutation) {
		out = append(out, ci.Vector{ID: id, Base: "H0", Mutations: muts, Expected: e})
	}
	first := func(code string, fields map[string]any) ci.Expected {
		return exp(ci.HeadlineRefused, nil, est("first", code, fields))
	}
	malformed := func(part string, index int, reason string, got, want int) ci.Expected {
		return first("evidence_malformed", map[string]any{"part": part, "index": uint64(index), "reason": reason, "got_len": uint64(got), "want_len": uint64(want)})
	}
	raw := f.built.Inputs.Container
	// VS8-001: the manifest bytes are not the bytes the pin names (a stale pin)
	add("VS8-001.stale_pin", first("manifest_corrupt", map[string]any{}), ci.Mutation{Op: "set_pin", Target: "manifest", Value: json.RawMessage(`"` + strings.Repeat("00", 32) + `"`)})
	// VS8-010 / VS8-012: the magic is CIE1; a trailing byte
	add("VS8-010.magic_cie2", malformed("magic", 0, "bad_magic", 0, 0), ci.Mutation{Op: "set_byte", Target: "container", Offset: intp(3), Value: json.RawMessage(`"32"`)})
	add("VS8-012.trailing_byte", malformed("container", len(raw), "trailing_bytes", 1, 0), ci.Mutation{Op: "append_hex", Target: "container", Value: json.RawMessage(`"00"`)})
	// VS8-013: the lists are ascending (a reversed list is the first offending index 1)
	add("VS8-013.nodes_descending", malformed("nodes", 1, "nodes_not_ascending", 0, 0), ci.Mutation{Op: "reorder", Target: "container", List: "nodes"})
	add("VS8-013.codes_descending", malformed("codes", 1, "codes_not_ascending", 0, 0), ci.Mutation{Op: "reorder", Target: "container", List: "codes"})
	// VS8-018 (step 22b): one more node that no walk visits, sorted and unique: nodes_unreferenced at its index
	extra := append([]byte{0xf8, 0x44}, make([]byte, 0x44)...)
	for i := range extra[2:] {
		extra[2+i] = byte(i*7 + 1)
	}
	c, err := ci.Decode(raw, ci.DefaultLimits())
	if err != nil {
		a.t.Fatal(err)
	}
	idx := 0
	for _, n := range c.Nodes {
		if bytes.Compare(crypto.Keccak256(n), crypto.Keccak256(extra)) < 0 {
			idx++
		}
	}
	add("VS8-018.one_unreferenced_node", malformed("nodes", idx, "nodes_unreferenced", 0, 0), ci.Mutation{Op: "add_node", Target: "container", Value: json.RawMessage(`"` + hex.EncodeToString(extra) + `"`)})
	// VS8-182 / VS8-183 (step 23, n2): a judgement R is a refusal only when the state root is authenticated; a framework R always is
	anchor := hexAddr(sp.Roles.Anchor)
	hole := []ci.Mutation{world.SetStorage(world.StationPre, anchor, ci.SlotIndex(6), common.Hash{}), world.SetStorage(world.StationPost, anchor, ci.SlotIndex(6), common.Hash{})}
	other := ci.Mutation{Op: "set_field", Target: "s7", Path: "finalized_block.hash", Value: json.RawMessage(`"0x` + strings.Repeat("11", 32) + `"`)}
	e182 := exp(ci.HeadlinePending, nil)
	e182.S7FinalizedStatus = "verified_other_block"
	add("VS8-182.judgement_refusal_not_authenticated", e182, append(append([]ci.Mutation(nil), hole...), other)...)
	// the framework refusal of step 1 halts the run before step 24: the headline is refused whatever S7 says
	add("VS8-183.framework_refusal_not_authenticated", malformed("magic", 0, "bad_magic", 0, 0), ci.Mutation{Op: "set_byte", Target: "container", Offset: intp(3), Value: json.RawMessage(`"32"`)}, other)
	return out
}

func intp(n int) *int { return &n }

func TestVectorSetInt2IsPublishedRunsAndIsReproducible(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	a := &authorInt{t, f}
	vectors := a.vectors2()
	if _, err := os.Stat(setDir(vectorSetInt2)); err != nil && os.Getenv("CERTEN_WRITE_S8_INT2") == "1" {
		if err := world.WriteSet(setDir(vectorSetInt2), f.spec, vectors); err != nil {
			t.Fatal(err)
		}
	}
	set, err := ci.LoadVectorSet(setDir(vectorSetInt2))
	if err != nil {
		t.Fatalf("the set %s is not published: %v", vectorSetInt2, err)
	}
	if len(set.Vectors) != len(vectors) {
		t.Fatalf("published %d vectors, the author defines %d", len(set.Vectors), len(vectors))
	}
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range ci.RunSet(set, nil, ver) {
		if r.Outcome != ci.OutcomePass {
			t.Errorf("%s: %s %s", r.ID, r.Outcome, r.Detail)
		}
	}
	checkPublishedBytes(t, f, vectorSetInt2, vectors)
}
