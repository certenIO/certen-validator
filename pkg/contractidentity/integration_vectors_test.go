// Copyright 2026 Certen Protocol

package contractidentity_test

import (
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
		add("VS8-076.drift_"+c.id, vc(drift(c.id, was, now)), world.SetStorage(world.StationSettle, anchor, c.slot, now))
	}
	// a key rotation after the attestation: the BLS key bytes of one listed validator change at N (the set root does not commit to keys)
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
	add("VS8-076.key_rotation", vc(drift(key+":key", crypto.Keccak256Hash(oldKey), crypto.Keccak256Hash(newKey))),
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
	add("VS8-162.key_not_canonical_is_not_a_registry9", noncanon, ctxSet("registry9.members.2.bls_key", "0x"+k2))

	// VS8-180 (step 23): every outcome prints rules_not_judged, with the reason (the four rows of the "Not judged" paragraph of Policy rules)
	e180 := exp(ci.HeadlineVerified, nil)
	e180.RulesNotJudged = []ci.ExpectedRuleNotJudged{
		{Row: "A21", Reason: "minimumGovernanceLevelForValueOps is read only by executeWithGovernance (CertenAnchorV8_2.sol:1398), not on the attestation path; reported in registry"},
		{Row: "A09:3", Reason: "registeredAt is informational; no acceptance decision reads it"},
		{Row: "slot19:usedNonces", Reason: "restrict-only: its single reader is nonceValid = !usedNonces[...] (CertenAnchorV8_2.sol:2002) and its single writer assigns the literal true (:1352)"},
		{Row: "slot28:operators", Reason: "not read by the attestation path"},
	}
	add("VS8-180.rules_not_judged", e180)
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
