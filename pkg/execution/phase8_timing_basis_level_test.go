// Copyright 2026 Certen Protocol
//
// Phase 8 item 2, the storage hop: the timing basis reaches level_json BESIDE
// the result, and its absence is not a claim.
//
// pkg/proof proves the record is built correctly and reaches no hash. This
// proves it survives the last hop — the one Stage 2 found was where the real
// G-results had been dying all along, silently, for 401 rows.
package execution

import (
	"encoding/json"
	"testing"

	certenproof "github.com/certen/independant-validator/pkg/proof"
)

func p8Basis(level, signerPage, principalPage string, localChecked bool) certenproof.SignatureTimingBasis {
	basis := certenproof.TimingBasisExecutionInclusion
	if localChecked {
		basis = certenproof.TimingBasisLocalOrdering
	}
	return certenproof.SignatureTimingBasis{
		Level:                level,
		MessageID:            "acc://ab@" + signerPage,
		MessageHash:          "ab",
		SignerPage:           signerPage,
		PrincipalPage:        principalPage,
		LocalOrderingChecked: localChecked,
		ReceiptLocalBlock:    10200307,
		ExecMBI:              10199460,
		Basis:                basis,
	}
}

// TestP8_TimingBasisReachesLevelJSON: a cross-partition proof's stored row names
// the signature whose ordering rests on execution inclusion.
func TestP8_TimingBasisReachesLevelJSON(t *testing.T) {
	tb := []certenproof.SignatureTimingBasis{
		p8Basis("G1", "acc://certen-p7f-omega.acme/book/1", "acc://certen-kermit-12.acme/book/1", false),
	}
	out := BuildGovernanceLevelJSON("G1", json.RawMessage(`{"threshold_satisfied":true}`), nil, tb,
		map[string]interface{}{"level": "G1", "verified": true})

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("level_json is not valid JSON: %v", err)
	}
	raw, ok := obj[GovLevelTimingBasisKey]
	if !ok {
		t.Fatalf("level_json carries no %q key; a reader of this row cannot tell which counted "+
			"signature's timing rests on the weaker basis", GovLevelTimingBasisKey)
	}

	// The flags that were already there must survive. The evidence report and
	// the approval console read them.
	for _, k := range []string{"level", "verified"} {
		if _, ok := obj[k]; !ok {
			t.Errorf("key %q was dropped; level_json must be additive", k)
		}
	}
	if _, ok := obj[GovLevelResultKey]; !ok {
		t.Error("the result key was dropped")
	}

	var got []certenproof.SignatureTimingBasis
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("stored timing basis does not round-trip: %v", err)
	}
	if len(certenproof.WeakenedTimingBasis(got)) != 1 {
		t.Fatalf("the stored row does not name the weakened signature: %+v", got)
	}
}

// TestP8_SamePartitionRowNamesNothingWeakened is the other half: an ordinary
// proof's row carries the records and names none of them weakened.
func TestP8_SamePartitionRowNamesNothingWeakened(t *testing.T) {
	tb := []certenproof.SignatureTimingBasis{
		p8Basis("G1", "acc://certen-kermit-12.acme/book/1", "acc://certen-kermit-12.acme/book/1", true),
	}
	out := BuildGovernanceLevelJSON("G1", json.RawMessage(`{"threshold_satisfied":true}`), nil, tb, nil)

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	var got []certenproof.SignatureTimingBasis
	if err := json.Unmarshal(obj[GovLevelTimingBasisKey], &got); err != nil {
		t.Fatal(err)
	}
	if n := len(certenproof.WeakenedTimingBasis(got)); n != 0 {
		t.Fatalf("a same-partition row named %d signature(s) as weakened; it must name none", n)
	}
}

// TestP8_AbsentTimingBasisWritesNoKey: an empty array in the row would assert
// "we looked, and none were weakened". A generator that recorded nothing must
// produce no key at all, so the two cannot be confused.
func TestP8_AbsentTimingBasisWritesNoKey(t *testing.T) {
	for _, tb := range [][]certenproof.SignatureTimingBasis{nil, {}} {
		out := BuildGovernanceLevelJSON("G1", json.RawMessage(`{"x":1}`), nil, tb, nil)
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatal(err)
		}
		if _, ok := obj[GovLevelTimingBasisKey]; ok {
			t.Errorf("an absent timing basis wrote a %q key; absence must stay absence",
				GovLevelTimingBasisKey)
		}
	}
}

// TestP8_TimingBasisIsFiledPerLevel: G1's signature set must not be borrowed for
// G0 or G2. ReceiptFor legitimately falls back across levels because all three
// describe one execution receipt; the timing basis is per signature and has no
// such shared meaning.
func TestP8_TimingBasisIsFiledPerLevel(t *testing.T) {
	in := &GovernanceLevelInputs{
		TimingBasis: []certenproof.SignatureTimingBasis{
			p8Basis("G1", "acc://certen-p7f-omega.acme/book/1", "acc://certen-kermit-12.acme/book/1", false),
			p8Basis("G2", "acc://certen-p7f-omega.acme/book/1", "acc://certen-kermit-12.acme/book/1", false),
		},
	}
	if n := len(in.TimingBasisFor("G1")); n != 1 {
		t.Errorf("G1 got %d record(s), want 1", n)
	}
	if n := len(in.TimingBasisFor("G2")); n != 1 {
		t.Errorf("G2 got %d record(s), want 1", n)
	}
	if n := len(in.TimingBasisFor("G0")); n != 0 {
		t.Errorf("G0 got %d record(s); G0 evaluates no signatures and must borrow none", n)
	}
}
