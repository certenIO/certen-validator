// Copyright 2026 Certen Protocol
//
// Phase 8 item 2 — the weakened cross-partition timing basis is RECORDED, and
// recording it moves no hash.
//
// Three claims are under test, and they are the three that can go wrong:
//
//  1. a cross-partition signature is NAMED as resting on execution inclusion,
//     and a same-partition one is not;
//  2. an ABSENT record does not read as "every signature was locally ordered";
//  3. the record cannot reach the govRoot preimage — the G1Result parsed from
//     a document that carries it is byte-identical to one parsed from a
//     document that does not.
//
// (3) is the one the runbook gates on. The obvious implementation — a field on
// ValidatedSignature — would satisfy (1) and (2) and silently move every
// govRoot ever signed.
package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A G1 document as the govproof CLI emits it for a DELEGATED, cross-partition
// transaction: the principal's page is on certen-kermit-12.acme (BVN1) and the
// delegated signer is on certen-p7f-omega.acme (BVN2). Those two identities
// really do route to different partitions on Kermit — verified live by
// `p7corpus -stage partitions` — which is what makes the second signature's
// localBlock incomparable to execMBI.
//
// Note that BOTH signatures carry timingVerified: true in validated_signatures.
// That is the condition this evidence exists to qualify.
const p8CrossPartitionG1 = `{
  "tx_hash": "aa",
  "exec_mbi": 10199460,
  "validated_signatures": [
    {"messageID": "acc://11@acc://certen-kermit-12.acme/book/1", "timingVerified": true},
    {"messageID": "acc://22@acc://certen-p7f-omega.acme/book/1", "timingVerified": true}
  ],
  "threshold_satisfied": true,
  "timingBasis": [
    {"messageID": "acc://11@acc://certen-kermit-12.acme/book/1",
     "messageHash": "11",
     "signerPage": "acc://certen-kermit-12.acme/book/1",
     "signerIdentity": "certen-kermit-12.acme",
     "principalPage": "acc://certen-kermit-12.acme/book/1",
     "principalIdentity": "certen-kermit-12.acme",
     "localOrderingChecked": true,
     "receiptLocalBlock": 10199455,
     "execMBI": 10199460,
     "basis": "local-ordering"},
    {"messageID": "acc://22@acc://certen-p7f-omega.acme/book/1",
     "messageHash": "22",
     "signerPage": "acc://certen-p7f-omega.acme/book/1",
     "signerIdentity": "certen-p7f-omega.acme",
     "principalPage": "acc://certen-kermit-12.acme/book/1",
     "principalIdentity": "certen-kermit-12.acme",
     "localOrderingChecked": false,
     "receiptLocalBlock": 10200307,
     "execMBI": 10199460,
     "basis": "execution-inclusion"}
  ]
}`

// The same document with only the same-partition signature — the shape every
// proof on record has.
const p8SamePartitionG1 = `{
  "tx_hash": "aa",
  "exec_mbi": 10199460,
  "validated_signatures": [
    {"messageID": "acc://11@acc://certen-kermit-12.acme/book/1", "timingVerified": true}
  ],
  "threshold_satisfied": true,
  "timingBasis": [
    {"messageID": "acc://11@acc://certen-kermit-12.acme/book/1",
     "messageHash": "11",
     "signerPage": "acc://certen-kermit-12.acme/book/1",
     "signerIdentity": "certen-kermit-12.acme",
     "principalPage": "acc://certen-kermit-12.acme/book/1",
     "principalIdentity": "certen-kermit-12.acme",
     "localOrderingChecked": true,
     "receiptLocalBlock": 10199455,
     "execMBI": 10199460,
     "basis": "local-ordering"}
  ]
}`

// TestP8_CrossPartitionTimingIsNamed is Gate 2's third criterion.
func TestP8_CrossPartitionTimingIsNamed(t *testing.T) {
	tb := TimingBasisFromRaw("G1", json.RawMessage(p8CrossPartitionG1))
	if len(tb) != 2 {
		t.Fatalf("expected 2 timing records, got %d", len(tb))
	}

	weak := WeakenedTimingBasis(tb)
	if len(weak) != 1 {
		t.Fatalf("expected exactly 1 signature on the weaker basis, got %d", len(weak))
	}
	w := weak[0]
	if w.SignerPage != "acc://certen-p7f-omega.acme/book/1" {
		t.Errorf("the wrong signature was named as weakened: %s", w.SignerPage)
	}
	if w.Basis != TimingBasisExecutionInclusion {
		t.Errorf("basis = %q, want %q", w.Basis, TimingBasisExecutionInclusion)
	}
	if w.LocalOrderingChecked {
		t.Error("a weakened record must not claim the local ordering check ran")
	}

	// The two numbers that were deliberately NOT compared are both present, so
	// a reader can see that comparing them WOULD have produced a rejection —
	// which is precisely why the comparison was skipped.
	if w.ReceiptLocalBlock <= w.ExecMBI {
		t.Errorf("fixture is not the interesting case: localBlock %d <= execMBI %d means "+
			"the comparison would have passed anyway", w.ReceiptLocalBlock, w.ExecMBI)
	}

	// The partitions are named from THIS module's routing table — the one
	// production routes proof legs with — not from anything the generator said.
	if !strings.EqualFold(w.SignerPartition, "bvn2") {
		t.Errorf("signer partition = %q, want bvn2", w.SignerPartition)
	}
	if !strings.EqualFold(w.PrincipalPartition, "bvn1") {
		t.Errorf("principal partition = %q, want bvn1", w.PrincipalPartition)
	}
	if strings.EqualFold(w.SignerPartition, w.PrincipalPartition) {
		t.Error("a signature recorded as cross-partition resolved to ONE partition; " +
			"either the record or the routing table is wrong, and either way the " +
			"skipped comparison cannot be justified")
	}
}

// TestP8_SamePartitionNamesNoWeakerBasis is the other half of Gate 2's third
// criterion: the marker must not appear on an ordinary proof.
func TestP8_SamePartitionNamesNoWeakerBasis(t *testing.T) {
	tb := TimingBasisFromRaw("G1", json.RawMessage(p8SamePartitionG1))
	if len(tb) != 1 {
		t.Fatalf("expected 1 timing record, got %d", len(tb))
	}
	if weak := WeakenedTimingBasis(tb); len(weak) != 0 {
		t.Fatalf("a same-partition proof named %d signature(s) as weakened; it must name none", len(weak))
	}
	if tb[0].Basis != TimingBasisLocalOrdering {
		t.Errorf("basis = %q, want %q", tb[0].Basis, TimingBasisLocalOrdering)
	}
	if !tb[0].LocalOrderingChecked {
		t.Error("a same-partition signature must record that the local check ran")
	}
}

// TestP8_AbsentTimingBasisIsNotAClaim: a govproof build predating this evidence
// emits no timingBasis at all. That must come back as ABSENCE, never as an
// empty set of weakened signatures — the two read identically to
// WeakenedTimingBasis and mean opposite things.
func TestP8_AbsentTimingBasisIsNotAClaim(t *testing.T) {
	for _, doc := range []string{
		`{"tx_hash":"aa","threshold_satisfied":true}`, // no such field
		`{"tx_hash":"aa","timingBasis":[]}`,           // present and empty
		``,                                            // nothing at all
	} {
		if tb := TimingBasisFromRaw("G1", json.RawMessage(doc)); tb != nil {
			t.Errorf("document %q produced %d record(s); an absent basis must be nil so a "+
				"reader cannot mistake it for 'checked, none weakened'", doc, len(tb))
		}
	}
}

// TestP8_G0CarriesNoTimingBasis: a G0 result evaluates no signatures, so it has
// no timing claim to qualify. Filed under its own level or not at all — never
// borrowed from another level's signature set, the way ReceiptFor legitimately
// borrows the shared execution receipt.
func TestP8_G0CarriesNoTimingBasis(t *testing.T) {
	tb := TimingBasisFromRaw("G1", json.RawMessage(p8CrossPartitionG1))
	if got := TimingBasisFor(tb, "G0"); len(got) != 0 {
		t.Fatalf("G1 records leaked into G0: got %d", len(got))
	}
	if got := TimingBasisFor(tb, "G1"); len(got) != 2 {
		t.Fatalf("G1 records not filed under G1: got %d", len(got))
	}
}

// TestP8_TimingBasisIsNotInTheGovRootPreimage is the gate that matters.
//
// The govRoot commits to CanonicalJSONMarshal(G1Result). If parsing a document
// that carries timingBasis yields a G1Result that marshals differently from one
// parsed without it, the field reached the preimage and every govRoot moved.
//
// Compared as BYTES, not as a hash of them: a byte diff says which field moved,
// a hash diff only says that one did.
func TestP8_TimingBasisIsNotInTheGovRootPreimage(t *testing.T) {
	strip := func(doc string) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("fixture is not JSON: %v", err)
		}
		delete(m, "timingBasis")
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	marshalAsG1 := func(raw []byte) []byte {
		var g1 G1Result
		if err := json.Unmarshal(raw, &g1); err != nil {
			t.Fatalf("parse G1Result: %v", err)
		}
		// The same call SetG1FromJSON makes, minus the hashing step.
		out, err := json.Marshal(&g1)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	with := marshalAsG1([]byte(p8CrossPartitionG1))
	without := marshalAsG1(strip(p8CrossPartitionG1))

	if string(with) != string(without) {
		t.Fatalf("timingBasis CHANGED the G1Result preimage — every govRoot ever signed has "+
			"moved. Put the marker BESIDE the hashed struct, not inside it.\n with:    %s\n without: %s",
			with, without)
	}
	if strings.Contains(string(with), "timingBasis") {
		t.Fatal("the govRoot preimage contains the string \"timingBasis\"")
	}
}

// TestP8_TimingBasisConstantsMatchGovproof pins the cross-binary contract.
//
// consolidated_governance-proof is `package main` and ships as a separate
// executable (/app/govproof), so its constants cannot be imported — there is
// nothing to import. The two sides agree by string, and a string agreement that
// nothing checks is a string agreement that will drift. This reads the
// generator's source and requires the literals to match.
func TestP8_TimingBasisConstantsMatchGovproof(t *testing.T) {
	src := filepath.Join("..", "..", "accumulate-lite-client-2", "liteclient", "proof",
		"consolidated_governance-proof", "g1_timing_basis.go")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("cannot read the generator's source at %s: %v — if this file moved, the "+
			"contract between the two binaries is no longer checked anywhere", src, err)
	}
	got := string(b)
	for _, want := range []string{
		`TimingBasisLocalOrdering = "` + TimingBasisLocalOrdering + `"`,
		`TimingBasisExecutionInclusion = "` + TimingBasisExecutionInclusion + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("govproof does not declare %s — the validator would read a basis string "+
				"the generator never emits, and every signature would look locally ordered", want)
		}
	}
	// The JSON tags the side read depends on. A rename on the generator side
	// would make TimingBasisFromRaw return nil, which reads as "no records"
	// rather than as a broken contract.
	for _, tag := range []string{`json:"timingBasis,omitempty"`} {
		if !strings.Contains(readGovproofTypes(t), tag) {
			t.Errorf("govproof G1Result no longer carries %s; the side read would silently "+
				"find nothing", tag)
		}
	}
}

func readGovproofTypes(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "accumulate-lite-client-2", "liteclient",
		"proof", "consolidated_governance-proof", "types.go"))
	if err != nil {
		t.Fatalf("cannot read govproof types.go: %v", err)
	}
	return string(b)
}
