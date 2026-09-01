package consensus_test

// The validator must TOLERATE a subject in blob 0 and must never READ one.
//
// `subject` names the end user an intent is about, so an off-chain policy engine can route a decision
// to the right enrolled person. It is written by the producer into blob 0 and consumed off chain. The
// validator's job here is to keep doing nothing with it — deliberately, and for two reasons:
//
//   - The entitlement verifier may not depend on any self-declared intent field. `PrincipalOf` says why
//     in the file it lives in: the account URL is the ONLY field a submitter cannot forge, because
//     Accumulate's own consensus verified they can sign for it. `subject` is not that; it is an
//     assertion by whoever wrote the intent.
//   - Consensus is deterministic, so anything the validator did read would become a chain rule. An
//     off-chain routing hint is not a chain rule.
//
// So this file adds NO production code. It exists to make "nothing changes here" a thing that fails
// loudly if someone later makes the validator strict about blob-0 shape, or teaches it to read the
// subject.
//
// It is an EXTERNAL test package (`consensus_test`) so it can import `pkg/intent` — which aliases this
// package's own type — without creating an import cycle.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/intent"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// blob0 as a producer writes it. `subject` is the new field; `someFutureField` is a key no version of
// this code has ever heard of, and it is here because forward tolerance is the actual property under
// test — `subject` is only today's instance of it.
func subjectBlob0() map[string]interface{} {
	return map[string]interface{}{
		"kind":            "CERTEN_INTENT",
		"version":         "2.0",
		"proof_class":     "on_demand",
		"intentType":      "single_leg_cross_chain_transfer",
		"organizationAdi": "acc://acme-bank.acme",
		"intent_id":       "INT-2026-0101",
		"created_by":      "ops@acme",
		"subject": map[string]interface{}{
			"adi":        "acc://alice.acme",
			"keyBook":    "acc://alice.acme/book",
			"id":         "cust-99213",
			"assertedBy": "acc://acme-bank.acme",
		},
		"someFutureField": map[string]interface{}{"we": "do not know what this is"},
	}
}

func plainBlob0() map[string]interface{} {
	b := subjectBlob0()
	delete(b, "subject")
	delete(b, "someFutureField")
	return b
}

func otherBlobs() (cross, gov, replay map[string]interface{}) {
	return map[string]interface{}{
			"protocol": "CERTEN",
			"version":  "2.0",
			"legs": []interface{}{map[string]interface{}{
				"legId": "l0", "chain": "ethereum-sepolia", "to": "0xAlice", "amountWei": "1500",
			}},
		},
		map[string]interface{}{
			"organizationAdi": "acc://acme-bank.acme",
			"authorization":   map[string]interface{}{"required_key_book": "acc://acme-bank.acme/book", "signature_threshold": 1},
		},
		map[string]interface{}{"nonce": "certen_1", "expires_at": 4102444800}
}

func build(t *testing.T, blob0 map[string]interface{}) *consensus.CertenIntent {
	t.Helper()
	cross, gov, replay := otherBlobs()
	// Validate() checks the hash length, so this has to be a real 64-hex one.
	ci, err := intent.BuildCertenIntent(strings.Repeat("a1", 32), blob0, cross, gov, replay)
	if err != nil {
		t.Fatalf("BuildCertenIntent: %v", err)
	}
	return ci
}

// A subject-bearing intent must pass validation and parse, with the unknown keys ignored rather than
// rejected. `Validate()` checks JSON well-formedness only, and nothing anywhere uses
// DisallowUnknownFields — this asserts that stays true.
func TestIntentWithSubject_ParsesAndValidates(t *testing.T) {
	ci := build(t, subjectBlob0())

	if err := ci.Validate(); err != nil {
		t.Fatalf("a subject-bearing intent must validate, got: %v", err)
	}

	parsed, err := ci.ParseIntentData()
	if err != nil {
		t.Fatalf("ParseIntentData: %v", err)
	}
	if parsed.Kind != "CERTEN_INTENT" {
		t.Errorf("Kind = %q, want CERTEN_INTENT", parsed.Kind)
	}
	if parsed.IntentID != "INT-2026-0101" {
		t.Errorf("IntentID = %q, want INT-2026-0101", parsed.IntentID)
	}
	if parsed.CreatedBy != "ops@acme" {
		t.Errorf("CreatedBy = %q, want ops@acme", parsed.CreatedBy)
	}
	if parsed.ProofClass != "on_demand" {
		t.Errorf("ProofClass = %q, want on_demand — routing must not be disturbed by a new field", parsed.ProofClass)
	}

	// The raw bytes keep everything, because that is what the commitment is taken over. A struct that
	// dropped the field would still hash correctly (the hash reads the bytes), but the separation is
	// the load-bearing part and it should be visible.
	if !bytes.Contains(ci.IntentData, []byte(`"subject"`)) {
		t.Error("IntentData raw bytes lost the subject; the blob must be retained verbatim")
	}
}

// The operationID is computed from the RAW BYTES, not from a re-marshalled struct — which is the whole
// reason an additive field is safe. Two things are asserted: the value agrees with a direct call to the
// canonical hash over the same bytes, and it MOVES when the subject is added, proving the field is
// genuinely inside the commitment rather than being silently dropped somewhere.
func TestIntentWithSubject_OperationIDMatchesRawBytes(t *testing.T) {
	withSubject := build(t, subjectBlob0())
	without := build(t, plainBlob0())

	got, err := withSubject.OperationID()
	if err != nil {
		t.Fatalf("OperationID: %v", err)
	}
	_, wantHex, err := certenproof.ComputeCanonical4BlobHash(
		withSubject.IntentData, withSubject.CrossChainData, withSubject.GovernanceData, withSubject.ReplayData,
	)
	if err != nil {
		t.Fatalf("ComputeCanonical4BlobHash: %v", err)
	}
	if got != "0x"+wantHex {
		t.Errorf("OperationID = %s, want 0x%s — it must be the hash of the published bytes", got, wantHex)
	}

	plain, err := without.OperationID()
	if err != nil {
		t.Fatalf("OperationID (no subject): %v", err)
	}
	if got == plain {
		t.Error("adding a subject did not change the operationID; the field is being dropped before the hash")
	}
}

// `UserID` is the INITIATOR, sourced from created_by. `subject` is who the transaction is ABOUT. They
// are different questions and they must not merge — the temptation to "improve" UserID by reading the
// subject is exactly what this pins.
func TestIntentWithSubject_UserIDStillFromCreatedBy(t *testing.T) {
	ci := build(t, subjectBlob0())

	if ci.UserID != "ops@acme" {
		t.Errorf("UserID = %q, want ops@acme (created_by) — not the subject", ci.UserID)
	}
	if ci.UserID == "acc://alice.acme" {
		t.Error("UserID was taken from the subject; initiator and subject are different parties")
	}
	// And the organization ADI is still the organization's, not the subject's.
	if strings.Contains(ci.OrganizationADI, "alice") {
		t.Errorf("OrganizationADI = %q; the subject must not leak into it", ci.OrganizationADI)
	}
}

// The entitlement gate keys on the account URL, which is the one unforgeable field. A subject in blob 0
// must not change what it sees.
func TestSubjectDoesNotEnterEntitlement(t *testing.T) {
	withSubject := build(t, subjectBlob0())
	without := build(t, plainBlob0())

	vbWith := &consensus.ValidatorBlock{}
	vbWith.AccumulateAnchorReference.AccountURL = withSubject.AccountURL
	vbWithout := &consensus.ValidatorBlock{}
	vbWithout.AccumulateAnchorReference.AccountURL = without.AccountURL

	got := consensus.PrincipalOf(vbWith)
	if got != consensus.PrincipalOf(vbWithout) {
		t.Errorf("PrincipalOf moved when a subject was added: %q vs %q", got, consensus.PrincipalOf(vbWithout))
	}
	if got == "" {
		t.Fatal("PrincipalOf returned empty; the fixture is not exercising the gate's input")
	}
	if strings.Contains(got, "alice") {
		t.Errorf("the principal is %q — the subject reached the one field a submitter cannot forge", got)
	}
}

// Nothing in the validator may READ the subject. This is a source-level assertion because that is the
// only way to state it: a behavioural test can only show that today's code paths ignore the field,
// while the rule is that no code path may consult it at all.
//
// If a genuine need ever arises, deleting this test is the deliberate act that records the decision —
// which is the point of writing it down here rather than in a comment.
func TestNoValidatorCodeReadsTheSubject(t *testing.T) {
	var offenders []string

	for _, root := range []string{"..", "../../cmd"} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// A struct tag reading the field, or a map lookup of it. Prose in a comment is fine.
			for _, pattern := range []string{`json:"subject`, `["subject"]`, `("subject")`} {
				if bytes.Contains(src, []byte(pattern)) {
					offenders = append(offenders, path+" contains "+pattern)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("validator code reads the intent subject, which consensus determinism forbids:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// Belt and braces on the tolerance claim: a blob 0 carrying keys this binary has never seen must
// round-trip through the generic canonicalizer without loss, because the commitment is taken over the
// bytes and not over any struct's view of them.
func TestUnknownBlob0KeysSurviveCanonicalization(t *testing.T) {
	ci := build(t, subjectBlob0())

	var back map[string]interface{}
	if err := json.Unmarshal(ci.IntentData, &back); err != nil {
		t.Fatalf("unmarshal IntentData: %v", err)
	}
	if _, ok := back["someFutureField"]; !ok {
		t.Error("an unknown blob-0 key was dropped; forward tolerance is the property that makes additive change safe")
	}
	subj, ok := back["subject"].(map[string]interface{})
	if !ok {
		t.Fatal("subject is not an object in the retained bytes")
	}
	if subj["adi"] != "acc://alice.acme" {
		t.Errorf("subject.adi = %v, want acc://alice.acme", subj["adi"])
	}
}
