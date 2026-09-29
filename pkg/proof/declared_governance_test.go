// Copyright 2026 Certen Protocol

package proof

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// RB4-F64d: the governance an intent declares is checked against the governance its vote record says executed it.

// intentWith builds an intent writeData whose governance blob is gov, as its vote evidence would carry it.
func intentWith(t *testing.T, gov string) *govvote.Evidence {
	t.Helper()
	u, err := url.Parse("acc://rb4-phase-c-09282125.acme/data")
	if err != nil {
		t.Fatal(err)
	}
	txn := &protocol.Transaction{Body: &protocol.WriteData{Entry: &protocol.DoubleHashDataEntry{Data: [][]byte{
		[]byte(`{"intent":1}`), []byte(`{"legs":[]}`), []byte(gov), []byte(`{"nonce":1}`)}}}}
	txn.Header.Principal = u
	b, err := txn.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return &govvote.Evidence{Transaction: hex.EncodeToString(b)}
}

func phaseCRecord(t *testing.T) *AuthorizationRecord {
	t.Helper()
	_, rec, _ := voteEvidenceFixture(t, "vote_evidence_g1_phasec_98e40472.json")
	return rec
}

// The live Phase C intent was built by a bridge that declared no authority set: nothing to check, said so.
func TestDeclaredGovernance_ALiveIntentWithoutADeclaration(t *testing.T) {
	_, _, raw := voteEvidenceFixture(t, "vote_evidence_g1_phasec_98e40472.json")
	ev, _ := VoteEvidenceFromRaw(raw)
	d, err := DeclaredGovernanceOfEvidence(ev)
	if err != nil || d != nil {
		t.Fatalf("declared %+v, err %v; the Phase C intent declares no authority set", d, err)
	}
	if DescribeDeclaredGovernance(nil) != "no declared authority set" {
		t.Fatal("an undeclared set is not named")
	}
}

func TestDeclaredGovernance_TheDeclaredSetMustBeTheOneThatExecuted(t *testing.T) {
	rec := phaseCRecord(t)
	if len(rec.Authorities) != 1 || rec.Authorities[0].Authority != "acc://rb4-phase-c-09282125.acme/book" {
		t.Fatalf("the Phase C record's authorities: %+v", rec.Authorities)
	}
	match := `{"authorization":{"required_key_page":"acc://rb4-phase-c-09282125.acme/book/1",
		"authorities":[{"url":"acc://RB4-phase-c-09282125.acme/book","disabled":false}]}}`
	d, err := DeclaredGovernanceOfEvidence(intentWith(t, match))
	if err != nil || d == nil {
		t.Fatalf("declared %+v, err %v", d, err)
	}
	if err := CheckDeclaredGovernance(d, rec); err != nil {
		t.Fatalf("the governance that executed the intent is refused as undeclared: %v", err)
	}

	for name, gov := range map[string]string{
		"another authority": `{"authorization":{"authorities":[{"url":"acc://other.acme/book","disabled":false}]}}`,
		"one more authority": `{"authorization":{"authorities":[{"url":"acc://rb4-phase-c-09282125.acme/book","disabled":false},
			{"url":"acc://other.acme/book","disabled":false}]}}`,
		"declared disabled": `{"authorization":{"authorities":[{"url":"acc://rb4-phase-c-09282125.acme/book","disabled":true}]}}`,
		"an additional authority the transaction did not require": `{"authorization":{"authorities":[{"url":
			"acc://rb4-phase-c-09282125.acme/book","disabled":false}],"additional_authorities":["acc://other.acme/book"]}}`,
	} {
		d, err := DeclaredGovernanceOfEvidence(intentWith(t, gov))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = CheckDeclaredGovernance(d, rec)
		if !errors.Is(err, ErrDeclaredGovernanceMismatch) {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: %v", name, err)
	}
}

// A declaration that is present and cannot be read is refused, never read as absent.
func TestDeclaredGovernance_AMalformedDeclarationIsNotAnAbsentOne(t *testing.T) {
	for name, gov := range map[string]string{
		"not a list":     `{"authorization":{"authorities":"acc://p.acme/book"}}`,
		"unknown field":  `{"authorization":{"authorities":[{"url":"acc://p.acme/book","weight":2}]}}`,
		"empty":          `{"authorization":{"authorities":[]}}`,
		"no url":         `{"authorization":{"authorities":[{"disabled":false}]}}`,
		"twice":          `{"authorization":{"authorities":[{"url":"acc://p.acme/book"},{"url":"acc://P.acme/book"}]}}`,
		"bad additional": `{"authorization":{"authorities":[{"url":"acc://p.acme/book"}],"additional_authorities":[7]}}`,
		"blob not JSON":  `authorization`,
	} {
		if d, err := DeclaredGovernanceOfEvidence(intentWith(t, gov)); err == nil {
			t.Fatalf("%s: read as %+v", name, d)
		}
	}
	if d, err := DeclaredGovernanceOfEvidence(intentWith(t, `{"authorization":{"required_key_page":"acc://p.acme/book/1"}}`)); err != nil || d != nil {
		t.Fatalf("a governance blob without authorities: %+v %v", d, err)
	}
}
