// Copyright 2026 Certen Protocol

package intent

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB3-F112: the account a proof is built for is the transaction's discovered principal, never the
// intent's self-declared organization. With no principal read, the conversion used to leave the account
// derived from the declared ADI - the attacker-controlled value discovery's own comment warns about.
func TestAnIntentIsNeverProvedAgainstItsDeclaredOrganization(t *testing.T) {
	id := &IntentDiscovery{logger: log.New(os.Stderr, "", 0)}
	tx := func(principal string) *accumulate.CertenTransaction {
		return &accumulate.CertenTransaction{
			Hash: strings.Repeat("a1", 32), AccountURL: principal, Partition: "BVN1",
			IntentData: map[string]interface{}{
				"intentData":     map[string]interface{}{"intent_id": "f112", "proof_class": "on_cadence"},
				"crossChainData": map[string]interface{}{},
				"governanceData": map[string]interface{}{"organizationAdi": "acc://victim.acme"},
				"replayData":     map[string]interface{}{"expires_at": 1790600000},
			},
		}
	}
	if ci, err := id.convertCertenTransactionToIntent(tx("")); err == nil {
		t.Fatalf("an intent with no discovered principal was built for %q", ci.AccountURL)
	}
	ci, err := id.convertCertenTransactionToIntent(tx("acc://harbor.acme/data"))
	if err != nil {
		t.Fatal(err)
	}
	if ci.AccountURL != "acc://harbor.acme/data" || ci.OrganizationADI != "acc://harbor.acme" {
		t.Fatalf("account %q org %q; want the discovered principal", ci.AccountURL, ci.OrganizationADI)
	}
}

// The single- and multi-leg paths refuse rather than derive an account or default a proof class.
func TestNoAccountIsDerivedAndNoProofClassDefaulted(t *testing.T) {
	raw, err := os.ReadFile("discovery.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if strings.Contains(src, `accountURL = fmt.Sprintf("%s/data", intent.OrganizationADI)`) {
		t.Error("an account is still derived from the declared organization")
	}
	if strings.Contains(src, `proofClass = "on_cadence"`) {
		t.Error("an unreadable proof class is still defaulted")
	}
}
