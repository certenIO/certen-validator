// Copyright 2026 Certen Protocol

package intent

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB4-F46: an intent is proved on the BVN it was written on. Discovery reads a Directory Network block through
// the BVN blocks it anchored and stamped every intent with "acc://dn.acme"; the L1-L3 proof refuses a non-BVN
// partition, so no intent could be proved (Phase C, 2026-09-29: "partition acc://dn.acme ... is not a BVN").
// The discovery pair (the DN block and its height) stays the batch commit pair; the BVN rides beside it.
func TestAnIntentCarriesTheBVNItWasWrittenOn(t *testing.T) {
	id := &IntentDiscovery{logger: log.New(os.Stderr, "", 0)}
	ci, err := id.convertCertenTransactionToIntent(&accumulate.CertenTransaction{
		Hash: strings.Repeat("b2", 32), AccountURL: "acc://harbor.acme/data", BlockHeight: 9987981,
		Partition: "acc://dn.acme", ProofPartition: "bvn1", ProofBlockIndex: 8270001,
		IntentData: map[string]interface{}{
			"intentData":     map[string]interface{}{"intent_id": "f46", "proof_class": "on_demand"},
			"crossChainData": map[string]interface{}{},
			"governanceData": map[string]interface{}{"organizationAdi": "acc://harbor.acme"},
			"replayData":     map[string]interface{}{"expires_at": 1790600000},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ci.ProofPartition != "bvn1" {
		t.Fatalf("the intent is proved on %q; it was written on bvn1", ci.ProofPartition)
	}
	if ci.Partition != "acc://dn.acme" {
		t.Fatalf("the discovery partition (the batch commit pair) became %q", ci.Partition)
	}
}
