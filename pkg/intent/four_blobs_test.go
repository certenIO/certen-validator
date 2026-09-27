// Copyright 2026 Certen Protocol

package intent

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/accumulate"
)

// RB3-F113: a CERTEN intent is exactly its four JSON blobs. A transaction missing one was built with it
// empty; one carrying none had each element's role guessed from its contents.
func TestAnIntentIsExactlyItsFourBlobs(t *testing.T) {
	id := &IntentDiscovery{logger: log.New(os.Stderr, "", 0)}
	four := func() map[string]interface{} {
		return map[string]interface{}{
			"intentData":     map[string]interface{}{"intent_id": "f113", "proof_class": "on_cadence"},
			"crossChainData": map[string]interface{}{},
			"governanceData": map[string]interface{}{"organizationAdi": "acc://harbor.acme"},
			"replayData":     map[string]interface{}{"expires_at": 1790600000},
		}
	}
	build := func(data map[string]interface{}) error {
		_, err := id.convertCertenTransactionToIntent(&accumulate.CertenTransaction{
			Hash: strings.Repeat("b2", 32), AccountURL: "acc://harbor.acme/data", Partition: "BVN1", IntentData: data})
		return err
	}
	if err := build(four()); err != nil {
		t.Fatalf("the four blobs were refused: %v", err)
	}
	missing := four()
	delete(missing, "governanceData")
	if err := build(missing); err == nil {
		t.Error("an intent missing its governance blob was built")
	}
	unlabelled := map[string]interface{}{
		"rawElement_0": map[string]interface{}{"intent_id": "f113"},
		"rawElement_1": map[string]interface{}{"legs": []interface{}{}},
	}
	if err := build(unlabelled); err == nil {
		t.Error("an intent whose blobs had to be guessed was built")
	}
	extra := four()
	extra["additionalData_4"] = map[string]interface{}{"x": 1}
	if err := build(extra); err == nil {
		t.Error("an intent with a fifth element was built")
	}
}
