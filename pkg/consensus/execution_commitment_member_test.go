// Copyright 2026 Certen Protocol

package consensus

import (
	"encoding/json"
	"strings"
	"testing"
)

// RB3-F66: a member's execution commitment is the member's - its own chain's signed leg - and states
// nothing the intent does not bind. Live on intent 3b990fe3 it named the retired Sepolia anchor 0x4C8F…
// and the retired V3 three-step workflow, and every write-back carried both.
func TestExecutionCommitmentIsTheMembersOwn(t *testing.T) {
	ci := batchableIntent(t, "i-commit", 11155111, 84532)
	// Give each chain's leg its own committed target and value.
	var env map[string]interface{}
	if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
		t.Fatal(err)
	}
	legs := env["legs"].([]interface{})
	legs[0].(map[string]interface{})["executionPayload"].(map[string]interface{})["target"] = "0x1111111111111111111111111111111111111111"
	legs[1].(map[string]interface{})["executionPayload"].(map[string]interface{})["target"] = "0x2222222222222222222222222222222222222222"
	legs[1].(map[string]interface{})["executionPayload"].(map[string]interface{})["value"] = "7"
	legs[1].(map[string]interface{})["to"] = "0x9999999999999999999999999999999999999999" // never the executed target
	ci.CrossChainData, _ = json.Marshal(env)

	bv := refusalValidator(newFakeEnqueuer())
	var bundle [32]byte
	bundle[0] = 0xab

	base, err := bv.buildExecutionCommitmentFromIntent(ci, bundle, 84532)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(base["finalTarget"].(string), "0x2222222222222222222222222222222222222222") || base["finalValue"] != "7" {
		t.Fatalf("Base member states target %v value %v; want its own committed leg (0x2222…, 7)", base["finalTarget"], base["finalValue"])
	}
	if base["chainID"] != int64(84532) {
		t.Fatalf("chainID %v, want the member's chain 84532", base["chainID"])
	}
	for _, k := range []string{"anchorContract", "step1", "step2", "step3", "expectedEvents", "verified", "createdAt"} {
		if _, ok := base[k]; ok {
			t.Fatalf("the commitment states %q, which the signed intent does not bind", k)
		}
	}
	blob, _ := json.Marshal(base)
	if strings.Contains(strings.ToLower(string(blob)), "4c8f0141") {
		t.Fatal("the commitment names the retired Sepolia anchor")
	}

	// Reproducible: the same member always commits to the same hash.
	again, err := bv.buildExecutionCommitmentFromIntent(ci, bundle, 84532)
	if err != nil || again["commitmentHash"] != base["commitmentHash"] {
		t.Fatalf("commitment hash not reproducible: %v vs %v (%v)", base["commitmentHash"], again["commitmentHash"], err)
	}
	sep, err := bv.buildExecutionCommitmentFromIntent(ci, bundle, 11155111)
	if err != nil || sep["commitmentHash"] == base["commitmentHash"] ||
		!strings.EqualFold(sep["finalTarget"].(string), "0x1111111111111111111111111111111111111111") {
		t.Fatalf("Sepolia member: %v (%v)", sep, err)
	}

	if _, err := bv.buildExecutionCommitmentFromIntent(ci, bundle, 421614); err == nil {
		t.Fatal("a chain the intent has no leg on must be an error, not a commitment for another chain's leg")
	}
}
