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

// A leg value reads exactly as its author's BigInt did: "0x" is hexadecimal, anything else decimal.
func TestALegValueReadsAsItsAuthorComputedIt(t *testing.T) {
	for in, want := range map[string]int64{"": 0, "0": 0, "16": 16, "0x10": 16, "0X10": 16, "0xff": 255, " 7 ": 7} {
		got, err := ParseLegValue(in)
		if err != nil || got.Int64() != want {
			t.Errorf("%q: (%v, %v), want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"0x", "-1", "+1", "0x-1", "abc", "0xzz", "1.5", "1e3"} {
		if v, err := ParseLegValue(bad); err == nil {
			t.Errorf("%q accepted as %v", bad, v)
		}
	}
}

// The commitment states the member's target and value as the settlement parses them: a TRON or malformed
// target is an error (it was base58-decoded, or silently HexToAddress'd), a hex value is its number.
func TestTheCommitmentStatesWhatTheSettlementExecutes(t *testing.T) {
	bv := refusalValidator(newFakeEnqueuer())
	var bundle [32]byte
	set := func(target, value string) *CertenIntent {
		ci := batchableIntent(t, "i-target", 84532)
		var env map[string]interface{}
		if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
			t.Fatal(err)
		}
		ep := env["legs"].([]interface{})[0].(map[string]interface{})["executionPayload"].(map[string]interface{})
		ep["target"], ep["value"] = target, value
		ci.CrossChainData, _ = json.Marshal(env)
		return ci
	}
	c, err := bv.buildExecutionCommitmentFromIntent(set("0x2222222222222222222222222222222222222222", "0x10"), bundle, 84532)
	if err != nil || c["finalValue"] != "16" {
		t.Fatalf("hex value: (%v, %v)", c["finalValue"], err)
	}
	for _, bad := range []string{"TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE", "0x1234", "not-an-address", ""} {
		if _, err := bv.buildExecutionCommitmentFromIntent(set(bad, "1"), bundle, 84532); err == nil {
			t.Errorf("target %q produced a commitment", bad)
		}
	}
}

// The settled leg carries the author's number: "0x10" is 16 wei, not 10.
func TestTheSettledLegCarriesTheAuthorsValue(t *testing.T) {
	ci := batchableIntent(t, "i-hex", 84532)
	var env map[string]interface{}
	if err := json.Unmarshal(ci.CrossChainData, &env); err != nil {
		t.Fatal(err)
	}
	env["legs"].([]interface{})[0].(map[string]interface{})["executionPayload"].(map[string]interface{})["value"] = "0x10"
	ci.CrossChainData, _ = json.Marshal(env)
	legs, _, _, _, err := MemberLegsForChain(ci, 84532)
	if err != nil || legs[0].Value.Int64() != 16 {
		t.Fatalf("value 0x10 read as %v (%v), want 16", legs[0].Value, err)
	}
}
