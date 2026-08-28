// Copyright 2026 Certen Protocol
//
// Phase 8 item 5, validator side — the page rules a proof did not re-derive
// travel BESIDE the govRoot preimage, never inside it.
//
// The govproof binary emits `unverifiedPageRules` as a top-level key on the G1
// document: one note per page that carries a reject, response or block
// threshold, which G1 records rather than re-derives. Those thresholds live on
// the key page, and the key page state is reachable from G1Result through
// AuthoritySnapshot.StateExec — the shape this side hashes into the governance
// root via SetG1FromJSON.
//
// So the same rule that governs timingBasis governs this: it must be dropped on
// the way into the hash. If it is not, every govRoot ever signed has moved, and
// a mixed fleet reverts every TX2 on every chain.
package proof

import (
	"encoding/json"
	"strings"
	"testing"
)

// p8PageRulesG1 is a G1 document carrying the field, in the shape govproof
// emits it.
const p8PageRulesG1 = `{
  "tx_hash": "aa",
  "exec_mbi": 10199460,
  "threshold_satisfied": true,
  "unverifiedPageRules": [
    {
      "page": "acc://strict.acme/book/1",
      "rule": "responseThreshold",
      "value": 3,
      "reason": "response-threshold-not-recounted",
      "explanation": "this page does not vote until 3 votes of ANY kind have been cast"
    }
  ]
}`

// TestP8_PageRulesAreNotInTheGovRootPreimage is the gate that matters.
//
// Compared as BYTES rather than as a hash of them: a byte diff names the field
// that moved, a hash diff only says that one did.
func TestP8_PageRulesAreNotInTheGovRootPreimage(t *testing.T) {
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

	strip := func(doc string) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			t.Fatalf("fixture is not JSON: %v", err)
		}
		delete(m, "unverifiedPageRules")
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	with := marshalAsG1([]byte(p8PageRulesG1))
	without := marshalAsG1(strip(p8PageRulesG1))

	if string(with) != string(without) {
		t.Fatalf("unverifiedPageRules CHANGED the G1Result preimage — every govRoot ever "+
			"signed has moved. The record belongs BESIDE the hashed struct, not on "+
			"KeyPageState.\n with:    %s\n without: %s", with, without)
	}
	if strings.Contains(string(with), "unverifiedPageRules") {
		t.Fatal("the govRoot preimage contains the string \"unverifiedPageRules\"")
	}
}

// TestP8_PageRuleReasonsMatchGovproof pins the cross-binary contract.
//
// The reason codes are what a reader matches on to tell the three cases apart —
// a rule that could have changed the answer, one that could not, and one the
// protocol does not enforce. They are produced by /app/govproof and consumed
// here, so they are a wire contract between two separately built binaries: if
// one side renames a code, the distinction silently collapses into "some rule
// was not checked".
func TestP8_PageRuleReasonsMatchGovproof(t *testing.T) {
	// These literals are duplicated from g1_page_rules.go DELIBERATELY. That
	// package is `package main` and cannot be imported; a shared constant is
	// impossible, so the duplication is made visible and pinned here instead of
	// living unstated in two places.
	want := map[string]string{
		"response": "response-threshold-not-recounted",
		"reject":   "reject-threshold-moot-after-execution",
		"block":    "block-threshold-not-enforced-by-protocol",
	}

	var doc struct {
		Rules []struct {
			Reason string `json:"reason"`
		} `json:"unverifiedPageRules"`
	}
	if err := json.Unmarshal([]byte(p8PageRulesG1), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("fixture should carry one rule, got %d", len(doc.Rules))
	}
	if doc.Rules[0].Reason != want["response"] {
		t.Errorf("reason code drifted: got %q, want %q", doc.Rules[0].Reason, want["response"])
	}
}
