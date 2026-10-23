// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// The real direct-route vector is NOT superseded by the wallet rule: set 1's real_valid keeps its recorded verdict (route direct), is in
// neither superseded map, and set 3 carries it again under the pins file with the wallet pins with the same literal.
func TestTheRealDirectRouteVectorIsUnchanged(t *testing.T) {
	f1, f3 := loadSet(t, vectorDir), loadSet(t, vectorDir3)
	find := func(f vFile, n string) vVec {
		for _, v := range f.Vectors {
			if v.Name == n {
				return v
			}
		}
		t.Fatalf("%s: no vector %s", f.dir, n)
		return vVec{}
	}
	r1, r3 := find(f1, "real_valid"), find(f3, "real_valid_direct_route_unchanged")
	if _, ok := supersededInSet3["real_valid"]; ok {
		t.Fatal("real_valid must not be superseded")
	}
	if _, ok := supersededInSet2To3["real_valid"]; ok {
		t.Fatal("real_valid must not be superseded")
	}
	if !strings.Contains(r1.Expect, `"confirmation_route":"direct"`) || r3.Expect != r1.Expect {
		t.Fatalf("set 1: %s\nset 3: %s", r1.Expect, r3.Expect)
	}
	if got := outcome(arbfinal.New().Verify(pinsOf(t, f1, r1), legOf(t, r1), evidenceOf(t, f1, r1))); got != r1.Expect {
		t.Errorf("set 1 real vector: got %s", got)
	}
	if got := outcome(arbfinal.New().Verify(pinsOf(t, f3, r3), legOf(t, r3), evidenceOf(t, f3, r3))); got != r1.Expect {
		t.Errorf("set 3 real vector: got %s", got)
	}
}

// outcomeKind is the part of an expected literal that names what the state is: the code and its reason or path, or the route.
func outcomeKind(expect string) string {
	var o struct {
		Code   string            `json:"code"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal([]byte(expect), &o); err != nil {
		return "unparsable: " + expect
	}
	for _, k := range []string{"reason", "path", "confirmation_route", "which"} {
		if v, ok := o.Fields[k]; ok {
			return o.Code + "/" + k + "=" + v
		}
	}
	return o.Code
}

// Every superseded case of sets 1 and 2 is carried again in set 3 with a wallet proof, and the proven world answers what the recorded
// literal says: the recorded expectation is what a verifier that proves the wallet answers; the unproven world answers indirect.
func TestEverySupersededCaseIsCarriedAgainWithAWalletProof(t *testing.T) {
	again := map[string]string{
		"synth_valid_wallet_execute_transaction":                    "synth_valid_wallet_execute_transaction_proven",
		"synth_valid_wallet_execute_transactions":                   "synth_valid_wallet_execute_transactions_proven",
		"synth_valid_wallet_execute_transaction_with_gas_refunder":  "synth_valid_wallet_execute_transaction_with_gas_refunder_proven",
		"synth_valid_wallet_execute_transactions_with_gas_refunder": "synth_valid_wallet_execute_transactions_with_gas_refunder_proven",
		"synth_valid_wallet_call_is_the_bare_selector":              "synth_valid_wallet_call_is_the_bare_selector_proven",
		"adv_conf_wallet_call_targets_other_contract":               "adv_wallet_no_confirm_call_other_target_proven",
		"adv_conf_wallet_call_other_selector":                       "adv_wallet_no_confirm_call_other_selector_proven",
		"adv_conf_wallet_fast_call":                                 "adv_wallet_fast_call_proven",
		"adv_conf_wallet_force_call":                                "adv_wallet_force_call_proven",
		"adv_conf_wallet_fast_confirmer_nonzero":                    "adv_wallet_fast_confirmer_set_proven",
		"adv_conf_wallet_call_data_three_bytes":                     "adv_wallet_call_data_three_bytes_proven",
		"adv_conf_wallet_fast_confirmer_slot_unproven":              "adv_wallet_fast_confirmer_slot_proof_missing_proven",
	}
	if len(again) != len(supersededInSet3) {
		t.Fatalf("%d cases carried again, %d superseded in set 1", len(again), len(supersededInSet3))
	}
	f1, f3 := loadSet(t, vectorDir), loadSet(t, vectorDir3)
	byName := func(f vFile, n string) vVec {
		for _, v := range f.Vectors {
			if v.Name == n {
				return v
			}
		}
		t.Fatalf("%s: no vector %s", f.dir, n)
		return vVec{}
	}
	for old, nw := range again {
		if _, ok := supersededInSet3[old]; !ok {
			t.Errorf("%s is not in supersededInSet3", old)
		}
		o, n := byName(f1, old), byName(f3, nw)
		if outcomeKind(o.Expect) != outcomeKind(n.Expect) {
			t.Errorf("%s -> %s: recorded %s, proven world %s", old, nw, outcomeKind(o.Expect), outcomeKind(n.Expect))
		}
		if outcomeKind(supersededInSet3[old]) != "confirmation_path_unproven/reason=indirect" {
			t.Errorf("%s: the verdict now is %s", old, supersededInSet3[old])
		}
	}
	// set 2: the callee-code-is-not-examined vector
	o := byName(loadSet(t, vectorDir2), "synth_valid_wallet_route_callee_code_is_not_examined")
	if _, ok := supersededInSet2To3[o.Name]; !ok || outcomeKind(supersededInSet2To3[o.Name]) != "confirmation_path_unproven/reason=indirect" {
		t.Errorf("set 2: %s is not superseded to indirect", o.Name)
	}
	if outcomeKind(o.Expect) != "finalized/confirmation_route=wallet" {
		t.Errorf("set 2 recorded %s", o.Expect)
	}
}
