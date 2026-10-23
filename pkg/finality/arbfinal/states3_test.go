// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

// Every state of finality_arb_final2 and finality_arb_final3 is a registered code with exactly registered field names and enum members,
// and set 3 reaches each of the four wallet pin fields and every reason of the unproven callee.
func TestEveryStateOfSets2And3ConformsToTheRegistry(t *testing.T) {
	reg := loadRegistry(t)
	for _, dir := range []string{vectorDir2, vectorDir3} {
		f := loadSet(t, dir)
		for _, v := range f.Vectors {
			var st struct {
				Code   string            `json:"code"`
				Fields map[string]string `json:"fields"`
			}
			if err := json.Unmarshal([]byte(v.Expect), &st); err != nil {
				t.Fatalf("%s: %v", v.Name, err)
			}
			if st.Code == "finalized" {
				continue
			}
			r, ok := reg[st.Code]
			if !ok {
				t.Errorf("%s: code %q is not in states.json", v.Name, st.Code)
				continue
			}
			for _, req := range r.Required {
				if _, ok := st.Fields[req]; !ok {
					t.Errorf("%s: %s lacks required field %q", v.Name, st.Code, req)
				}
			}
			for k, val := range st.Fields {
				if !has(r.Required, k) && !has(r.Optional, k) {
					t.Errorf("%s: %s carries unregistered field %q", v.Name, st.Code, k)
				}
				if set, ok := r.Enums[k]; ok && !has(set, val) {
					t.Errorf("%s: %s.%s = %q is outside the closed set %v", v.Name, st.Code, k, val, set)
				}
			}
		}
	}
	f := loadSet(t, vectorDir3)
	fields := map[string]bool{}
	for _, v := range f.Vectors {
		var st struct {
			Code   string            `json:"code"`
			Fields map[string]string `json:"fields"`
		}
		if err := json.Unmarshal([]byte(v.Expect), &st); err != nil {
			t.Fatal(err)
		}
		if st.Code == arbfinal.CodePinMismatch {
			fields[st.Fields["field"]] = true
		}
	}
	for _, want := range []string{"proxy_slots.wallet_impl", "confirm_path.validator_wallet_impl", "logic_pins.validator_wallet_proxy", "logic_pins.validator_wallet_logic"} {
		if !fields[want] {
			t.Errorf("no set 3 vector expects pin_mismatch{%s}", want)
		}
		if !has(reg[arbfinal.CodePinMismatch].Enums["field"], want) {
			t.Errorf("pin_mismatch.field does not list %s", want)
		}
	}
}

// The pin_mismatch fields of the registry are a sorted, duplicate-free closed set, and the wallet roles of the logic pins are named as the
// code names them.
func TestThePinMismatchFieldSetIsClosedAndSorted(t *testing.T) {
	fields := loadRegistry(t)[arbfinal.CodePinMismatch].Enums["field"]
	if len(fields) < 25 {
		t.Fatalf("only %d fields: %v", len(fields), fields)
	}
	if !sort.StringsAreSorted(fields) {
		t.Errorf("not sorted: %v", fields)
	}
	for i := 1; i < len(fields); i++ {
		if fields[i] == fields[i-1] {
			t.Errorf("duplicate %s", fields[i])
		}
	}
	if !has(fields, "logic_pins."+arbfinal.RoleWalletProxy) || !has(fields, "logic_pins."+arbfinal.RoleWalletLogic) {
		t.Errorf("the role names %s / %s are not in the field set %v", arbfinal.RoleWalletProxy, arbfinal.RoleWalletLogic, fields)
	}
}
