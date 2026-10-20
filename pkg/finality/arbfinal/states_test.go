// Copyright 2026 Certen Protocol

package arbfinal_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/certen/independant-validator/pkg/finality"
	"github.com/certen/independant-validator/pkg/finality/arbfinal"
)

type regState struct {
	Enums    map[string][]string `json:"enums"`
	Optional []string            `json:"optional"`
	Required []string            `json:"required"`
}

func loadRegistry(t *testing.T) map[string]regState {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "finality", "states.json"))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		States map[string]regState `json:"states"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	return reg.States
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Every state in the published vectors is a registered code with exactly registered field names and enum values.
func TestEveryStateOfTheVectorsConformsToTheRegistry(t *testing.T) {
	reg := loadRegistry(t)
	f := loadSet(t, vectorDir)
	seen := map[string]bool{}
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
		seen[st.Code] = true
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
	for _, c := range []string{
		arbfinal.CodeMachineNotFinished, arbfinal.CodeNotConfirmed, arbfinal.CodeAssertionUnknown, arbfinal.CodePreimageMismatch,
		arbfinal.CodeHeaderChainExceeds, arbfinal.CodeHeaderChainBroken, arbfinal.CodeConfirmedByOwner, arbfinal.CodeConfirmationUnproof,
		arbfinal.CodeContractIdentity, arbfinal.CodeStateProofInvalid, arbfinal.CodeTxProofInvalid, arbfinal.CodeL1FinalityUnproven,
		arbfinal.CodePreBold, arbfinal.CodePinMismatch,
	} {
		if !seen[c] {
			t.Errorf("no vector expects %s", c)
		}
	}
}

// The typed reason constants of this package are exactly the closed sets of the registry.
func TestTheClosedReasonSetsAreTheRegistrys(t *testing.T) {
	reg := loadRegistry(t)
	check := func(code, field string, got ...string) {
		t.Helper()
		want := append([]string(nil), reg[code].Enums[field]...)
		sort.Strings(want)
		sort.Strings(got)
		if len(want) != len(got) {
			t.Errorf("%s.%s: constants %v, registry %v", code, field, got, want)
			return
		}
		for i := range want {
			if want[i] != got[i] {
				t.Errorf("%s.%s: constants %v, registry %v", code, field, got, want)
				return
			}
		}
	}
	check(arbfinal.CodeConfirmationUnproof, "reason", string(arbfinal.ConfirmIndirect), string(arbfinal.ConfirmReceiptStatus), string(arbfinal.ConfirmLogMissing),
		string(arbfinal.ConfirmWalletNoConfirm), string(arbfinal.ConfirmWalletUndecodable), string(arbfinal.ConfirmFastConfirmerSet))
	check(arbfinal.CodeL1FinalityUnproven, "reason", string(arbfinal.L1FinalityLCRefused), string(arbfinal.L1FinalitySpineRefused))
	check(arbfinal.CodePreimageMismatch, "part", string(arbfinal.PreimageParentConfig), string(arbfinal.PreimageConfirmationLog))
	for _, c := range []string{arbfinal.CodeHeaderChainBroken} {
		for _, r := range []string{string(arbfinal.ReasonParentHash), string(arbfinal.ReasonNumberGap)} {
			if !has(reg[c].Enums["reason"], r) {
				t.Errorf("%s.reason %q is not in the registry", c, r)
			}
		}
	}
	if !has(reg[arbfinal.CodeHeaderChainBroken].Enums["reason"], "number_gap") {
		t.Fatal("registry lost number_gap")
	}
	// the framework's own constructors used by this package must be registered too.
	for _, c := range []string{finality.CodeBlockMismatch, finality.CodeEvidenceMalformed, finality.CodeEvidenceUnrecognised, finality.CodePinUnknown, finality.CodeVerifierFailed} {
		if _, ok := reg[c]; !ok {
			t.Errorf("framework code %s is not in the registry", c)
		}
	}
}
