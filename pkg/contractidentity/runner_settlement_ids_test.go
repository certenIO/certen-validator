// Copyright 2026 Certen Protocol

package contractidentity

import "testing"

// RB12 final review D3: the settlement rule ids (REGISTERED, POWER, TOTAL-POWER) belong to step 13 only.
func TestSettlementRuleIdsAreAcceptedFromStep13Only(t *testing.T) {
	out := StepOutput{RulesJudged: []string{"REGISTERED", "POWER", "TOTAL-POWER"}}
	if err := validateOutput(&Env{}, StepSpec{ID: Step13}, out); err != nil {
		t.Fatalf("step 13 prints its settlement rule ids: %v", err)
	}
	if err := validateOutput(&Env{}, StepSpec{ID: Step12}, out); err == nil {
		t.Fatal("a step other than 13 printed settlement rule ids and the runner accepted them")
	}
}
