// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// [r3.5:H10] step 13 evaluates three rules that are not rows of the manifest policy.rules (registered == 1, votingPower > 0, sum(power) ==
// totalVotingPower). The report names them in rules_judged with the ids of the closed vocabulary `settlement rule id`; the vocabulary `rule id`
// stays the id set of the manifest rules, and a report with any other id is malformed.
func TestRulesJudgedNamesTheSettlementConsistencyRules(t *testing.T) {
	f := newFixture(t, 11155111, world.VariantH0)
	ver, err := ci.NewDefaultVerifier()
	if err != nil {
		t.Fatal(err)
	}
	rep, err := ver.Verify(f.built.Inputs.Ctx, f.built.Inputs.Container, f.m)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, id := range rep.RulesJudged {
		have[id] = true
	}
	for _, id := range []string{"PAUSED", "BINDING", "ENABLED", "THRESHOLD-A", "THRESHOLD-V", "OWNER", "GOVVERIFIER", "MINGOV", "SETROOT", "VERIFIER-ID", "REGISTERED", "POWER", "TOTAL-POWER"} {
		if !have[id] {
			t.Errorf("rules_judged %v lacks %s", rep.RulesJudged, id)
		}
	}
	if err := rep.Validate(); err != nil {
		t.Fatalf("an honest report with the settlement rule ids is not valid: %v", err)
	}
	if !ci.Check("settlement_rule_id", "TOTAL-POWER") || ci.Check("settlement_rule_id", "PAUSED") || ci.Check("rule_id", "POWER") {
		t.Fatal("the two rule vocabularies must be disjoint and closed")
	}
	bad := rep
	bad.RulesJudged = append(append([]string(nil), rep.RulesJudged...), "NOT-A-RULE")
	if bad.Validate() == nil {
		t.Fatal("a rule id outside both vocabularies was accepted")
	}
}
