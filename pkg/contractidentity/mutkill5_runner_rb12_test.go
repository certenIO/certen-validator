// Copyright 2026 Certen Protocol

package contractidentity

import (
	"strings"
	"testing"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the survivors and uncovered sites of runner.go.

func TestMutKill5RunStepsRefusesAnEnvPreludeDidNotBuild(t *testing.T) {
	m, err := parseManifest(embeddedManifest)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewStepRegistry()
	for name, env := range map[string]*Env{"nil": nil, "no facts": {Manifest: m}, "no manifest": {Facts: &Facts{}}, "empty": {}} {
		if res, err := RunSteps(env, reg); err == nil || res != nil || !strings.Contains(err.Error(), "env was not built by Prelude") {
			t.Errorf("%s: %v %v", name, res, err)
		}
	}
}

func TestMutKill5MergePartsKeepsTheOrderOfContributionsOfOneStep(t *testing.T) {
	p := JudgedParts[0]
	contribs := []contribution{{Step4, refusedPart(p)}, {Step4, unprovenPart(p)}}
	parts, supers, err := mergeParts(contribs, nil, map[StepID]bool{}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].Status != StatusRefused {
		t.Errorf("the first contribution of the step decides: %+v", parts)
	}
	if len(supers) != 1 || supers[0].State.Code != stUnproven().Code || !supers[0].Superseded {
		t.Errorf("the second is recorded as superseded: %+v", supers)
	}
}

func TestMutKill5EarlyReportRefusesAStateThatIsNotAFrameworkRefusal(t *testing.T) {
	m, err := parseManifest(embeddedManifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := earlyReport(LegContext{}, m, &StateError{Code: "no_such_code"}); err == nil {
		t.Error("a state outside the registry built an early report")
	}
}

func TestMutKill5ValidateOutputRefusals(t *testing.T) {
	p0 := JudgedParts[0]
	cases := []struct {
		name string
		spec StepID
		out  StepOutput
		want string // "" = accepted
	}{
		{"valid finding", Step12, StepOutput{Findings: []Finding{{Part: p0, State: stRefused()}}}, ""},
		{"finding on an unknown part", Step12, StepOutput{Findings: []Finding{{Part: "no_such_part", State: stRefused()}}}, "finding on part"},
		{"finding without a state", Step12, StepOutput{Findings: []Finding{{Part: p0}}}, "finding on part"},
		{"finding with a state outside the registry", Step12, StepOutput{Findings: []Finding{{Part: p0, State: &StateError{Code: "no_such_code"}}}}, "finding on part"},
		{"open entry of an unknown kind", Step12, StepOutput{Open: []OpenEntry{{Part: p0, Kind: "no_such_kind", State: stRefused()}}}, "malformed Open entry"},
		{"valid rule id", Step12, StepOutput{RulesJudged: []string{"PAUSED"}}, ""},
		{"rule id outside the vocabulary", Step12, StepOutput{RulesJudged: []string{"no_such_rule"}}, "outside the vocabulary"},
		{"rule id outside the vocabulary on step 13", Step13, StepOutput{RulesJudged: []string{"no_such_rule"}}, "outside the vocabulary"},
		{"framework refusal that is not one", Step12, StepOutput{Framework: &StateError{Code: "no_such_code"}}, "output:"},
	}
	for _, c := range cases {
		err := validateOutput(&Env{}, StepSpec{ID: c.spec}, c.out)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestMutKill5RunStepsAccounting(t *testing.T) {
	if n := len(stepIndex[Step22b].Parts); n != 0 {
		t.Fatalf("step 22b declares %d parts; the executed flag of step 22b would then matter to mergeParts", n)
	}
	ctx, raw, m := skInputs(t)

	_, _, _, err := skRun(t, ctx, raw, m, map[StepID]override{Step23: func(env *Env, out *StepOutput) error {
		env.Facts.C.RulesNotJudged = nil
		return nil
	}})
	if err == nil || !strings.Contains(err.Error(), "wrote no rules_not_judged") {
		t.Errorf("step 23 wrote no rules_not_judged: %v", err)
	}

	rep, _, _, err := skRun(t, ctx, raw, m, map[StepID]override{Step12: func(env *Env, out *StepOutput) error {
		out.RulesJudged = []string{"PAUSED"}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rep.RulesJudged {
		found = found || r == "PAUSED"
	}
	if !found {
		t.Errorf("a rule judged by a step is reported: %v", rep.RulesJudged)
	}
}

func TestMutKill5HaltAfterNodeAccountingKeepsItsNodesCheck(t *testing.T) {
	ctx, raw, m := skInputs(t)
	var after StepID
	for i, id := range ExecOrder {
		if id == Step22b && i+1 < len(ExecOrder) {
			after = ExecOrder[i+1]
		}
	}
	if after == "" {
		t.Fatal("no step after 22b")
	}
	_, tr, _, err := skRun(t, ctx, raw, m, map[StepID]override{after: func(env *Env, out *StepOutput) error {
		out.Halt, out.HaltReason = true, "mk5_halt"
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Halt == nil || tr.Halt.Step != after {
		t.Fatalf("halt: %+v", tr.Halt)
	}
	if strings.HasPrefix(tr.NodesCheck.Reason, "halted_at_step_") {
		t.Errorf("the node accounting of step 22b is kept when a later step halts: %+v", tr.NodesCheck)
	}
}
