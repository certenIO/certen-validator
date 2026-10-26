// Copyright 2026 Certen Protocol

package contractidentity

import (
	"math/big"
	"testing"
)

// RB12 EPSILON stage 2, part B: literal-expectation tests for the survivors and uncovered sites of report.go.

func mk5Report(h Headline, parts ...PartResult) Report {
	return Report{Headline: h, Parts: parts, Residuals: FixedResiduals(), S6: S6Report{Status: S6Proven}, ManifestSource: "embedded"}
}

func mk5Unproven() Headline {
	return Headline{Kind: HeadlineUnproven, Parts: []string{JudgedParts[0]}}
}

func TestMutKill5AuthorityObjectMap(t *testing.T) {
	good := func() AuthorityObject {
		return AuthorityObject{Level: "ADMIN", LoggedLevel: "NONE", Source: "stored", Legs: []AuthorityLeg{{Value: big.NewInt(1), Required: "ROOT"}}}
	}
	m, err := good().Map()
	if err != nil || m["level"] != "ADMIN" || m["logged_level"] != "NONE" || m["source"] != "stored" || len(m["legs"].([]any)) != 1 {
		t.Fatalf("good object: %v %v", m, err)
	}
	for name, mut := range map[string]func(*AuthorityObject){
		"level":    func(a *AuthorityObject) { a.Level = "BOGUS" },
		"logged":   func(a *AuthorityObject) { a.LoggedLevel = "BOGUS" },
		"source":   func(a *AuthorityObject) { a.Source = "bogus" },
		"required": func(a *AuthorityObject) { a.Legs[0].Required = "BOGUS" },
		"value":    func(a *AuthorityObject) { a.Legs[0].Value = nil },
	} {
		a := good()
		mut(&a)
		if m, err := a.Map(); err == nil || m != nil {
			t.Errorf("%s outside the vocabulary was accepted: %v", name, m)
		}
	}
}

func TestMutKill5RegistryMemberWithoutPowerIsRefused(t *testing.T) {
	r := RegistryObject{TotalVotingPower: big.NewInt(1), Members: []RegistryMemberObject{{}}}
	if m, err := r.Map(); err == nil || m != nil {
		t.Errorf("a member without power: %v %v", m, err)
	}
}

func TestMutKill5ReportValidateRefusals(t *testing.T) {
	if err := mk5Report(mk5Unproven()).Validate(); err != nil {
		t.Fatalf("base report: %v", err)
	}
	if err := mk5Report(Headline{Kind: HeadlineRefused}).Validate(); err == nil {
		t.Error("a refused headline without its first refusal")
	}
	if err := mk5Report(mk5Unproven(), PartResult{Part: "no_such_part", Status: StatusVerified}).Validate(); err == nil {
		t.Error("an unknown part")
	}
	p := PartResult{Part: JudgedParts[0], Status: StatusVerified}
	if err := mk5Report(mk5Unproven(), p, p).Validate(); err == nil {
		t.Error("a repeated part")
	}
	bad := PartResult{Part: JudgedParts[0], Status: StatusRefused, State: &StateError{Code: "no_such_code"}}
	if err := mk5Report(mk5Unproven(), bad).Validate(); err == nil {
		t.Error("a part whose state is outside the registry")
	}
}

func TestMutKill5IsPreludeRefusal(t *testing.T) {
	fr := ContextIncomplete([]string{})
	cases := []struct {
		name string
		r    Report
		want bool
	}{
		{"refused, FR code, no parts", Report{Headline: Headline{Kind: HeadlineRefused, First: fr}}, true},
		{"not a refusal", Report{Headline: Headline{Kind: HeadlineUnproven, First: fr}}, false},
		{"refused without a first state", Report{Headline: Headline{Kind: HeadlineRefused}}, false},
		{"refused with parts", Report{Headline: Headline{Kind: HeadlineRefused, First: fr}, Parts: []PartResult{{Part: JudgedParts[0]}}}, false},
		{"refused with a code outside the registry", Report{Headline: Headline{Kind: HeadlineRefused, First: &StateError{Code: "no_such_code"}}}, false},
	}
	for _, c := range cases {
		if got := c.r.isPreludeRefusal(); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestMutKill5ReportMapShape(t *testing.T) {
	p0 := PartResult{Part: JudgedParts[1], Status: StatusRefused, Reason: "why"}
	p1 := PartResult{Part: JudgedParts[0], Status: StatusVerified}
	r := mk5Report(mk5Unproven(), p0, p1)
	r.Headline.Findings = []Finding{{Part: JudgedParts[0], State: ContextIncomplete([]string{})}}
	r.RulesNotJudged = []RuleNotJudged{{Row: "b", Reason: "x"}, {Row: "a", Reason: "z"}, {Row: "a", Reason: "y"}}
	r.S6 = S6Report{Status: S6Silent, Reason: "absent"}
	m, err := r.Map()
	if err != nil {
		t.Fatal(err)
	}
	parts := m["parts"].([]any)
	if len(parts) != 2 || parts[0].(map[string]any)["part"] != JudgedParts[0] && parts[0].(map[string]any)["part"] != JudgedParts[1] {
		t.Fatalf("parts: %v", parts)
	}
	if a, b := parts[0].(map[string]any)["part"].(string), parts[1].(map[string]any)["part"].(string); a >= b {
		t.Errorf("parts must be sorted by name: %s %s", a, b)
	}
	for _, o := range parts {
		om := o.(map[string]any)
		_, has := om["reason"]
		if has != (om["part"] == JudgedParts[1]) {
			t.Errorf("reason only for the part that has one: %v", om)
		}
	}
	if _, ok := m["findings"]; ok {
		t.Error("a non-pending headline reports no findings")
	}
	rn := m["rules_not_judged"].([]any)
	want := [][2]string{{"a", "y"}, {"a", "z"}, {"b", "x"}}
	for i, w := range want {
		if rn[i].(map[string]any)["row"] != w[0] || rn[i].(map[string]any)["reason"] != w[1] {
			t.Errorf("rules_not_judged[%d] = %v", i, rn[i])
		}
	}
	s6 := m["s6"].(map[string]any)
	if s6["reason"] != "absent" {
		t.Errorf("s6: %v", s6)
	}
	if _, ok := s6["state"]; ok {
		t.Errorf("s6_silent carries no state: %v", s6)
	}
	r.S6 = S6Report{Status: S6NotProven, State: "some_state"}
	m, err = r.Map()
	if err != nil {
		t.Fatal(err)
	}
	s6 = m["s6"].(map[string]any)
	if s6["state"] != "some_state" {
		t.Errorf("s6: %v", s6)
	}
	if _, ok := s6["reason"]; ok {
		t.Errorf("s6_not_proven carries no reason: %v", s6)
	}
	r.S6 = S6Report{Status: S6Proven}
	if m, err = r.Map(); err != nil {
		t.Fatal(err)
	}
	if s6 := m["s6"].(map[string]any); len(s6) != 1 {
		t.Errorf("s6_proven carries only its status: %v", s6)
	}
}

func TestMutKill5ReportMapFindings(t *testing.T) {
	f := []Finding{{Part: JudgedParts[0], State: ContextIncomplete([]string{})}}
	pending := mk5Report(Headline{Kind: HeadlinePending, LevelReached: "included", Findings: f})
	m, err := pending.Map()
	if err != nil {
		t.Fatal(err)
	}
	if fs, ok := m["findings"].([]any); !ok || len(fs) != 1 {
		t.Errorf("one finding of a pending headline: %v", m["findings"])
	}
	none := mk5Report(Headline{Kind: HeadlinePending, LevelReached: "included"})
	if m, err = none.Map(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["findings"]; ok {
		t.Error("a pending headline without findings reports none")
	}
}
