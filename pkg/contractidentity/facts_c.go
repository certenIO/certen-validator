// Copyright 2026 Certen Protocol

package contractidentity

// FactsC are the facts of package 2c (steps 21, 23 and 24). Package 2c owns this file.
type FactsC struct {
	// Registry is the report's `registry` object (step 21a); nil when step 21 could not emit it.
	Registry *RegistryObject
	// RegistryLink is the value a `verified` headline reports (vocabulary registry_link_value); empty unless registry_link is verified.
	RegistryLink string
	// Level is the level binding of step 24.
	Level LevelBinding
	// RulesNotJudged are the AUTH rows and exempt words that no rule judges, each with its reason (step 23, printed in every outcome).
	RulesNotJudged []RuleNotJudged
}

// LevelBinding is the result of step 24.
type LevelBinding struct {
	// Authenticated is state_root_authenticated: S7 finalized is verified for this very block.
	Authenticated bool
	// JudgedAtLevel is the highest verified S7 level (the report's judged_at_level and a pending headline's level_reached).
	JudgedAtLevel string
	// S7FinalizedStatus is the S7 finalized status or refusal, carried by a pending headline so that it never hides it.
	S7FinalizedStatus string
}

var factSpecsC = []FactSpec{
	{"C.Registry", Step21, []StepID{Step23}, "report.registry (21a); emitted whenever the attestation was captured"},
	{"C.RegistryLink", Step21, []StepID{Step23}, "via S9 | via manifest_history{keys:digest,pkc:exact_set}; read by the runner for a verified headline"},
	{"C.Level", Step24, []StepID{Step23}, "state_root_authenticated, judged_at_level, s7_finalized_status; read by the runner for the headline"},
	{"C.RulesNotJudged", Step23, nil, "rules_not_judged of the report"},
}
