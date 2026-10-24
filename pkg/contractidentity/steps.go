// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"sort"
)

// ---- the steps of "Offline verification algorithm" (V2_SPEC_S8, r3.2) ----
//
// The verifier is a fixed sequence of steps. Four parallel packages (2a, 2b-1, 2b-2, 2c) implement the steps they own, each in files of its
// own and in the Facts group of its own; this file is the contract between them and the runner: the step ids, who owns them, which parts
// each must account for, what each reads, in which order they decision-order and in which order they execute. NewVerifier refuses to be
// built when any registrable step has no function, so a forgotten step is a construction error, never a silent pass.

// StepID is a step id exactly as the specification numbers it ("1b", "18b", "22b").
type StepID string

// The 29 step ids of the algorithm.
const (
	Step0   StepID = "0"
	Step1   StepID = "1"
	Step1b  StepID = "1b"
	Step1c  StepID = "1c"
	Step2   StepID = "2"
	Step3   StepID = "3"
	Step4   StepID = "4"
	Step5   StepID = "5"
	Step6   StepID = "6"
	Step7   StepID = "7"
	Step8   StepID = "8"
	Step9   StepID = "9"
	Step10  StepID = "10"
	Step11  StepID = "11"
	Step12  StepID = "12"
	Step13  StepID = "13"
	Step14  StepID = "14"
	Step15  StepID = "15"
	Step16  StepID = "16"
	Step17  StepID = "17"
	Step18  StepID = "18"
	Step18b StepID = "18b"
	Step19  StepID = "19"
	Step20  StepID = "20"
	Step21  StepID = "21"
	Step22  StepID = "22"
	Step22b StepID = "22b"
	Step23  StepID = "23"
	Step24  StepID = "24"
)

// Owner is the package (work package) that implements a step and owns the Facts group it writes.
type Owner string

const (
	// OwnerSkeleton: steps 0, 1, 1b (and 1c(a)) are the prelude that BUILDS the Env, step 22b is the runner's node accounting. They are
	// real code of this skeleton (thin wrappers over ResolveManifest/Decode/ValidateContext/NodeSet), tested here, and cannot be registered.
	OwnerSkeleton Owner = "skeleton"
	Owner2a       Owner = "2a"
	Owner2b1      Owner = "2b-1"
	Owner2b2      Owner = "2b-2"
	Owner2c       Owner = "2c"
)

// StepSpec is the contract of one step.
type StepSpec struct {
	ID    StepID
	Owner Owner
	Title string
	// Parts are the judged parts the step MUST account for whenever it runs and the part is not already decided by an earlier step (in
	// decision order): it emits `verified` or the state it judged. A part is `verified` only if every executed declared contributor says so;
	// a contributor that stays silent about a part that nobody has refused is a defect of the implementation (an error, never a verdict).
	Parts []string
	// Needs are the steps whose Facts this step reads: each executes before it (checked by TestStepTable).
	Needs []StepID
}

// Registrable reports whether a package registers a function for the step.
func (s StepSpec) Registrable() bool { return s.Owner != OwnerSkeleton }

// stepTable is the table of the 29 steps. Parts and Needs are derived from the specification text (the step texts and Item 5).
var stepTable = []StepSpec{
	{Step0, OwnerSkeleton, "manifest and chain row", nil, nil},
	{Step1, OwnerSkeleton, "strict decode", nil, []StepID{Step0}},
	{Step1b, OwnerSkeleton, "context completeness", nil, []StepID{Step1}},
	{Step1c, Owner2a, "presence of the parts; carried Stated reasons; settle-dependent parts when settle is Stated", nil, []StepID{Step1b}},
	{Step2, Owner2a, "leg block, hash and chain", nil, []StepID{Step1c}},
	{Step3, Owner2a, "settlement facts and path; generation by code", []string{JudgedSettlementPath, JudgedS6Link}, []StepID{Step2}},
	{Step4, Owner2a, "roots and S6 link", []string{JudgedS6Link}, []StepID{Step2, Step3}},
	{Step5, Owner2a, "account code identity (settle)", []string{JudgedCodeIdentity}, []StepID{Step3, Step4}},
	{Step6, Owner2a, "account strings", []string{JudgedAccountProvenance}, []StepID{Step5}},
	{Step7, Owner2a, "account immutables", []string{JudgedAccountProvenance}, []StepID{Step5, Step6}},
	{Step8, Owner2a, "account provenance: CREATE2 and factory registry", []string{JudgedAccountProvenance}, []StepID{Step5, Step6, Step7}},
	{Step9, Owner2a, "anchor pointer", []string{JudgedPointer}, []StepID{Step5}},
	{Step10, Owner2a, "anchor identity (settle)", []string{JudgedCodeIdentity}, []StepID{Step9}},
	{Step11, Owner2a, "anchor record and record binding", []string{JudgedRecord}, []StepID{Step3, Step9, Step10}},
	{Step12, Owner2a, "verifier chain identity (settle)", []string{JudgedCodeIdentity}, []StepID{Step10, Step11}},
	// 13 reads the attestation-station AUTH values for `drift` when step 18 produced them (the facts are absent when the attest part is
	// Stated: no drift is then computed), so it executes after 18.
	{Step13, Owner2a, "state at settlement (Open entries)", []string{JudgedStateAtSettlement}, []StepID{Step9, Step10, Step12, Step18}},
	{Step14, Owner2a, "authority level of the settled call", []string{JudgedAuthorityLevel}, []StepID{Step3, Step5, Step6, Step7}},
	{Step15, Owner2b1, "attest present?", nil, []StepID{Step1c}},
	{Step16, Owner2b1, "attestation header link", []string{JudgedAuthorizationAttest}, []StepID{Step2, Step15}},
	{Step17, Owner2b1, "attestation transaction and receipt; strict ABI; blob layout", []string{JudgedAuthorizationAttest}, []StepID{Step3, Step9, Step11, Step16}},
	{Step18, Owner2b2, "authorization state at B_v, pre and post; byte rule; flips", []string{JudgedAuthorizationAttest, JudgedCodeIdentity}, []StepID{Step3, Step9, Step10, Step12, Step16, Step17}},
	{Step18b, Owner2b2, "attestation uniqueness (lemma U)", []string{JudgedAuthorizationAttest}, []StepID{Step10, Step11, Step18}},
	{Step19, Owner2b2, "authorization rules at B_v", []string{JudgedAuthorizationAttest}, []StepID{Step12, Step17, Step18, Step22}},
	{Step20, Owner2b1, "message binding", []string{JudgedAuthorizationAttest}, []StepID{Step11, Step17, Step18}},
	{Step21, Owner2c, "registry emit, owner pin, registry link, pkc cross-check", []string{JudgedAuthorizationAttest, JudgedRegistryLink}, []StepID{Step17, Step18, Step22}},
	{Step22, Owner2b2, "intra-block window (rule IB)", []string{JudgedIntraBlockWindow}, []StepID{Step16, Step18}},
	{Step22b, OwnerSkeleton, "node accounting", nil, []StepID{Step12, Step13, Step14, Step19, Step20, Step21, Step22}},
	{Step23, Owner2c, "report assembly inputs: rules_not_judged", nil, []StepID{Step13, Step14, Step19, Step21, Step24}},
	{Step24, Owner2c, "level binding to S7", nil, []StepID{Step2}},
}

// SpecOrder is the order of the specification text. The first failing step of a part, in THIS order, decides the part.
var SpecOrder = []StepID{
	Step0, Step1, Step1b, Step1c, Step2, Step3, Step4, Step5, Step6, Step7, Step8, Step9, Step10, Step11, Step12, Step13, Step14,
	Step15, Step16, Step17, Step18, Step18b, Step19, Step20, Step21, Step22, Step22b, Step23, Step24,
}

// ExecOrder is the order the runner executes the steps in (the 25 registrable ones and 22b): the spec order except where a step reads a fact that the spec text
// produces LATER. Rule IB (22) executes before the policy rules (19) and the owner pin (21): their `R` verdict is conditional on IB being
// `verified` ("Verdict precedence", step 19, 21b). Step 13 executes after 18 (its `drift` entries compare the settle values with the attest
// values) and 23 after 24 (the headline reads the level binding). Node accounting (22b) runs after the LAST step that reads a proof (it
// counts the nodes of steps 5-22 and of every read the steps 13 and 21 make), before the level binding. The prelude (0, 1, 1b) runs before the
// first step and is not in this list.
var ExecOrder = []StepID{
	Step1c, Step2, Step3, Step4, Step5, Step6, Step7, Step8, Step9, Step10, Step11, Step12, Step14,
	Step15, Step16, Step17, Step18, Step18b, Step22, Step19, Step20, Step21, Step13, Step22b, Step24, Step23,
}

var stepIndex = func() map[StepID]StepSpec {
	m := make(map[StepID]StepSpec, len(stepTable))
	for _, s := range stepTable {
		m[s.ID] = s
	}
	return m
}()

// Spec returns the contract of a step.
func Spec(id StepID) (StepSpec, bool) { s, ok := stepIndex[id]; return s, ok }

// Specs returns the 29 steps in spec order.
func Specs() []StepSpec {
	out := make([]StepSpec, len(SpecOrder))
	for i, id := range SpecOrder {
		out[i] = stepIndex[id]
	}
	return out
}

// RegistrableSteps are the 25 steps a package registers, in spec order.
func RegistrableSteps() []StepID {
	var out []StepID
	for _, id := range SpecOrder {
		if stepIndex[id].Registrable() {
			out = append(out, id)
		}
	}
	return out
}

// OwnedBy returns the registrable steps of one package, in spec order.
func OwnedBy(o Owner) []StepID {
	var out []StepID
	for _, id := range SpecOrder {
		if s := stepIndex[id]; s.Registrable() && s.Owner == o {
			out = append(out, id)
		}
	}
	return out
}

func specPos(id StepID) int {
	for i, x := range SpecOrder {
		if x == id {
			return i
		}
	}
	return -1
}

// ---- step functions and their output ----

// StepFunc is one step of the algorithm. It reads the Env (inputs) and the Facts of earlier steps (env.Facts), writes ONLY the Facts group
// of its owner, and returns what it decided. It does not mutate the Env's inputs, performs no I/O and does not panic on hostile evidence
// (a defect of the verifier is an error; a fact about the evidence is a state).
type StepFunc func(env *Env) (StepOutput, error)

// StepOutput is what a step hands to the runner.
type StepOutput struct {
	// Parts are the results this step contributes, one per part it judged. `verified` is a contribution too (see StepSpec.Parts). A step
	// does not emit the status `open`: a non-core part whose only decision is Open entries is derived by the runner.
	Parts []PartResult
	// Open are Open entries (alert, drift, not_checked); they attach to OpenEntry.Part whatever that part's status is.
	Open []OpenEntry
	// Findings are additional states the step judged on a part beside the one it decides (diagnostics for reviewers; never in the Report).
	Findings []Finding
	// RulesJudged are the rule ids (vocabulary rule_id, or settlement_rule_id for the step 13 consistency rules [r3.5:H10]) this step executed (steps 13, 19, 21).
	RulesJudged []string
	// ReadPlanIncomplete, when non-empty, says that a proof read of this step could not be derived because a prerequisite value was absent
	// or invalid: step 22b then reports nodes_check not_evaluated{reason} (spec step 22b).
	ReadPlanIncomplete string
	// Framework is a framework refusal (class FR: steps 0-2, 1c(b) and 15 for unknown_stated_reason). It implies Halt.
	Framework *StateError
	// Halt says the specification forbids the later steps from running (for instance the call-into-infrastructure answer of step 3).
	Halt bool
	// HaltReason names why (printed in the trace).
	HaltReason string
	// Supersede is reserved for step 24: the `s7_chain_unsupported` row voids every earlier decision ("no S8 statement"); Parts then
	// replaces the whole parts table. Any other step setting it is an error.
	Supersede bool
}

// StepRegistry holds the function of every registered step.
type StepRegistry struct {
	fns map[StepID]StepFunc
}

// NewStepRegistry returns an empty registry.
func NewStepRegistry() *StepRegistry { return &StepRegistry{fns: map[StepID]StepFunc{}} }

// Register adds the function of a step. Unknown ids, prelude ids, nil functions and double registration are errors: there is no
// override and no default.
func (r *StepRegistry) Register(id StepID, fn StepFunc) error {
	s, ok := stepIndex[id]
	switch {
	case r == nil || r.fns == nil:
		return fmt.Errorf("contractidentity: register step %s: nil registry", id)
	case !ok:
		return fmt.Errorf("contractidentity: register step %q: not a step of the algorithm", id)
	case !s.Registrable():
		return fmt.Errorf("contractidentity: register step %s: it belongs to the skeleton (prelude or runner) and cannot be registered", id)
	case fn == nil:
		return fmt.Errorf("contractidentity: register step %s: nil function", id)
	}
	if _, dup := r.fns[id]; dup {
		return fmt.Errorf("contractidentity: register step %s: already registered", id)
	}
	r.fns[id] = fn
	return nil
}

// Missing returns the registrable steps without a function, in spec order.
func (r *StepRegistry) Missing() []StepID {
	var out []StepID
	for _, id := range RegistrableSteps() {
		if r == nil || r.fns[id] == nil {
			out = append(out, id)
		}
	}
	return out
}

// Registered returns the registered ids in spec order.
func (r *StepRegistry) Registered() []StepID {
	var out []StepID
	if r == nil {
		return out
	}
	for _, id := range SpecOrder {
		if r.fns[id] != nil {
			out = append(out, id)
		}
	}
	return out
}

// Registrar is what each package file provides: `func RegisterSteps2a(reg *StepRegistry) error` (steps_2a.go), `RegisterSteps2b1`,
// `RegisterSteps2b2`, `RegisterSteps2c`. The integration file (not part of the skeleton) composes them.
type Registrar func(reg *StepRegistry) error

// BuildRegistry runs the registrars into a fresh registry.
func BuildRegistry(regs ...Registrar) (*StepRegistry, error) {
	reg := NewStepRegistry()
	for i, f := range regs {
		if f == nil {
			return nil, fmt.Errorf("contractidentity: registrar %d is nil", i)
		}
		if err := f(reg); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

func sortedIDs(ids []StepID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	sort.SliceStable(out, func(i, j int) bool { return specPos(StepID(out[i])) < specPos(StepID(out[j])) })
	return out
}
