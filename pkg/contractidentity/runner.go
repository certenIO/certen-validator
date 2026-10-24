// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
)

// ---- the runner: executes the steps, decides the parts, accounts for the nodes, builds the Report ----

// PanicError is returned when a step (or the prelude) panicked. The registry has no state for a verifier panic, so it is NEVER a verdict:
// the caller gets an error, and no Report that could be mistaken for a judgement of the evidence.
type PanicError struct {
	Step  StepID // empty: the prelude or the report assembly
	Value any
	Stack string
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("contractidentity: verifier panic in step %q: %v", e.Step, e.Value)
}

// UndecidedPartError is a defect of a step implementation: a declared contributor ran, nobody refused the part, and it stayed silent.
type UndecidedPartError struct {
	Part   string
	Step   StepID // the silent contributor; empty when no step reported the part at all
	Reason string
}

func (e *UndecidedPartError) Error() string {
	if e.Step == "" {
		return fmt.Sprintf("contractidentity: part %s was not decided by any step (%s)", e.Part, e.Reason)
	}
	return fmt.Sprintf("contractidentity: step %s ran and did not account for part %s (%s)", e.Step, e.Part, e.Reason)
}

// HaltTrace says where and why the run stopped early.
type HaltTrace struct {
	Step      StepID
	Reason    string
	Framework bool
}

// NodesCheck is step 22b's outcome: evaluated with the first unreferenced node, or `not_evaluated{reason}`.
type NodesCheck struct {
	Evaluated         bool
	Reason            string // not_evaluated{reason}
	Unreferenced      int
	FirstUnreferenced int
}

// TraceFinding is a state a step judged beside the one that decided its part, or one the runner discarded.
type TraceFinding struct {
	Step       StepID
	Part       string
	State      *StateError
	Superseded bool // true: a later step in decision order found a state for a part an earlier step had already decided
}

// Trace records how a run went. It is not part of the Report (the Report's keys are frozen): the nodes_check of step 22b lives here.
type Trace struct {
	Executed   []StepID
	NotRun     []StepID
	Halt       *HaltTrace
	NodesCheck NodesCheck
	Findings   []TraceFinding
}

// RunResult is what RunSteps hands to the report assembly.
type RunResult struct {
	Parts       []PartResult
	Framework   *StateError
	RulesJudged []string
	Trace       Trace
}

type contribution struct {
	step StepID
	p    PartResult
}

// RunSteps executes the registered steps in ExecOrder on env, decides each part ("the first failing step of a part decides that part;
// parts are independent, the report lists all"), honours Halt, accounts for the visited nodes (step 22b) and returns the part table.
// Steps run to completion even when an earlier step has decided a part (step 22b needs every read); a step skips only what its own
// prerequisites forbid. env must come from Prelude.
func RunSteps(env *Env, reg *StepRegistry) (*RunResult, error) {
	if env == nil || env.Facts == nil || env.Manifest == nil {
		return nil, fmt.Errorf("contractidentity: run: env was not built by Prelude")
	}
	if miss := reg.Missing(); len(miss) > 0 {
		return nil, fmt.Errorf("contractidentity: run: steps without a function: %s", strings.Join(sortedIDs(miss), ", "))
	}
	res := &RunResult{}
	if env.NoEvidence() {
		// 1c(a): steps 0 and 1b ran (the prelude); every part is unproven, steps 2-24 do not run.
		parts, err := noEvidenceParts(env)
		if err != nil {
			return nil, err
		}
		res.Parts = parts
		res.Trace.NodesCheck = NodesCheck{Reason: UnprovenNoEvidence}
		for _, id := range ExecOrder {
			res.Trace.NotRun = append(res.Trace.NotRun, id)
		}
		return res, nil
	}
	var (
		contribs   []contribution
		opens      []OpenEntry
		judged     = map[string]bool{}
		executed   = map[StepID]bool{}
		incomplete []string
		halted     *HaltTrace
	)
	for _, id := range ExecOrder {
		if halted != nil {
			res.Trace.NotRun = append(res.Trace.NotRun, id)
			continue
		}
		if id == Step22b {
			runNodeAccounting(env, res, incomplete)
			res.Trace.Executed = append(res.Trace.Executed, id)
			executed[id] = true
			continue
		}
		spec := stepIndex[id]
		out, err := callStep(env, reg.fns[id], spec)
		if err != nil {
			return nil, err
		}
		res.Trace.Executed = append(res.Trace.Executed, id)
		executed[id] = true
		if err := validateOutput(env, spec, out); err != nil {
			return nil, err
		}
		if out.Supersede {
			// the s7_chain_unsupported row: no S8 statement; every earlier decision is kept only in the trace
			for _, c := range contribs {
				if c.p.State != nil {
					res.Trace.Findings = append(res.Trace.Findings, TraceFinding{Step: c.step, Part: c.p.Part, State: c.p.State, Superseded: true})
				}
			}
			contribs, opens = nil, nil
		}
		for _, p := range out.Parts {
			contribs = append(contribs, contribution{id, p})
		}
		opens = append(opens, out.Open...)
		for _, f := range out.Findings {
			res.Trace.Findings = append(res.Trace.Findings, TraceFinding{Step: id, Part: f.Part, State: f.State})
		}
		for _, r := range out.RulesJudged {
			judged[r] = true
		}
		if out.ReadPlanIncomplete != "" {
			incomplete = append(incomplete, fmt.Sprintf("%s:%s", id, out.ReadPlanIncomplete))
		}
		if out.Framework != nil {
			if res.Framework == nil {
				res.Framework = out.Framework
			}
			halted = &HaltTrace{Step: id, Reason: "framework_refusal", Framework: true}
		} else if out.Halt {
			halted = &HaltTrace{Step: id, Reason: out.HaltReason}
		}
	}
	if halted != nil {
		res.Trace.Halt = halted
		if !res.Trace.NodesCheck.Evaluated && res.Trace.NodesCheck.Reason == "" {
			res.Trace.NodesCheck = NodesCheck{Reason: fmt.Sprintf("halted_at_step_%s", halted.Step)}
		}
	}
	if halted != nil && halted.Framework {
		// the step that refused as a framework has said what it had to say: it owes no part
		delete(executed, halted.Step)
	}
	parts, supers, err := mergeParts(contribs, opens, executed, env.Registry9Present(), halted != nil && halted.Framework)
	if err != nil {
		return nil, err
	}
	res.Parts = parts
	res.Trace.Findings = append(res.Trace.Findings, supers...)
	for r := range judged {
		res.RulesJudged = append(res.RulesJudged, r)
	}
	sort.Strings(res.RulesJudged)
	return res, nil
}

// callStep runs one step with its panic contained and its Facts writes checked.
func callStep(env *Env, fn StepFunc, spec StepSpec) (out StepOutput, err error) {
	before := snapshotFacts(env.Facts)
	defer func() {
		if r := recover(); r != nil {
			out, err = StepOutput{}, &PanicError{Step: spec.ID, Value: r, Stack: string(debug.Stack())}
		}
	}()
	out, err = fn(env)
	if err != nil {
		return StepOutput{}, fmt.Errorf("contractidentity: step %s: %w", spec.ID, err)
	}
	for _, g := range changedGroups(before, env.Facts) {
		if o, _ := GroupOwner(g); o != spec.Owner {
			return StepOutput{}, &FactsOwnershipError{Step: spec.ID, Owner: spec.Owner, Group: g}
		}
	}
	return out, nil
}

// validateOutput rejects a step output that is malformed: those are defects of the step, not verdicts.
func validateOutput(env *Env, spec StepSpec, out StepOutput) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("contractidentity: step %s output: %s", spec.ID, fmt.Sprintf(format, a...))
	}
	if out.Supersede && spec.ID != Step24 {
		return bad("only step 24 may supersede the part table")
	}
	seen := map[string]bool{}
	for i := range out.Parts {
		p := out.Parts[i]
		if partIndex(p.Part) < 0 {
			return bad("unknown part %q", p.Part)
		}
		if p.Status == StatusOpen {
			return bad("part %s has the status open: the runner derives it from the Open entries", p.Part)
		}
		if seen[p.Part] {
			return bad("part %s reported twice", p.Part)
		}
		seen[p.Part] = true
		if err := validatePartResult(&p, env.Registry9Present()); err != nil {
			return bad("%v", err)
		}
	}
	if out.Supersede && len(out.Parts) != len(JudgedParts) {
		return bad("a superseding output carries all %d parts, got %d", len(JudgedParts), len(out.Parts))
	}
	for _, o := range out.Open {
		if err := validatePartResult(&PartResult{Part: o.Part, Status: StatusVerified, Open: []OpenEntry{o}}, env.Registry9Present()); err != nil {
			return bad("%v", err)
		}
	}
	for _, f := range out.Findings {
		if partIndex(f.Part) < 0 || f.State == nil || Validate(f.State) != nil {
			return bad("finding on part %q is malformed", f.Part)
		}
	}
	for _, r := range out.RulesJudged {
		if !Check("rule_id", r) {
			return bad("rule id %q is outside the vocabulary", r)
		}
	}
	if out.Framework != nil {
		if err := validateHeadlineInput(HeadlineInput{Framework: out.Framework}); err != nil {
			return bad("%v", err)
		}
	}
	if out.Halt && out.HaltReason == "" {
		return bad("Halt without HaltReason")
	}
	return nil
}

// mergeParts decides every part from the contributions. The first non-verified contribution in SPEC order decides the part (later ones are
// returned as superseded findings); a part with only verified contributions is verified iff every executed declared contributor reported
// it. A non-core part whose only content is Open entries is `open`. allowUndecided is true only for a run that HALTED on a framework
// refusal (steps 0-2, unknown Stated reason), which has no part table to complete; every other run must decide all eleven parts.
func mergeParts(contribs []contribution, opens []OpenEntry, executed map[StepID]bool, registry9, allowUndecided bool) ([]PartResult, []TraceFinding, error) {
	var out []PartResult
	var supers []TraceFinding
	for _, part := range JudgedParts {
		var cs []contribution
		for _, c := range contribs {
			if c.p.Part == part {
				cs = append(cs, c)
			}
		}
		sort.SliceStable(cs, func(i, j int) bool { return specPos(cs[i].step) < specPos(cs[j].step) })
		var entries []OpenEntry
		for _, c := range cs {
			entries = append(entries, c.p.Open...)
		}
		for _, o := range opens {
			if o.Part == part {
				entries = append(entries, o)
			}
		}
		var decisive *contribution
		for i := range cs {
			if cs[i].p.Status != StatusVerified {
				if decisive == nil {
					decisive = &cs[i]
				} else if cs[i].p.State != nil {
					supers = append(supers, TraceFinding{Step: cs[i].step, Part: part, State: cs[i].p.State, Superseded: true})
				}
			}
		}
		var res PartResult
		switch {
		case decisive != nil:
			res = decisive.p
		default:
			for _, id := range SpecOrder {
				s := stepIndex[id]
				if !executed[id] || !hasString(s.Parts, part) {
					continue
				}
				found := false
				for _, c := range cs {
					found = found || c.step == id
				}
				if !found {
					return nil, nil, &UndecidedPartError{Part: part, Step: id, Reason: "declared contributor reported nothing and no step refused the part"}
				}
			}
			if len(cs) == 0 {
				if allowUndecided {
					continue
				}
				return nil, nil, &UndecidedPartError{Part: part, Reason: "no step reported it"}
			}
			res = PartResult{Part: part, Status: StatusVerified}
			if len(entries) > 0 && !IsCoreJudgedPart(part, registry9) {
				res.Status = StatusOpen
			}
		}
		res.Open = nil
		if len(entries) > 0 {
			res.Open = append(res.Open, entries...)
			sortOpen(res.Open)
		}
		out = append(out, res)
	}
	return out, supers, nil
}

func hasString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// runNodeAccounting is step 22b: NODES must be exactly the nodes the walks visited. It is evaluated only when every read plan completed.
func runNodeAccounting(env *Env, res *RunResult, incomplete []string) {
	switch {
	case env.Nodes == nil:
		res.Trace.NodesCheck = NodesCheck{Reason: "no_container"}
	case len(incomplete) > 0:
		res.Trace.NodesCheck = NodesCheck{Reason: strings.Join(incomplete, ";")}
	default:
		un := env.Nodes.Unvisited()
		res.Trace.NodesCheck = NodesCheck{Evaluated: true, Unreferenced: len(un)}
		if len(un) > 0 {
			res.Trace.NodesCheck.FirstUnreferenced = un[0]
			if res.Framework == nil {
				res.Framework = Malformed(PartNodes, MalformedNodesUnreferenced, un[0], 0, 0)
			}
		}
	}
}

// noEvidenceParts is step 1c(a): every judged part is unproven{part:all, reason:no_evidence_in_file}.
func noEvidenceParts(env *Env) ([]PartResult, error) {
	st, err := New(CodeUnproven, RowUnprovenNoEvidenceInFile, map[string]any{"part": UnprovenPartAll})
	if err != nil {
		return nil, err
	}
	parts := make([]PartResult, len(JudgedParts))
	for i, p := range JudgedParts {
		parts[i] = PartResult{Part: p, Status: StatusUnproven, State: st}
	}
	return parts, nil
}

// UnprovenNoEvidence is the reason text of step 1c(a).
const UnprovenNoEvidence = "no_evidence_in_file"

// buildReport assembles the Report from a run: the headline algebra of step 23 over the part table, the framework refusal and the level
// binding, and every printed member of Item 2b. A headline algebra error (pending without a level, verified without a registry value) is
// a defect of the steps that should have filled Facts.C, never a verdict.
func buildReport(env *Env, res *RunResult) (Report, error) {
	f := env.Facts
	leg := env.Leg()
	in := HeadlineInput{
		Parts: res.Parts, Framework: res.Framework, Registry9: env.Registry9Present(),
		StateRootAuthenticated: f.C.Level.Authenticated, LevelReached: f.C.Level.JudgedAtLevel, S7FinalizedStatus: f.C.Level.S7FinalizedStatus,
		JudgedAtLevel: f.C.Level.JudgedAtLevel, StateRoot: f.A.StateRootN, Block: leg.Number, RegistryLink: f.C.RegistryLink,
	}
	h, err := ComputeHeadline(in)
	if err != nil {
		return Report{}, fmt.Errorf("contractidentity: report: %w", err)
	}
	return Report{
		Headline: h, Parts: res.Parts, RulesJudged: res.RulesJudged, RulesNotJudged: f.C.RulesNotJudged, Residuals: FixedResiduals(),
		Registry: f.C.Registry, Authority: f.A.Authority, S6: s6Report(env.Ctx),
		JudgedAtLevel: f.C.Level.JudgedAtLevel, StateRootAuthenticated: f.C.Level.Authenticated, S7FinalizedStatus: f.C.Level.S7FinalizedStatus,
		Chain: env.Ctx.Chain, Block: leg.Number, BlockHash: leg.Hash, ManifestSHA256: env.Manifest.SHA256, ManifestSource: env.Manifest.Source,
	}, nil
}

func s6Report(c LegContext) S6Report {
	return S6Report{Status: c.S6Status, Reason: c.S6Reason, State: c.S6State}
}

// earlyReport is the Report of a framework refusal in the prelude (steps 0, 1, 1b): the refused headline with the framework state first.
func earlyReport(ctx LegContext, m *Manifest, st *StateError) (Report, error) {
	h, err := ComputeHeadline(HeadlineInput{Framework: st})
	if err != nil {
		return Report{}, err
	}
	r := Report{Headline: h, Residuals: FixedResiduals(), Chain: ctx.Chain, ManifestSHA256: m.SHA256, ManifestSource: m.Source}
	r.S6 = s6Report(ctx)
	return r, nil
}
