// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/capture/capturetest"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// ---- shared loading: every published set, once ----

func loadEverySet(t *testing.T) map[string]*ci.VectorSet {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "contractidentity", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*ci.VectorSet{}
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "s8_") {
			set, err := ci.LoadVectorSet(setDir(e.Name()))
			if err != nil {
				t.Fatalf("%s: %v", e.Name(), err)
			}
			out[e.Name()] = set
		}
	}
	return out
}

func sortedNames(sets map[string]*ci.VectorSet) []string {
	var names []string
	for n := range sets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ---- every one of the 25 steps is killed by at least one vector of the composed verifier ----

// inert wraps a real step: it runs (its reads and its Facts stay, so the node accounting of step 22b and the later steps are undisturbed) but
// every part it contributes becomes `verified` and its Open entries, findings, framework refusal, halt and supersede are dropped. A vector
// that expects any decision of that step then fails: the step is killed by that vector.
func inert(id ci.StepID, real ci.StepFunc) ci.StepFunc {
	return func(env *ci.Env) (ci.StepOutput, error) {
		out, err := real(env)
		if err != nil {
			return out, err
		}
		sp, _ := ci.Spec(id)
		parts := make([]ci.PartResult, 0, len(out.Parts))
		for _, p := range out.Parts {
			parts = append(parts, env.Verified(p.Part))
		}
		if len(parts) == 0 && out.Framework != nil {
			for _, p := range sp.Parts {
				parts = append(parts, env.Verified(p))
			}
		}
		return ci.StepOutput{Parts: parts, RulesJudged: out.RulesJudged, ReadPlanIncomplete: out.ReadPlanIncomplete}, nil
	}
}

// disabled is the gate of the package tests: the step is replaced by a stand-in that reports its parts verified and runs nothing (its Facts
// stay empty, so a later step that needs them fails loudly, which also kills the step).
func disabled(id ci.StepID) ci.StepFunc {
	return func(env *ci.Env) (ci.StepOutput, error) {
		sp, _ := ci.Spec(id)
		var out ci.StepOutput
		for _, p := range sp.Parts {
			out.Parts = append(out.Parts, env.Verified(p))
		}
		return out, nil
	}
}

// inertEquivalents are the steps whose own verdicts are observably redundant in the composition, with the reason: a later step carries the
// same state, so a vector cannot tell a step that decides from one that does not. They are killed by the "disabled" gate.
var inertEquivalents = map[ci.StepID]string{
	ci.Step10: "a refusal of step 10 is kept in Facts.A.AnchorRefusal and step 12 (and 11) carry it onto code_identity (step_2a_settle.go: a2Step12, AnchorRefusal): the report is identical",
}

func TestEveryStepOfTheComposedVerifierIsKilledByAVector(t *testing.T) {
	for _, mode := range []string{"disabled", "inert"} {
		t.Run(mode, func(t *testing.T) { killGate(t, mode) })
	}
}

func killGate(t *testing.T, mode string) {
	sets := loadEverySet(t)
	real := map[ci.StepID]ci.StepFunc{}
	for _, m := range []map[ci.StepID]ci.StepFunc{ci.Steps2a(), ci.Steps2b2(), ci.Steps2c()} {
		for id, fn := range m {
			real[id] = fn
		}
	}
	for _, id := range ci.OwnedBy(ci.Owner2b1) {
		real[id] = ci.B1Step(id)
	}
	steps := ci.RegistrableSteps()
	if len(steps) != 25 || len(real) != 25 {
		t.Fatalf("%d registrable steps, %d registered functions, want 25 and 25", len(steps), len(real))
	}
	for _, id := range steps {
		t.Run(string(id), func(t *testing.T) {
			t.Parallel()
			reg := ci.NewStepRegistry()
			for _, s := range steps {
				fn := real[s]
				if s == id && mode == "inert" {
					fn = inert(s, fn)
				}
				if s == id && mode == "disabled" {
					fn = disabled(s)
				}
				if err := reg.Register(s, fn); err != nil {
					t.Fatal(err)
				}
			}
			ver, err := ci.NewVerifier(reg)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range sortedNames(sets) {
				set := sets[name]
				for _, v := range set.Vectors {
					one := *set
					one.Vectors = []ci.Vector{v}
					if res := ci.RunSet(&one, nil, ver); res[0].Outcome != ci.OutcomePass {
						t.Logf("killed by %s/%s: %s", name, v.ID, truncate(res[0].Detail, 120))
						return
					}
				}
			}
			if why, ok := inertEquivalents[id]; ok && mode == "inert" {
				t.Logf("step %s is observably redundant under inert verdicts: %s", id, why)
				return
			}
			t.Errorf("step %s survives (%s): no vector of any published set fails", id, mode)
		})
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- step 22b exactness of the composed verifier, minimal and rich-storage worlds, four chains ----

func TestComposedVerifierVisitsExactlyTheNodesItCarriesOnEveryChainAndWorld(t *testing.T) {
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	var tr ci.Trace
	ver, err := ci.NewDefaultVerifier(ci.WithTrace(func(x ci.Trace) { tr = x }))
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []uint64{11155111, 84532, 421614, 2017} {
		for _, variant := range []string{world.VariantH0, world.VariantS6Silent, world.VariantHops} {
			for _, rich := range []bool{false, true} {
				t.Run(fmt.Sprintf("%d/%s/rich=%v", chain, variant, rich), func(t *testing.T) {
					sp, err := world.Generate(m, chain, variant)
					if err != nil {
						t.Fatal(err)
					}
					if rich {
						capturetest.Enrich(sp)
					}
					b, err := world.Apply(m, sp, nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					tr = ci.Trace{}
					rep, err := ver.Verify(b.Inputs.Ctx, b.Inputs.Container, m)
					if err != nil {
						t.Fatal(err)
					}
					if rep.Headline.Kind == ci.HeadlineRefused || rep.Headline.Kind == ci.HeadlineUnproven {
						t.Fatalf("the honest world is %s", rep.Headline.Kind)
					}
					if !tr.NodesCheck.Evaluated || tr.NodesCheck.Unreferenced != 0 {
						t.Fatalf("node accounting: %+v", tr.NodesCheck)
					}
				})
			}
		}
	}
}
