// Copyright 2026 Certen Protocol

package contractidentity_test

import (
	"fmt"
	"math/big"
	"testing"

	ci "github.com/certen/independant-validator/pkg/contractidentity"
	"github.com/certen/independant-validator/pkg/contractidentity/world"
)

// RB12 final fix: the (f3) alert of step 19 (the blob's inner signed or total power differs from the outer call) had no test and no vector,
// because the world derives both from the same registry. This test perturbs the decoded call just before step 19 of the composed verifier and
// asserts the alert with its fields, that an honest world raises none, and that the alert only moves the headline from verified to verified_core.
func TestStep19AlertsWhenTheBlobInnerAndTheOuterPowerDiffer(t *testing.T) {
	m, err := ci.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := world.Generate(m, 11155111, world.VariantH0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := world.Apply(m, sp, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	real := map[ci.StepID]ci.StepFunc{}
	for _, mm := range []map[ci.StepID]ci.StepFunc{ci.Steps2a(), ci.Steps2b2(), ci.Steps2c()} {
		for id, fn := range mm {
			real[id] = fn
		}
	}
	for _, id := range ci.OwnedBy(ci.Owner2b1) {
		real[id] = ci.B1Step(id)
	}
	var seen struct{ signed, total string }
	verifier := func(perturb func(*ci.Env)) ci.Verifier {
		reg := ci.NewStepRegistry()
		for _, s := range ci.RegistrableSteps() {
			fn := real[s]
			inner := fn
			switch {
			case s == ci.Step19:
				// an observer only: step 19 may not write Facts.B1 (the runner enforces the owner of every fact)
				fn = func(env *ci.Env) (ci.StepOutput, error) {
					if c := env.Facts.B1.Call; c.BlobInnerSigned != nil && c.OuterSigned != nil {
						seen.signed, seen.total = c.BlobInnerSigned.String()+"/"+c.BlobInnerTotal.String(), c.OuterSigned.String()+"/"+c.OuterTotal.String()
					}
					return inner(env)
				}
			case perturb != nil && specOwner(s) == ci.Owner2b1:
				// the perturbation is made by a step of the package that owns the call (2b-1), after the blob and the outer call are decoded
				fn = func(env *ci.Env) (ci.StepOutput, error) {
					out, err := inner(env)
					if c := env.Facts.B1.Call; err == nil && c.BlobInnerSigned != nil && c.BlobInnerTotal != nil && c.OuterSigned != nil && c.OuterTotal != nil {
						perturb(env)
					}
					return out, err
				}
			}
			if err := reg.Register(s, fn); err != nil {
				t.Fatal(err)
			}
		}
		ver, err := ci.NewVerifier(reg)
		if err != nil {
			t.Fatal(err)
		}
		return ver
	}
	run := func(perturb func(*ci.Env)) (ci.Report, []ci.OpenEntry) {
		rep, err := verifier(perturb).Verify(b.Inputs.Ctx, b.Inputs.Container, m)
		if err != nil {
			t.Fatal(err)
		}
		var alerts []ci.OpenEntry
		for _, o := range rep.OpenEntries() {
			if o.State != nil && o.State.Code == ci.CodeAlert && o.State.Fields["field"] == "inner_outer_differ" {
				alerts = append(alerts, o)
			}
		}
		return rep, alerts
	}
	honest, none := run(nil)
	if len(none) != 0 {
		t.Fatalf("the honest world raised %d inner_outer_differ alerts", len(none))
	}
	for _, tc := range []struct {
		name    string
		perturb func(*ci.Env)
	}{
		{"signed power differs", func(env *ci.Env) {
			env.Facts.B1.Call.BlobInnerSigned = new(big.Int).Add(env.Facts.B1.Call.OuterSigned, big.NewInt(1))
		}},
		{"total power differs", func(env *ci.Env) {
			env.Facts.B1.Call.BlobInnerTotal = new(big.Int).Sub(env.Facts.B1.Call.OuterTotal, big.NewInt(1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rep, alerts := run(tc.perturb)
			if len(alerts) != 1 {
				t.Fatalf("want exactly one inner_outer_differ alert, got %d (seen inner %s, outer %s)", len(alerts), seen.signed, seen.total)
			}
			f := alerts[0].State.Fields
			if alerts[0].Kind != ci.OpenAlert || alerts[0].Part != ci.JudgedAuthorizationAttest || f["at"] != ci.AtAttestPost {
				t.Fatalf("alert shape: kind %q part %q fields %v", alerts[0].Kind, alerts[0].Part, f)
			}
			if f["onchain"] != seen.signed || f["want"] != seen.total {
				t.Fatalf("alert carries onchain %v want %v, the call had inner %s outer %s", f["onchain"], f["want"], seen.signed, seen.total)
			}
			// an Open alert moves the headline from verified to verified_core and never to refused or unproven
			if fmt.Sprint(honest.Headline.Kind) != "verified" || fmt.Sprint(rep.Headline.Kind) != "verified_core" {
				t.Fatalf("headline with the alert %v, honest %v: want verified_core and verified", rep.Headline.Kind, honest.Headline.Kind)
			}
		})
	}
}

func specOwner(id ci.StepID) ci.Owner {
	sp, _ := ci.Spec(id)
	return sp.Owner
}
