// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// StepVerifier is the S8 Verifier built from a complete StepRegistry. It is pure: no network, database or clock, and it does not mutate
// its inputs. Verify implements the Verifier interface (the frozen signature of vectors.go); VerifyTrace also returns the run Trace.
type StepVerifier struct {
	fns     map[StepID]StepFunc
	onTrace func(Trace)
}

// Option configures NewVerifier.
type Option func(*StepVerifier)

// WithTrace delivers the Trace of every run to f (the nodes_check of step 22b, the halt, the superseded findings).
func WithTrace(f func(Trace)) Option { return func(v *StepVerifier) { v.onTrace = f } }

// NewVerifier builds the verifier from a registry. It returns an ERROR when any registrable step (all 25 of them) has no function: a step
// has no default behaviour and cannot be left out, so a package that forgot one cannot ship a verifier that quietly passes. The registry is
// copied: later registrations do not change a built verifier.
func NewVerifier(reg *StepRegistry, opts ...Option) (*StepVerifier, error) {
	if reg == nil {
		return nil, fmt.Errorf("contractidentity: new verifier: nil step registry")
	}
	if miss := reg.Missing(); len(miss) > 0 {
		return nil, fmt.Errorf("contractidentity: new verifier: %d steps have no registered function: %s", len(miss), strings.Join(sortedIDs(miss), ", "))
	}
	v := &StepVerifier{fns: make(map[StepID]StepFunc, len(reg.fns))}
	for id, fn := range reg.fns {
		v.fns[id] = fn
	}
	for _, o := range opts {
		if o == nil {
			return nil, fmt.Errorf("contractidentity: new verifier: nil option")
		}
		o(v)
	}
	return v, nil
}

var _ Verifier = (*StepVerifier)(nil)

// Verify judges one leg (steps 0-24 of the specification).
func (v *StepVerifier) Verify(ctx LegContext, container []byte, m *Manifest) (Report, error) {
	r, _, err := v.VerifyTrace(ctx, container, m)
	return r, err
}

// VerifyTrace is Verify with the run trace. The returned error is never a verdict: a nil manifest, a step that returned an error, a
// panic (PanicError), a Facts ownership violation, a part no step decided and a headline the algebra rejected are defects of the caller
// or of an implementation, reported as errors with no Report.
func (v *StepVerifier) VerifyTrace(ctx LegContext, container []byte, m *Manifest) (rep Report, tr Trace, err error) {
	defer func() {
		if r := recover(); r != nil {
			rep, tr, err = Report{}, Trace{}, &PanicError{Value: r, Stack: string(debug.Stack())}
		}
	}()
	env, fw, err := Prelude(ctx, container, m)
	if err != nil {
		return Report{}, Trace{}, err
	}
	if fw != nil {
		rep, err = earlyReport(ctx, m, fw)
		tr = Trace{Halt: &HaltTrace{Step: preludeStep(fw), Reason: "framework_refusal", Framework: true}, NodesCheck: NodesCheck{Reason: "prelude_refusal"}}
		if err != nil {
			return Report{}, Trace{}, err
		}
		if v.onTrace != nil {
			v.onTrace(tr)
		}
		return rep, tr, nil
	}
	reg := &StepRegistry{fns: v.fns}
	res, err := RunSteps(env, reg)
	if err != nil {
		return Report{}, Trace{}, err
	}
	rep, err = buildReport(env, res)
	if err != nil {
		return Report{}, Trace{}, err
	}
	if v.onTrace != nil {
		v.onTrace(res.Trace)
	}
	return rep, res.Trace, nil
}

// preludeStep names the prelude step a framework refusal came from, by its code.
func preludeStep(st *StateError) StepID {
	switch st.Code {
	case CodeManifestUnknown:
		return Step0
	case CodeContextIncomplete:
		return Step1b
	}
	return Step1
}
