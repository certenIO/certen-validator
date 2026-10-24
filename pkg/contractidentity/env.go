// Copyright 2026 Certen Protocol

package contractidentity

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/finality"
)

// Env is the world of one verification: the immutable inputs, the decoded container and the effective manifest, plus the three members
// that are mutable by design and single-goroutine by contract: Facts (what earlier steps hand to later ones), Nodes (the visited-node
// recorder of step 22b) and the decoded-header cache. A StepFunc never mutates anything else.
//
// An Env exists only after the prelude (steps 0, 1, 1b) succeeded; see Prelude.
type Env struct {
	// Ctx is the leg context (item 2a). Its pointers (settlement, transaction, receipt, S6, Registry9, S7) are shared with the caller and are
	// read-only by contract.
	Ctx LegContext
	// Raw are the container bytes as given (nil or empty: no container, step 1c(a)).
	Raw []byte
	// Container is the strictly decoded container (step 1); nil iff Raw is empty.
	Container *Container
	// Manifest is the effective manifest (embedded, override or extension); Chain is the chains[] row of the settlement chain (step 0).
	Manifest *Manifest
	Chain    ChainEntry
	// Limits are the decode limits the container was checked under.
	Limits Limits
	// Nodes indexes Container.Nodes by hash and records which nodes the proof reads visited (step 22b). Every ReadAccount/ReadSlot/ReadString/
	// ReadBytes/ReadIndexedLeaf of a step goes through it; nil iff there is no container.
	Nodes *NodeSet
	// Facts are the values steps hand to later steps (facts.go). A step writes only the group of its owner.
	Facts *Facts

	headers map[string]headerEntry
}

type headerEntry struct {
	h   finality.HeaderFields
	err error
}

// Prelude is steps 0, 1 and 1b (and the detection of 1c(a)): it builds the Env or returns the framework refusal that ends the run.
//
//   - 0: the manifest must be present (a nil manifest is a defect of the caller: error) and, when the context names a chain, chains[] must
//     have its row (`manifest_unknown{chain}`). A zero chain is not looked up: it is `context_incomplete{missing:[settlement]}` (item 2a:
//     "Chain zero is part of the token settlement"), judged in 1b. The embedded-hash and no-shadow checks of step 0 happen when the manifest
//     is loaded (LoadManifest, WithExtension / Inputs.ResolveManifest): a Manifest value is already hash-checked.
//   - 1: a non-empty container is decoded strictly under DefaultLimits; a refusal is the framework state of Decode. An empty container is
//     not decoded (step 1c(a)).
//   - 1b: ValidateContext; the first of {step 0, step 1, step 1b} that refuses decides.
func Prelude(ctx LegContext, container []byte, m *Manifest) (*Env, *StateError, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("contractidentity: verify: nil manifest")
	}
	fail := func(err error) (*Env, *StateError, error) {
		if st, ok := AsState(err); ok {
			return nil, st, nil
		}
		return nil, nil, err // not a registry state: a defect, never a verdict
	}
	env := &Env{Ctx: ctx, Raw: container, Manifest: m, Limits: DefaultLimits(), Facts: &Facts{}, headers: map[string]headerEntry{}}
	if ctx.Chain != 0 {
		row, err := m.Chain(ctx.Chain)
		if err != nil {
			return fail(err)
		}
		env.Chain = row
	}
	if len(container) > 0 {
		c, err := Decode(container, env.Limits)
		if err != nil {
			return fail(err)
		}
		env.Container = c
	}
	if err := ctx.ValidateContext(); err != nil {
		return fail(err)
	}
	if env.Container != nil {
		ns, err := NewNodeSet(env.Container.Nodes)
		if err != nil {
			// Decode guarantees ascending, unique, non-empty nodes: reaching here is a defect of the codec, not a fact about the evidence.
			return nil, nil, fmt.Errorf("contractidentity: verify: node set of a decoded container: %w", err)
		}
		env.Nodes = ns
	}
	return env, nil, nil
}

// NoEvidence reports step 1c(a): the proof file carries no container for the leg.
func (e *Env) NoEvidence() bool { return e.Container == nil }

// Leg is the container's leg block (number and hash of the settlement block as the container names it); zero without a container.
func (e *Env) Leg() BlockRef {
	if e.Container == nil {
		return BlockRef{}
	}
	return e.Container.Leg
}

// SettleStated is the carried Stated of the settle part, nil when the part is captured (or there is no container).
func (e *Env) SettleStated() *Stated {
	if e.Container == nil || e.Container.Settle.Tag != TagStated {
		return nil
	}
	return e.Container.Settle.Stated
}

// AttestStated is the carried Stated of the attest part, nil when it is captured. An absent attest part does not exist in a decoded
// container (the codec has two part tags); NoEvidence covers the missing container.
func (e *Env) AttestStated() *Stated {
	if e.Container == nil || e.Container.Attest.Tag != TagStated {
		return nil
	}
	return e.Container.Attest.Stated
}

// Registry9Present says whether a (valid) Registry9 was supplied: it makes registry_link a core part.
func (e *Env) Registry9Present() bool { return e.Ctx.Registry9 != nil }

// Header reads a raw header positionally (finality.ReadHeader) once per distinct byte string. The error is the S7 malformed state of the
// header; callers map it to the state their step names.
func (e *Env) Header(raw []byte) (finality.HeaderFields, error) {
	if h, ok := e.headers[string(raw)]; ok {
		return h.h, h.err
	}
	h, err := finality.ReadHeader(raw)
	e.headers[string(raw)] = headerEntry{h, err}
	return h, err
}

// Context is the common data every state of the report carries (registry common_fields), kept beside the fields of a state.
func (e *Env) Context() Context {
	c := Context{Chain: e.Ctx.Chain, ManifestSHA256: e.Manifest.SHA256, ManifestSource: e.Manifest.Source}
	if e.Container != nil {
		c.Block, c.BlockHash = e.Container.Leg.Number, e.Container.Leg.Hash
	}
	if e.Facts != nil {
		c.JudgedAtLevel = e.Facts.C.Level.JudgedAtLevel
	}
	return c
}

// StateJSON renders a state in the report form {code, context, fields} with this Env's common data.
func (e *Env) StateJSON(s *StateError) ([]byte, error) { return s.CanonicalWithContext(e.Context()) }

// ---- raising states: every helper validates against the registry, so a misspelt code, field or vocabulary value is an error of the step,
// never a state that reaches the report ----

// `pending` is not a state a step can raise: it is a headline row that ComputeHeadline derives from the part results and the level binding of
// step 24 (Facts.C.Level); step 24 only reports the S7 result.

// Verified is the contribution `part verified`.
func (e *Env) Verified(part string) PartResult { return PartResult{Part: part, Status: StatusVerified} }

// Refuse is the contribution `part refused` with a judgement-refusal state of the registry (code, row, fields).
func (e *Env) Refuse(part, code, row string, fields map[string]any) (PartResult, error) {
	st, err := New(code, row, fields)
	if err != nil {
		return PartResult{}, err
	}
	return PartResult{Part: part, Status: StatusRefused, State: st}, nil
}

// Unprove is the contribution `part unproven` with an unproven state of the registry.
func (e *Env) Unprove(part, code, row string, fields map[string]any) (PartResult, error) {
	st, err := New(code, row, fields)
	if err != nil {
		return PartResult{}, err
	}
	return PartResult{Part: part, Status: StatusUnproven, State: st}, nil
}

// Open builds an Open entry; kind is alert, drift or not_checked and must match the code.
func (e *Env) Open(part, kind, code, row string, fields map[string]any) (OpenEntry, error) {
	st, err := New(code, row, fields)
	if err != nil {
		return OpenEntry{}, err
	}
	return OpenEntry{Part: part, Kind: kind, State: st}, nil
}

// NotApplicableS6 is the contribution `s6_link not_applicable{reason}` (step 3 row table, step 4) with reason s6_silent or s6_not_proven.
func (e *Env) NotApplicableS6(reason string) PartResult {
	return PartResult{Part: JudgedS6Link, Status: StatusNotApplicable, Reason: reason}
}

// Framework builds a framework-refusal state of the registry (class FR).
func (e *Env) Framework(code, row string, fields map[string]any) (*StateError, error) {
	return New(code, row, fields)
}
