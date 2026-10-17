// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// Prover builds finality evidence for settlements on one chain. It is the online half: it may call RPC providers, a beacon
// node or an L1 and may take long; the worker runs it under a deadline and never on the settlement path.
//
// Build returns the strongest evidence it can build now:
//
//   - err == nil: the Evidence proves the returned Level (never more), about s.Subject.
//   - err is a *Pending: the Evidence is the strongest level reached when that level is above none (the Level returned),
//     or zero Evidence with LevelNone; the Pending names the next level, why not yet, and an ETA. The worker appends the
//     reached level if it is new and schedules the next attempt from the ETA.
//   - any other error is a Named state (an unavailability or a refusal); no level is claimed.
//
// A Prover's evidence is not trusted when built: the worker runs the registered offline verifier over it before appending.
type Prover interface {
	Chain() uint64
	Build(ctx context.Context, s Settlement) (Evidence, Level, error)
}

// Ceilinged is an optional Prover interface: the highest level the prover can ever return. The worker skips a prover whose
// ceiling the leg has already reached. A prover without it is run on every pass.
type Ceilinged interface{ Ceiling() Level }

// Verifier is the offline half for one chain and evidence kind: pure, no I/O, no clock, no randomness. Its Verify returns
// the level the evidence proves about s (or a Named state), judging the Body against the pins; the container (version, kind,
// subject) has already been checked by the dispatcher.
type Verifier interface {
	Chain() uint64
	Kind() string
	// MaxLevel is the highest level this kind can prove; the dispatcher refuses a verifier that returns more.
	MaxLevel() Level
	Verify(s Settlement, ev Evidence, pins *Pins) (Level, error)
}

// Pins are the trust inputs a verifier is handed (a weak-subjectivity checkpoint ledger, a committee genesis, contract
// identities), by chain and kind. They are never read from evidence. A nil *Pins holds none.
type Pins struct {
	mu sync.RWMutex
	m  map[pinKey]any
}

type pinKey struct {
	chain uint64
	kind  string
}

// NewPins returns an empty pin set.
func NewPins() *Pins { return &Pins{m: map[pinKey]any{}} }

// Set pins a value for a chain and kind (a chain package defines the value's type).
func (p *Pins) Set(chain uint64, kind string, v any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[pinKey]any{}
	}
	p.m[pinKey{chain, kind}] = v
}

// Get returns the pinned value, or the named finality_pin_unknown state saying which pin was asked for.
func (p *Pins) Get(chain uint64, kind string) (any, error) {
	if p != nil {
		p.mu.RLock()
		defer p.mu.RUnlock()
		if v, ok := p.m[pinKey{chain, kind}]; ok {
			return v, nil
		}
	}
	return nil, NewState(CodePinMissing, "chain", chain, "kind", kind)
}

// Registry holds the provers and verifiers of every chain package. Chain packages register into Default from their own
// init or from an explicit Register call at startup; tests build their own with NewRegistry.
type Registry struct {
	mu        sync.RWMutex
	provers   map[uint64][]Prover
	verifiers map[verifierKey]Verifier
	profiles  map[uint64]ChainProfile
}

type verifierKey struct {
	chain uint64
	kind  string
}

// NewRegistry returns a registry holding the chain profiles (profile.go) and the included level for every profiled chain.
func NewRegistry() *Registry {
	r := &Registry{provers: map[uint64][]Prover{}, verifiers: map[verifierKey]Verifier{}, profiles: map[uint64]ChainProfile{}}
	for _, p := range DefaultProfiles() {
		if err := r.RegisterProfile(p); err != nil {
			panic(err) // the built-in profiles are fixed data; a conflict is a build defect
		}
		if err := r.RegisterVerifier(IncludedVerifier{ChainID: p.Chain}); err != nil {
			panic(err)
		}
		if err := r.RegisterProver(IncludedProver{ChainID: p.Chain}); err != nil {
			panic(err)
		}
	}
	return r
}

// Default is the registry the validator and the offline verifier use.
var Default = NewRegistry()

// RegisterProfile adds a chain's profile; a second profile for a chain is refused.
func (r *Registry) RegisterProfile(p ChainProfile) error {
	if err := p.validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.profiles[p.Chain]; dup {
		return fmt.Errorf("finality: chain %d already has a profile", p.Chain)
	}
	r.profiles[p.Chain] = p
	return nil
}

// RegisterVerifier adds the verifier of one chain and kind; a second verifier for the pair is refused.
func (r *Registry) RegisterVerifier(v Verifier) error {
	if !kindOK(v.Kind()) {
		return fmt.Errorf("finality: verifier kind %q is not a valid kind", v.Kind())
	}
	if !v.MaxLevel().Valid() {
		return fmt.Errorf("finality: verifier %d/%s declares no valid maximum level", v.Chain(), v.Kind())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := verifierKey{v.Chain(), v.Kind()}
	if _, dup := r.verifiers[k]; dup {
		return fmt.Errorf("finality: chain %d kind %q already has a verifier", k.chain, k.kind)
	}
	r.verifiers[k] = v
	return nil
}

// RegisterProver adds a prover for its chain. Several provers may serve one chain (the included prover and the chain's
// finality prover); the worker takes the strongest level any of them reaches.
func (r *Registry) RegisterProver(p Prover) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.provers[p.Chain()] = append(r.provers[p.Chain()], p)
	return nil
}

// Provers returns a chain's provers in registration order.
func (r *Registry) Provers(chain uint64) []Prover {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]Prover(nil), r.provers[chain]...)
}

// Profile returns a chain's profile, or finality_chain_unsupported.
func (r *Registry) Profile(chain uint64) (ChainProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[chain]
	if !ok {
		return ChainProfile{}, NewState(CodeChainUnsupported, "chain", chain)
	}
	return p, nil
}

// Chains returns the profiled chains, ascending.
func (r *Registry) Chains() []uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]uint64, 0, len(r.profiles))
	for c := range r.profiles {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Verify is the pure offline check: it judges evidence about settlement s on chain and returns the level the evidence
// proves, exactly as the registered verifier for (chain, ev.Kind) returned it. It never returns a level above what the
// verifier returned, above the verifier's declared maximum, or that the chain does not offer; every other outcome is a Named
// state: finality_chain_unsupported, finality_subject_mismatch, finality_kind_unknown, a verifier's own refusal (wrapped as
// finality_verifier_failed only when it is not already a Named state), finality_level_exceeds_evidence,
// finality_level_not_offered.
func (r *Registry) Verify(chain uint64, s Settlement, ev Evidence, pins *Pins) (Level, error) {
	profile, err := r.Profile(chain)
	if err != nil {
		return LevelNone, err
	}
	if s.Chain != chain {
		return LevelNone, NewState(CodeSubjectMismatch, "field", "chain", "got", s.Chain, "want", chain)
	}
	if ev.Version != EvidenceVersion {
		return LevelNone, NewState(CodeEvidenceUnrecognised, "version", ev.Version, "want", EvidenceVersion)
	}
	if ev.Subject.BlockHash != s.BlockHash {
		return LevelNone, NewState(CodeSubjectMismatch, "field", "blockHash", "chain", chain)
	}
	if ev.Subject.TxHash != s.TxHash {
		return LevelNone, NewState(CodeSubjectMismatch, "field", "txHash", "chain", chain)
	}
	if ev.Subject.BlockNumber != s.BlockNumber {
		return LevelNone, NewState(CodeSubjectMismatch, "field", "blockNumber", "chain", chain, "got", ev.Subject.BlockNumber, "want", s.BlockNumber)
	}
	r.mu.RLock()
	v, ok := r.verifiers[verifierKey{chain, ev.Kind}]
	r.mu.RUnlock()
	if !ok {
		return LevelNone, NewState(CodeKindUnknown, "chain", chain, "kind", ev.Kind)
	}
	level, err := v.Verify(s, ev, pins)
	if err != nil {
		if _, named := AsNamed(err); named {
			return LevelNone, err
		}
		return LevelNone, NewState(CodeVerifierFailed, "chain", chain, "kind", ev.Kind, "cause", err.Error())
	}
	if !level.Valid() || level > v.MaxLevel() {
		return LevelNone, NewState(CodeLevelExceedsEvidence, "chain", chain, "kind", ev.Kind, "returned", level, "kind_max", v.MaxLevel())
	}
	if !profile.Offers(level) {
		return LevelNone, NewState(CodeLevelNotOffered, "chain", chain, "level", level)
	}
	return level, nil
}

// Verify is Registry.Verify over the Default registry.
func Verify(chain uint64, s Settlement, ev Evidence, pins *Pins) (Level, error) {
	return Default.Verify(chain, s, ev, pins)
}

// VerifyAddendum is the per-addendum judgement a document or store verifier needs after VerifyChain: the evidence must
// decode, must prove exactly the level the addendum claims (a claim above the evidence is finality_level_exceeds_evidence;
// a claim below it is finality_level_mismatch, so a chain never under-states what it proves either), about the chain's subject.
func (r *Registry) VerifyAddendum(a Addendum, pins *Pins) (Level, error) {
	ev, err := DecodeEvidence(a.Evidence)
	if err != nil {
		return LevelNone, err
	}
	level, err := r.Verify(a.Chain, Settlement{Chain: a.Chain, Subject: ev.Subject}, ev, pins)
	if err != nil {
		return LevelNone, err
	}
	if level < a.Level {
		return LevelNone, NewState(CodeLevelExceedsEvidence, "chain", a.Chain, "seq", a.Seq, "claimed", a.Level, "proven", level)
	}
	if level > a.Level {
		return LevelNone, NewState(CodeLevelMismatch, "chain", a.Chain, "seq", a.Seq, "claimed", a.Level, "proven", level)
	}
	return level, nil
}
