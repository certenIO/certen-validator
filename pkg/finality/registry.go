// Copyright 2026 Certen Protocol

package finality

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/certen/independant-validator/pkg/ethproof"
)

// Verdict is what a Kind returns for evidence it accepted: the level proven and the fields of the "Result" of its
// V2_SPEC_S7 section 5 subsection.
type Verdict struct {
	Level  Level
	Kind   string
	Fields map[string]any
}

// Kind is the offline half for one (chain, level) row of the table: PURE (no I/O, no clock, no randomness; sole exception:
// the Adiri batch scalars, spec 5.8). Verify judges the whole CFE1 container `evidence` about the leg block b against the
// pins and returns the verdict, or a named state (a *StateError). The dispatcher has already checked the container header
// against the addendum and the leg.
type Kind interface {
	Name() string
	Chain() uint64
	Level() Level
	Verify(p *Pins, b BlockRef, evidence []byte) (Verdict, error)
}

// Prover builds finality addenda for settlements on one chain. It is the online half: it may call RPC providers, a beacon
// node or an L1, may take long, and calls the registered Kind's Verify on what it built before returning. The worker runs
// it under a deadline and never on the settlement path.
//
// Build returns the addendum for `target` if it can be built now (Level, Chain, Kind and Evidence set; ProofID, Seq,
// PrevHash and OwnHash are assigned by NewAddendum when the worker appends it), or a PendingState naming the level reached,
// the next level, the reason and an ETA, or an error that is a named state (an unavailability or a refusal). `have` is the
// set of levels the leg already holds, in any order (R1); a prover never rebuilds one of them.
type Prover interface {
	Chain() uint64
	Build(ctx context.Context, s *ethproof.Settlement, have LevelSet, target Level) (*Addendum, *PendingState, error)
}

// Ceilinged is an optional Prover interface: the highest level the prover can ever return. The worker skips a prover whose
// ceiling the leg already holds.
type Ceilinged interface{ Ceiling() Level }

// Registry holds the provers and Kinds of every chain package. Chain packages register into Default from an explicit call at
// startup; tests build their own with NewRegistry.
type Registry struct {
	mu        sync.RWMutex
	provers   map[uint64][]Prover
	kinds     map[string]Kind
	profiles  map[uint64]ChainProfile
	capturers map[uint64][]Capturer
}

// NewRegistry returns a registry holding the chain profiles (profile.go). No Kind or Prover is registered: level 1 is
// derived (DeriveIncluded), and the kinds of levels 2 and 3 are registered by the chain packages (RB11-C..F).
func NewRegistry() *Registry {
	r := &Registry{provers: map[uint64][]Prover{}, kinds: map[string]Kind{}, profiles: map[uint64]ChainProfile{}}
	for _, p := range DefaultProfiles() {
		if err := r.RegisterProfile(p); err != nil {
			panic(err) // the built-in profiles are fixed data; a conflict is a build defect
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

// RegisterKind adds the Kind of one table row; a Kind that is not a row of the table, or a second Kind for a name, is refused.
func (r *Registry) RegisterKind(k Kind) error {
	if !IsRow(k.Chain(), k.Level(), k.Name()) {
		return fmt.Errorf("finality: kind %q (chain %d, level %s) is not a row of the V2_SPEC_S7 section 1 table", k.Name(), k.Chain(), k.Level())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.kinds[k.Name()]; dup {
		return fmt.Errorf("finality: kind %q already has a verifier", k.Name())
	}
	r.kinds[k.Name()] = k
	return nil
}

// RegisterProver adds a prover for its chain. Several provers may serve one chain; the worker asks each for the level it can
// build.
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

// Profile returns a chain's profile, or finality_chain_unsupported{chain}.
func (r *Registry) Profile(chain uint64) (ChainProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.profiles[chain]
	if !ok {
		return ChainProfile{}, ChainUnsupported(chain)
	}
	return p, nil
}

// Chains returns the profiled chains, ascending.
func (r *Registry) Chains() []uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sortedChainsLocked()
}

func (r *Registry) sortedChainsLocked() []uint64 {
	out := make([]uint64, 0, len(r.profiles))
	for c := range r.profiles {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (r *Registry) kind(name string) (Kind, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.kinds[name]
	return k, ok
}

// kindVersion is the "/vN" suffix of a kind name ("v1"), the version field of finality_evidence_unrecognised.
func kindVersion(kind string) string {
	if i := strings.LastIndex(kind, "/"); i >= 0 {
		return kind[i+1:]
	}
	return ""
}

// JudgeAddendum is the per-addendum judgement after VerifyChain: the container decodes (bounded, strict), its header's kind,
// chain and level equal the addendum's, it is about the leg block b (else finality_block_mismatch), a Kind is registered for
// it (else finality_evidence_unrecognised) and that Kind accepts it at exactly the row's level. A refusal here affects no
// other level (R3).
func (r *Registry) JudgeAddendum(b BlockRef, a Addendum, p *Pins) (Verdict, error) {
	c, err := DecodeContainer(a.Evidence, DefaultLimits())
	if err != nil {
		return Verdict{}, err
	}
	h := c.Header
	for _, f := range []struct {
		part    string
		differs bool
	}{{"header.kind", h.Kind != a.Kind}, {"header.chain", h.Chain != a.Chain}, {"header.level", h.Level != a.Level}} {
		if f.differs {
			return Verdict{}, Malformed(f.part, ReasonDiffersFromAddendum, 0, 0)
		}
	}
	if h.Chain != b.Chain {
		return Verdict{}, BlockMismatch("chain", b.Chain, h.Chain)
	}
	if h.BlockNumber != b.Number {
		return Verdict{}, BlockMismatch("blockNumber", b.Number, h.BlockNumber)
	}
	if h.BlockHash != b.Hash {
		return Verdict{}, BlockMismatch("blockHash", b.Hash, h.BlockHash)
	}
	k, ok := r.kind(a.Kind)
	if !ok {
		return Verdict{}, EvidenceUnrecognised(a.Kind, kindVersion(a.Kind))
	}
	v, err := k.Verify(p, b, a.Evidence)
	if err != nil {
		if _, named := AsNamed(err); named {
			return Verdict{}, err
		}
		return Verdict{}, NewState(CodeVerifierFailed, "chain", a.Chain, "kind", a.Kind, "cause", err.Error())
	}
	if v.Level != k.Level() || v.Level != a.Level {
		return Verdict{}, NewState(CodeVerifierFailed, "chain", a.Chain, "kind", a.Kind, "cause",
			fmt.Sprintf("the kind returned level %s for a %s row", v.Level, k.Level()))
	}
	if v.Kind == "" {
		v.Kind = a.Kind
	}
	return v, nil
}
