// Copyright 2026 Certen Protocol

// Package s6replay2 is the second conformance set of the S6 replay-guard evidence (the same wire format and domain tag,
// certen:s6-replay:v1): the vectors of the CertenAccountV7_2 layout pinned by RB10-F3, proven and refused, and their
// bounded mutation corpus. It supersedes the s6replay1 vectors that state V7_2 has no pinned layout
// (testdata/s6replay1/SUPERSEDED.md); s6replay1 itself is kept byte-identical. `go run ./cmd/s6replayvectors -set
// s6replay2` writes it to pkg/ethproof/testdata/s6replay2; the TypeScript verifier consumes byte-identical copies.
package s6replay2

import (
	"fmt"
	"math/big"

	"github.com/certen/independant-validator/pkg/ethproof"
	"github.com/certen/independant-validator/pkg/ethproof/replayworld"
	"github.com/certen/independant-validator/pkg/ethproof/s6replay1"
)

// Generator is the command line that writes this set.
const Generator = "cmd/s6replayvectors -set s6replay2"

// panicTB is the builder's TB outside a test.
type panicTB struct{}

func (panicTB) Helper()                   {}
func (panicTB) Fatal(args ...interface{}) { panic(fmt.Sprint(args...)) }

type builder struct{ vectors []s6replay1.Vector }

func (b *builder) add(name, desc string, s s6replay1.Settlement, evidence []byte) {
	b.vectors = append(b.vectors, s6replay1.Vector{Name: fmt.Sprintf("%03d_%s", len(b.vectors)+1, name), Description: desc,
		Settlement: s, Evidence: string(evidence), Expect: s6replay1.Judge(s, evidence)})
}

// v72 is the world's proof stated as a CertenAccountV7_2 proof (the same slot: V7_2's base is 4, as V7_3's).
func v72(w *replayworld.World, f func(p *ethproof.ReplayGuardProof)) []byte {
	p := s6replay1.CloneProof(w.Proof)
	p.Generation = ethproof.AccountGenerationV7_2
	if f != nil {
		f(p)
	}
	return s6replay1.ProofEvidence(p)
}

// BuildVectors builds every vector, in order.
func BuildVectors() []s6replay1.Vector {
	tb := panicTB{}
	world := func(o replayworld.Opts) *replayworld.World { return replayworld.New(tb, o) }
	b := &builder{}

	// Proven, through both of V7_2's settlement entry points.
	exec := world(replayworld.Opts{Selector: replayworld.V72Execute})
	sExec := s6replay1.SettlementOf(exec)
	b.add("v7_2_valid_execute", "a CertenAccountV7_2 executeGovernanceProofDirect (0x57f8567d) settlement: After at the settlement block, Before at its parent",
		sExec, v72(exec, nil))
	batch := world(replayworld.Opts{After: 1, Selector: replayworld.V72Batch})
	b.add("v7_2_valid_batch", "a CertenAccountV7_2 batchExecuteGovernanceProofDirect (0xb7daa901) settlement, After 1 block later",
		s6replay1.SettlementOf(batch), v72(batch, nil))
	chain := world(replayworld.Opts{After: 3, Selector: replayworld.V72Execute})
	b.add("v7_2_valid_after_header_chain", "a CertenAccountV7_2 settlement, After proven 3 blocks later through linked headers",
		s6replay1.SettlementOf(chain), v72(chain, nil))
	b.add("v7_2_before_unavailable_disclosed", "a CertenAccountV7_2 settlement, Before not served and disclosed", sExec,
		v72(exec, func(p *ethproof.ReplayGuardProof) {
			p.Before = nil
			p.BeforeUnavailable = &ethproof.ReplayBeforeUnavailable{Reason: ethproof.ReasonStateUnavailable,
				Providers: []ethproof.ReplayProviderFailure{{Host: "sepolia.base.org", Error: "missing trie node"}}}
		}))

	// Refused: the generation must be the one the calldata calls, at its pinned base, and the slot as it proves.
	v73 := world(replayworld.Opts{})
	b.add("v7_2_proof_of_a_v7_3_call", "a CertenAccountV7_2 proof of a CertenAccountV7_3 settlement call (0x606f2c8d)",
		s6replay1.SettlementOf(v73), v72(v73, nil))
	b.add("v7_3_proof_of_a_v7_2_call", "a CertenAccountV7_3 proof of a CertenAccountV7_2 settlement call (0x57f8567d)", sExec,
		s6replay1.ProofEvidence(exec.Proof))
	b.add("v7_2_wrong_base", "base 5 is not V7_2's pinned base 4", sExec, v72(exec, func(p *ethproof.ReplayGuardProof) {
		p.Slot.Base = 5
		p.Slot.Slot = ethproof.ReplaySlotFor(exec.Leaf, 5)
	}))
	set := world(replayworld.Opts{Selector: replayworld.V72Execute, BeforeValue: big.NewInt(1)})
	b.add("v7_2_slot_set_at_parent", "a CertenAccountV7_2 settlement whose Before proves the slot already 1",
		s6replay1.SettlementOf(set), v72(set, nil))
	unset := world(replayworld.Opts{Selector: replayworld.V72Execute, AfterValue: big.NewInt(0)})
	b.add("v7_2_after_value_zero", "a CertenAccountV7_2 settlement whose After proves the slot 0",
		s6replay1.SettlementOf(unset), v72(unset, nil))
	b.add("generation_unpinned", "CertenAccountV7_1 has no pinned layout", sExec, v72(exec, func(p *ethproof.ReplayGuardProof) {
		p.Generation = "CertenAccountV7_1"
	}))
	return b.vectors
}

// MutationBases are the vectors the corpus mutates: the valid V7_2 ones.
var MutationBases = []string{"001_v7_2_valid_execute", "002_v7_2_valid_batch", "003_v7_2_valid_after_header_chain",
	"004_v7_2_before_unavailable_disclosed"}

// Files are the set's files by name: one JSON per vector, mutations.json.gz, manifest.json and MANIFEST.
func Files() map[string][]byte {
	vectors := BuildVectors()
	return s6replay1.SuiteFiles(vectors, s6replay1.BuildMutationsOf(vectors, MutationBases), Generator)
}
