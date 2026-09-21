package intent

import (
	"context"
	"io"
	"log"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// countingGovGen records every governance proof it is asked for.
type countingGovGen struct{ calls int }

func (g *countingGovGen) GenerateG0(context.Context, *proof.GovernanceRequest) (*proof.GovernanceProof, error) {
	g.calls++
	return &proof.GovernanceProof{}, nil
}
func (g *countingGovGen) GenerateG1(context.Context, *proof.GovernanceRequest) (*proof.GovernanceProof, error) {
	g.calls++
	return &proof.GovernanceProof{}, nil
}
func (g *countingGovGen) GenerateG2(context.Context, *proof.GovernanceRequest) (*proof.GovernanceProof, error) {
	g.calls++
	return &proof.GovernanceProof{}, nil
}
func (g *countingGovGen) GenerateAtLevel(context.Context, proof.GovernanceLevel, *proof.GovernanceRequest) (*proof.GovernanceProof, error) {
	g.calls++
	return &proof.GovernanceProof{}, nil
}

// With no batch system the discovery-time governance proof has no consumer - consensus builds its
// own - so it must not be generated. Live it held every intent ~2.5 minutes before consensus began.
func TestDiscoveryGovernanceProofIsNotBuiltWithoutABatchSystem(t *testing.T) {
	gen := &countingGovGen{}
	id := &IntentDiscovery{logger: log.New(io.Discard, "", 0), governanceProofGen: gen, batchingEnabled: false}

	got := id.discoveryGovernanceProof(&CertenIntent{IntentID: "x", TransactionHash: "ab"}, &proof.CertenProof{}, "acc://a.acme/data")

	if got != nil || gen.calls != 0 {
		t.Fatalf("generated %d governance proof(s) (result %v) with no batch system to route them to", gen.calls, got)
	}
}

// With a batch system it is still generated: that is the proof the batch system persists.
func TestDiscoveryGovernanceProofIsBuiltForTheBatchSystem(t *testing.T) {
	gen := &countingGovGen{}
	id := &IntentDiscovery{logger: log.New(io.Discard, "", 0), governanceProofGen: gen, batchingEnabled: true}

	got := id.discoveryGovernanceProof(&CertenIntent{IntentID: "x", TransactionHash: "ab"}, &proof.CertenProof{}, "acc://a.acme/data")

	if got == nil || gen.calls == 0 {
		t.Fatalf("no governance proof generated for the batch system (calls=%d)", gen.calls)
	}
}
