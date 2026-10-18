// Copyright 2026 Certen Protocol

package intent

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// RB9-I item 4: the intent discovery builds evidence 2.1 for the intent's certificate exactly when the rules v15 cross-partition activation
// is in force for the next block, and otherwise behaves as before. These tests drive proveV2, the one place discovery asks the prover.

type g1Gate struct {
	required, g1 bool
	err, g1Err   error
}

func (g g1Gate) ProofV2Bound() (bool, uint64, error)     { return g.required, 7, g.err }
func (g g1Gate) G1CrossPartitionRequired() (bool, error) { return g.g1, g.g1Err }

// legacyGate is a gate that knows nothing of the activation (a node of rules before v15).
type legacyGate struct{}

func (legacyGate) ProofV2Bound() (bool, uint64, error) { return true, 7, nil }

type g1Prover struct {
	proveCalls, g1Calls int
	lastAllow21         bool
	err                 error
}

func (p *g1Prover) Capture(intentID, account, tx, keyBook, keyPage string) {}
func (p *g1Prover) Build(intentID, account, tx, bvn string)                {}
func (p *g1Prover) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	p.proveCalls++
	p.lastAllow21 = false
	return &proofv2.Evidence{Version: proofv2.Version}, p.err
}
func (p *g1Prover) ProveG1(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64, g1 bool) (*proofv2.Evidence, error) {
	p.g1Calls++
	p.lastAllow21 = g1
	if p.err != nil {
		return nil, p.err
	}
	if g1 {
		return &proofv2.Evidence{Version: proofv2.Version21}, nil
	}
	return &proofv2.Evidence{Version: proofv2.Version}, nil
}

// plainProver has no cross-partition entry point (a shadow of rules before v15).
type plainProver struct{ calls int }

func (p *plainProver) Capture(intentID, account, tx, keyBook, keyPage string) {}
func (p *plainProver) Build(intentID, account, tx, bvn string)                {}
func (p *plainProver) Prove(ctx context.Context, intentID, account, tx, bvn string, maxMajors uint64) (*proofv2.Evidence, error) {
	p.calls++
	return &proofv2.Evidence{Version: proofv2.Version}, nil
}

func discoveryWith(gate ProofV2Gate, sh ProofV2Shadow) *IntentDiscovery {
	id := &IntentDiscovery{logger: log.New(io.Discard, "", 0)}
	id.SetProofV2Gate(gate)
	id.SetProofV2Shadow(sh)
	return id
}

func TestProveV2AsksForEvidence21ExactlyWhenTheActivationIsInForce(t *testing.T) {
	// Not in force: the prover is asked for the certificate exactly as before (2.0 form), and says what it cannot build by name.
	p := &g1Prover{}
	cp := &proof.CertenProof{}
	if err := discoveryWith(g1Gate{required: true}, p).proveV2(context.Background(), "i1", "acc://a.acme/x", "tx", "BVN1", cp); err != nil {
		t.Fatal(err)
	}
	if p.g1Calls != 0 || p.proveCalls != 1 || !strings.Contains(string(cp.ProofV2), `"2.0"`) {
		t.Fatalf("activation not in force: 2.1 calls %d, 2.0 calls %d, proof %s", p.g1Calls, p.proveCalls, cp.ProofV2)
	}

	// In force: the prover is told, and the certificate's proof is the 2.1 document.
	p = &g1Prover{}
	cp = &proof.CertenProof{}
	if err := discoveryWith(g1Gate{required: true, g1: true}, p).proveV2(context.Background(), "i1", "acc://a.acme/x", "tx", "BVN1", cp); err != nil {
		t.Fatal(err)
	}
	if p.g1Calls != 1 || !p.lastAllow21 || !strings.Contains(string(cp.ProofV2), `"2.1"`) {
		t.Fatalf("activation in force: g1 calls %d allow21 %v proof %s", p.g1Calls, p.lastAllow21, cp.ProofV2)
	}

	// v3 not yet required: nothing is proven for a certificate, whatever the activation says (the activation is v3's).
	p = &g1Prover{}
	cp = &proof.CertenProof{}
	if err := discoveryWith(g1Gate{required: false, g1: true}, p).proveV2(context.Background(), "i1", "acc://a.acme/x", "tx", "BVN1", cp); err != nil {
		t.Fatal(err)
	}
	if p.g1Calls != 0 || p.proveCalls != 0 || cp.ProofV2 != nil {
		t.Fatalf("v3 not required: prover asked (%d, %d) or proof set %s", p.g1Calls, p.proveCalls, cp.ProofV2)
	}
}

func TestProveV2NeverFallsBackWhenEvidence21IsRequired(t *testing.T) {
	// The activation cannot be read: the intent is retried, never proven under a guess.
	p := &g1Prover{}
	err := discoveryWith(g1Gate{required: true, g1Err: errors.New("db down")}, p).proveV2(context.Background(), "i1", "a", "tx", "BVN1", &proof.CertenProof{})
	if !errors.Is(err, errChainedProofUnavailable) || p.g1Calls+p.proveCalls != 0 {
		t.Fatalf("unreadable activation: %v (prover calls %d)", err, p.g1Calls+p.proveCalls)
	}

	// The prover names a state it cannot establish (g1_evidence_21_not_in_force, a missing authority, ...): the intent is retried and
	// the certificate carries no proof.
	p = &g1Prover{err: &proofv2.NamedState{Code: proofv2.StateEvidence21NotInForce, Block: 9}}
	cp := &proof.CertenProof{}
	err = discoveryWith(g1Gate{required: true}, p).proveV2(context.Background(), "i1", "a", "tx", "BVN1", cp)
	if !errors.Is(err, errChainedProofUnavailable) || !strings.Contains(err.Error(), proofv2.StateEvidence21NotInForce) || cp.ProofV2 != nil {
		t.Fatalf("a named state from the prover: %v proof %s", err, cp.ProofV2)
	}

	// The activation is in force and the prover has no way to build 2.1: the intent is retried, and the 2.0 entry point is NOT used.
	pp := &plainProver{}
	cp = &proof.CertenProof{}
	err = discoveryWith(g1Gate{required: true, g1: true}, pp).proveV2(context.Background(), "i1", "a", "tx", "BVN1", cp)
	if !errors.Is(err, errChainedProofUnavailable) || pp.calls != 0 || cp.ProofV2 != nil {
		t.Fatalf("2.1 required of a prover that cannot build it: %v (2.0 calls %d, proof %s)", err, pp.calls, cp.ProofV2)
	}

	// A gate that knows nothing of the activation (rules before v15) behaves exactly as before.
	pp = &plainProver{}
	cp = &proof.CertenProof{}
	if err := discoveryWith(legacyGate{}, pp).proveV2(context.Background(), "i1", "a", "tx", "BVN1", cp); err != nil || pp.calls != 1 || cp.ProofV2 == nil {
		t.Fatalf("a legacy gate: %v (2.0 calls %d)", err, pp.calls)
	}
}
