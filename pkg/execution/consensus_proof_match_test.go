// Copyright 2026 Certen Protocol

package execution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB3-F87: the chained proof a cycle stores is the one consensus signed over.
func TestTheStoredProofMustBeTheOneConsensusSignedOver(t *testing.T) {
	signed := p6LoadFixture(t, "proof_bvn1.json")
	raw, err := json.Marshal(proof.LiteClientProofData{CompleteProof: proof.ChainedProofToCompleteProof(signed)})
	if err != nil {
		t.Fatal(err)
	}
	commitment := map[string]interface{}{consensusProofCommitmentKey: string(raw)}

	if compared, err := matchesConsensusProof(commitment, p6LoadFixture(t, "proof_bvn1.json")); !compared || err != nil {
		t.Fatalf("the same proof, rebuilt: compared=%v %v", compared, err)
	}
	if _, err := matchesConsensusProof(commitment, p6LoadFixture(t, "proof_bvn3.json")); err == nil {
		t.Fatal("another transaction's proof was stored as the one consensus signed over")
	}
	moved := p6LoadFixture(t, "proof_bvn1.json")
	moved.Layer3.DNStateTreeAnchor = "00" + moved.Layer3.DNStateTreeAnchor[2:]
	if _, err := matchesConsensusProof(commitment, moved); err == nil {
		t.Fatal("a proof anchored to another DN state was stored as the one consensus signed over")
	}
	if compared, err := matchesConsensusProof(map[string]interface{}{}, signed); compared || err != nil {
		t.Fatalf("no consensus-time proof: nothing to compare, stated as such (compared=%v %v)", compared, err)
	}
	if _, err := matchesConsensusProof(map[string]interface{}{consensusProofCommitmentKey: "{"}, signed); err == nil {
		t.Fatal("an undecodable consensus proof was accepted")
	}
}

type fixtureProofGenerator struct{ cp *chained_proof.ChainedProof }

func (g fixtureProofGenerator) GenerateChainedProofForTx(context.Context, string, string, string) (*ChainedProofResult, error) {
	return &ChainedProofResult{CompleteProof: g.cp}, nil
}

func TestTheBundleWriterRefusesAProofConsensusDidNotSignOver(t *testing.T) {
	db := s1OpenDB(t)
	c, intentID := f73Cycle(t, nil, nil)
	t.Cleanup(func() { cleanupProofArtifacts(db, intentID) })

	raw, err := json.Marshal(proof.LiteClientProofData{CompleteProof: proof.ChainedProofToCompleteProof(p6LoadFixture(t, "proof_bvn1.json"))})
	if err != nil {
		t.Fatal(err)
	}
	c.Request.CommitmentData[consensusProofCommitmentKey] = string(raw)

	o := f73Orchestrator(db)
	o.config.ProofGenerator = fixtureProofGenerator{p6LoadFixture(t, "proof_bvn3.json")}
	err = o.generateAndPersistBundle(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "not the one consensus signed over") {
		t.Fatalf("the cycle stored a proof other than the one consensus signed over (err=%v)", err)
	}
	var layers int
	if err := db.QueryRow(`SELECT count(*) FROM chained_proof_layers l JOIN proof_artifacts a ON a.proof_id=l.proof_id WHERE a.intent_id=$1 AND l.layer_number > 0`, intentID).Scan(&layers); err != nil {
		t.Fatal(err)
	}
	if layers != 0 {
		t.Fatalf("%d layers of the unsigned proof were stored", layers)
	}
}
