// Copyright 2026 Certen Protocol

package consensus

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/proof"
)

// RB3-F88: a ValidatorBlock is built on its intent's proof and the Accumulate anchor that proof
// established, whole - never on placeholders standing in for them.

func TestAnOnCadenceIntentWithoutItsProofIsRefused(t *testing.T) {
	bv := refusalValidator(newFakeEnqueuer())
	_, err := bv.executeCanonicalBFTWorkflow(context.Background(), batchableIntent(t, "i1", 84532), nil, "i1:7", 7)
	if err == nil || !strings.Contains(err.Error(), "without its CertenProof") {
		t.Fatalf("an on_cadence intent was built into a block without its proof (err=%v)", err)
	}
}

func TestTheBlockAnchorIsTheOneTheProofEstablished(t *testing.T) {
	whole := &proof.AccumulateAnchorData{BlockHash: strings.Repeat("ab", 32), BlockHeight: 1234, TxHash: strings.Repeat("cd", 32)}
	p := &proof.CertenProof{AccountURL: "acc://org.acme/data", AccumulateAnchor: whole}
	ref, err := accumulateAnchorOf(p)
	if err != nil {
		t.Fatal(err)
	}
	if ref.BlockHash != whole.BlockHash || ref.BlockHeight != 1234 || ref.TxHash != whole.TxHash || ref.AccountURL != "acc://org.acme/data" {
		t.Fatalf("anchor reference %+v is not the proof's", ref)
	}
	for name, a := range map[string]*proof.AccumulateAnchorData{
		"no anchor":       nil,
		"no block hash":   {BlockHeight: 1234, TxHash: whole.TxHash},
		"no block height": {BlockHash: whole.BlockHash, TxHash: whole.TxHash},
		"no transaction":  {BlockHash: whole.BlockHash, BlockHeight: 1234},
	} {
		if ref, err := accumulateAnchorOf(&proof.CertenProof{AccumulateAnchor: a}); err == nil {
			t.Errorf("%s: a block anchor was made up: %+v", name, ref)
		}
	}
}

func TestTheBuilderInventsNoAnchorAndNoValidator(t *testing.T) {
	whole := AccumulateAnchorReference{BlockHash: strings.Repeat("ab", 32), BlockHeight: 1234, TxHash: strings.Repeat("cd", 32), AccountURL: "acc://org.acme/data"}
	build := func(validatorID string, ref AccumulateAnchorReference) (*ValidatorBlock, error) {
		return NewValidatorBlockBuilder(BuilderConfig{ValidatorID: validatorID, BLSValidatorSetPubKey: "aa"}).BuildFromIntent(BuilderInputs{
			Intent:      batchableIntent(t, "i1", 84532),
			Governance:  GovernanceInputs{BLSAggregateSignature: "bb", GovernanceLevel: "G2"},
			Execution:   ExecutionInputs{Stage: ExecutionStagePre, ProofClass: "on_cadence", ValidatorSignatures: []string{"cc"}},
			AnchorRef:   ref,
			BlockHeight: 7,
		})
	}
	vb, err := build("validator-test", whole)
	if err != nil {
		t.Fatalf("a block with its whole anchor: %v", err)
	}
	if vb.AccumulateAnchorReference != whole || vb.ValidatorID != "validator-test" {
		t.Fatalf("block anchor %+v by %q; want %+v by validator-test", vb.AccumulateAnchorReference, vb.ValidatorID, whole)
	}
	for name, ref := range map[string]AccumulateAnchorReference{
		"no block hash":   {BlockHeight: 1234, TxHash: whole.TxHash},
		"no block height": {BlockHash: whole.BlockHash, TxHash: whole.TxHash},
		"no transaction":  {BlockHash: whole.BlockHash, BlockHeight: 1234},
	} {
		if vb, err := build("validator-test", ref); err == nil {
			t.Errorf("%s: built on anchor %+v", name, vb.AccumulateAnchorReference)
		}
	}
	if vb, err := build("", whole); err == nil {
		t.Errorf("built with no validator ID, as %q", vb.ValidatorID)
	}
}

// A failed BLS pre-execution signature ends the workflow with its own reason. It used to be logged and
// the block refused later by the builder as "ensure BLS key is initialized", whatever had gone wrong.
func TestABLSSigningFailureIsRefusedByName(t *testing.T) {
	raw, err := os.ReadFile("bft_integration.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	at := strings.Index(src, "sig, err := signV6_1PreExecBLS(bv.logger, certenIntent, certenProof)")
	if at < 0 {
		t.Fatal("BLS pre-execution signing not found in the workflow")
	}
	next := src[at : at+strings.Index(src[at:], "blsSignature = sig")]
	if !strings.Contains(next, "if err != nil {\n\t\t\t// Refused here by name.") || !strings.Contains(next, "return nil, fmt.Errorf(") {
		t.Fatalf("a BLS signing error does not end the workflow:\n%s", next)
	}
}
