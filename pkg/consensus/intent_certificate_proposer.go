package consensus

import (
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/intentcert"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// certifyIntent builds the block's intent certificate with this validator's BLS key (RB5 D3). Everything it needs
// is what the block's own proof was built from; nothing here is optional, and the result is verified by the same
// function FinalizeBlock runs before the block is broadcast.
func (bv *BFTValidator) certifyIntent(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord,
	spine *ledger.AccumulateSpineLog, certenProof *govproof.CertenProof, keyPageURL, keyBookURL string, authorization *govproof.AuthorizationRecord,
	voteEvidence *govvote.Evidence) error {
	if certenProof == nil || certenProof.LiteClientProof == nil || certenProof.LiteClientProof.ChainedProof == nil {
		return fmt.Errorf("the intent's chained proof is not carried, so its certificate cannot prove it")
	}
	if voteEvidence == nil {
		return fmt.Errorf("the governance proof carries no vote evidence")
	}
	ev, err := json.Marshal(voteEvidence)
	if err != nil {
		return fmt.Errorf("the vote evidence: %w", err)
	}
	// Once the chain requires the v3 certificate, the intent's proof v2 is part of it: discovery built it on the
	// checkpoints the chain had verified (intent.ProofV2Gate). Without it the certificate cannot be built.
	var pv2 *proofv2.Evidence
	if ProofV3Required(spine, reg) {
		if len(certenProof.ProofV2) == 0 {
			return ErrIntentProofV2Missing
		}
		pv2 = new(proofv2.Evidence)
		if err := json.Unmarshal(certenProof.ProofV2, pv2); err != nil {
			return fmt.Errorf("%w: it does not decode: %v", ErrIntentProofV2Invalid, err)
		}
	}
	key := bls.GetValidatorBLSKey()
	if key == nil {
		return fmt.Errorf("this validator's BLS key is not initialized")
	}
	return BuildIntentCertificate(vb, chainID, reg, key.PrivateKey(), keyPageURL, keyBookURL, authorization, ev,
		certenProof.LiteClientProof.ChainedProof, spine, pv2)
}

// PortableInputsRecorder is told, for each intent whose v3 certificate this validator built, the govRoot v3 inputs that are not
// proof facts (the sha256 of each governance level's canonical JSON, the key page, the key book, the operation id), so the
// intent's portable proof v2 document can carry them (RB7b-F30). It is a record, never a gate.
type PortableInputsRecorder func(intentID string, in *proofv2.PortableGovRootV3Inputs)

// SetPortableInputsRecorder installs the recorder. Without one nothing is recorded and nothing else changes.
func (bv *BFTValidator) SetPortableInputsRecorder(r PortableInputsRecorder) {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	bv.portableInputs = r
}

// recordPortableInputs hands the recorder an intent's govRoot v3 inputs after its certificate was built. Failing to derive them is
// logged and changes nothing: the certificate is already built and verified, and the document simply carries no inputs.
func (bv *BFTValidator) recordPortableInputs(intentID string, vb *ValidatorBlock, keyPageURL, keyBookURL string) {
	bv.mu.RLock()
	rec := bv.portableInputs
	bv.mu.RUnlock()
	if rec == nil || vb == nil || vb.IntentCertificate == nil || vb.IntentCertificate.ProofV2 == nil {
		return
	}
	gp := &vb.GovernanceProof
	op, err := hex32(vb.CrossChainProof.OperationID)
	if err == nil {
		var in *proofv2.PortableGovRootV3Inputs
		if in, err = intentcert.PortableGovRootV3Inputs(intentcert.GovRootV3Inputs{G0: gp.G0Proof, G1: gp.G1Proof, G2: gp.G2Proof,
			KeyPageURL: keyPageURL, KeyBookURL: keyBookURL, OperationID: op}); err == nil {
			rec(intentID, in)
			return
		}
	}
	bv.logger.Printf("portable govRoot v3 inputs for intent %s were not recorded: %v", intentID, err)
}
