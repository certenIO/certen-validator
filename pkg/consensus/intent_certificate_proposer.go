package consensus

import (
	"encoding/json"
	"fmt"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/ledger"
	govproof "github.com/certen/independant-validator/pkg/proof"
)

// certifyIntent builds the block's intent certificate with this validator's BLS key (RB5 D3). Everything it needs
// is what the block's own proof was built from; nothing here is optional, and the result is verified by the same
// function FinalizeBlock runs before the block is broadcast.
func (bv *BFTValidator) certifyIntent(vb *ValidatorBlock, chainID string, reg *ledger.BLSRegistryRecord,
	certenProof *govproof.CertenProof, keyPageURL, keyBookURL string, authorization *govproof.AuthorizationRecord,
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
	key := bls.GetValidatorBLSKey()
	if key == nil {
		return fmt.Errorf("this validator's BLS key is not initialized")
	}
	return BuildIntentCertificate(vb, chainID, reg, key.PrivateKey(), keyPageURL, keyBookURL, authorization, ev,
		certenProof.LiteClientProof.ChainedProof)
}
