package consensus

import (
	"encoding/json"
	"fmt"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// blsSignatureHexBytes is what the intent signature adds to a block that does not carry it yet: a compressed G1 point, hex (48 bytes).
const blsSignatureHexBytes = 96

// checkCertificateFitsBeforeSigning is the whole-certificate pre-sign check of evidence 2.1 (RB9-F5 package F5-4, V-E A4). The block is
// judged as it will be broadcast (json.Marshal of the ValidatorBlock, the bytes the proposer logs as "ValidatorBlock marshaled") plus the
// signature it does not carry yet, against the transaction limit the whole path accepts (proofv2.ConsensusTxLimit). Over it is
// certificate_budget{size,limit}, the same decision as the broadcast's tx_too_large, and nothing is signed. Evidence 2.0 is not judged here: its
// transactions are decided exactly as before.
func checkCertificateFitsBeforeSigning(vb *ValidatorBlock) error {
	ic := vb.IntentCertificate
	if ic == nil || ic.ProofV2 == nil || ic.ProofV2.Version != proofv2.Version21 {
		return nil
	}
	raw, err := json.Marshal(vb)
	if err != nil {
		return fmt.Errorf("encode the block to judge its size: %w", err)
	}
	if size := len(raw) + blsSignatureHexBytes; size > proofv2.ConsensusTxLimit {
		return proofv2.CertificateTooLarge(size, fmt.Sprintf("the intent certificate of %d bytes of block, %d pages", len(raw), len(ic.ProofV2.Pages)))
	}
	return nil
}
