package consensus

import (
	"encoding/json"
	"fmt"
	"strings"

	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// The members BuildIntentCertificate fills AFTER this check, each at the length it will have: a 32-byte root or message as "0x" + 64 hex
// characters, and the intent signature, a compressed G1 point (48 bytes), as 96 hex characters.
var (
	rootPlaceholder      = "0x" + strings.Repeat("0", 64)
	signaturePlaceholder = strings.Repeat("0", 96)
)

// checkCertificateFitsBeforeSigning is the whole-certificate pre-sign check of evidence 2.1 (RB9-F5 package F5-4, V-E A4; V-I D3). The block
// is judged as the engine will be given it: json.Marshal of the ValidatorBlock (the bytes the proposer logs as "ValidatorBlock marshaled"),
// with the members that are filled after this check - gov_root_v3, accumulate_set_root, message and signature - already present at their final
// length, against the transaction limit the whole path accepts (proofv2.ConsensusTxLimit). Their lengths are fixed (66, 66, 66 and 96
// characters, and gov_root_v3's key is omitted while empty), so the size judged here is the size the broadcast marshals as long as the
// caller does not change the block between BuildIntentCertificate and the broadcast; the check is not an estimate of those members. Over the
// limit is certificate_budget{size,limit} with the size the block will have on the wire, the same decision as the broadcast's tx_too_large,
// and nothing is signed. Evidence 2.0 is not judged here: its transactions are decided exactly as before.
func checkCertificateFitsBeforeSigning(vb *ValidatorBlock) error {
	ic := vb.IntentCertificate
	if ic == nil || ic.ProofV2 == nil || ic.ProofV2.Version != proofv2.Version21 {
		return nil
	}
	// Evidence is carried only when the chain requires the v3 certificate (ProofV3Required), so the root BuildIntentCertificate fills is
	// gov_root_v3, and gov_root_v2 stays empty ("empty under v3").
	govRootV3, setRoot, message, signature := ic.GovRootV3, ic.AccumulateSetRoot, ic.Message, ic.Signature
	defer func() {
		ic.GovRootV3, ic.AccumulateSetRoot, ic.Message, ic.Signature = govRootV3, setRoot, message, signature
	}()
	ic.GovRootV3, ic.AccumulateSetRoot, ic.Message, ic.Signature = rootPlaceholder, rootPlaceholder, rootPlaceholder, signaturePlaceholder
	raw, err := json.Marshal(vb)
	if err != nil {
		return fmt.Errorf("encode the block to judge its size: %w", err)
	}
	if size := len(raw); size > proofv2.ConsensusTxLimit {
		return proofv2.CertificateTooLarge(size, fmt.Sprintf("the intent certificate of %d bytes of block, %d pages", size, len(ic.ProofV2.Pages)))
	}
	return nil
}
