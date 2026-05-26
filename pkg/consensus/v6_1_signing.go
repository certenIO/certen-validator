// V6.1 A+++ BLS signing helper. Called from bft_integration.go AFTER G0/G1/G2
// + L1-L4 have been computed and attached to certenProof. Produces the
// pre-execution BLS signature over the EXACT messageHash that
// CertenAnchorV6_1._verifyBLSProof recomputes and verifies on-chain.
//
// Pre-V6.1 the validator signed `[]byte(opID)` and the contract checked a
// chain-bound multi-field hash — the mismatch is why every TX2 reverted with
// "BLS signature verification failed". A+++ closes this by making signer and
// verifier compute the SAME 6-field abi.encode preimage from the SAME 10-field
// Accumulate govRoot.
package consensus

import (
	"fmt"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

// signV6_1PreExecBLS extracts every primitive the V6.1 A+++ binding needs from
// (intent, proof), builds the bundle via contracts.BuildV6_1PreExecBundle, and
// signs the resulting messageHash with the validator's BLS key under the
// pre-exec attestation domain.
//
// IMPORTANT: certenProof MUST already have G0Result, G1Result, G2Result,
// KeypageURL and KeybookURL populated. The caller does this immediately
// before signing, so the EVM submitter sees a proof object whose govRoot
// inputs are byte-identical to what we just signed.
func signV6_1PreExecBLS(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
) (string, error) {
	if certenIntent == nil {
		return "", fmt.Errorf("nil certenIntent")
	}
	if certenProof == nil {
		return "", fmt.Errorf("nil certenProof — V6.1 signing requires governance + lite-client proof")
	}

	// EVM chain ID from the intent's target leg. NOT the validator's BFT
	// chainID (which is a CometBFT string). V6.1's DEPLOYMENT_CHAIN_ID is
	// the target EVM chain's block.chainid.
	_, evmChainID, err := certenIntent.GetTargetChain()
	if err != nil {
		return "", fmt.Errorf("intent target chain: %w", err)
	}
	if evmChainID == 0 {
		return "", fmt.Errorf("intent has zero EVM chain ID (target leg malformed)")
	}

	// Validator set root: single shared value computed once from operator
	// config. Same 7 addresses + powers + threshold on all 7 chains → same
	// root.
	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return "", fmt.Errorf("validator-set root: %w", err)
	}

	// Build the V6_1PreExecBundleInputs by extracting primitives from intent
	// + proof. This is the SINGLE SOURCE OF TRUTH for the BFT signing side;
	// pkg/execution/ethereum_contracts.go mirrors it for EVM submission.
	in, err := buildV6_1InputsFromIntent(certenIntent, certenProof, evmChainID, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V6.1 inputs: %w", err)
	}
	anchorId, govRoot, msgHash := contracts.BuildV6_1PreExecBundle(in)

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V6.1] chainId=%d anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			evmChainID, anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		// V6.1 diagnostic — emit every gov-root input + commitment primitive
		// so divergence vs the EVM submission path (ethereum_contracts.go::
		// computeV6_1AccumulateGovRoot) is directly identifiable.
		logger.Printf("🧮 [BFT-GOV-INPUTS] opID=%x L1=%x L2=%x L3=%x L4=%x kp=%x kb=%x",
			in.GovRootInputs.OperationID[:8],
			in.GovRootInputs.L1AccountHash[:8],
			in.GovRootInputs.L2BPTRoot[:8],
			in.GovRootInputs.L3BlockHash[:8],
			in.GovRootInputs.L4ConsensusProofH[:8],
			in.GovRootInputs.KeypageURLHash[:8],
			in.GovRootInputs.KeybookURLHash[:8],
		)
		logger.Printf("🧮 [BFT-PRIMITIVES] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
			in.AdiURLHash[:8],
			in.OperationCommitment[:8],
			in.CrossChainCommitment[:8],
			in.ExecutionCommitment[:8],
			in.OperationID[:8],
			in.AccumulateBlockHeight,
		)
	}

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return "", fmt.Errorf("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return "", fmt.Errorf("validator BLS private key not loaded")
	}
	// V6.1 A+++: sign using HashMessageToG1V2 so the resulting signature
	// satisfies the BLSZKVerifierV2 circuit's pairing constraint. Using
	// SignWithDomain produces a signature over a DIFFERENT G1 point
	// (RFC-9380 ExpandMsgXmd hash-to-curve) and makes the V2 prover
	// unsatisfiable (constraint #774716 was failing on Sepolia test #7).
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V6.1 BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// buildV6_1InputsFromIntent pulls every primitive the V6.1 bundle binding
// needs out of (intent, proof). Mirror of the equivalent extraction inside
// pkg/execution/ethereum_contracts.go (BuildV6_1InputsForSubmission); both
// MUST stay in lockstep or signer/verifier hashes drift.
func buildV6_1InputsFromIntent(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	evmChainID int64,
	setRoot [32]byte,
) (contracts.V6_1PreExecBundleInputs, error) {
	// adiURL — proof's AccountURL wins over intent fallback.
	adiURL := ""
	if certenProof != nil && certenProof.AccountURL != "" {
		adiURL = certenProof.AccountURL
	} else if certenIntent != nil {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI)
	}

	// opID + blockHeight + txHash for opCommitment derivation.
	intentID := ""
	if certenIntent != nil {
		intentID = certenIntent.IntentID
	}
	blockHeight := uint64(0)
	txHash := ""
	if certenProof != nil {
		blockHeight = certenProof.BlockHeight
		txHash = certenProof.TransactionHash
	}

	// BPT root from lite client proof.
	var bptRoot []byte
	if certenProof != nil && certenProof.LiteClientProof != nil {
		bptRoot = certenProof.LiteClientProof.BPTRoot
	}

	// CrossChainData JSON (proof first, intent fallback) — execCommitment.
	var ccData []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		ccData = certenProof.CrossChainData
	} else if certenIntent != nil && len(certenIntent.CrossChainData) > 0 {
		ccData = certenIntent.CrossChainData
	}

	// OperationID as a 32-byte value.
	opIDStr := ""
	if certenIntent != nil {
		if s, err := certenIntent.OperationID(); err == nil {
			opIDStr = s
		}
	}
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(opIDStr)

	// govRoot inputs — L1-L4 + G0/G1/G2 + URLs + opID.
	gb := contracts.NewAccumulateGovRootInputsBuilder().
		SetOperationIDBytes32(opIDBytes32)
	if certenProof != nil && certenProof.LiteClientProof != nil {
		lc := certenProof.LiteClientProof
		gb.SetL1AccountHash(lc.AccountHash).
			SetL2BPTRoot(lc.BPTRoot).
			SetL3BlockHash(lc.BlockHash).
			SetL4ConsensusProofFromJSON(lc.ConsensusProof)
	}
	if certenProof != nil {
		gb.SetG0FromJSON(certenProof.G0Result).
			SetG1FromJSON(certenProof.G1Result).
			SetG2FromJSON(certenProof.G2Result).
			SetKeypageURL(certenProof.KeypageURL).
			SetKeybookURL(certenProof.KeybookURL)
	}

	return contracts.V6_1PreExecBundleInputs{
		ChainID:               evmChainID,
		ValidatorSetRoot:      setRoot,
		AdiURLHash:            contracts.DeriveAdiURLHashFromString(adiURL),
		OperationCommitment:   contracts.DeriveOperationCommitmentFromFields(intentID, blockHeight, txHash),
		CrossChainCommitment:  contracts.DeriveCrossChainCommitmentFromBPT(bptRoot),
		ExecutionCommitment:   contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData),
		OperationID:           opIDBytes32,
		AccumulateBlockHeight: blockHeight,
		GovRootInputs:         gb.Build(),
	}, nil
}
