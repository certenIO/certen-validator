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
	"strings"

	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

// nearNetworkIDForChain maps the canonical NEAR chain name to the
// network_id string used in CertenAnchorV6_1::compute_deployment_chain_id
// (testnet/mainnet). Same logic the on-chain contract uses to derive its
// deployment_chain_id at init() from env::current_account_id() — anyone
// with the public chain name can reproduce the resulting 32-byte chainID.
func nearNetworkIDForChain(chainName string) string {
	n := strings.ToLower(chainName)
	if strings.Contains(n, "mainnet") || n == "near" {
		// Plain "near" defaults to mainnet to match the NEAR ecosystem
		// convention (mainnet accounts end in .near, testnet in .testnet).
		return "mainnet"
	}
	// near-testnet, near-protocol-testnet, etc.
	return "testnet"
}

// nearValidatorSetForChain returns the validator account_ids + powers +
// threshold that drive the NEAR-flavored validator-set-root. Production
// posture: same 7 operators as EVM, but expressed as NEAR account names
// (validator-1.testnet … validator-7.testnet on testnet). Env override
// matches the EVM operator override pattern so config can shift without
// a rebuild.
func nearValidatorSetForChain(networkID string) (
	accounts []string,
	powers []uint64,
	num uint64,
	den uint64,
) {
	// Defaults — must match what register_validator was called with on the
	// on-chain anchor. On testnet, the 7 validator accounts deployed under
	// near-testnet are validator-{1..7}.testnet.
	suffix := ".testnet"
	if networkID == "mainnet" {
		suffix = ".near"
	}
	accounts = make([]string, 7)
	powers = make([]uint64, 7)
	for i := 0; i < 7; i++ {
		accounts[i] = fmt.Sprintf("validator-%d%s", i+1, suffix)
		powers[i] = 100
	}
	num, den = 2, 3
	return
}

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

	chainName, evmChainID, err := certenIntent.GetTargetChain()
	if err != nil {
		return "", fmt.Errorf("intent target chain: %w", err)
	}

	// NEAR target: substitute the synthesized 32-byte chain identifier for
	// EVM's uint256(block.chainid), and the NEAR-flavored validator-set-root
	// (over account_id strings, not 20-byte addresses).
	if strings.HasPrefix(strings.ToLower(chainName), "near") {
		return signV6_1PreExecBLSNear(logger, certenIntent, certenProof, chainName)
	}

	if evmChainID == 0 {
		return "", fmt.Errorf("intent has zero EVM chain ID (target leg malformed)")
	}

	// Validator set root: single shared value computed once from operator
	// config. Same 7 addresses + powers + threshold on all 7 EVM chains →
	// same root.
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

// =============================================================================
// NEAR-flavored V6.1 pre-execution BLS signing.
// =============================================================================

// signV6_1PreExecBLSNear is the NEAR target dispatch from signV6_1PreExecBLS.
// Same overall flow (extract primitives → build bundle → sign messageHash)
// but substitutes:
//   - the 32-byte synthesized deployment_chain_id for EVM's int64 chainID
//   - the NEAR-flavored validator-set-root (over account_id strings, not
//     20-byte addresses)
//   - the NEAR-specific BuildV6_1PreExecBundleNear instead of the EVM one
//
// The signed sig is byte-equivalent to what the NEAR-side
// CertenAnchorV6_1::execute_comprehensive_proof recomputes and verifies.
//
// `chainName` comes from certenIntent.GetTargetChain() and looks like
// "near", "near-testnet", or "near-mainnet" — used to derive network_id.
func signV6_1PreExecBLSNear(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainName string,
) (string, error) {
	networkID := nearNetworkIDForChain(chainName)
	chainID32 := contracts.ComputeNearDeploymentChainIDV6_1(networkID)

	// NEAR-flavored validator-set-root. Production deployment uses the
	// same operator set on every chain, but the SHAPE of the root differs
	// (account_id strings instead of EVM addresses), so the value is
	// NEAR-specific even though the underlying operators match.
	accts, powers, num, den := nearValidatorSetForChain(networkID)
	setRoot := contracts.ComputeNearValidatorSetRootV6_1(accts, powers, num, den)

	// Build the NEAR-flavored bundle inputs by extracting the same
	// Accumulate-side primitives we use for EVM, just delivered to the
	// NEAR variant of BuildV6_1PreExecBundle.
	in, err := buildV6_1NearInputsFromIntent(certenIntent, certenProof, chainID32, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V6.1 NEAR inputs: %w", err)
	}
	anchorId, govRoot, msgHash := contracts.BuildV6_1PreExecBundleNear(in)

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V6.1-NEAR] chain=%s networkID=%s chainID32=0x%x anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			chainName, networkID, chainID32[:8],
			anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		logger.Printf("🧮 [BFT-GOV-INPUTS-NEAR] opID=%x L1=%x L2=%x L3=%x L4=%x kp=%x kb=%x",
			in.GovRootInputs.OperationID[:8],
			in.GovRootInputs.L1AccountHash[:8],
			in.GovRootInputs.L2BPTRoot[:8],
			in.GovRootInputs.L3BlockHash[:8],
			in.GovRootInputs.L4ConsensusProofH[:8],
			in.GovRootInputs.KeypageURLHash[:8],
			in.GovRootInputs.KeybookURLHash[:8],
		)
		logger.Printf("🧮 [BFT-PRIMITIVES-NEAR] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
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
	// Same V2 hash-to-G1 path as EVM — the ZK circuit constraints are
	// chain-agnostic; only the messageHash input differs.
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V6.1 NEAR BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// buildV6_1NearInputsFromIntent mirrors buildV6_1InputsFromIntent but
// produces the NEAR-flavored bundle inputs (32-byte chain id, NEAR set
// root). All Accumulate-side primitives (adiURLHash, opCommitment,
// ccCommitment, execCommitment, opID, govRoot inputs) are chain-agnostic
// and reused verbatim.
func buildV6_1NearInputsFromIntent(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainID32 [32]byte,
	setRoot [32]byte,
) (contracts.V6_1PreExecBundleInputsNear, error) {
	adiURL := ""
	if certenProof != nil && certenProof.AccountURL != "" {
		adiURL = certenProof.AccountURL
	} else if certenIntent != nil {
		adiURL = fmt.Sprintf("%s/data", certenIntent.OrganizationADI)
	}

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

	var bptRoot []byte
	if certenProof != nil && certenProof.LiteClientProof != nil {
		bptRoot = certenProof.LiteClientProof.BPTRoot
	}

	var ccData []byte
	if certenProof != nil && len(certenProof.CrossChainData) > 0 {
		ccData = certenProof.CrossChainData
	} else if certenIntent != nil && len(certenIntent.CrossChainData) > 0 {
		ccData = certenIntent.CrossChainData
	}

	opIDStr := ""
	if certenIntent != nil {
		if s, err := certenIntent.OperationID(); err == nil {
			opIDStr = s
		}
	}
	opIDBytes32 := contracts.DeriveOperationIDBytes32FromString(opIDStr)

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

	return contracts.V6_1PreExecBundleInputsNear{
		DeploymentChainID:     chainID32,
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
