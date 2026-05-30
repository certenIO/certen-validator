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
	"math/big"
	"os"
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
// posture: same 7 operators as EVM, but expressed as NEAR account names.
// On testnet the docker-compose's NEAR_SIGNER_ACCOUNT_ID is certen-v{1..7}
// .testnet — these are the accounts that actually CALL create_anchor /
// execute_comprehensive_proof on the V6.1 anchor, so they're the ones
// registered via register_validator. The locally-computed setRoot MUST be
// derived over the same names or the BFT-signed messageHash diverges from
// the on-chain reconstruction.
func nearValidatorSetForChain(networkID string) (
	accounts []string,
	powers []uint64,
	num uint64,
	den uint64,
) {
	suffix := ".testnet"
	if networkID == "mainnet" {
		suffix = ".near"
	}
	accounts = make([]string, 7)
	powers = make([]uint64, 7)
	for i := 0; i < 7; i++ {
		accounts[i] = fmt.Sprintf("certen-v%d%s", i+1, suffix)
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

	// Cardano target: same pattern as NEAR but uses lovelace amounts +
	// bech32 target identifiers, with a Cardano-tagged deployment_chain_id
	// derived from the Preview/Preprod/Mainnet network discriminator.
	if strings.HasPrefix(strings.ToLower(chainName), "cardano") {
		return signV6_1PreExecBLSCardano(logger, certenIntent, certenProof, chainName)
	}

	// Solana target: 32-byte synthesized deployment_chain_id tagged "solana",
	// a Solana-flavored validator-set-root (over 32-byte pubkeys), and the
	// opaque Solana execution-commitment stub. The signed sig is byte-equivalent
	// to what CertenAnchorV6_1 reconstructs in execute_comprehensive_proof.
	if strings.HasPrefix(strings.ToLower(chainName), "solana") {
		return signV6_1PreExecBLSSolana(logger, certenIntent, certenProof, chainName)
	}

	// Aptos target: 32-byte synthesized deployment_chain_id tagged "aptos", a
	// validator-set-root over 32-byte account addresses, and the opaque Aptos
	// execution-commitment stub. Byte-equivalent to what certen_anchor_v6_1.move
	// reconstructs in its proof verification.
	if strings.HasPrefix(strings.ToLower(chainName), "aptos") {
		return signV6_1PreExecBLSAptos(logger, certenIntent, certenProof, chainName)
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
// produces the NEAR-flavored bundle inputs. Diverges from the EVM variant
// in two places:
//   - DeploymentChainID is the 32-byte synthesized value (not int64)
//   - ExecutionCommitment is computed via ComputeNearExecutionCommitmentV6_1
//     (network_id ‖ target_account ‖ u128-LE deposit ‖ keccak256(method‖args))
//     instead of the EVM-style abi.encodePacked variant. This is critical:
//     the NEAR anchor's create_anchor recomputes its own bundleId from these
//     inputs, and rejects mismatches. Same execCommitment on both sides ⇒
//     same bundleId ⇒ same messageHash that the contract reconstructs at
//     execute_comprehensive_proof time.
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

	// NEAR-flavored executionCommitment from the target leg. Falls back to
	// the EVM-style commitment if the intent's target leg can't be parsed
	// — but for any NEAR-routed intent the leg will be present, so the
	// fallback is just safety.
	execCommitment := nearExecutionCommitmentFromIntent(certenIntent, ccData)

	return contracts.V6_1PreExecBundleInputsNear{
		DeploymentChainID:     chainID32,
		ValidatorSetRoot:      setRoot,
		AdiURLHash:            contracts.DeriveAdiURLHashFromString(adiURL),
		OperationCommitment:   contracts.DeriveOperationCommitmentFromFields(intentID, blockHeight, txHash),
		CrossChainCommitment:  contracts.DeriveCrossChainCommitmentFromBPT(bptRoot),
		ExecutionCommitment:   execCommitment,
		OperationID:           opIDBytes32,
		AccumulateBlockHeight: blockHeight,
		GovRootInputs:         gb.Build(),
	}, nil
}

// =============================================================================
// NEAR execution-commitment helper.
// =============================================================================

// nearExecutionCommitmentFromIntent extracts the NEAR target leg from the
// intent and computes the same execution_commitment the on-chain
// CertenAnchorV6_1 will recompute at execute_with_governance time.
//
// The intent's CrossChainEnvelope contains 1-N legs; we pick the leg whose
// chain prefix is "near". The leg's `to` is the destination account_id
// and `amountWei` is the deposit in yoctoNEAR. The method is fixed to
// "transfer" with no args (same as the validator submission path).
//
// If no NEAR leg is found, returns the EVM-style commitment as a fallback
// so the function is never wrong-by-default for non-NEAR routes.
func nearExecutionCommitmentFromIntent(certenIntent *CertenIntent, ccData []byte) [32]byte {
	if certenIntent == nil {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}
	env, err := certenIntent.ParseCrossChain()
	if err != nil || env == nil || len(env.Legs) == 0 {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}

	// Pick the destination NEAR leg (or first NEAR leg).
	var leg *CCLeg
	for i := range env.Legs {
		l := &env.Legs[i]
		if strings.HasPrefix(strings.ToLower(l.Chain), "near") {
			leg = l
			if l.Role == "destination" {
				break
			}
		}
	}
	if leg == nil {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}

	// network_id derived from chain name (testnet vs mainnet).
	networkID := nearNetworkIDForChain(leg.Chain)
	if !strings.Contains(strings.ToLower(leg.Network), "mainnet") &&
		!strings.HasSuffix(strings.ToLower(leg.Network), ".near") {
		// Network is a secondary signal; honor leg.Network when it's explicit.
	}

	// amountWei is the deposit (yoctoNEAR for NEAR legs).
	deposit := new(big.Int)
	if leg.AmountWei != "" {
		_, ok := deposit.SetString(leg.AmountWei, 10)
		if !ok {
			deposit = big.NewInt(0)
		}
	}

	// Plain NEAR transfer: method="transfer", args=[].
	return contracts.ComputeNearExecutionCommitmentV6_1(
		networkID,
		leg.To,
		deposit,
		"transfer",
		nil,
	)
}

// =============================================================================
// Solana V6.1 dispatch — 32-byte synthesized deployment_chain_id tagged
// "solana", validator-set-root over 32-byte pubkeys, and the opaque Solana
// execution-commitment stub. Cluster + set-root resolved via the shared
// contracts helpers so this signed value matches the submission path.
// =============================================================================

func signV6_1PreExecBLSSolana(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainName string,
) (string, error) {
	cluster := contracts.SolanaClusterFromEnv()
	chainID32 := contracts.ComputeSolanaDeploymentChainIDV6_1(cluster)

	// Solana-flavored validator-set-root. During bring-up this is the
	// empty-set root (matches a freshly-initialized contract); once validators
	// are registered on-chain, pin SOLANA_VALIDATOR_SET_ROOT to the program's
	// get_validator_set_root value. 2/3 threshold matches the contract default.
	setRoot := contracts.SolanaValidatorSetRootFromEnvOrEmpty(2, 3)

	in, err := buildV6_1SolanaInputsFromIntent(certenIntent, certenProof, chainID32, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V6.1 Solana inputs: %w", err)
	}
	anchorId, govRoot, msgHash := contracts.BuildV6_1PreExecBundleSolana(in)

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V6.1-SOLANA] chain=%s cluster=%s chainID32=0x%x anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			chainName, cluster, chainID32[:8],
			anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		logger.Printf("🧮 [BFT-PRIMITIVES-SOLANA] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
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
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V6.1 Solana BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// buildV6_1SolanaInputsFromIntent mirrors buildV6_1NearInputsFromIntent but
// produces Solana-flavored bundle inputs. The only divergence is the
// ExecutionCommitment: Solana uses the opaque stub (shared with the submission
// path via contracts.SolanaExecutionCommitmentStubV6_1) because the value-moving
// target/amount aren't known at anchor time. govRoot is computed here first so
// the stub binds it; BuildV6_1PreExecBundleSolana recomputes the identical
// govRoot from GovRootInputs.
func buildV6_1SolanaInputsFromIntent(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainID32 [32]byte,
	setRoot [32]byte,
) (contracts.V6_1PreExecBundleInputsSolana, error) {
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
	govInputs := gb.Build()

	adiURLHash := contracts.DeriveAdiURLHashFromString(adiURL)
	opCommitment := contracts.DeriveOperationCommitmentFromFields(intentID, blockHeight, txHash)
	ccCommitment := contracts.DeriveCrossChainCommitmentFromBPT(bptRoot)
	govRoot := contracts.ComputeAccumulateGovRoot(govInputs)

	// Opaque Solana execution-commitment stub — identical to the submission path.
	execCommitment := contracts.SolanaExecutionCommitmentStubV6_1(
		adiURLHash, opCommitment, ccCommitment, govRoot,
	)

	return contracts.V6_1PreExecBundleInputsSolana{
		DeploymentChainID:     chainID32,
		ValidatorSetRoot:      setRoot,
		AdiURLHash:            adiURLHash,
		OperationCommitment:   opCommitment,
		CrossChainCommitment:  ccCommitment,
		ExecutionCommitment:   execCommitment,
		OperationID:           opIDBytes32,
		AccumulateBlockHeight: blockHeight,
		GovRootInputs:         govInputs,
	}, nil
}

// =============================================================================
// Aptos V6.1 dispatch — mirror of the Solana path; 32-byte synthesized
// deployment_chain_id tagged "aptos", validator-set-root over 32-byte account
// addresses, opaque Aptos execution-commitment stub.
// =============================================================================

func signV6_1PreExecBLSAptos(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainName string,
) (string, error) {
	network := contracts.AptosNetworkFromEnv()
	chainID32 := contracts.ComputeAptosDeploymentChainIDV6_1(network)
	setRoot := contracts.AptosValidatorSetRootFromEnvOrEmpty(2, 3)

	in, err := buildV6_1AptosInputsFromIntent(certenIntent, certenProof, chainID32, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V6.1 Aptos inputs: %w", err)
	}
	anchorId, govRoot, msgHash := contracts.BuildV6_1PreExecBundleAptos(in)

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V6.1-APTOS] chain=%s network=%s chainID32=0x%x anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			chainName, network, chainID32[:8],
			anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		logger.Printf("🧮 [BFT-PRIMITIVES-APTOS] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
			in.AdiURLHash[:8], in.OperationCommitment[:8], in.CrossChainCommitment[:8],
			in.ExecutionCommitment[:8], in.OperationID[:8], in.AccumulateBlockHeight)
	}

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return "", fmt.Errorf("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return "", fmt.Errorf("validator BLS private key not loaded")
	}
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V6.1 Aptos BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// buildV6_1AptosInputsFromIntent mirrors buildV6_1SolanaInputsFromIntent with
// the Aptos opaque execution-commitment stub (shared with the submission path
// via contracts.AptosExecutionCommitmentStubV6_1).
func buildV6_1AptosInputsFromIntent(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainID32 [32]byte,
	setRoot [32]byte,
) (contracts.V6_1PreExecBundleInputsAptos, error) {
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
	govInputs := gb.Build()

	adiURLHash := contracts.DeriveAdiURLHashFromString(adiURL)
	opCommitment := contracts.DeriveOperationCommitmentFromFields(intentID, blockHeight, txHash)
	ccCommitment := contracts.DeriveCrossChainCommitmentFromBPT(bptRoot)
	govRoot := contracts.ComputeAccumulateGovRoot(govInputs)

	execCommitment := contracts.AptosExecutionCommitmentStubV6_1(
		adiURLHash, opCommitment, ccCommitment, govRoot,
	)

	return contracts.V6_1PreExecBundleInputsAptos{
		DeploymentChainID:     chainID32,
		ValidatorSetRoot:      setRoot,
		AdiURLHash:            adiURLHash,
		OperationCommitment:   opCommitment,
		CrossChainCommitment:  ccCommitment,
		ExecutionCommitment:   execCommitment,
		OperationID:           opIDBytes32,
		AccumulateBlockHeight: blockHeight,
		GovRootInputs:         govInputs,
	}, nil
}

// =============================================================================
// Cardano V6.1 dispatch — same pattern as NEAR; lovelace amounts replace
// yoctoNEAR, bech32 targets replace account_ids, and the chain identifier
// is tagged "certen:chain:v1:cardano:".
// =============================================================================

// cardanoNetworkForChain maps the canonical Cardano chain name to the
// network discriminator that goes into deployment_chain_id. Same mapping
// the Aiken validator was compiled with; both sides MUST agree or the
// on-chain messageHash recomputation drifts.
func cardanoNetworkForChain(chainName string) string {
	n := strings.ToLower(chainName)
	switch {
	case strings.Contains(n, "preview"):
		return "preview"
	case strings.Contains(n, "preprod"):
		return "preprod"
	case strings.Contains(n, "mainnet") || n == "cardano":
		return "mainnet"
	}
	// Default unknown / bare "cardano-testnet" → preview for now (the
	// most active Plutus V3 testnet); revisit if preprod takes over.
	return "preview"
}

// cardanoValidatorSetForChain returns the validator identifiers + powers +
// threshold that drive the Cardano-flavored validator-set-root. For now we
// reuse the certen-v1..7 operator set, identified by their Cardano payment
// pubkey hashes (or addresses) once the wallet is generated. The exact
// values get loaded from env at boot to avoid hard-coding before the wallet
// exists; until then we return placeholder zero hashes so the set root
// derives cleanly (the on-chain validator was compiled with a matching
// placeholder so the BLS sig still verifies during testnet bring-up).
func cardanoValidatorSetForChain(networkID string) (
	ids []string,
	powers []uint64,
	num uint64,
	den uint64,
) {
	// The Cardano deployment uses one shared multi-sig wallet for the
	// validator set initially (matches how NEAR uses certen-v1..7). The
	// IDs are bech32 addresses set via CARDANO_VALIDATOR_IDS env (comma-
	// separated). If unset, fall back to the 7-operator certen-v1..7
	// labels so the placeholder still produces a deterministic root.
	raw := os.Getenv("CARDANO_VALIDATOR_IDS")
	if raw != "" {
		ids = strings.Split(raw, ",")
	} else {
		ids = make([]string, 7)
		for i := 0; i < 7; i++ {
			ids[i] = fmt.Sprintf("certen-v%d.cardano.%s", i+1, networkID)
		}
	}
	powers = make([]uint64, len(ids))
	for i := range powers {
		powers[i] = 100
	}
	num, den = 2, 3
	return
}

// cardanoValidatorSetRootOverride returns the 32-byte validator_set_root
// value to bind into the messageHash, taking the CARDANO_VALIDATOR_SET_ROOT
// env var (hex) when set so the off-chain hash matches the on-chain script
// parameter the anchor validator was deployed with. Returns (root, true)
// when the override is in effect, (_, false) to fall back to the computed
// root. The current Preview deployment uses an all-zero placeholder, so
// we set CARDANO_VALIDATOR_SET_ROOT=000...000 in .env.shared during
// bring-up; when the real validator-set wallet bootstrap happens, drop
// the override and the computed root takes over (alongside a script
// re-deploy with the matching value baked in).
func cardanoValidatorSetRootOverride() ([32]byte, bool) {
	raw := os.Getenv("CARDANO_VALIDATOR_SET_ROOT")
	if raw == "" {
		return [32]byte{}, false
	}
	clean := strings.TrimPrefix(raw, "0x")
	if len(clean) != 64 {
		return [32]byte{}, false
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		var hi, lo byte
		hi = hexNibble(clean[2*i])
		lo = hexNibble(clean[2*i+1])
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// signV6_1PreExecBLSCardano is the Cardano target dispatch from
// signV6_1PreExecBLS. Same overall shape as the NEAR dispatch:
//   - 32-byte synthesized deployment_chain_id (tagged "cardano")
//   - Cardano-flavored validator_set_root (bech32 / pubkey-hash strings)
//   - Cardano-flavored execution_commitment (lovelace u128-LE deposit,
//     bech32 target, "transfer" method by default)
//
// The signed sig is byte-equivalent to what the on-chain Aiken anchor
// validator reconstructs via binding.ak::message_hash_pre and verifies via
// bls.ak::verify.
func signV6_1PreExecBLSCardano(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainName string,
) (string, error) {
	networkID := cardanoNetworkForChain(chainName)
	chainID32 := contracts.ComputeCardanoDeploymentChainIDV6_1(networkID)

	ids, powers, num, den := cardanoValidatorSetForChain(networkID)
	setRoot := contracts.ComputeCardanoValidatorSetRootV6_1(ids, powers, num, den)
	if override, ok := cardanoValidatorSetRootOverride(); ok {
		setRoot = override
	}

	in, err := buildV6_1CardanoInputsFromIntent(certenIntent, certenProof, chainID32, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V6.1 Cardano inputs: %w", err)
	}
	anchorId, govRoot, msgHash := contracts.BuildV6_1PreExecBundleCardano(in)

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V6.1-CARDANO] chain=%s networkID=%s chainID32=0x%x anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			chainName, networkID, chainID32[:8],
			anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		logger.Printf("🧮 [BFT-GOV-INPUTS-CARDANO] opID=%x L1=%x L2=%x L3=%x L4=%x kp=%x kb=%x",
			in.GovRootInputs.OperationID[:8],
			in.GovRootInputs.L1AccountHash[:8],
			in.GovRootInputs.L2BPTRoot[:8],
			in.GovRootInputs.L3BlockHash[:8],
			in.GovRootInputs.L4ConsensusProofH[:8],
			in.GovRootInputs.KeypageURLHash[:8],
			in.GovRootInputs.KeybookURLHash[:8],
		)
		logger.Printf("🧮 [BFT-PRIMITIVES-CARDANO] adi=%x op=%x cc=%x exec=%x opID=%x height=%d",
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
	// Cardano uses the BLS12-381 V2 hash-to-G1 (reduces messageHash mod
	// BLS12-381 Fr, matching BLSSignatureCircuitV2BLS381's in-circuit
	// MapToG1). EVM/NEAR use the BN254-reduced variant; the curves differ so
	// the H(m) point differs — signing with the wrong one makes the on-chain
	// Cardano pairing check unsatisfiable.
	sig := bls_zkp.SignV6_1PreExecBLS12381(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V6.1 Cardano BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// buildV6_1CardanoInputsFromIntent mirrors buildV6_1NearInputsFromIntent.
// Only the ExecutionCommitment derivation diverges: Cardano uses lovelace
// u128-LE deposits and bech32 / pubkey-hash targets.
func buildV6_1CardanoInputsFromIntent(
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
	chainID32 [32]byte,
	setRoot [32]byte,
) (contracts.V6_1PreExecBundleInputsCardano, error) {
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

	execCommitment := cardanoExecutionCommitmentFromIntent(certenIntent, ccData)

	return contracts.V6_1PreExecBundleInputsCardano{
		DeploymentChainID:     chainID32,
		ValidatorSetRoot:      setRoot,
		AdiURLHash:            contracts.DeriveAdiURLHashFromString(adiURL),
		OperationCommitment:   contracts.DeriveOperationCommitmentFromFields(intentID, blockHeight, txHash),
		CrossChainCommitment:  contracts.DeriveCrossChainCommitmentFromBPT(bptRoot),
		ExecutionCommitment:   execCommitment,
		OperationID:           opIDBytes32,
		AccumulateBlockHeight: blockHeight,
		GovRootInputs:         gb.Build(),
	}, nil
}

// cardanoExecutionCommitmentFromIntent extracts the Cardano target leg
// from the intent and computes the same execution_commitment the on-chain
// validator will recompute at TX2 / TX3 time.
//
// Leg shape: chain starts with "cardano", `to` is the destination bech32
// address (or pubkey hash), `amountWei` is the deposit in lovelace.
func cardanoExecutionCommitmentFromIntent(certenIntent *CertenIntent, ccData []byte) [32]byte {
	if certenIntent == nil {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}
	env, err := certenIntent.ParseCrossChain()
	if err != nil || env == nil || len(env.Legs) == 0 {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}

	var leg *CCLeg
	for i := range env.Legs {
		l := &env.Legs[i]
		if strings.HasPrefix(strings.ToLower(l.Chain), "cardano") {
			leg = l
			if l.Role == "destination" {
				break
			}
		}
	}
	if leg == nil {
		return contracts.DeriveExecutionCommitmentFromCrossChainJSON(ccData)
	}

	networkID := cardanoNetworkForChain(leg.Chain)

	deposit := new(big.Int)
	if leg.AmountWei != "" {
		_, ok := deposit.SetString(leg.AmountWei, 10)
		if !ok {
			deposit = big.NewInt(0)
		}
	}

	return contracts.ComputeCardanoExecutionCommitmentV6_1(
		networkID,
		leg.To,
		deposit,
		"transfer",
		nil,
	)
}
