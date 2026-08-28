package consensus

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/crypto/bls_zkp"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

// =============================================================================
// V8.2 pre-exec signing — EVM ONLY.
//
// V8.1 committed CERTEN's own validator set and nothing about Accumulate's.
// V8.2 adds two fields to the signed pre-exec message: the Accumulate
// validator-set root (membership AND threshold, not just the signers) and the
// incarnation identity. See pkg/execution/contracts/v8_2_binding.go for the
// wire format and the reasoning.
//
// SCOPE. This path is EVM-only and covers exactly three active deployments —
// ethereum-sepolia, base-sepolia and arbitrum-sepolia — which must move
// together under the one bumped domain tag so an old signature can never
// replay against the new message. Every other target (NEAR, Solana, Aptos,
// Sui, TON, Cardano, and the inactive EVM testnets) is LEGACY and stays on
// signV6_1PreExecBLS. That is deliberate, not an omission: those deployments
// run contracts that are no longer supported, and touching them would add risk
// and reviewer confusion for zero benefit. If a change here appears to require
// editing one of them, stop — the design has drifted.
// =============================================================================

// accumulateIncarnationEnv names the environment variable carrying this
// deployment's Accumulate incarnation identity.
const accumulateIncarnationEnv = "ACCUMULATE_INCARNATION"

// resolveAccumulateIncarnation returns the incarnation identity: the genesis
// root anchor of the Accumulate chain this validator proves against, which is
// anchor(directory)-root[0] on the Directory's anchor pool.
//
// WHY THIS IS CONFIGURED RATHER THAN READ FROM THE PROOF. The L4 evidence does
// not carry it yet. Nothing in an L4 leg identifies which Accumulate chain it
// belongs to — the signed preimage is a SequencedMessage over a PartitionAnchor,
// and every URL in it (acc://dn.acme, acc://bvn-BVN1.acme) is a protocol
// constant that is identical on MainNet, on Kermit, and on every incarnation of
// both. That is exactly the gap this field exists to close, so until the L4
// artifact carries it the value has to come from outside the proof.
//
// It FAILS CLOSED. There is deliberately no default and no zero encoding: a
// zero would be a weaker claim wearing the same shape as a real one, and the
// V8.2 contract rejects it at anchor creation anyway.
func resolveAccumulateIncarnation() ([32]byte, error) {
	var out [32]byte
	raw := strings.TrimSpace(os.Getenv(accumulateIncarnationEnv))
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "0x"), "0X")
	if raw == "" {
		return out, fmt.Errorf("%s is not set: V8.2 signing requires the Accumulate "+
			"incarnation identity (the genesis root anchor, anchor(directory)-root[0]); "+
			"there is no default because a proof that cannot name its chain is not a "+
			"governance proof", accumulateIncarnationEnv)
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return out, fmt.Errorf("%s is not valid hex: %w", accumulateIncarnationEnv, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("%s must be 32 bytes, got %d", accumulateIncarnationEnv, len(b))
	}
	copy(out[:], b)
	if out == ([32]byte{}) {
		return out, fmt.Errorf("%s is all zeroes, which is not a valid incarnation",
			accumulateIncarnationEnv)
	}
	return out, nil
}

// accumulateSetFromL4 reduces an L4 leg's evidence to the inputs the Accumulate
// validator-set root commits to.
//
// It reads the DIRECTORY leg, because the validator set lives in
// acc://dn.acme/network and the Directory quorum is what signs over it. The
// full set is taken — not just the signers — because the signers alone are the
// numerator without a denominator, which is the whole defect V8.2 removes.
func accumulateSetFromL4(dn *chained_proof.Layer4, incarnation [32]byte) (
	contracts.AccumulateValidatorSetRootInputs, error,
) {
	var out contracts.AccumulateValidatorSetRootInputs

	if dn == nil {
		return out, fmt.Errorf("V8.2 signing requires the Directory L4 leg; a proof " +
			"without it cannot say which Accumulate validator set it was checked against")
	}
	if len(dn.ValidatorSet) == 0 {
		return out, fmt.Errorf("Directory L4 leg carries an empty validator set")
	}
	if dn.AcceptThreshold.Denominator == 0 {
		return out, fmt.Errorf("Directory L4 leg carries a zero accept-threshold denominator")
	}

	out.Incarnation = incarnation
	out.ThresholdNumerator = dn.AcceptThreshold.Numerator
	out.ThresholdDenominator = dn.AcceptThreshold.Denominator

	for i, v := range dn.ValidatorSet {
		raw, err := hex.DecodeString(strings.TrimPrefix(v.PublicKey, "0x"))
		if err != nil {
			return out, fmt.Errorf("validator %d: public key is not valid hex: %w", i, err)
		}
		if len(raw) != 32 {
			return out, fmt.Errorf("validator %d: public key must be 32 bytes, got %d", i, len(raw))
		}
		var pk [32]byte
		copy(pk[:], raw)

		activeOn := make([]string, len(v.ActiveOn))
		copy(activeOn, v.ActiveOn)

		out.Validators = append(out.Validators, contracts.AccumulateValidator{
			PublicKey: pk,
			ActiveOn:  activeOn,
		})
	}
	return out, nil
}

// BuildV8_2AccumulateSetInputs is the exported seam the EVM submission path uses
// so it derives the identical root the signing path signed. Both sides must call
// this — a second, independent reduction of the same L4 evidence is exactly how
// the two paths drift.
func BuildV8_2AccumulateSetInputs(certenProof *proof.CertenProof) (
	contracts.AccumulateValidatorSetRootInputs, error,
) {
	var out contracts.AccumulateValidatorSetRootInputs
	if certenProof == nil {
		return out, fmt.Errorf("nil certenProof — V8.2 signing requires the L4 evidence")
	}
	if certenProof.LiteClientProof == nil || certenProof.LiteClientProof.CompleteProof == nil {
		return out, fmt.Errorf("certenProof carries no lite-client CompleteProof — V8.2 " +
			"signing requires the L4 evidence, not just the govRoot conclusion")
	}
	incarnation, err := resolveAccumulateIncarnation()
	if err != nil {
		return out, err
	}
	return accumulateSetFromL4(certenProof.LiteClientProof.CompleteProof.Layer4DN, incarnation)
}

// signV8_2PreExecBLS is the V8.2 successor to signV6_1PreExecBLS for EVM
// targets. It extracts the same primitives, adds the Accumulate half, and signs
// the resulting messageHash under the bumped pre-exec domain.
//
// Non-EVM targets are REFUSED rather than silently routed to the V6.1 path. A
// caller that reaches here with a NEAR or Solana intent has a routing bug, and
// quietly signing the old message would hide it.
//
// IMPORTANT: as with signV6_1PreExecBLS, certenProof MUST already have
// G0Result, G1Result, G2Result, KeypageURL and KeybookURL populated, and it
// must additionally carry LiteClientProof.CompleteProof.Layer4DN. The caller
// does this immediately before signing, so the EVM submitter sees a proof whose
// inputs are byte-identical to what was just signed.
func signV8_2PreExecBLS(
	logger Logger,
	certenIntent *CertenIntent,
	certenProof *proof.CertenProof,
) (string, error) {
	if certenIntent == nil {
		return "", fmt.Errorf("nil certenIntent")
	}
	if certenProof == nil {
		return "", fmt.Errorf("nil certenProof — V8.2 signing requires governance + lite-client proof")
	}

	chainName, evmChainID, err := certenIntent.GetTargetChain()
	if err != nil {
		return "", fmt.Errorf("intent target chain: %w", err)
	}
	if !isV8_2SupportedEVMTarget(chainName) {
		return "", fmt.Errorf("V8.2 signing is EVM-only and scoped to the three active "+
			"deployments (ethereum-sepolia, base-sepolia, arbitrum-sepolia); target %q is "+
			"legacy and must use signV6_1PreExecBLS", chainName)
	}
	if evmChainID == 0 {
		return "", fmt.Errorf("intent has zero EVM chain ID (target leg malformed)")
	}

	accSet, err := BuildV8_2AccumulateSetInputs(certenProof)
	if err != nil {
		return "", fmt.Errorf("accumulate validator set: %w", err)
	}

	setRoot, err := contracts.GetV6_1ValidatorSetRoot()
	if err != nil {
		return "", fmt.Errorf("validator-set root: %w", err)
	}

	v61, err := buildV6_1InputsFromIntent(certenIntent, certenProof, evmChainID, setRoot)
	if err != nil {
		return "", fmt.Errorf("build V8.2 inputs: %w", err)
	}

	in := contracts.V8_2PreExecBundleInputs{
		ChainID:                v61.ChainID,
		ValidatorSetRoot:       v61.ValidatorSetRoot,
		AdiURLHash:             v61.AdiURLHash,
		OperationCommitment:    v61.OperationCommitment,
		CrossChainCommitment:   v61.CrossChainCommitment,
		ExecutionCommitment:    v61.ExecutionCommitment,
		OperationID:            v61.OperationID,
		AccumulateBlockHeight:  v61.AccumulateBlockHeight,
		GovRootInputs:          v61.GovRootInputs,
		AccumulateValidatorSet: accSet,
	}

	anchorId, govRoot, accRoot, msgHash, err := contracts.BuildV8_2PreExecBundle(in)
	if err != nil {
		return "", fmt.Errorf("build V8.2 pre-exec bundle: %w", err)
	}

	if logger != nil {
		logger.Printf("🔗 [BLS-SIG-V8.2] chainId=%d anchorId=0x%x govRoot=0x%x msgHash=0x%x setRoot=0x%x",
			evmChainID, anchorId[:8], govRoot[:8], msgHash[:8], setRoot[:8])
		logger.Printf("🧬 [BFT-ACCUMULATE] accSetRoot=0x%x incarnation=0x%x validators=%d threshold=%d/%d",
			accRoot[:8], accSet.Incarnation[:8], len(accSet.Validators),
			accSet.ThresholdNumerator, accSet.ThresholdDenominator)
	}

	km := bls.GetValidatorBLSKey()
	if km == nil {
		return "", fmt.Errorf("validator BLS key manager not initialized")
	}
	sk := km.PrivateKey()
	if sk == nil {
		return "", fmt.Errorf("validator BLS private key not loaded")
	}
	// Same curve/hash-to-G1 path as V6.1 — only the MESSAGE changed, not how it
	// is signed. SignV6_1PreExec uses HashMessageToG1V2 so the signature
	// satisfies the BLSZKVerifierV2 circuit's pairing constraint; SignWithDomain
	// would produce a signature over a different G1 point and make the V2 prover
	// unsatisfiable. The V8.2 domain separation lives inside msgHash, which is
	// where it belongs.
	sig := bls_zkp.SignV6_1PreExec(sk, msgHash)
	if sig == nil {
		return "", fmt.Errorf("V8.2 BLS sign returned nil")
	}
	return sig.Hex(), nil
}

// isV8_2SupportedEVMTarget reports whether a target chain is one of the three
// active EVM deployments V8.2 covers. Everything else — including the inactive
// EVM testnets (polygon-amoy, optimism-sepolia, moonbase-alpha, bsc-testnet,
// tron-shasta, hedera) — is legacy and stays on V6.1.
func isV8_2SupportedEVMTarget(chainName string) bool {
	switch strings.ToLower(strings.TrimSpace(chainName)) {
	case "sepolia", "ethereum-sepolia", "ethereum_sepolia", "eth-sepolia":
		return true
	case "base-sepolia", "base_sepolia", "basesepolia":
		return true
	case "arbitrum-sepolia", "arbitrum_sepolia", "arbitrumsepolia", "arb-sepolia":
		return true
	default:
		return false
	}
}
