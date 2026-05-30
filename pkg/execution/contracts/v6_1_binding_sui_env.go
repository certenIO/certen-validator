// Shared Sui V6.1 deployment-config resolvers (mirror of the Aptos env file).
// Live in the contracts package so BOTH the BFT signing path
// (pkg/consensus/v6_1_signing.go) and the submission path
// (pkg/execution/bft_target_chain_integration.go) resolve the network name and
// validator-set-root from the same source — guaranteeing the signed messageHash
// and the submitted/anchored messageHash are byte-identical.

package contracts

import (
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// SuiNetworkFromEnv returns the network the on-chain certen_anchor_v6_1 was
// initialized with (it stores deployment_chain_id =
// keccak256("certen:chain:v1:sui:" || network)). Set via SUI_DEPLOYMENT_NETWORK;
// defaults to "testnet".
func SuiNetworkFromEnv() string {
	n := strings.TrimSpace(os.Getenv("SUI_DEPLOYMENT_NETWORK"))
	if n == "" {
		return "testnet"
	}
	return n
}

// SuiValidatorSetRootFromEnvOrEmpty resolves the 32-byte validator_set_root to
// fold into the V6.1 messageHash. It MUST equal the contract's stored
// current_validator_set_root at verify time, else the proof reverts with
// E_MESSAGE_HASH_MISMATCH. Before any validator is registered the contract's
// root is the empty-set root (returned here when the env var is unset); after
// registering validators on-chain, read the program's get_validator_set_root
// view and pin it in SUI_VALIDATOR_SET_ROOT (hex, 64 chars).
func SuiValidatorSetRootFromEnvOrEmpty(thresholdNum, thresholdDen uint64) [32]byte {
	if root, ok := parseHex32(os.Getenv("SUI_VALIDATOR_SET_ROOT")); ok {
		return root
	}
	return ComputeSuiValidatorSetRootV6_1(nil, nil, thresholdNum, thresholdDen)
}

// SuiExecutionCommitmentStubV6_1 is the opaque execution-commitment Sui binds at
// create_anchor time. As on Aptos, the value-move executes later through the
// user's abstract account, so the anchor commits a deterministic value derived
// from the Accumulate-side commitments. It is OPAQUE to the V6.1 gates
// (create_anchor and the proof verification never recompute it; they only
// require the same value to flow into bundle_id derivation and the messageHash).
// BOTH off-chain sides MUST call this so they agree.
//
//	keccak256(adiURLHash || operationCommitment || crossChainCommitment || governanceRoot)
func SuiExecutionCommitmentStubV6_1(
	adiURLHash, operationCommitment, crossChainCommitment, governanceRoot [32]byte,
) [32]byte {
	preimage := make([]byte, 0, 4*32)
	preimage = append(preimage, adiURLHash[:]...)
	preimage = append(preimage, operationCommitment[:]...)
	preimage = append(preimage, crossChainCommitment[:]...)
	preimage = append(preimage, governanceRoot[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}
