// Shared TON V6.1 deployment-config resolvers (mirror of the Sui env file, but
// the hashes are TON cell-hashes, not keccak256). Live in the contracts package
// so BOTH the BFT signing path (pkg/consensus/v6_1_signing.go) and the
// submission path (pkg/execution/bft_target_chain_integration.go) resolve the
// network name and validator-set-root from the same source — guaranteeing the
// signed messageHash and the submitted/anchored messageHash are byte-identical.

package contracts

import (
	"os"
	"strings"
)

// TonNetworkFromEnv returns the network the on-chain certen_anchor_v6_1 was
// initialized with (it derives deployment_chain_id =
// cellHash("certen:chain:v1:ton:" || network)). Set via TON_DEPLOYMENT_NETWORK;
// defaults to "testnet".
func TonNetworkFromEnv() string {
	n := strings.TrimSpace(os.Getenv("TON_DEPLOYMENT_NETWORK"))
	if n == "" {
		return "testnet"
	}
	return n
}

// TonValidatorSetRootFromEnvOrEmpty resolves the 32-byte validator_set_root to
// fold into the V6.1 messageHash. It MUST equal the contract's stored
// current_validator_set_root at verify time, else the proof reverts in the
// message-hash gate. On TON the root is computed off-chain and SET on the
// contract by the owner at bring-up (then pinned here in TON_VALIDATOR_SET_ROOT,
// hex, 64 chars). Before it is set, the empty-set root is returned.
func TonValidatorSetRootFromEnvOrEmpty(thresholdNum, thresholdDen uint64) [32]byte {
	if root, ok := parseHex32(os.Getenv("TON_VALIDATOR_SET_ROOT")); ok {
		return root
	}
	return ComputeTonValidatorSetRootV6_1(nil, nil, thresholdNum, thresholdDen)
}

// TonExecutionCommitmentStubV6_1 is the opaque execution-commitment TON binds at
// create_anchor time. As on Aptos/Sui, the value-move executes later through the
// user's abstract account, so the anchor commits a deterministic value derived
// from the Accumulate-side commitments. It is OPAQUE to the V6.1 gates
// (create_anchor and the proof verification never recompute it; they only require
// the same value to flow into bundle_id derivation and the messageHash). BOTH
// off-chain sides MUST call this so they agree. Cell-hash chain over four slots:
//
//	chain( adiURLHash, operationCommitment, crossChainCommitment, governanceRoot )
func TonExecutionCommitmentStubV6_1(
	adiURLHash, operationCommitment, crossChainCommitment, governanceRoot [32]byte,
) [32]byte {
	return tonCellHashChain([][32]byte{
		adiURLHash, operationCommitment, crossChainCommitment, governanceRoot,
	})
}
