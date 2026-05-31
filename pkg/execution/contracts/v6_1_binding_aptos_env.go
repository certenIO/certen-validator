// Shared Aptos V6.1 deployment-config resolvers (mirror of the Solana env file).
// Live in the contracts package so BOTH the BFT signing path
// (pkg/consensus/v6_1_signing.go) and the submission path
// (pkg/execution/bft_target_chain_integration.go) resolve the network name and
// validator-set-root from the same source — guaranteeing the signed messageHash
// and the submitted/anchored messageHash are byte-identical.

package contracts

import (
	"encoding/binary"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// AptosNetworkFromEnv returns the network the on-chain certen_anchor_v6_1 was
// initialized with (it stores deployment_chain_id =
// keccak256("certen:chain:v1:aptos:" || network)). Set via
// APTOS_DEPLOYMENT_NETWORK; defaults to "testnet".
func AptosNetworkFromEnv() string {
	n := strings.TrimSpace(os.Getenv("APTOS_DEPLOYMENT_NETWORK"))
	if n == "" {
		return "testnet"
	}
	return n
}

// AptosValidatorSetRootFromEnvOrEmpty resolves the 32-byte validator_set_root
// to fold into the V6.1 messageHash. It MUST equal the contract's stored
// current_validator_set_root at verify time, else the proof reverts with
// E_MESSAGE_HASH_MISMATCH. Before any validator is registered the contract's
// root is the empty-set root (returned here when the env var is unset); after
// registering validators on-chain, read the program's get_validator_set_root
// view and pin it in APTOS_VALIDATOR_SET_ROOT (hex, 64 chars).
func AptosValidatorSetRootFromEnvOrEmpty(thresholdNum, thresholdDen uint64) [32]byte {
	if root, ok := parseHex32(os.Getenv("APTOS_VALIDATOR_SET_ROOT")); ok {
		return root
	}
	return ComputeAptosValidatorSetRootV6_1(nil, nil, thresholdNum, thresholdDen)
}

// AptosExecutionCommitmentStubV6_1 is the opaque execution-commitment Aptos
// binds at create_anchor time. As on Solana, the value-move executes later
// through the user's abstract account, so the anchor commits a deterministic
// value derived from the Accumulate-side commitments. It is OPAQUE to the V6.1
// gates (create_anchor and the proof verification never recompute it; they only
// require the same value to flow into bundle_id derivation and the messageHash).
// BOTH off-chain sides MUST call this so they agree.
//
//	keccak256(adiURLHash || operationCommitment || crossChainCommitment || governanceRoot)
func AptosExecutionCommitmentStubV6_1(
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

// AptosExecutionCommitmentV6_1 is the CRITICAL-001 value-bound execution commitment
// that binds the EXACT transfer (target + amount in octas) the intent authorizes,
// REPLACING the opaque stub above. The on-chain
// certen_account_v4::compute_aptos_execution_commitment recomputes this from the
// runtime (target, value_octas) at execute time and asserts equality with the
// anchor's stored execution_commitment (EVM CertenAccountV4.sol CRITICAL-001 parity).
//
// Byte layout (MUST match the Move twin exactly):
//
//	keccak256("certen:exec:aptos" || target(32B) || amount(u64 little-endian, 8B))
//
// target is the 32-byte Aptos address (== Move bcs(address)); amount is LE because
// Move bcs::to_bytes(&u64) is LE. The Move side folds the keccak through
// bytes32_to_u256 (big-endian) into the u256 execution_commitment, matching how the
// off-chain CreateAnchor encodes this [32]byte as a u256. BOTH off-chain sides
// (consensus signer + executor) MUST call this so all derivations agree.
func AptosExecutionCommitmentV6_1(target [32]byte, amount uint64) [32]byte {
	preimage := make([]byte, 0, 17+32+8)
	preimage = append(preimage, []byte("certen:exec:aptos")...)
	preimage = append(preimage, target[:]...)
	amt := make([]byte, 8)
	binary.LittleEndian.PutUint64(amt, amount)
	preimage = append(preimage, amt...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// AptosRecipient32 normalizes an Aptos address (hex, optionally 0x-prefixed and
// possibly short due to leading-zero stripping) into a left-padded 32-byte array —
// the form Move bcs(address) and AptosExecutionCommitmentV6_1 expect. Both the
// consensus signer and the executor MUST derive the target through this.
func AptosRecipient32(addr string) [32]byte {
	return common.HexToHash(strings.TrimSpace(addr))
}
