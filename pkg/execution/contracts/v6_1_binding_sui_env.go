// Shared Sui V6.1 deployment-config resolvers (mirror of the Aptos env file).
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

// SuiExecutionCommitmentV6_1 is the CRITICAL-001 value-bound execution commitment
// that binds the EXACT transfer (recipient + amount) the intent authorizes, so a
// compromised/buggy elected executor cannot redirect funds. It REPLACES the opaque
// stub above. The on-chain certen_account_v4::compute_sui_execution_commitment
// recomputes this from the runtime (recipient, amount) at withdraw time and asserts
// equality with the anchor's stored execution_commitment, mirroring EVM
// CertenAccountV4.sol's CRITICAL-001 check.
//
// Byte layout (MUST match the Move twin exactly):
//
//	keccak256("certen:exec:sui" || recipient(32B) || amount(u64 little-endian, 8B))
//
// amount is little-endian because the Move side uses bcs::to_bytes(&u64) (LE).
// A native SUI transfer carries no calldata, so data is omitted on both sides.
// BOTH off-chain sides (consensus signer + executor) MUST call this so the signed
// messageHash, the bundle_id, and the anchored commitment all agree.
func SuiExecutionCommitmentV6_1(recipient [32]byte, amount uint64) [32]byte {
	preimage := make([]byte, 0, 15+32+8)
	preimage = append(preimage, []byte("certen:exec:sui")...)
	preimage = append(preimage, recipient[:]...)
	amt := make([]byte, 8)
	binary.LittleEndian.PutUint64(amt, amount)
	preimage = append(preimage, amt...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// SuiRecipient32 normalizes a Sui address (hex, optionally 0x-prefixed, possibly
// shorter than 32 bytes due to leading-zero stripping) into a left-padded 32-byte
// array — the form the on-chain `address` and SuiExecutionCommitmentV6_1 expect.
// Both the consensus signer and the executor MUST derive the recipient through
// this so their commitments are byte-identical.
func SuiRecipient32(addr string) [32]byte {
	// common.HexToHash decodes the hex (tolerating the 0x prefix and a short,
	// leading-zero-stripped Sui address) and right-aligns it into 32 bytes —
	// exactly the on-chain `address` representation.
	return common.HexToHash(strings.TrimSpace(addr))
}
