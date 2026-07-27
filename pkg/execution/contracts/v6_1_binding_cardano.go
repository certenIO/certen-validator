// V6.1 A+++ binding primitives for Cardano. Mirror of v6_1_binding_near.go
// adapted for Cardano's UTXO model: lovelace amounts in u128-LE (same shape
// as NEAR yoctoNEAR), variable-length target identifiers (bech32 / pubkey
// hash bytes), and a synthesized 32-byte chain identifier in place of EVM
// `uint256(block.chainid)`.
//
// Each function here has a byte-equivalent twin in
// certen-contracts/cardano/lib/certen/binding.ak. ANY change here MUST be
// mirrored on the Aiken side or the on-chain messageHash recomputation
// won't match what the BFT signer produced, and TX2 BLS verification fails.
//
// Domain literals are NOT padded to 32 bytes (Cardano-only choice; the
// Aiken binding uses the raw UTF-8 string as well). EVM and NEAR pad
// because their contracts read fixed-width slots; Aiken's keccak builtin
// concatenates raw bytearrays so padding would only add noise.

package contracts

import (
	"encoding/hex"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

// cardanoTargetBytes decodes a target identifier into the raw bytes that go
// into execution_commitment. On Cardano the target is the destination's
// 28-byte payment-credential hash, carried as a hex string; the on-chain
// validator sees it as a 28-byte ByteArray, so we hash the DECODED bytes (not
// the hex characters). Falls back to the raw string bytes if not valid hex
// (defensive — e.g. a legacy bech32 target).
func cardanoTargetBytes(target string) []byte {
	s := strings.TrimPrefix(target, "0x")
	if len(s) > 0 && len(s)%2 == 0 {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw
		}
	}
	return []byte(target)
}

// ============================================================================
// Domain tags — keep in lockstep with cardano/lib/certen/binding.ak
// ============================================================================

var (
	cardanoV6_1BLSPreDomain   = []byte("certen:bls:v1:pre")
	cardanoV6_1ChainDomain    = []byte("certen:chain:v1:cardano:")
	cardanoV6_1BundleIDDomain = []byte("certen:bundleid:v1.1")
	cardanoV6_1ExecDomain     = []byte("certen:exec:v1:cardano:")
)

// ============================================================================
// deployment_chain_id
// ============================================================================
//
// Synthesized 32-byte chain identifier:
//
//	chain_id = keccak256("certen:chain:v1:cardano:" || network)
//
// network is the Cardano network discriminator ("preview", "preprod",
// "mainnet"). Tagged so it can never collide with NEAR's
// "certen:chain:v1:near:" or EVM's `uint256(block.chainid)` values.
func ComputeCardanoDeploymentChainIDV6_1(network string) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(cardanoV6_1ChainDomain, []byte(network)))
	return out
}

// ============================================================================
// messageHash (V6.1 A+++ 6-field pre-execution binding)
// ============================================================================
//
// Validators sign this; the Cardano anchor validator reconstructs it from
// datum + script params and rejects any mismatch:
//
//	keccak256(
//	    "certen:bls:v1:pre"
//	  ‖ deployment_chain_id
//	  ‖ anchor_id
//	  ‖ execution_commitment
//	  ‖ operation_id
//	  ‖ validator_set_root
//	)
func ComputeCardanoMessageHashV6_1_Pre(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	preimage := make([]byte, 0, len(cardanoV6_1BLSPreDomain)+32*5)
	preimage = append(preimage, cardanoV6_1BLSPreDomain...)
	preimage = append(preimage, deploymentChainID[:]...)
	preimage = append(preimage, anchorID[:]...)
	preimage = append(preimage, executionCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, validatorSetRoot[:]...)
	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// ============================================================================
// bundleId (V6.1 — 9-input formula matching EVM byte-equivalent)
// ============================================================================
//
// Same field ordering as DeriveV6_1BundleID (EVM) and DeriveNearBundleIDV6_1
// (NEAR); chain_id slot carries the Cardano-synthesized value.
//
//	keccak256(
//	    "certen:bundleid:v1.1"
//	  ‖ deployment_chain_id      (32 bytes)
//	  ‖ adi_url_hash             (32 bytes)
//	  ‖ operation_commitment     (32 bytes)
//	  ‖ cross_chain_commitment   (32 bytes)
//	  ‖ governance_root          (32 bytes)
//	  ‖ execution_commitment     (32 bytes)
//	  ‖ operation_id             (32 bytes)
//	  ‖ u256-BE(block_height)    (32 bytes)
//	)
func DeriveCardanoBundleIDV6_1(
	deploymentChainID [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	var heightBE [32]byte
	heightBE[24] = byte(accumulateBlockHeight >> 56)
	heightBE[25] = byte(accumulateBlockHeight >> 48)
	heightBE[26] = byte(accumulateBlockHeight >> 40)
	heightBE[27] = byte(accumulateBlockHeight >> 32)
	heightBE[28] = byte(accumulateBlockHeight >> 24)
	heightBE[29] = byte(accumulateBlockHeight >> 16)
	heightBE[30] = byte(accumulateBlockHeight >> 8)
	heightBE[31] = byte(accumulateBlockHeight)

	preimage := make([]byte, 0, len(cardanoV6_1BundleIDDomain)+32*8)
	preimage = append(preimage, cardanoV6_1BundleIDDomain...)
	preimage = append(preimage, deploymentChainID[:]...)
	preimage = append(preimage, adiURLHash[:]...)
	preimage = append(preimage, operationCommitment[:]...)
	preimage = append(preimage, crossChainCommitment[:]...)
	preimage = append(preimage, governanceRoot[:]...)
	preimage = append(preimage, executionCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, heightBE[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// ============================================================================
// validator_set_root (canonical ordering identical to NEAR)
// ============================================================================
//
// Wire format — byte-equivalent to ComputeNearValidatorSetRootV6_1 so
// cross-chain audits use the same canonicalization:
//
//	For each (id, power) sorted ASC by id bytes:
//	  u32-BE(len(id))    (4 bytes)
//	  id_bytes           (variable)
//	  u64-BE(power)      (8 bytes)
//	Then appended at the end:
//	  u64-BE(threshold_num)
//	  u64-BE(threshold_den)
//	keccak256 over the concatenated bytes.
//
// Cardano validators are identified by their wallet's bech32 string (or
// any canonical form the deployment chose). Sorting is done internally so
// the caller can pass entries in any order.
func ComputeCardanoValidatorSetRootV6_1(
	validatorIDs []string,
	weights []uint64,
	thresholdNum uint64,
	thresholdDen uint64,
) [32]byte {
	if len(validatorIDs) != len(weights) {
		validatorIDs = nil
		weights = nil
	}

	idx := make([]int, len(validatorIDs))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return validatorIDs[idx[a]] < validatorIDs[idx[b]]
	})

	hasher := crypto.NewKeccakState()
	for _, i := range idx {
		idBytes := []byte(validatorIDs[i])
		power := weights[i]
		_, _ = hasher.Write([]byte{
			byte(len(idBytes) >> 24),
			byte(len(idBytes) >> 16),
			byte(len(idBytes) >> 8),
			byte(len(idBytes)),
		})
		_, _ = hasher.Write(idBytes)
		_, _ = hasher.Write([]byte{
			byte(power >> 56), byte(power >> 48), byte(power >> 40), byte(power >> 32),
			byte(power >> 24), byte(power >> 16), byte(power >> 8), byte(power),
		})
	}
	_, _ = hasher.Write([]byte{
		byte(thresholdNum >> 56), byte(thresholdNum >> 48), byte(thresholdNum >> 40), byte(thresholdNum >> 32),
		byte(thresholdNum >> 24), byte(thresholdNum >> 16), byte(thresholdNum >> 8), byte(thresholdNum),
	})
	_, _ = hasher.Write([]byte{
		byte(thresholdDen >> 56), byte(thresholdDen >> 48), byte(thresholdDen >> 40), byte(thresholdDen >> 32),
		byte(thresholdDen >> 24), byte(thresholdDen >> 16), byte(thresholdDen >> 8), byte(thresholdDen),
	})
	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// ============================================================================
// execution_commitment (Cardano flavour)
// ============================================================================
//
// keccak256(
//
//	  "certen:exec:v1:cardano:"
//	‖ network
//	‖ target_address    (raw bytes — bech32 string OR pubkey hash bytes;
//	                    caller decides, but must match Aiken side)
//	‖ u128-LE(deposit_lovelace)
//	‖ keccak256(method ‖ args)
//
// )
//
// For a plain ADA transfer: method="transfer", args=[]. The validator
// recomputes this from its calls list and rejects any mismatch.
func ComputeCardanoExecutionCommitmentV6_1(
	network string,
	target string,
	depositLovelace *big.Int,
	method string,
	args []byte,
) [32]byte {
	// data_hash = keccak256(method || args)
	dataHasher := crypto.NewKeccakState()
	_, _ = dataHasher.Write([]byte(method))
	_, _ = dataHasher.Write(args)
	var dataHash [32]byte
	_, _ = dataHasher.Read(dataHash[:])

	// 16-byte little-endian deposit (matches Aiken's int_to_le_16).
	depositLE := make([]byte, 16)
	if depositLovelace != nil {
		be := depositLovelace.Bytes()
		for i, b := range be {
			depositLE[len(be)-1-i] = b
		}
	}

	hasher := crypto.NewKeccakState()
	_, _ = hasher.Write(cardanoV6_1ExecDomain)
	_, _ = hasher.Write([]byte(network))
	_, _ = hasher.Write(cardanoTargetBytes(target))
	_, _ = hasher.Write(depositLE)
	_, _ = hasher.Write(dataHash[:])
	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// ============================================================================
// Bundle inputs + builder — keeps BFT signer + EVM/NEAR/Cardano in sync
// ============================================================================

// V6_1PreExecBundleInputsCardano is the Cardano analogue of
// V6_1PreExecBundleInputs / V6_1PreExecBundleInputsNear. Substitutes the
// synthesized 32-byte DeploymentChainID for the EVM int64 chainID and the
// Cardano-flavored ValidatorSetRoot. Other fields are identical because the
// Accumulate-side primitives (govRoot inputs, opID, commitments, ADI hash)
// are chain-agnostic.
type V6_1PreExecBundleInputsCardano struct {
	DeploymentChainID     [32]byte
	ValidatorSetRoot      [32]byte
	AdiURLHash            [32]byte
	OperationCommitment   [32]byte
	CrossChainCommitment  [32]byte
	ExecutionCommitment   [32]byte
	OperationID           [32]byte
	AccumulateBlockHeight uint64
	GovRootInputs         AccumulateGovRootInputs
}

// BuildV6_1PreExecBundleCardano is the Cardano counterpart of
// BuildV6_1PreExecBundle / BuildV6_1PreExecBundleNear. Same govRoot formula
// (Accumulate state is chain-agnostic), but uses DeriveCardanoBundleIDV6_1
// + ComputeCardanoMessageHashV6_1_Pre instead of the EVM/NEAR variants.
//
// Returns (anchorId, govRoot, messageHash) — validator logs all three for
// debugging; the on-chain Aiken validator reconstructs messageHash via
// binding.ak::message_hash_pre and rejects any mismatch.
func BuildV6_1PreExecBundleCardano(in V6_1PreExecBundleInputsCardano) (anchorId, govRoot, messageHash [32]byte) {
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)

	anchorId = DeriveCardanoBundleIDV6_1(
		in.DeploymentChainID,
		in.AdiURLHash,
		in.OperationCommitment,
		in.CrossChainCommitment,
		govRoot,
		in.ExecutionCommitment,
		in.OperationID,
		in.AccumulateBlockHeight,
	)

	messageHash = ComputeCardanoMessageHashV6_1_Pre(
		in.DeploymentChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}
