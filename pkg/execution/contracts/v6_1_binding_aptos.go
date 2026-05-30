// V6.1 A+++ binding primitives for Aptos. Mirror of v6_1_binding_solana.go,
// adapted for Aptos: the deployment chain id is tagged "aptos", and the
// validator-set root keys on 32-byte Aptos account addresses (Aptos addresses
// are 32 bytes, like Solana pubkeys). Aptos has native keccak256
// (aptos_std::aptos_hash::keccak256) and represents hashes on-chain as u256
// (32 big-endian bytes), so the byte layouts here are identical to Solana's.
//
// Every primitive has a counterpart in
// certen-contracts/move/aptos/sources/certen_anchor_v6_1.move. ANY change here
// MUST be mirrored on the contract side and vice versa, or the BFT signer vs
// on-chain verifier produce different hashes and the proof reverts with
// E_MESSAGE_HASH_MISMATCH (57) — or create_anchor reverts with
// E_BUNDLE_ID_MISMATCH (56).

package contracts

import (
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// ComputeAptosDeploymentChainIDV6_1 produces the 32-byte chain identifier the
// Move contract stores at initialize() —
// keccak256("certen:chain:v1:aptos:" || network). network is "testnet" or
// "mainnet". Globally unique vs EVM chainIds and vs the Solana/NEAR/Cardano
// variants because of the domain prefix (so an Aptos sig can't replay on Sui,
// which shares the small numeric tag 2).
func ComputeAptosDeploymentChainIDV6_1(network string) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(
		[]byte("certen:chain:v1:aptos:"),
		[]byte(network),
	))
	return out
}

// Aptos V6.1 BLS messageHash domain constants — right-padded to 32 bytes
// (matches pad_domain_32 in the Move contract).
var (
	aptosV6_1PreDomain  = padAptosDomain32([]byte("certen:bls:v1:pre"))
	aptosV6_1PostDomain = padAptosDomain32([]byte("certen:bls:v1:post"))
)

// ComputeAptosMessageHashV6_1_Pre produces the 32-byte pre-execution BLS
// messageHash the Move anchor reconstructs and verifies. Byte-equivalent to
// compute_v6_1_message_hash in certen_anchor_v6_1.move.
//
// Wire format (192 bytes, six 32-byte slots):
//
//	keccak256(
//	    bytes32("certen:bls:v1:pre") ||
//	    deployment_chain_id          ||
//	    anchor_id                    ||
//	    execution_commitment         ||
//	    operation_id                 ||
//	    validator_set_root
//	)
func ComputeAptosMessageHashV6_1_Pre(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeAptosMessageHashV6_1(
		aptosV6_1PreDomain, deploymentChainID, anchorID,
		executionCommitment, operationID, validatorSetRoot,
	)
}

// ComputeAptosMessageHashV6_1_Post — same as Pre but with the post-exec domain
// (Phase 8 attestations). Differs by one byte of the domain literal.
func ComputeAptosMessageHashV6_1_Post(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeAptosMessageHashV6_1(
		aptosV6_1PostDomain, deploymentChainID, anchorID,
		executionCommitment, operationID, validatorSetRoot,
	)
}

func computeAptosMessageHashV6_1(
	domain [32]byte,
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	preimage := make([]byte, 0, 6*32)
	preimage = append(preimage, domain[:]...)
	preimage = append(preimage, deploymentChainID[:]...)
	preimage = append(preimage, anchorID[:]...)
	preimage = append(preimage, executionCommitment[:]...)
	preimage = append(preimage, operationID[:]...)
	preimage = append(preimage, validatorSetRoot[:]...)

	var out [32]byte
	copy(out[:], crypto.Keccak256(preimage))
	return out
}

// DeriveAptosBundleIDV6_1 reproduces compute_bundle_id_v6_1 in the Move anchor.
// Identical wire format to the NEAR/Solana variants (32-byte synthesized chain id).
//
//	keccak256(
//	  "certen:bundleid:v1.1"  (20 bytes)
//	  deployment_chain_id     (32 bytes)
//	  adi_url_hash            (32 bytes)
//	  operation_commitment    (32 bytes)
//	  cross_chain_commitment  (32 bytes)
//	  governance_root         (32 bytes)
//	  execution_commitment    (32 bytes)
//	  operation_id            (32 bytes)
//	  block_height            (32 bytes, big-endian uint256)
//	)
func DeriveAptosBundleIDV6_1(
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
	new(big.Int).SetUint64(accumulateBlockHeight).FillBytes(heightBE[:])

	preimage := make([]byte, 0, 20+8*32)
	preimage = append(preimage, []byte("certen:bundleid:v1.1")...)
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

// ComputeAptosValidatorSetRootV6_1 reproduces recompute_validator_set_root in
// certen_anchor_v6_1.move. Operates on 32-byte Aptos account addresses;
// structurally identical to the Solana variant.
//
// Wire format:
//
//	For each (address, power) sorted ASC by the 32-byte address:
//	  u32-BE(32)        (4 bytes — length prefix, always 32)
//	  address           (32 bytes, big-endian)
//	  u64-BE(power)     (8 bytes)
//	Then:
//	  u64-BE(threshold_num)
//	  u64-BE(threshold_den)
//	keccak256 over the concatenated bytes.
func ComputeAptosValidatorSetRootV6_1(
	addresses [][32]byte,
	votingPowers []uint64,
	thresholdNum uint64,
	thresholdDen uint64,
) [32]byte {
	if len(addresses) != len(votingPowers) {
		addresses = nil
		votingPowers = nil
	}

	idx := make([]int, len(addresses))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ai, bi := addresses[idx[a]], addresses[idx[b]]
		for k := 0; k < 32; k++ {
			if ai[k] != bi[k] {
				return ai[k] < bi[k]
			}
		}
		return false
	})

	hasher := crypto.NewKeccakState()
	for _, i := range idx {
		addr := addresses[i]
		power := votingPowers[i]
		_, _ = hasher.Write([]byte{0, 0, 0, 32}) // u32-BE(32) length prefix
		_, _ = hasher.Write(addr[:])
		_, _ = hasher.Write(uint64BEAptos(power))
	}
	_, _ = hasher.Write(uint64BEAptos(thresholdNum))
	_, _ = hasher.Write(uint64BEAptos(thresholdDen))

	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// =============================================================================
// Aptos-flavored V6.1 pre-exec bundle (mirrors BuildV6_1PreExecBundleSolana).
// =============================================================================

type V6_1PreExecBundleInputsAptos struct {
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

// BuildV6_1PreExecBundleAptos is the Aptos-side counterpart of
// BuildV6_1PreExecBundleSolana. Same chain-agnostic govRoot formula, Aptos
// bundleId + messageHash primitives. Returns (anchorId, govRoot, messageHash).
func BuildV6_1PreExecBundleAptos(in V6_1PreExecBundleInputsAptos) (anchorId, govRoot, messageHash [32]byte) {
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)

	anchorId = DeriveAptosBundleIDV6_1(
		in.DeploymentChainID,
		in.AdiURLHash,
		in.OperationCommitment,
		in.CrossChainCommitment,
		govRoot,
		in.ExecutionCommitment,
		in.OperationID,
		in.AccumulateBlockHeight,
	)

	messageHash = ComputeAptosMessageHashV6_1_Pre(
		in.DeploymentChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}

func uint64BEAptos(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

func padAptosDomain32(label []byte) [32]byte {
	if len(label) > 32 {
		panic("V6.1 Aptos domain label exceeds 32 bytes")
	}
	var out [32]byte
	copy(out[:], label)
	return out
}
