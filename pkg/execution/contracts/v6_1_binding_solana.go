// V6.1 A+++ binding primitives for Solana. Mirror of v6_1_binding_near.go
// (NEAR) adapted for Solana's model: 32-byte ed25519 program-derived/account
// pubkeys instead of NEAR account-id strings or EVM 20-byte addresses, a
// 32-byte synthesized chain identifier in place of EVM's uint256(block.chainid),
// and u64 lamports (8 bytes LE) instead of NEAR's u128 yocto deposit.
//
// Every primitive here has a counterpart in
// certen-contracts/solana/programs/certen-anchor-v6-1/src/crypto.rs (and the
// execution commitment in instructions/governance.rs). ANY change here MUST be
// mirrored on the contract side and vice versa, or the BFT signer vs on-chain
// verifier produce different hashes and TX2 reverts with the V6.1 messageHash
// mismatch error (custom error 6057) — or create_anchor reverts with
// BundleIdMismatch (6056).

package contracts

import (
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// solanaClusterPadded16 reproduces how the contract stores deployment_cluster:
// the cluster name right-padded with zeros into a fixed 16-byte array
// (initialize.rs). The execution commitment hashes this padded form, NOT the
// raw string.
func solanaClusterPadded16(cluster string) [16]byte {
	var out [16]byte
	b := []byte(cluster)
	if len(b) > 16 {
		b = b[:16]
	}
	copy(out[:], b)
	return out
}

// ComputeSolanaExecutionCommitmentV6_1 reproduces
// CertenAnchorV6_1::compute_execution_commitment (governance.rs). The on-chain
// contract recomputes this at execute_with_governance time and rejects the call
// if the runtime params don't match the value committed at create_anchor.
//
// Wire format (matches the Rust contract exactly):
//
//	data_hash  = keccak256(instruction_data)
//	commitment = keccak256(
//	               cluster_padded_16          // 16 bytes (deployment_cluster)
//	               ‖ target_program_pubkey    // 32 bytes
//	               ‖ u64-LE(lamports)         // 8 bytes
//	               ‖ data_hash                // 32 bytes
//	             )
//
// `cluster` is the deployment cluster name ("devnet", "mainnet-beta", ...).
func ComputeSolanaExecutionCommitmentV6_1(
	cluster string,
	targetProgram [32]byte,
	lamports uint64,
	instructionData []byte,
) [32]byte {
	dataHasher := crypto.NewKeccakState()
	_, _ = dataHasher.Write(instructionData)
	var dataHash [32]byte
	_, _ = dataHasher.Read(dataHash[:])

	clusterPadded := solanaClusterPadded16(cluster)

	lamportsLE := make([]byte, 8)
	for i := 0; i < 8; i++ {
		lamportsLE[i] = byte(lamports >> (8 * uint(i)))
	}

	hasher := crypto.NewKeccakState()
	_, _ = hasher.Write(clusterPadded[:])
	_, _ = hasher.Write(targetProgram[:])
	_, _ = hasher.Write(lamportsLE)
	_, _ = hasher.Write(dataHash[:])
	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// Solana V6.1 BLS messageHash domain constants — right-padded to 32 bytes
// (matches pad_bytes32 in the Rust contract).
var (
	solanaV6_1PreDomain  = padSolanaDomain32([]byte("certen:bls:v1:pre"))
	solanaV6_1PostDomain = padSolanaDomain32([]byte("certen:bls:v1:post"))
)

// ComputeSolanaDeploymentChainIDV6_1 produces the 32-byte chain identifier
// CertenAnchorV6_1 stores at initialize() —
// keccak256("certen:chain:v1:solana:" || cluster). Globally unique vs EVM
// uint256(block.chainid) values and vs the NEAR variant because of the domain
// prefix.
func ComputeSolanaDeploymentChainIDV6_1(cluster string) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(
		[]byte("certen:chain:v1:solana:"),
		[]byte(cluster),
	))
	return out
}

// ComputeSolanaMessageHashV6_1_Pre produces the 32-byte pre-execution BLS
// messageHash that CertenAnchorV6_1::execute_comprehensive_proof reconstructs
// (inside verify_all_components) and verifies. Byte-equivalent to
// compute_v6_1_message_hash in the Solana contract.
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
func ComputeSolanaMessageHashV6_1_Pre(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeSolanaMessageHashV6_1(
		solanaV6_1PreDomain,
		deploymentChainID,
		anchorID,
		executionCommitment,
		operationID,
		validatorSetRoot,
	)
}

// ComputeSolanaMessageHashV6_1_Post — same as Pre but with the post-exec domain
// (Phase 8 attestations). Differs from pre by one byte of the domain literal so
// a pre-exec sig can never be replayed as post-exec.
func ComputeSolanaMessageHashV6_1_Post(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeSolanaMessageHashV6_1(
		solanaV6_1PostDomain,
		deploymentChainID,
		anchorID,
		executionCommitment,
		operationID,
		validatorSetRoot,
	)
}

func computeSolanaMessageHashV6_1(
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

// DeriveSolanaBundleIDV6_1 reproduces CertenAnchorV6_1::compute_bundle_id_v6_1
// on the validator side. Required equality with the on-chain computation —
// create_anchor reverts with BundleIdMismatch on any mismatch. Identical wire
// format to the NEAR variant (both take the 32-byte synthesized chain id).
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
func DeriveSolanaBundleIDV6_1(
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

// ComputeSolanaValidatorSetRootV6_1 reproduces the on-chain
// recompute_validator_set_root in CertenAnchorV6_1 (crypto.rs). Operates on
// 32-byte Solana pubkeys; structurally identical to the NEAR variant
// (length-prefixed entries) but keys on the raw pubkey bytes.
//
// Wire format:
//
//	For each (pubkey, power) sorted ASC by pubkey bytes:
//	  u32-BE(32)        (4 bytes — length prefix, always 32 for a pubkey)
//	  pubkey            (32 bytes)
//	  u64-BE(power)     (8 bytes)
//	Then:
//	  u64-BE(threshold_num)
//	  u64-BE(threshold_den)
//	keccak256 over the concatenated bytes.
//
// Caller passes pubkeys + powers in any order; this function sorts internally.
func ComputeSolanaValidatorSetRootV6_1(
	pubkeys [][32]byte,
	votingPowers []uint64,
	thresholdNum uint64,
	thresholdDen uint64,
) [32]byte {
	if len(pubkeys) != len(votingPowers) {
		// Mismatched input — fail loud by hashing an empty active set rather
		// than producing a wrong-but-valid-looking root.
		pubkeys = nil
		votingPowers = nil
	}

	idx := make([]int, len(pubkeys))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ai, bi := pubkeys[idx[a]], pubkeys[idx[b]]
		for k := 0; k < 32; k++ {
			if ai[k] != bi[k] {
				return ai[k] < bi[k]
			}
		}
		return false
	})

	hasher := crypto.NewKeccakState()
	for _, i := range idx {
		pk := pubkeys[i]
		power := votingPowers[i]
		// u32-BE length prefix (32) — retained from the NEAR length-prefixed
		// layout so the two implementations stay structurally identical.
		_, _ = hasher.Write([]byte{0, 0, 0, 32})
		_, _ = hasher.Write(pk[:])
		_, _ = hasher.Write(uint64BE(power))
	}
	_, _ = hasher.Write(uint64BE(thresholdNum))
	_, _ = hasher.Write(uint64BE(thresholdDen))

	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// =============================================================================
// Solana-flavored V6.1 pre-exec bundle (mirrors BuildV6_1PreExecBundleNear).
// =============================================================================

// V6_1PreExecBundleInputsSolana is the Solana analogue of
// V6_1PreExecBundleInputsNear. Substitutes the 32-byte synthesized
// DeploymentChainID and the Solana-flavored ValidatorSetRoot. The
// Accumulate-side primitives (govRoot inputs, opID, commitments, ADI hash) are
// chain-agnostic.
type V6_1PreExecBundleInputsSolana struct {
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

// BuildV6_1PreExecBundleSolana is the Solana-side counterpart of
// BuildV6_1PreExecBundle / BuildV6_1PreExecBundleNear. Same chain-agnostic
// govRoot formula, but uses the Solana bundleId + messageHash primitives.
//
// Returns (anchorId, govRoot, messageHash); the validator stores and logs all
// three for debugging.
func BuildV6_1PreExecBundleSolana(in V6_1PreExecBundleInputsSolana) (anchorId, govRoot, messageHash [32]byte) {
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)

	anchorId = DeriveSolanaBundleIDV6_1(
		in.DeploymentChainID,
		in.AdiURLHash,
		in.OperationCommitment,
		in.CrossChainCommitment,
		govRoot,
		in.ExecutionCommitment,
		in.OperationID,
		in.AccumulateBlockHeight,
	)

	messageHash = ComputeSolanaMessageHashV6_1_Pre(
		in.DeploymentChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}

func uint64BE(v uint64) []byte {
	return []byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	}
}

// padSolanaDomain32 right-pads a domain label up to 32 bytes (Solidity
// bytes32(label) semantics; the Rust contract does the same via pad_bytes32).
func padSolanaDomain32(label []byte) [32]byte {
	if len(label) > 32 {
		panic("V6.1 Solana domain label exceeds 32 bytes")
	}
	var out [32]byte
	copy(out[:], label)
	return out
}
