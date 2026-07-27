// V6.1 A+++ binding primitives for NEAR Protocol. Mirror of v6_1_binding.go
// (EVM) but adapted for NEAR's account-id model: variable-length UTF-8
// account IDs instead of 20-byte EVM addresses, and a 32-byte synthesized
// chain identifier in place of EVM's `uint256(block.chainid)`.
//
// All four primitives below have a corresponding on-chain counterpart in
// certen-contracts/near/contracts/certen-anchor-v6-1/src/lib.rs. ANY change
// here MUST be mirrored on the contract side and vice versa, or BFT signer
// vs on-chain verifier produce different hashes and TX2 reverts with the
// V6.1 messageHash mismatch error.

package contracts

import (
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
)

// ComputeNearExecutionCommitmentV6_1 reproduces
// CertenAnchorV6_1::compute_execution_commitment on NEAR. The on-chain
// contract recomputes this at execute_with_governance time and rejects the
// call if the runtime params don't match. The validator's local
// computation MUST be byte-identical or TX3 reverts with
// "Execution commitment mismatch".
//
// Wire format (matches the Rust contract exactly):
//
//	data_hash   = keccak256(method || args)
//	commitment  = keccak256(
//	                network_id_bytes
//	                ‖ target_account_bytes
//	                ‖ u128-LE(deposit_yocto)    // 16 bytes
//	                ‖ data_hash                  // 32 bytes
//	              )
//
// For a plain NEAR transfer the call shape is method="transfer" and args=[];
// the BFT signing path passes the same (target, deposit, method, args) so
// the result lines up with what the contract computes from its stored
// values at execute time.
func ComputeNearExecutionCommitmentV6_1(
	networkID string,
	target string,
	depositYocto *big.Int,
	method string,
	args []byte,
) [32]byte {
	// data_hash = keccak256(method || args)
	dataHasher := crypto.NewKeccakState()
	_, _ = dataHasher.Write([]byte(method))
	_, _ = dataHasher.Write(args)
	var dataHash [32]byte
	_, _ = dataHasher.Read(dataHash[:])

	// Little-endian 16-byte deposit (matches Rust to_le_bytes() for u128).
	depositLE := make([]byte, 16)
	if depositYocto != nil {
		be := depositYocto.Bytes()
		// Reverse big-endian → little-endian, copy into the first
		// len(be) bytes of the 16-byte slot.
		for i, b := range be {
			depositLE[len(be)-1-i] = b
		}
	}

	hasher := crypto.NewKeccakState()
	_, _ = hasher.Write([]byte(networkID))
	_, _ = hasher.Write([]byte(target))
	_, _ = hasher.Write(depositLE)
	_, _ = hasher.Write(dataHash[:])
	var out [32]byte
	_, _ = hasher.Read(out[:])
	return out
}

// NEAR V6.1 BLS messageHash domain constants — right-padded to 32 bytes
// (matches what the Rust contract does via pad_bytes32 on the same labels).
var (
	nearV6_1PreDomain  = padNearDomain32([]byte("certen:bls:v1:pre"))
	nearV6_1PostDomain = padNearDomain32([]byte("certen:bls:v1:post"))
)

// ComputeNearDeploymentChainIDV6_1 produces the 32-byte chain identifier
// CertenAnchorV6_1 stores at init() — keccak256("certen:chain:v1:near:" ||
// network_id). network_id is "testnet" or "mainnet". Globally unique vs
// EVM `uint256(block.chainid)` values because of the domain prefix.
func ComputeNearDeploymentChainIDV6_1(networkID string) [32]byte {
	var out [32]byte
	copy(out[:], crypto.Keccak256(
		[]byte("certen:chain:v1:near:"),
		[]byte(networkID),
	))
	return out
}

// ComputeNearMessageHashV6_1_Pre produces the 32-byte pre-execution BLS
// messageHash that CertenAnchorV6_1::execute_comprehensive_proof
// reconstructs and verifies. Validators sign this and the contract
// recomputes it byte-for-byte. Byte-equivalent to
// compute_v6_1_message_hash in the NEAR contract.
//
// Wire format (192 bytes, six 32-byte slots):
//
//	keccak256(
//	    bytes32("certen:bls:v1:pre")  ||
//	    deployment_chain_id           ||
//	    anchor_id                     ||
//	    execution_commitment          ||
//	    operation_id                  ||
//	    validator_set_root
//	)
func ComputeNearMessageHashV6_1_Pre(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeNearMessageHashV6_1(
		nearV6_1PreDomain,
		deploymentChainID,
		anchorID,
		executionCommitment,
		operationID,
		validatorSetRoot,
	)
}

// ComputeNearMessageHashV6_1_Post — same as Pre but with the post-exec
// domain. Used by Phase 8 attestations. Differs from pre by one byte of
// the domain literal so a pre-exec sig can never be replayed as post-exec.
func ComputeNearMessageHashV6_1_Post(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return computeNearMessageHashV6_1(
		nearV6_1PostDomain,
		deploymentChainID,
		anchorID,
		executionCommitment,
		operationID,
		validatorSetRoot,
	)
}

func computeNearMessageHashV6_1(
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

// DeriveNearBundleIDV6_1 reproduces CertenAnchorV6_1::compute_bundle_id_v6_1
// on the validator side. Required equality with the on-chain computation —
// create_anchor rejects any mismatch.
//
// Wire format (same field ordering and slot widths as EVM
// DeriveV6_1BundleID; NEAR substitutes its synthesized 32-byte chain id):
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
func DeriveNearBundleIDV6_1(
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

// ComputeNearValidatorSetRootV6_1 reproduces the on-chain
// recompute_validator_set_root in CertenAnchorV6_1. Operates on NEAR
// account IDs (variable-length UTF-8 strings), not 20-byte addresses, so
// the wire format differs from EVM's ComputeValidatorSetRootV6_1.
//
// Wire format:
//
//	For each (acct, power) sorted ASC by acct bytes:
//	  u32-BE(len(acct))    (4 bytes)
//	  acct_bytes           (variable)
//	  u64-BE(power)        (8 bytes)
//	Then:
//	  u64-BE(threshold_num)
//	  u64-BE(threshold_den)
//	keccak256 over the concatenated bytes.
//
// Caller passes accounts + powers in any order; this function sorts
// internally before hashing.
func ComputeNearValidatorSetRootV6_1(
	accounts []string,
	votingPowers []uint64,
	thresholdNum uint64,
	thresholdDen uint64,
) [32]byte {
	if len(accounts) != len(votingPowers) {
		// Mismatched input — treat as empty active set so the validator
		// fails loud rather than producing a wrong-but-valid-looking root.
		accounts = nil
		votingPowers = nil
	}

	idx := make([]int, len(accounts))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return accounts[idx[a]] < accounts[idx[b]]
	})

	hasher := crypto.NewKeccakState()
	for _, i := range idx {
		acct := []byte(accounts[i])
		power := votingPowers[i]
		_, _ = hasher.Write([]byte{
			byte(len(acct) >> 24),
			byte(len(acct) >> 16),
			byte(len(acct) >> 8),
			byte(len(acct)),
		})
		_, _ = hasher.Write(acct)
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

// =============================================================================
// NEAR-flavored V6.1 pre-exec bundle (mirrors BuildV6_1PreExecBundle in
// v6_1_binding.go but uses NEAR primitives).
// =============================================================================

// V6_1PreExecBundleInputsNear is the NEAR analogue of V6_1PreExecBundleInputs.
// Substitutes the 32-byte synthesized DeploymentChainID for the EVM int64
// chainID, and the NEAR-flavored ValidatorSetRoot. Other fields are identical
// because the underlying Accumulate-side primitives (govRoot inputs, opID,
// commitments, ADI hash) are chain-agnostic.
type V6_1PreExecBundleInputsNear struct {
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

// BuildV6_1PreExecBundleNear is the NEAR-side counterpart of
// BuildV6_1PreExecBundle. Same govRoot formula (Accumulate state is chain-
// agnostic), but uses DeriveNearBundleIDV6_1 + ComputeNearMessageHashV6_1_Pre
// instead of the EVM variants.
//
// Returns (anchorId, govRoot, messageHash); validator stores and logs all
// three for debugging.
func BuildV6_1PreExecBundleNear(in V6_1PreExecBundleInputsNear) (anchorId, govRoot, messageHash [32]byte) {
	// govRoot — chain-agnostic; same formula on EVM and NEAR. The 10-field
	// AccumulateGovRoot binds Accumulate-side state which doesn't depend on
	// the target chain.
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)

	anchorId = DeriveNearBundleIDV6_1(
		in.DeploymentChainID,
		in.AdiURLHash,
		in.OperationCommitment,
		in.CrossChainCommitment,
		govRoot,
		in.ExecutionCommitment,
		in.OperationID,
		in.AccumulateBlockHeight,
	)

	messageHash = ComputeNearMessageHashV6_1_Pre(
		in.DeploymentChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}

// padNearDomain32 right-pads a domain label up to 32 bytes (Solidity
// bytes32(label) semantics). The NEAR Rust contract does the same via
// pad_bytes32 — kept in lockstep here.
func padNearDomain32(label []byte) [32]byte {
	if len(label) > 32 {
		panic("V6.1 NEAR domain label exceeds 32 bytes")
	}
	var out [32]byte
	copy(out[:], label)
	return out
}
