// V6.1 A+++ binding primitives for TON. UNLIKE the EVM/Aptos/Sui/Solana
// variants, TON cannot compute keccak256 on-chain — TVM hashing is Cell.hash()
// (SHA-256 over the TON *cell representation*, not a flat byte string). So the
// TON V6.1 hashes are built from cell-hash CHAINS that the Tact contract
// reproduces exactly with the same begin_cell/store_uint/store_ref/end_cell
// sequence. The byte LAYOUT (which fields, in what order) matches the other
// chains; only the hash primitive differs (cell-hash instead of keccak256).
//
// Every primitive here has a counterpart in
// certen-contracts/ton/contracts/certen-anchor-v6-1/src/*.tact. ANY change MUST
// be mirrored on the contract side and vice versa, or the BFT signer vs on-chain
// verifier produce different hashes and the proof reverts (message-hash gate) or
// create_anchor reverts (bundle_id derivation check).
//
// The cell conventions mirror the proven V5 helpers in ton_client.go
// (TonComputeDomainTagHash / TonSortedHash / TonComputeBoundMerkleRoot5), which
// already round-trip byte-for-byte against the deployed Tact V5 contract.

package contracts

import (
	"math/big"
	"sort"

	"github.com/xssnick/tonutils-go/tvm/cell"
)

// tonCellHashChain hashes an ordered list of 32-byte values the way the Tact
// contract does: a linked chain of cells where cell[i] stores values[i] as a
// 256-bit uint and a ref to cell[i+1]; the last cell has no ref. The returned
// hash is Cell.hash() of the head cell (SHA-256 of the TON cell representation).
//
//	cell[n-1] = C{ uint256(v[n-1]) }
//	cell[i]   = C{ uint256(v[i]), ref: cell[i+1] }
//	result    = cell[0].hash()
func tonCellHashChain(values [][32]byte) [32]byte {
	var child *cell.Cell
	for i := len(values) - 1; i >= 0; i-- {
		b := cell.BeginCell().MustStoreBigUInt(new(big.Int).SetBytes(values[i][:]), 256)
		if child != nil {
			b.MustStoreRef(child)
		}
		child = b.EndCell()
	}
	if child == nil {
		child = cell.BeginCell().EndCell()
	}
	var out [32]byte
	copy(out[:], child.Hash())
	return out
}

// tonSnakeStringHash returns Cell.hash() of a single snake-encoded string cell —
// matches Tact beginString().append(s).toCell().hash() for s up to ~127 bytes.
func tonSnakeStringHash(s string) [32]byte {
	c := cell.BeginCell().MustStoreStringSnake(s).EndCell()
	var out [32]byte
	copy(out[:], c.Hash())
	return out
}

func uint64To32(v uint64) [32]byte {
	var out [32]byte
	new(big.Int).SetUint64(v).FillBytes(out[:])
	return out
}

// ComputeTonDeploymentChainIDV6_1 is the 32-byte chain identifier the Tact
// contract derives at init — Cell.hash() of the snake string
// "certen:chain:v1:ton:" || network. network is "testnet" or "mainnet".
// Globally unique vs the keccak-derived ids of the other chains (different hash
// primitive AND different domain), so a TON sig can't replay anywhere else.
func ComputeTonDeploymentChainIDV6_1(network string) [32]byte {
	return tonSnakeStringHash("certen:chain:v1:ton:" + network)
}

// TON V6.1 BLS messageHash domain values — Cell.hash() of the snake domain
// labels (the first slot of the message-hash chain; replaces the keccak
// pad32(domain) of the other chains).
var (
	tonV6_1PreDomain  = tonSnakeStringHash("certen:bls:v1:pre")
	tonV6_1PostDomain = tonSnakeStringHash("certen:bls:v1:post")
)

// ComputeTonMessageHashV6_1_Pre is the 32-byte pre-execution BLS messageHash the
// Tact anchor reconstructs and verifies. Cell-hash chain over six 32-byte slots:
//
//	chain( domainValue("certen:bls:v1:pre"), deployment_chain_id, anchor_id,
//	       execution_commitment, operation_id, validator_set_root )
func ComputeTonMessageHashV6_1_Pre(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return tonCellHashChain([][32]byte{
		tonV6_1PreDomain, deploymentChainID, anchorID,
		executionCommitment, operationID, validatorSetRoot,
	})
}

// ComputeTonMessageHashV6_1_Post — same as Pre but with the post-exec domain
// value (Phase 8 attestations). Differs by the first slot.
func ComputeTonMessageHashV6_1_Post(
	deploymentChainID [32]byte,
	anchorID [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	validatorSetRoot [32]byte,
) [32]byte {
	return tonCellHashChain([][32]byte{
		tonV6_1PostDomain, deploymentChainID, anchorID,
		executionCommitment, operationID, validatorSetRoot,
	})
}

// DeriveTonBundleIDV6_1 reproduces the Tact compute_bundle_id_v6_1 — a cell-hash
// chain over eight 32-byte slots:
//
//	chain( deployment_chain_id, adi_url_hash, operation_commitment,
//	       cross_chain_commitment, governance_root, execution_commitment,
//	       operation_id, block_height(as uint256) )
func DeriveTonBundleIDV6_1(
	deploymentChainID [32]byte,
	adiURLHash [32]byte,
	operationCommitment [32]byte,
	crossChainCommitment [32]byte,
	governanceRoot [32]byte,
	executionCommitment [32]byte,
	operationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	return tonCellHashChain([][32]byte{
		deploymentChainID, adiURLHash, operationCommitment, crossChainCommitment,
		governanceRoot, executionCommitment, operationID, uint64To32(accumulateBlockHeight),
	})
}

// ComputeTonValidatorSetRootV6_1 produces the 32-byte validator-set root folded
// into the messageHash. On TON this value is computed off-chain and SET on the
// contract by the owner at config time (Tact map iteration+sort on-chain is
// impractical), then read back into TON_VALIDATOR_SET_ROOT; the contract stores
// it opaquely and folds it into the gate. Layout: a cell-hash chain over the
// validator set sorted ASC by the 32-byte account hash —
//
//	for each (account_hash, power) sorted asc: a node cell
//	    C{ uint256(account_hash), uint64(power), ref: next }
//	terminal node: C{ uint64(threshold_num), uint64(threshold_den) }
//	result = head.hash()
func ComputeTonValidatorSetRootV6_1(
	accountHashes [][32]byte,
	votingPowers []uint64,
	thresholdNum uint64,
	thresholdDen uint64,
) [32]byte {
	if len(accountHashes) != len(votingPowers) {
		accountHashes = nil
		votingPowers = nil
	}
	idx := make([]int, len(accountHashes))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ai, bi := accountHashes[idx[a]], accountHashes[idx[b]]
		for k := 0; k < 32; k++ {
			if ai[k] != bi[k] {
				return ai[k] < bi[k]
			}
		}
		return false
	})

	// terminal cell carries the threshold
	tail := cell.BeginCell().
		MustStoreUInt(thresholdNum, 64).
		MustStoreUInt(thresholdDen, 64).
		EndCell()

	child := tail
	for j := len(idx) - 1; j >= 0; j-- {
		i := idx[j]
		child = cell.BeginCell().
			MustStoreBigUInt(new(big.Int).SetBytes(accountHashes[i][:]), 256).
			MustStoreUInt(votingPowers[i], 64).
			MustStoreRef(child).
			EndCell()
	}
	var out [32]byte
	copy(out[:], child.Hash())
	return out
}

// =============================================================================
// TON-flavored V6.1 pre-exec bundle (mirrors BuildV6_1PreExecBundleSui).
// =============================================================================

type V6_1PreExecBundleInputsTon struct {
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

// BuildV6_1PreExecBundleTon is the TON-side counterpart of
// BuildV6_1PreExecBundleSui. Same chain-agnostic govRoot formula, TON cell-hash
// bundleId + messageHash primitives. Returns (anchorId, govRoot, messageHash).
func BuildV6_1PreExecBundleTon(in V6_1PreExecBundleInputsTon) (anchorId, govRoot, messageHash [32]byte) {
	govRoot = ComputeAccumulateGovRoot(in.GovRootInputs)

	anchorId = DeriveTonBundleIDV6_1(
		in.DeploymentChainID,
		in.AdiURLHash,
		in.OperationCommitment,
		in.CrossChainCommitment,
		govRoot,
		in.ExecutionCommitment,
		in.OperationID,
		in.AccumulateBlockHeight,
	)

	messageHash = ComputeTonMessageHashV6_1_Pre(
		in.DeploymentChainID,
		anchorId,
		in.ExecutionCommitment,
		in.OperationID,
		in.ValidatorSetRoot,
	)
	return
}
