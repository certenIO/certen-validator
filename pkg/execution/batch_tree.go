package execution

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// =============================================================================
// Batch tree — the cross-language contract with CertenAnchorV7 / CertenAccountV7
// =============================================================================
//
// One anchor covers N intents, each committed as a Merkle leaf. Measured on live Sepolia,
// createAnchor + executeComprehensiveProof are 802,128 of the 987,644 gas an intent costs
// (81.2%), so amortising those two across a batch is where essentially all the saving is.
//
// EVERY function here must agree bit-for-bit with Solidity. If it does not, the validator
// mints anchors that no account can ever spend — after the gas for them has already been
// paid. TestBatchTree_MatchesSolidityVectors pins the whole schema against vectors emitted
// by certen-contracts/evm/test/CertenBatchTreeVector.t.sol.

const (
	// BatchLeafDomain must equal CertenAccountV7.LEAF_DOMAIN.
	BatchLeafDomain = "certen:batchleaf:v1"

	// BatchBundleDomain must equal the literal in CertenAnchorV7.createBatchAnchor.
	BatchBundleDomain = "certen:batchbundle:v1"
)

// BatchLeafInput is one intent's contribution to a batch.
type BatchLeafInput struct {
	ADIURL              string   // the owning ADI; hashed, never sent raw
	ExecutionCommitment [32]byte // single-call OR multi-leg batch commitment
	OperationID         [32]byte // the Accumulate 4-blob intent hash
}

// ADIURLHash is keccak256(adiURL) — the same value CertenAccountV7.adiURLHash() returns.
func (l BatchLeafInput) ADIURLHash() [32]byte {
	return ethcrypto.Keccak256Hash([]byte(l.ADIURL))
}

// ComputeBatchLeaf mirrors CertenAccountV7.computeLeaf:
//
//	keccak256(abi.encodePacked(
//	    "certen:batchleaf:v1", chainId, adiURLHash, executionCommitment, operationID
//	))
//
// abi.encodePacked layout (147 bytes):
//
//	domain   : 19 raw ASCII bytes (string is NOT length-prefixed under encodePacked)
//	chainId  : uint256  -> 32 bytes big-endian
//	adiHash  : bytes32  -> 32 bytes
//	execComm : bytes32  -> 32 bytes
//	opID     : bytes32  -> 32 bytes
//
// The domain tag is also the second-preimage defence: an internal Merkle node is
// keccak256(32||32) with no attacker-controlled prefix, so it can never be passed off as a
// leaf whose preimage must begin with this literal.
func ComputeBatchLeaf(chainID int64, in BatchLeafInput) [32]byte {
	chainIDBytes := make([]byte, 32)
	big.NewInt(chainID).FillBytes(chainIDBytes)

	adiHash := in.ADIURLHash()

	packed := make([]byte, 0, len(BatchLeafDomain)+128)
	packed = append(packed, []byte(BatchLeafDomain)...)
	packed = append(packed, chainIDBytes...)
	packed = append(packed, adiHash[:]...)
	packed = append(packed, in.ExecutionCommitment[:]...)
	packed = append(packed, in.OperationID[:]...)

	return ethcrypto.Keccak256Hash(packed)
}

// hashPair mirrors CertenAnchorV7._sortedHash / the loop in _verifyMerkleProof:
// the smaller value is written first, so the tree is order-independent at each node.
func hashPair(a, b [32]byte) [32]byte {
	var out [32]byte
	if bytesLess(a, b) {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, a[:]...), b[:]...))
	} else {
		out = ethcrypto.Keccak256Hash(append(append([]byte{}, b[:]...), a[:]...))
	}
	return out
}

func bytesLess(a, b [32]byte) bool {
	for i := 0; i < 32; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// MerkleRoot builds the batch root.
//
// Pairing rule (must match the Solidity test helper AND be walkable by
// CertenAnchorV7._verifyMerkleProof): adjacent pairs are sorted-hashed; an odd trailing node
// is PROMOTED unchanged to the next level rather than duplicated. Duplicating it would create
// two distinct leaf multisets with the same root.
//
// N=1 returns the leaf itself, which is why a single intent needs no special case anywhere:
// its root equals its leaf and its branch is empty.
func MerkleRoot(leaves [][32]byte) ([32]byte, error) {
	if len(leaves) == 0 {
		return [32]byte{}, fmt.Errorf("cannot build a Merkle root over zero leaves")
	}
	level := append([][32]byte(nil), leaves...)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, level[i]) // odd node promotes
			}
		}
		level = next
	}
	return level[0], nil
}

// MerkleBranch returns the sibling path proving leaves[index] is in MerkleRoot(leaves).
// The result is exactly what CertenAccountV7 passes as proof.merkleProof.
func MerkleBranch(leaves [][32]byte, index int) ([][32]byte, error) {
	if index < 0 || index >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range (%d leaves)", index, len(leaves))
	}
	var branch [][32]byte
	level := append([][32]byte(nil), leaves...)
	idx := index

	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		sib := idx ^ 1
		if sib < len(level) {
			branch = append(branch, level[sib])
		}
		idx /= 2
		level = next
	}
	return branch, nil
}

// VerifyBranch replays CertenAnchorV7._verifyMerkleProof exactly.
//
// The validator runs this on every leaf before spending gas on createBatchAnchor. A branch
// that fails here would fail on-chain too — after the anchor had been paid for.
func VerifyBranch(branch [][32]byte, root, leaf [32]byte) bool {
	computed := leaf
	for _, el := range branch {
		computed = hashPair(computed, el)
	}
	return computed == root
}

// DeriveBatchBundleID mirrors CertenAnchorV7.createBatchAnchor's required derivation:
//
//	keccak256(abi.encodePacked(
//	    "certen:batchbundle:v1", chainId, batchRoot, leafCount, batchOperationID, height
//	))
//
// The contract REQUIRES the submitted bundleId to equal this. That is EVM-004 in batch form:
// a rogue validator front-running with a different root, or restating the batch as a smaller
// one, produces a different id — which the honest quorum's BLS signature does not cover.
func DeriveBatchBundleID(
	chainID int64,
	batchRoot [32]byte,
	leafCount uint64,
	batchOperationID [32]byte,
	accumulateBlockHeight uint64,
) [32]byte {
	w := func(v *big.Int) []byte {
		b := make([]byte, 32)
		v.FillBytes(b)
		return b
	}

	packed := make([]byte, 0, len(BatchBundleDomain)+160)
	packed = append(packed, []byte(BatchBundleDomain)...)
	packed = append(packed, w(big.NewInt(chainID))...)
	packed = append(packed, batchRoot[:]...)
	packed = append(packed, w(new(big.Int).SetUint64(leafCount))...)
	packed = append(packed, batchOperationID[:]...)
	packed = append(packed, w(new(big.Int).SetUint64(accumulateBlockHeight))...)

	return ethcrypto.Keccak256Hash(packed)
}

// DeriveBatchOperationID aggregates the member operationIDs into the batch's own id.
//
// Sorted before hashing so the value depends only on the SET of members, not on the order
// they happened to arrive in the mempool — two validators forming the same batch must derive
// the same id or they cannot agree on the anchor.
//
// Third-party verifiability survives batching: anyone holding the member 4-blob intents can
// recompute each operationID, re-derive this aggregate, and check it against the anchor.
func DeriveBatchOperationID(operationIDs [][32]byte) [32]byte {
	sorted := append([][32]byte(nil), operationIDs...)
	sort.Slice(sorted, func(i, j int) bool { return bytesLess(sorted[i], sorted[j]) })

	packed := make([]byte, 0, 32+len(sorted)*32)
	packed = append(packed, []byte("certen:batchopid:v1")...)
	for _, id := range sorted {
		packed = append(packed, id[:]...)
	}
	return ethcrypto.Keccak256Hash(packed)
}

// =============================================================================
// Assembled batch
// =============================================================================

// BatchTree is a fully-formed batch ready to be anchored.
type BatchTree struct {
	ChainID          int64
	Leaves           [][32]byte
	Inputs           []BatchLeafInput
	Root             [32]byte
	BatchOperationID [32]byte
	BundleID         [32]byte
	BlockHeight      uint64
}

// BuildBatchTree assembles the tree and self-verifies every branch before returning.
//
// The self-verification is not paranoia: a silently wrong branch would only surface as a
// revert at TX3, after the anchor and its BLS proof had already been paid for, with the
// batch's other members stuck behind it.
func BuildBatchTree(
	chainID int64,
	inputs []BatchLeafInput,
	blockHeight uint64,
) (*BatchTree, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("cannot build a batch with no members")
	}

	leaves := make([][32]byte, 0, len(inputs))
	opIDs := make([][32]byte, 0, len(inputs))
	seen := make(map[[32]byte]int, len(inputs))

	for i, in := range inputs {
		if in.ADIURL == "" {
			return nil, fmt.Errorf("member %d has no ADI URL", i)
		}
		if in.OperationID == ([32]byte{}) {
			return nil, fmt.Errorf("member %d (%s) has a zero operationID; the anchor rejects it", i, in.ADIURL)
		}
		if in.ExecutionCommitment == ([32]byte{}) {
			return nil, fmt.Errorf("member %d (%s) has a zero executionCommitment", i, in.ADIURL)
		}

		leaf := ComputeBatchLeaf(chainID, in)

		// Duplicate leaves would be indistinguishable on-chain: the second could never be
		// consumed, because CertenAccountV7 keys single-use on the leaf itself. Catch it
		// here rather than stranding an intent.
		if prev, dup := seen[leaf]; dup {
			return nil, fmt.Errorf(
				"members %d and %d produce an identical leaf (same ADI, commitment and operationID); "+
					"the second could never be consumed", prev, i)
		}
		seen[leaf] = i

		leaves = append(leaves, leaf)
		opIDs = append(opIDs, in.OperationID)
	}

	root, err := MerkleRoot(leaves)
	if err != nil {
		return nil, err
	}

	batchOpID := DeriveBatchOperationID(opIDs)
	bundleID := DeriveBatchBundleID(chainID, root, uint64(len(leaves)), batchOpID, blockHeight)

	tree := &BatchTree{
		ChainID:          chainID,
		Leaves:           leaves,
		Inputs:           inputs,
		Root:             root,
		BatchOperationID: batchOpID,
		BundleID:         bundleID,
		BlockHeight:      blockHeight,
	}

	// Self-verify every branch against the algorithm the anchor will actually run.
	for i := range leaves {
		branch, berr := MerkleBranch(leaves, i)
		if berr != nil {
			return nil, berr
		}
		if !VerifyBranch(branch, root, leaves[i]) {
			return nil, fmt.Errorf("internal error: branch for member %d does not verify against its own root", i)
		}
	}

	return tree, nil
}

// BranchFor returns the Merkle branch for one member, by index.
func (t *BatchTree) BranchFor(index int) ([][32]byte, error) {
	return MerkleBranch(t.Leaves, index)
}

// BranchForADI returns the branch for the first member owned by adiURL.
func (t *BatchTree) BranchForADI(adiURL string) ([][32]byte, int, error) {
	for i, in := range t.Inputs {
		if in.ADIURL == adiURL {
			b, err := t.BranchFor(i)
			return b, i, err
		}
	}
	return nil, -1, fmt.Errorf("ADI %s is not a member of this batch", adiURL)
}

// Size returns the member count.
func (t *BatchTree) Size() int { return len(t.Leaves) }

// MerkleProofForContract converts a branch to the [][32]byte form the bindings expect.
func MerkleProofForContract(branch [][32]byte) [][32]byte {
	out := make([][32]byte, len(branch))
	copy(out, branch)
	return out
}

// AccountAddressForADI is a convenience for logging which account a leaf belongs to.
func AccountAddressForADI(adiURL string) common.Address {
	h := ethcrypto.Keccak256([]byte(adiURL))
	return common.BytesToAddress(h[12:])
}

// bigZero is a shared zero used where a nil *big.Int must encode as 0, matching how the
// Solidity side treats an absent value.
func bigZero() *big.Int { return new(big.Int) }
