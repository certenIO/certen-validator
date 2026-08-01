package execution

import (
	"encoding/hex"
	"testing"
)

// h decodes a 32-byte hex vector emitted by the Solidity side.
func h(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad fixture: " + s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func b32(v uint64) [32]byte {
	var out [32]byte
	for i := 0; i < 8; i++ {
		out[31-i] = byte(v >> (8 * i))
	}
	return out
}

const (
	vecChainID = int64(11155111) // Sepolia
	vecHeight  = uint64(987654)
)

func vecInputs() []BatchLeafInput {
	return []BatchLeafInput{
		{ADIURL: "acc://alice.acme", ExecutionCommitment: b32(0x1111), OperationID: b32(0xaaaa)},
		{ADIURL: "acc://bob.acme", ExecutionCommitment: b32(0x2222), OperationID: b32(0xbbbb)},
		{ADIURL: "acc://carol.acme", ExecutionCommitment: b32(0x3333), OperationID: b32(0xcccc)},
	}
}

// Ground truth emitted by certen-contracts/evm/test/CertenBatchTreeVector.t.sol.
var (
	vecLeaf0  = h("6816fe36b993bf4a78aab71019ac9c157f4314775876e4ee14520f513a1228fa")
	vecLeaf1  = h("2f07d3c62f0e72a8fa452fd08d8463578039e05a7a93fc19ddd7a39352a867b0")
	vecLeaf2  = h("face19409c023938d77a41018fb14e5219696ba9786fc188717b00d4ff2528e0")
	vecRoot   = h("669f53ca64df6f336239b25a62d466bfda28b5502e178ca6a69d9a1f3b97239c")
	vecNode01 = h("60b2d8feb29192f664f3e2aeac49869c3582b06ced90d8095258c94a90bc6a96")
)

// =============================================================================
// THE cross-language contract
// =============================================================================

// If this fails, the validator would mint anchors no account can ever spend — after paying
// for them. The identical fixture is asserted in Solidity by CertenBatchTreeVectorTest.
func TestBatchTree_MatchesSolidityVectors(t *testing.T) {
	in := vecInputs()

	got0 := ComputeBatchLeaf(vecChainID, in[0])
	got1 := ComputeBatchLeaf(vecChainID, in[1])
	got2 := ComputeBatchLeaf(vecChainID, in[2])

	if got0 != vecLeaf0 {
		t.Fatalf("leaf0 mismatch\n got: %x\nwant: %x", got0, vecLeaf0)
	}
	if got1 != vecLeaf1 {
		t.Fatalf("leaf1 mismatch\n got: %x\nwant: %x", got1, vecLeaf1)
	}
	if got2 != vecLeaf2 {
		t.Fatalf("leaf2 mismatch\n got: %x\nwant: %x", got2, vecLeaf2)
	}

	root, err := MerkleRoot([][32]byte{got0, got1, got2})
	if err != nil {
		t.Fatal(err)
	}
	if root != vecRoot {
		t.Fatalf("root mismatch\n got: %x\nwant: %x", root, vecRoot)
	}
}

// The odd-node promotion rule must match: with 3 leaves, level1 is [pair(l0,l1), l2].
func TestBatchTree_OddNodePromotionMatchesSolidity(t *testing.T) {
	got := hashPair(vecLeaf0, vecLeaf1)
	if got != vecNode01 {
		t.Fatalf("pair(l0,l1) mismatch\n got: %x\nwant: %x", got, vecNode01)
	}
	// root = pair(node01, leaf2) — leaf2 promoted unchanged, NOT duplicated.
	if hashPair(vecNode01, vecLeaf2) != vecRoot {
		t.Fatal("odd leaf must be promoted unchanged, not duplicated")
	}
}

func TestBatchTree_BranchesMatchSolidity(t *testing.T) {
	leaves := [][32]byte{vecLeaf0, vecLeaf1, vecLeaf2}

	b0, err := MerkleBranch(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b0) != 2 || b0[0] != vecLeaf1 || b0[1] != vecLeaf2 {
		t.Fatalf("branch0 mismatch: %x", b0)
	}

	b2, err := MerkleBranch(leaves, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(b2) != 1 || b2[0] != vecNode01 {
		t.Fatalf("branch2 mismatch: %x", b2)
	}
}

func TestBatchTree_BundleIDMatchesSolidity(t *testing.T) {
	// batchOpID from the Solidity fixture is keccak256("certen-batch-op"); the Go aggregate
	// differs by construction, so pin the DERIVATION using the Solidity value directly.
	batchOpID := h("a4b561c8cc4dcfd18aafd7bbcc729bcb6db9e10bae65b5f3adbf525d8ba856ee")
	want := h("02d03c588f3e41498cb44a11c9fb72735196cf962a4c841d9e40effe3d214b8a")

	got := DeriveBatchBundleID(vecChainID, vecRoot, 3, batchOpID, vecHeight)
	if got != want {
		t.Fatalf("bundleId mismatch\n got: %x\nwant: %x", got, want)
	}
}

// =============================================================================
// Tree invariants
// =============================================================================

func TestBatchTree_EveryBranchVerifies(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 16, 17, 31, 64} {
		inputs := make([]BatchLeafInput, n)
		for i := range inputs {
			inputs[i] = BatchLeafInput{
				ADIURL:              "acc://adi" + string(rune('a'+i%26)) + string(rune('0'+i/26)) + ".acme",
				ExecutionCommitment: b32(uint64(1000 + i)),
				OperationID:         b32(uint64(2000 + i)),
			}
		}
		tree, err := BuildBatchTree(vecChainID, inputs, vecHeight)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if tree.Size() != n {
			t.Fatalf("n=%d: size=%d", n, tree.Size())
		}
		for i := 0; i < n; i++ {
			branch, err := tree.BranchFor(i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyBranch(branch, tree.Root, tree.Leaves[i]) {
				t.Fatalf("n=%d: branch %d does not verify", n, i)
			}
		}
	}
}

// N=1: root == leaf, empty branch. Proves single intents need no special case.
func TestBatchTree_SingleMemberRootIsTheLeaf(t *testing.T) {
	in := []BatchLeafInput{{ADIURL: "acc://solo.acme", ExecutionCommitment: b32(1), OperationID: b32(2)}}
	tree, err := BuildBatchTree(vecChainID, in, vecHeight)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Root != tree.Leaves[0] {
		t.Fatal("one-leaf tree root must equal the leaf")
	}
	branch, _ := tree.BranchFor(0)
	if len(branch) != 0 {
		t.Fatalf("one-leaf branch must be empty, got %d", len(branch))
	}
	if !VerifyBranch(branch, tree.Root, tree.Leaves[0]) {
		t.Fatal("empty branch must verify")
	}
}

// A foreign leaf must never verify against someone else's root.
func TestBatchTree_ForeignLeafNeverVerifies(t *testing.T) {
	inputs := vecInputs()
	tree, err := BuildBatchTree(vecChainID, inputs, vecHeight)
	if err != nil {
		t.Fatal(err)
	}
	foreign := ComputeBatchLeaf(vecChainID, BatchLeafInput{
		ADIURL: "acc://mallory.acme", ExecutionCommitment: b32(9), OperationID: b32(9),
	})
	for i := range tree.Leaves {
		branch, _ := tree.BranchFor(i)
		if VerifyBranch(branch, tree.Root, foreign) {
			t.Fatal("a foreign leaf verified — membership is broken")
		}
	}
}

// The leaf binds the ADI: same commitment + opID under a different ADI is a different leaf.
func TestBatchTree_LeafBindsADI(t *testing.T) {
	a := ComputeBatchLeaf(vecChainID, BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1), OperationID: b32(2)})
	b := ComputeBatchLeaf(vecChainID, BatchLeafInput{ADIURL: "acc://b.acme", ExecutionCommitment: b32(1), OperationID: b32(2)})
	if a == b {
		t.Fatal("leaf must bind the ADI — otherwise one ADI could spend another's authorization")
	}
}

func TestBatchTree_LeafBindsChain(t *testing.T) {
	in := BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1), OperationID: b32(2)}
	if ComputeBatchLeaf(11155111, in) == ComputeBatchLeaf(8453, in) {
		t.Fatal("leaf must be chain-bound")
	}
}

func TestBatchTree_LeafBindsOperationID(t *testing.T) {
	base := BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1), OperationID: b32(2)}
	other := base
	other.OperationID = b32(3)
	if ComputeBatchLeaf(vecChainID, base) == ComputeBatchLeaf(vecChainID, other) {
		t.Fatal("leaf must bind the operationID")
	}
}

// =============================================================================
// BuildBatchTree guards
// =============================================================================

func TestBuildBatchTree_RejectsEmptyAndZeroFields(t *testing.T) {
	if _, err := BuildBatchTree(vecChainID, nil, vecHeight); err == nil {
		t.Fatal("empty batch must be rejected")
	}
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{
		{ADIURL: "", ExecutionCommitment: b32(1), OperationID: b32(1)}}, vecHeight); err == nil {
		t.Fatal("missing ADI URL must be rejected")
	}
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{
		{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1)}}, vecHeight); err == nil {
		t.Fatal("zero operationID must be rejected — the anchor rejects it too")
	}
	if _, err := BuildBatchTree(vecChainID, []BatchLeafInput{
		{ADIURL: "acc://a.acme", OperationID: b32(1)}}, vecHeight); err == nil {
		t.Fatal("zero executionCommitment must be rejected")
	}
}

// Duplicate leaves would strand the second member: single-use is keyed on the leaf.
func TestBuildBatchTree_RejectsDuplicateLeaves(t *testing.T) {
	dup := BatchLeafInput{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1), OperationID: b32(2)}
	_, err := BuildBatchTree(vecChainID, []BatchLeafInput{dup, dup}, vecHeight)
	if err == nil {
		t.Fatal("identical leaves must be rejected — the second could never be consumed")
	}
}

// The same ADI may appear twice with DIFFERENT operations — that is the legitimate case
// CertenAccountV7's per-leaf single-use exists to support.
func TestBuildBatchTree_AllowsSameADITwiceWithDistinctOps(t *testing.T) {
	in := []BatchLeafInput{
		{ADIURL: "acc://a.acme", ExecutionCommitment: b32(1), OperationID: b32(10)},
		{ADIURL: "acc://a.acme", ExecutionCommitment: b32(2), OperationID: b32(11)},
	}
	tree, err := BuildBatchTree(vecChainID, in, vecHeight)
	if err != nil {
		t.Fatalf("same ADI with distinct operations must be allowed: %v", err)
	}
	if tree.Size() != 2 {
		t.Fatalf("size=%d", tree.Size())
	}
}

// =============================================================================
// Batch operationID aggregate
// =============================================================================

// Two validators forming the same batch must derive the same id regardless of arrival order.
func TestDeriveBatchOperationID_OrderIndependent(t *testing.T) {
	a := [][32]byte{b32(1), b32(2), b32(3)}
	b := [][32]byte{b32(3), b32(1), b32(2)}
	if DeriveBatchOperationID(a) != DeriveBatchOperationID(b) {
		t.Fatal("batch operationID must depend only on the member set, not arrival order")
	}
}

func TestDeriveBatchOperationID_DistinctSetsDiffer(t *testing.T) {
	if DeriveBatchOperationID([][32]byte{b32(1), b32(2)}) ==
		DeriveBatchOperationID([][32]byte{b32(1), b32(3)}) {
		t.Fatal("different member sets must produce different batch operationIDs")
	}
}

// =============================================================================
// bundleId binding (EVM-004, batch form)
// =============================================================================

func TestDeriveBatchBundleID_BindsEveryField(t *testing.T) {
	base := DeriveBatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight)

	if base == DeriveBatchBundleID(8453, vecRoot, 3, b32(7), vecHeight) {
		t.Fatal("bundleId must bind chainId")
	}
	if base == DeriveBatchBundleID(vecChainID, vecLeaf0, 3, b32(7), vecHeight) {
		t.Fatal("bundleId must bind the root")
	}
	if base == DeriveBatchBundleID(vecChainID, vecRoot, 4, b32(7), vecHeight) {
		t.Fatal("bundleId must bind leafCount — a restated batch must not reuse a signed id")
	}
	if base == DeriveBatchBundleID(vecChainID, vecRoot, 3, b32(8), vecHeight) {
		t.Fatal("bundleId must bind the batch operationID")
	}
	if base == DeriveBatchBundleID(vecChainID, vecRoot, 3, b32(7), vecHeight+1) {
		t.Fatal("bundleId must bind the block height")
	}
}

func TestBatchTree_BranchForADI(t *testing.T) {
	tree, err := BuildBatchTree(vecChainID, vecInputs(), vecHeight)
	if err != nil {
		t.Fatal(err)
	}
	branch, idx, err := tree.BranchForADI("acc://bob.acme")
	if err != nil {
		t.Fatal(err)
	}
	if idx != 1 {
		t.Fatalf("expected index 1, got %d", idx)
	}
	if !VerifyBranch(branch, tree.Root, tree.Leaves[idx]) {
		t.Fatal("branch for bob must verify")
	}
	if _, _, err := tree.BranchForADI("acc://nobody.acme"); err == nil {
		t.Fatal("non-member lookup must error")
	}
}
