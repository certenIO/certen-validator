package execution

import (
	"strings"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
)

// RB4-F72: the canonical writer stores a member's merkle path 0x-prefixed (anchor_quorum_writer.go), the layer-5
// reader decodes bare hex, and the path was passed through as stored - so every multi-member canonical batch's
// layer 5 was refused as unverifiable and its members had none. Each node is now stated in one form.
func TestF72_APathStoredEitherWayIsOnePath(t *testing.T) {
	h := strings.Repeat("ab", 32)
	prefixed, err := merkleStepsFromNodes([]database.MerklePathNode{{Hash: "0x" + strings.ToUpper(h)}})
	if err != nil {
		t.Fatal(err)
	}
	bare, err := merkleStepsFromNodes([]database.MerklePathNode{{Hash: h}})
	if err != nil {
		t.Fatal(err)
	}
	if prefixed[0].Hash != h || bare[0].Hash != h {
		t.Fatalf("stated as %q and %q", prefixed[0].Hash, bare[0].Hash)
	}
	for _, bad := range []string{"0xabcd", "not hex", ""} {
		if _, err := merkleStepsFromNodes([]database.MerklePathNode{{Hash: bad}}); err == nil {
			t.Errorf("%q was taken as a node", bad)
		}
	}
}

// The layer built from a canonical row the live writer wrote verifies.
func TestF72_ALayerFromTheCanonicalWriterVerifies(t *testing.T) {
	inputs := []BatchLeafInput{
		{ADIURL: "acc://f72-a.acme", ExecutionCommitment: [32]byte{1}, OperationID: [32]byte{2}},
		{ADIURL: "acc://f72-b.acme", ExecutionCommitment: [32]byte{3}, OperationID: [32]byte{4}},
	}
	var leaves [][32]byte
	for _, in := range inputs {
		leaves = append(leaves, ComputeBatchLeaf(84532, in))
	}
	root, err := MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	branch, err := MerkleBranch(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []database.MerklePathNode
	for _, n := range branch {
		nodes = append(nodes, database.MerklePathNode{Hash: hexPrefixed(n[:])}) // as the canonical writer stores it
	}
	steps, err := merkleStepsFromNodes(nodes)
	if err != nil {
		t.Fatal(err)
	}
	l5 := &Layer5{ChainID: 84532, AnchorTx: "0x" + strings.Repeat("6a", 32), BlockNumber: 9,
		BatchRoot: hexPrefixless(root[:]), LeafHash: hexPrefixless(leaves[1][:]), LeafIndex: 1, Path: steps}
	if err := l5.VerifyOffline(); err != nil {
		t.Fatal(err)
	}
}

func hexPrefixless(b []byte) string { return strings.TrimPrefix(hexPrefixed(b), "0x") }
