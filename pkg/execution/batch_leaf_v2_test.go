package execution

import (
	"encoding/hex"
	"testing"
)

// The vector CertenAccountV7_2's test (CertenAccountV7_2Authority.t.sol) holds the contract to. Never
// update it on one side only.
func TestBatchLeafV2Vector(t *testing.T) {
	var ec, op [32]byte
	for i := range ec {
		ec[i], op[i] = 0x11, 0x22
	}
	leaf := ComputeBatchLeafV2(84532, BatchLeafInput{GovernanceCommitment: testGov, ADIURL: "acc://vector.acme", ExecutionCommitment: ec, OperationID: op}, 3)
	t.Logf("v2 leaf vector: 0x%s", hex.EncodeToString(leaf[:]))
	if got := hex.EncodeToString(leaf[:]); got != v2LeafVector {
		t.Fatalf("v2 leaf 0x%s, want 0x%s", got, v2LeafVector)
	}
	// The page is bound: another page, another leaf; and v1 is a different leaf altogether.
	if ComputeBatchLeafV2(84532, BatchLeafInput{GovernanceCommitment: testGov, ADIURL: "acc://vector.acme", ExecutionCommitment: ec, OperationID: op}, 1) == leaf {
		t.Fatal("page 1 and page 3 give the same leaf")
	}
	if ComputeBatchLeaf(84532, BatchLeafInput{GovernanceCommitment: testGov, ADIURL: "acc://vector.acme", ExecutionCommitment: ec, OperationID: op}) == leaf {
		t.Fatal("v1 and v2 leaves coincide")
	}
}

const v2LeafVector = "10ec677acf39e72f5cd5d63bd5697badff7e6b06af975166260312a8ee402fad"

func TestAuthorityPageIndex(t *testing.T) {
	for in, want := range map[string]uint64{"acc://harbor.acme/book/1": 1, "acc://harbor.acme/book/12/": 12, "ACC://h.acme/keys/3": 3} {
		if got, err := AuthorityPageIndex(in); err != nil || got != want {
			t.Fatalf("%s: %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "acc://harbor.acme/book", "acc://harbor.acme/book/0", "acc://harbor.acme/book/x", "https://h/book/1", "acc://harbor.acme"} {
		if n, err := AuthorityPageIndex(bad); err == nil {
			t.Fatalf("%q accepted as page %d", bad, n)
		}
	}
}
