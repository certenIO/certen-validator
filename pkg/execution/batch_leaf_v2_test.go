package execution

import (
	"encoding/hex"
	"testing"

	"github.com/certen/independant-validator/pkg/execution/contracts"
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

// The v3 leaf (RB5-F30) CertenAccountV7_2 consumes, pinned against an independent computation (Python, pycryptodome
// keccak over the exact encodePacked bytes) and held identically by CertenAccountV7_2Authority.t.sol. Never update it on
// one side only. Inputs: the v2 vector's, plus the book keccak256("acc://vector.acme/book").
func TestBatchLeafV3Vector(t *testing.T) {
	var ec, op [32]byte
	for i := range ec {
		ec[i], op[i] = 0x11, 0x22
	}
	book := contracts.HashURLString("acc://vector.acme/book")
	if hex.EncodeToString(book[:]) != "54aa9426ed213c7a8e7273387b5839f62fc5c61c9c92f9d6636c2d5a5184bfb6" {
		t.Fatalf("book hash 0x%x", book)
	}
	in := BatchLeafInput{GovernanceCommitment: testGov, ADIURL: "acc://vector.acme", ExecutionCommitment: ec, OperationID: op,
		AuthorityBook: book, AuthorityPage: 3}
	leaf := ComputeBatchLeafV3(84532, in)
	if got := hex.EncodeToString(leaf[:]); got != v3LeafVector {
		t.Fatalf("v3 leaf 0x%s, want 0x%s", got, v3LeafVector)
	}
	// The book is bound: the same page of another book is another leaf; and the page is bound.
	other := in
	other.AuthorityBook = contracts.HashURLString("acc://vector.acme/ops")
	if ComputeBatchLeafV3(84532, other) == leaf {
		t.Fatal("page 3 of two books gives one leaf")
	}
	other = in
	other.AuthorityPage = 1
	if ComputeBatchLeafV3(84532, other) == leaf {
		t.Fatal("pages 1 and 3 of one book give one leaf")
	}
	if ComputeBatchLeafV2(84532, in, 3) == leaf {
		t.Fatal("v2 and v3 leaves coincide")
	}
}

const v3LeafVector = "c18fc21bd9f62936d5896992ca97683afffb298c1854f689089f9b3aac45e317"

// A certified key page names its book's hash and its index only when it is a page OF the certified book; whose book it
// is, the account decides (RB5-F30).
func TestAuthorityOf(t *testing.T) {
	book, page, err := AuthorityOf("acc://Harbor.acme/book/3", "acc://harbor.acme/BOOK/")
	if err != nil || page != 3 || book != contracts.HashURLString("acc://harbor.acme/book") {
		t.Fatalf("(%x, %d, %v)", book, page, err)
	}
	// Another identity's book is a book like any other: the account gives it no authority unless granted.
	if _, _, err := AuthorityOf("acc://other.acme/book/1", "acc://other.acme/book"); err != nil {
		t.Fatalf("a page of another identity's book: %v", err)
	}
	for _, c := range [][2]string{
		{"acc://harbor.acme/book/1", "acc://harbor.acme/ops"}, // not a page of that book
		{"acc://harbor.acme/book/2/x", "acc://harbor.acme/book"},
		{"acc://harbor.acme/bookx/1", "acc://harbor.acme/book"},
		{"acc://harbor.acme/book/1", ""},
		{"acc://harbor.acme/book/0", "acc://harbor.acme/book"},
	} {
		page, book := c[0], c[1]
		if _, _, err := AuthorityOf(page, book); err == nil {
			t.Fatalf("%s accepted as a page of %q", page, book)
		}
	}
}

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
