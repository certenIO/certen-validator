package execution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"

	"github.com/certen/independant-validator/pkg/execution/contracts"
)

// RB5-F57: the v4 account leaf, pinned to vectors computed independently with Foundry's own encoder (`cast abi-encode
// --packed` + `cast keccak`, cast 1.5.1). testdata/account_leaf_v4_test_vectors.json is a byte-identical copy of
// certen-contracts test/vectors/account_leaf_v4_test_vectors.json, which evm/test/CertenAccountV7_3Window.t.sol asserts
// against CertenAccountV7_3.computeLeaf. Never update one side only.

type leafV4Vector struct {
	Name                string `json:"name"`
	ChainID             int64  `json:"chainId"`
	ADIURL              string `json:"adiURL"`
	ADIURLHash          string `json:"adiURLHash"`
	AuthorityBookURL    string `json:"authorityBookURL"`
	AuthorityBook       string `json:"authorityBook"`
	ExecutionCommitment string `json:"executionCommitment"`
	OperationID         string `json:"operationID"`
	AuthorityPage       uint64 `json:"authorityPage"`
	NotBefore           uint64 `json:"notBefore"`
	NotAfter            uint64 `json:"notAfter"`
	Packed              string `json:"packed"`
	ExpectedV4          string `json:"expectedV4"`
	ExpectedV3          string `json:"expectedV3"`
}

func loadLeafV4Vectors(t *testing.T) []leafV4Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "account_leaf_v4_test_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		DomainV3 string         `json:"domainV3"`
		DomainV4 string         `json:"domainV4"`
		Vectors  []leafV4Vector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.DomainV4 != BatchLeafDomainV4 || f.DomainV3 != BatchLeafDomainV3 {
		t.Fatalf("domains %q/%q", f.DomainV3, f.DomainV4)
	}
	if got := contracts.LeafDomainV7_3; got != f.DomainV4 {
		t.Fatalf("CertenAccountV7_3's domain is pinned as %q", got)
	}
	if len(f.Vectors) != 4 {
		t.Fatalf("%d vectors", len(f.Vectors))
	}
	return f.Vectors
}

func TestBatchLeafV4Vectors(t *testing.T) {
	for _, v := range loadLeafV4Vectors(t) {
		in := BatchLeafInput{ADIURL: v.ADIURL, ExecutionCommitment: common.HexToHash(v.ExecutionCommitment),
			OperationID: common.HexToHash(v.OperationID), AuthorityBook: common.HexToHash(v.AuthorityBook),
			AuthorityPage: v.AuthorityPage, NotBefore: v.NotBefore, NotAfter: v.NotAfter}
		if got := in.ADIURLHash(); got != common.HexToHash(v.ADIURLHash) {
			t.Fatalf("%s: adiURLHash %x", v.Name, got)
		}
		if got := contracts.HashURLString(v.AuthorityBookURL); got != common.HexToHash(v.AuthorityBook) {
			t.Fatalf("%s: book hash %x", v.Name, got)
		}
		if got := hexutil.Encode(batchLeafV4Preimage(v.ChainID, in)); got != v.Packed {
			t.Fatalf("%s: preimage\n got %s\nwant %s", v.Name, got, v.Packed)
		}
		if got := ComputeBatchLeafV4(v.ChainID, in); got != common.HexToHash(v.ExpectedV4) {
			t.Fatalf("%s: v4 leaf %x, cast says %s", v.Name, got, v.ExpectedV4)
		}
		if got := ComputeBatchLeafV3(v.ChainID, in); got != common.HexToHash(v.ExpectedV3) {
			t.Fatalf("%s: v3 leaf %x, cast says %s", v.Name, got, v.ExpectedV3)
		}
		if v.ExpectedV4 == v.ExpectedV3 {
			t.Fatalf("%s: a v4 leaf equals the v3 leaf", v.Name)
		}
	}
}

// The first vector, pinned here too, so an edit of the testdata copy alone cannot move it. Its v3 leaf is the one
// TestBatchLeafV3Vector has pinned since RB5-F30.
func TestBatchLeafV4PinnedVector(t *testing.T) {
	in := BatchLeafInput{ADIURL: "acc://vector.acme", ExecutionCommitment: fill32(0x11), OperationID: fill32(0x22),
		AuthorityBook: contracts.HashURLString("acc://vector.acme/book"), AuthorityPage: 3, NotBefore: 1759400000,
		NotAfter: 1759403600}
	if got := ComputeBatchLeafV4(84532, in); got != common.HexToHash("0x6f545f548450a01841e2ae1d9c93c3fb419b74e48ee98bec4568a1f0e3bb6e04") {
		t.Fatalf("v4 leaf %x", got)
	}
	if got := ComputeBatchLeafV3(84532, in); got != common.HexToHash("0xc18fc21bd9f62936d5896992ca97683afffb298c1854f689089f9b3aac45e317") {
		t.Fatalf("v3 leaf %x", got)
	}
	// One second more of window is another leaf: the window is bound.
	in.NotAfter++
	if got := ComputeBatchLeafV4(84532, in); got != common.HexToHash("0x8abc7b1e9924b5a0a0e36a3563cbbabc76035e5e76d615352a0aed3b34f0930b") {
		t.Fatalf("v4 leaf one second later %x", got)
	}
}
