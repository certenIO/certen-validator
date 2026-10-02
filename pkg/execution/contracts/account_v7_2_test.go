package contracts

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// The settlement path's calls exist in the embedded V7_2 ABI with exactly the shapes it packs and reads: the leaf and
// the proof carry the authority book and page (RB5-F30), and nothing carries a declared level.
func TestCertenAccountV7_2ABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV7_2ABI))
	if err != nil {
		t.Fatal(err)
	}
	proof := "(string,bytes32,bytes32[],bytes32,bytes,bytes,bytes,uint256,uint256,bytes,uint256,bytes32,uint64)"
	want := map[string]string{
		"executeGovernanceProofDirect":      "executeGovernanceProofDirect(address,uint256,bytes," + proof + ")",
		"batchExecuteGovernanceProofDirect": "batchExecuteGovernanceProofDirect(address[],uint256[],bytes[]," + proof + ")",
		"computeLeaf":                       "computeLeaf(bytes32,bytes32,bytes32,uint64)",
		"isLeafConsumed":                    "isLeafConsumed(bytes32)",
		"isKeylessOwner":                    "isKeylessOwner()",
		"adiURLHash":                        "adiURLHash()",
		"LEAF_DOMAIN":                       "LEAF_DOMAIN()",
		"authorityLevelOfPage":              "authorityLevelOfPage(bytes32,uint64)",
		"governingBookHash":                 "governingBookHash()",
		"anchorContract":                    "anchorContract()",
	}
	for name, sig := range want {
		if m, ok := parsed.Methods[name]; !ok || m.Sig != sig {
			t.Errorf("%s is %q, want %q", name, m.Sig, sig)
		}
	}
	// The proof struct the Go side packs has the contract's twelve fields in order.
	comps := parsed.Methods["executeGovernanceProofDirect"].Inputs[3].Type.TupleRawNames
	names := []string{"adiURL", "anchorId", "merkleProof", "operationID", "keyBookProof", "roleProof", "thresholdProof",
		"timestamp", "expiresAt", "validatorSignatures", "nonce", "authorityBook", "authorityPage"}
	if len(comps) != len(names) {
		t.Fatalf("proof has %d fields", len(comps))
	}
	for i, n := range names {
		if comps[i] != n {
			t.Fatalf("proof field %d is %s, want %s", i, comps[i], n)
		}
	}
}
