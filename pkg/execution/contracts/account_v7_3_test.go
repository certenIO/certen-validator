package contracts

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// RB5-F57: the settlement path's calls exist in the embedded V7_3 ABI with exactly the shapes it packs and reads - the
// leaf and the proof carry the member's window after the authority book and page - and its selectors are the ones forge
// reports for CertenAccountV7_3 (`forge inspect CertenAccountV7_3 methodIdentifiers`).
func TestCertenAccountV7_3ABI(t *testing.T) {
	parsed, err := abi.JSON(strings.NewReader(CertenAccountV7_3ABI))
	if err != nil {
		t.Fatal(err)
	}
	proof := "(string,bytes32,bytes32[],bytes32,bytes,bytes,bytes,uint256,uint256,bytes,uint256,bytes32,uint64,uint64,uint64)"
	want := map[string]string{
		"executeGovernanceProofDirect":      "executeGovernanceProofDirect(address,uint256,bytes," + proof + ")",
		"batchExecuteGovernanceProofDirect": "batchExecuteGovernanceProofDirect(address[],uint256[],bytes[]," + proof + ")",
		"computeLeaf":                       "computeLeaf(bytes32,bytes32,bytes32,uint64,uint64,uint64)",
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
	for name, id := range map[string]string{
		"executeGovernanceProofDirect": "606f2c8d",
		"computeLeaf":                  "c4c178a6",
		"isLeafConsumed":               "173102d0",
		"LEAF_DOMAIN":                  "d0f9ff9a",
	} {
		if got := hex.EncodeToString(parsed.Methods[name].ID); got != id {
			t.Errorf("%s selector %s, forge says %s", name, got, id)
		}
	}
	// The proof is CertenAccountV7_2's thirteen fields, in order, then the window.
	comps := parsed.Methods["executeGovernanceProofDirect"].Inputs[3].Type.TupleRawNames
	names := []string{"adiURL", "anchorId", "merkleProof", "operationID", "keyBookProof", "roleProof", "thresholdProof",
		"timestamp", "expiresAt", "validatorSignatures", "nonce", "authorityBook", "authorityPage", "notBefore", "notAfter"}
	if len(comps) != len(names) {
		t.Fatalf("proof has %d fields", len(comps))
	}
	for i, n := range names {
		if comps[i] != n {
			t.Fatalf("proof field %d is %s, want %s", i, comps[i], n)
		}
	}
	// The named refusals of a window the leaf does not open.
	for _, e := range []string{"LeafExpired", "LeafNotYetValid"} {
		if _, ok := parsed.Errors[e]; !ok {
			t.Errorf("no %s error", e)
		}
	}
	// Its selectors are not CertenAccountV7_2's: calldata names exactly one generation.
	v72, err := abi.JSON(strings.NewReader(CertenAccountV7_2ABI))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"executeGovernanceProofDirect", "batchExecuteGovernanceProofDirect", "computeLeaf"} {
		if string(v72.Methods[name].ID) == string(parsed.Methods[name].ID) {
			t.Errorf("%s has one selector in both generations", name)
		}
	}
	if LeafDomainV7_3 == LeafDomainV7_2 {
		t.Fatal("one leaf domain for two generations")
	}
}

// A V7_2 proof and its window convert to the V7_3 proof and back without loss.
func TestAccountProofV7_3Conversion(t *testing.T) {
	p := AccountProofV7_2{AdiURL: "acc://a.acme", AnchorId: [32]byte{1}, OperationID: [32]byte{2}, AuthorityBook: [32]byte{3},
		AuthorityPage: 4}
	q := AccountProofV7_3Of(p, 10, 20)
	if q.NotBefore != 10 || q.NotAfter != 20 || q.AnchorId != p.AnchorId || q.AuthorityPage != 4 || q.AdiURL != p.AdiURL {
		t.Fatalf("%+v", q)
	}
	if back := q.V7_2Fields(); back.AnchorId != p.AnchorId || back.AuthorityBook != p.AuthorityBook || back.OperationID != p.OperationID {
		t.Fatalf("%+v", back)
	}
}
