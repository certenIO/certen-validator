package execution

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// The anchor rejects a zero keyBookRoot when minimumGovernanceLevel >= 1, and rejects a
// non-zero root with an empty proof. Both shapes must therefore be impossible to produce.
func TestValidatorKeyPageProof_ReproducesRootForEverySigner(t *testing.T) {
	addrs := []string{
		"0xd4A3dBbAE0C04D4307c5E00A5E05b66AcC289f5D",
		"0x5555afA8Ff8048BddAAC1554AFd790c9bf7ec6E0",
		"0x6ACaa68417F5ad5d4a02D9d3d72E291efFcDf30A",
		"0x16aB06F3634218a8f1F3B01dCdd32DDFbdc8a69D",
		"0xf150Ff923E29F797b4598b89bD7D02002D00Db3a",
		"0x70A6A81bb5E3B63B1929301239DE1F5c63Ec4F3a",
		"0xee2EfA29989Fe6E53572087680c661EC29e045Fe",
	}
	var root0 [32]byte
	for i, a := range addrs {
		root, proof, err := buildValidatorKeyPageProof(common.HexToAddress(a))
		if err != nil {
			t.Fatalf("%s: %v", a, err)
		}
		if len(proof) == 0 {
			t.Fatalf("%s: empty proof — the anchor rejects a non-zero root with no proof", a)
		}
		if root == ([32]byte{}) {
			t.Fatalf("%s: zero root — the anchor rejects that outright", a)
		}
		if i == 0 {
			root0 = root
			continue
		}
		if root != root0 {
			t.Fatalf("%s produced a different root; every validator must prove against the same tree", a)
		}
	}
}

// A submitter outside the registered set must not be able to manufacture authority.
func TestValidatorKeyPageProof_RefusesUnregisteredSubmitter(t *testing.T) {
	if _, _, err := buildValidatorKeyPageProof(common.HexToAddress("0x00000000000000000000000000000000deadbeef")); err == nil {
		t.Fatal("an unregistered submitter must not be able to build key page authority")
	}
}
