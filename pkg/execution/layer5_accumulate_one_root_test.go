package execution

import (
	"encoding/hex"
	"encoding/json"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// The L5 artifact's root (from the set DERIVED from acc://dn.acme/network's chain bytes) and the root a V8.2 anchor
// commits (from the proofs' Directory L4 legs) come from different evidence but one reduction. Kermit's set never
// changed, so on every fixture proof they must agree exactly; a divergence would mean the two paths reduce differently.
func TestLayer5AccumulateSetRoot_EqualsTheCommittedRootOnEveryFixture(t *testing.T) {
	b, err := os.ReadFile(vspFixture)
	if err != nil {
		t.Fatal(err)
	}
	vsp := new(certenproof.ValidatorSetProof)
	if err := json.Unmarshal(b, vsp); err != nil {
		t.Fatal(err)
	}
	l5, err := AccumulateSetRoot(vsp)
	if err != nil {
		t.Fatal(err)
	}
	var inc [32]byte
	raw, _ := hex.DecodeString(vsp.Incarnation)
	copy(inc[:], raw)
	for _, name := range []string{"proof_bvn1.json", "proof_bvn3.json", "proof_multileg_bvn1_bvn2.json"} {
		pb, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		cp := new(chained_proof.ChainedProof)
		if err := json.Unmarshal(pb, cp); err != nil {
			t.Fatal(err)
		}
		committed, err := accumulateset.CommittedAccumulateSetRoot(cp.Layer4DN, inc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if hex.EncodeToString(committed[:]) != l5 {
			t.Fatalf("%s: committed %x, L5 %s", name, committed, l5)
		}
	}
}
