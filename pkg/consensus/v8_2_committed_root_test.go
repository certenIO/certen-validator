package consensus

import (
	"encoding/json"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

const kermitIncarnationHex = "cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0"

func loadLiteFixture(t *testing.T, name string) *chained_proof.ChainedProof {
	t.Helper()
	b, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/testdata/" + name)
	if err != nil {
		t.Fatalf("fixture %s is required: %v", name, err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(b, cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// The root a validator signs is the committed root the offline verifier expands, on every fixture proof (RB5 D2).
func TestV8_2Signing_SignsTheCommittedAccumulateSetRoot(t *testing.T) {
	t.Setenv(accumulateIncarnationEnv, "0x"+kermitIncarnationHex)
	inc, err := resolveAccumulateIncarnation()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proof_bvn1.json", "proof_bvn3.json", "proof_multileg_bvn1_bvn2.json"} {
		cp := loadLiteFixture(t, name)
		cert := &proof.CertenProof{LiteClientProof: &proof.LiteClientProofData{CompleteProof: proof.ChainedProofToCompleteProof(cp)}}
		in, err := BuildV8_2AccumulateSetInputs(cert)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		signed, err := contracts.ComputeAccumulateValidatorSetRoot(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		committed, err := accumulateset.CommittedAccumulateSetRoot(cp.Layer4DN, inc)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if signed != committed {
			t.Fatalf("%s: the signing path reduces to %x, the committed root is %x", name, signed, committed)
		}
	}
}

// The committed set is the Directory leg's. A BVN leg handed to the signing reduction is refused, never signed as if
// it were the Directory's.
func TestV8_2Signing_RefusesABVNLegAsTheCommittedSet(t *testing.T) {
	cp := loadLiteFixture(t, "proof_bvn1.json")
	var inc [32]byte
	inc[0] = 1
	if _, err := accumulateSetFromL4(cp.Layer4BVN, inc); err == nil {
		t.Fatal("a BVN leg was reduced as the committed (Directory) set")
	}
}
