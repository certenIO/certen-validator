package execution

import (
	"encoding/json"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB5-F4: the validator-set evidence a V8.2 proof carries verifies against a REAL stored proof's Directory leg (proof
// e1e34338, Kermit). The set and threshold it derives from account bytes are exactly the set and threshold that leg
// asserts - the two sources RB5-F4 named agree - and the verdict is validator_set_unbound: derived, but proven into the
// serving node's current root rather than the root the leg signed (binding needs historical state, AIP-058).
func TestTheEvidenceVerifiesAgainstAStoredKermitDirectoryLeg(t *testing.T) {
	raw, err := os.ReadFile("../consensus/testdata/intent_cert/proof_e1e34338.json")
	if err != nil {
		t.Fatal(err)
	}
	var stored struct {
		ChainedProof struct {
			Layer4DN chained_proof.Layer4 `json:"layer4Dn"`
		} `json:"chained_proof"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	dn := stored.ChainedProof.Layer4DN
	if len(dn.ValidatorSet) == 0 || dn.StateTreeAnchor == "" {
		t.Fatalf("the stored proof has no Directory leg to check against: %+v", dn)
	}
	binding := &AccumulateBinding{Incarnation: kermitIncarnationF4, ValidatorSetProof: kermitValidatorSetProof(t)}
	pin := kermitIncarnationF4
	res := binding.VerifyAgainstDirectoryLeg(&dn, &pin)
	if res.Err != nil {
		t.Fatalf("the evidence does not check out against the stored Directory leg: %s", res.Claim())
	}
	if res.Verdict != certenproof.VerdictValidatorSetUnbound {
		t.Fatalf("verdict %q; the evidence is proven into the current root, so it can only be %q today",
			res.Verdict, certenproof.VerdictValidatorSetUnbound)
	}

	// The same evidence against a Directory leg that asserted another set is proven wrong, not weaker.
	other := append([]chained_proof.ValidatorKey(nil), dn.ValidatorSet...)
	other = other[:len(other)-1]
	leg := dn
	leg.ValidatorSet = other
	if bad := binding.VerifyAgainstDirectoryLeg(&leg, &pin); bad.Err == nil {
		t.Fatalf("evidence of one set verified a leg that asserted another: %s", bad.Claim())
	}
}
