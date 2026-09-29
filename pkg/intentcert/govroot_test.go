package intentcert

import (
	"encoding/json"
	"os"
	"testing"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/proof"
)

func fixtureInputs(t *testing.T, validator string) GovRootV2Inputs {
	t.Helper()
	b, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/testdata/proof_bvn1.json")
	if err != nil {
		t.Fatal(err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(b, cp); err != nil {
		t.Fatal(err)
	}
	in := GovRootV2Inputs{Lite: proof.ChainedProofToCompleteProof(cp), KeyPageURL: "acc://harbor-mfg-tcl1.acme/book/1",
		KeyBookURL: "acc://harbor-mfg-tcl1.acme/book", OperationID: [32]byte{7}}
	read := func(level string, v interface{}) {
		b, err := os.ReadFile("../proof/testdata/govroot_v2/0x34b9c023_" + validator + "_" + level + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	in.G0, in.G1, in.G2 = new(proof.G0Result), new(proof.G1Result), new(proof.G2Result)
	read("g0", in.G0)
	read("g1", in.G1)
	read("g2", in.G2)
	return in
}

// Validators 1 and 3 committed different v1 G1 hashes for this operation (totalEntries 6 vs 5); under v2 their
// govRoots are identical.
func TestGovRootV2_TwoValidatorsThatDisagreedUnderV1Agree(t *testing.T) {
	a, _, err := GovRootV2(fixtureInputs(t, "validator-1_2152"))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := GovRootV2(fixtureInputs(t, "validator-3_2150"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("v2 govRoots differ: %x vs %x", a, b)
	}
}

func TestGovRootV2_RefusesIncompleteEvidence(t *testing.T) {
	for name, mut := range map[string]func(in *GovRootV2Inputs){
		"no lite proof":   func(in *GovRootV2Inputs) { in.Lite = nil },
		"no L4":           func(in *GovRootV2Inputs) { c := *in.Lite; c.ConsensusProof = nil; in.Lite = &c },
		"short L1":        func(in *GovRootV2Inputs) { c := *in.Lite; c.AccountHash = c.AccountHash[:16]; in.Lite = &c },
		"no G0":           func(in *GovRootV2Inputs) { in.G0 = nil },
		"no G1":           func(in *GovRootV2Inputs) { in.G1 = nil },
		"no G2":           func(in *GovRootV2Inputs) { in.G2 = nil },
		"no key page":     func(in *GovRootV2Inputs) { in.KeyPageURL = "" },
		"no operation id": func(in *GovRootV2Inputs) { in.OperationID = [32]byte{} },
	} {
		in := fixtureInputs(t, "validator-1_2152")
		mut(&in)
		if _, _, err := GovRootV2(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The same two validators' results through the v1 entry point production runs today (the builder's SetG*FromJSON):
// their v1 govRoots differ - the defect v2 removes (RB5-F19 fail-before at the old code's own entry point).
func TestGovRootV1_TheSamePairDisagrees(t *testing.T) {
	v1 := func(in GovRootV2Inputs) [32]byte {
		b := contracts.NewAccumulateGovRootInputsBuilder().SetOperationIDBytes32(in.OperationID).
			SetL1AccountHash(in.Lite.AccountHash).SetL2BPTRoot(in.Lite.BPTRoot).SetL3BlockHash(in.Lite.BlockHash).
			SetL4ConsensusProofFromJSON(in.Lite.ConsensusProof).
			SetG0FromJSON(in.G0).SetG1FromJSON(in.G1).SetG2FromJSON(in.G2).
			SetKeypageURL(in.KeyPageURL).SetKeybookURL(in.KeyBookURL)
		return contracts.ComputeAccumulateGovRoot(b.Build())
	}
	if v1(fixtureInputs(t, "validator-1_2152")) == v1(fixtureInputs(t, "validator-3_2150")) {
		t.Fatal("the recorded v1 divergence did not reproduce")
	}
}
