package execution

import (
	"encoding/hex"
	"encoding/json"
	"os"

	chained_proof "github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit"
	"github.com/certen/independant-validator/pkg/accumulateset"
	"github.com/certen/independant-validator/pkg/consensus"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/ethereum/go-ethereum/common"
)

// testAtt is a round's snapshot as the batch path receives it: carrying the governance decision its member commits
// to, testGov (RB4-F66), and a real Kermit L1-L4 proof whose Directory leg reduces - under testIncarnation, Kermit's
// v1 incarnation - to testAccSet, the Accumulate set root its V8.2 anchor commits (RB5 design D2).
var (
	testGovDecision = []byte("certen:gdr:v1 test decision")
	testGov         = certenproof.GovernanceCommitment(testGovDecision)
	testIncarnation = mustHex32("cac6698ed49a286ad8a3de94540a3354dfe964f366a439f4fdfb34533059fda0")
	testAtt         = &consensus.PendingAttestation{GovDecision: testGovDecision, CertenProof: kermitCertenProof()}
	testAccSet      = mustAccSet()
)

func mustHex32(s string) [32]byte {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("bad hex32 " + s)
	}
	copy(out[:], b)
	return out
}

// kermitCertenProof is a CertenProof carrying the real Kermit fixture proof (proof_bvn1.json) the way the proof cycle
// carries it: a CompleteProof converted by the production path.
func kermitCertenProof() *certenproof.CertenProof {
	b, err := os.ReadFile("../../accumulate-lite-client-2/liteclient/proof/working-proof_do_not_edit/testdata/proof_bvn1.json")
	if err != nil {
		panic(err)
	}
	cp := new(chained_proof.ChainedProof)
	if err := json.Unmarshal(b, cp); err != nil {
		panic(err)
	}
	return &certenproof.CertenProof{LiteClientProof: &certenproof.LiteClientProofData{CompleteProof: certenproof.ChainedProofToCompleteProof(cp)}}
}

func mustAccSet() [32]byte {
	root, err := accumulateset.CommittedAccumulateSetRoot(kermitCertenProof().LiteClientProof.CompleteProof.Layer4DN, testIncarnation)
	if err != nil {
		panic(err)
	}
	return root
}

// withAccSet gives every input without one the fixture's Accumulate set root: what admission derives for a member
// whose round carried testAtt's proof.
func withAccSet(inputs []BatchLeafInput) []BatchLeafInput {
	out := append([]BatchLeafInput(nil), inputs...)
	for i := range out {
		if out[i].AccumulateSetRoot == ([32]byte{}) {
			out[i].AccumulateSetRoot = testAccSet
		}
	}
	return out
}

// testBatchOperationID is the v2 batch operation id of a batch whose members are ops, each committing to testGov:
// what a canonical row's batch_operation_id is for those members (RB4-F66).
func testBatchOperationID(ops ...string) string {
	inputs := make([]BatchLeafInput, 0, len(ops))
	for _, op := range ops {
		in := BatchLeafInput{GovernanceCommitment: testGov}
		copy(in.OperationID[:], common.FromHex(op))
		inputs = append(inputs, in)
	}
	id, err := DeriveBatchOperationIDV2(inputs)
	if err != nil {
		panic(err)
	}
	return "0x" + hex.EncodeToString(id[:])
}
