package execution

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/execution/contracts"

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
		// A V8.2 leaf binds the certified authority page (RB5-F29): page 1 of the member's own book.
		if out[i].AuthorityPage == 0 {
			out[i].AuthorityPage = 1
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

// asV8_2Anchor makes rec a self-consistent V8.2 anchor record over its own root and batch operation id, at height, with
// leafCount leaves: the bundle id and the message are what createBatchAnchor and the quorum would derive (RB5), so a
// layer 5 built from the row re-derives both.
func asV8_2Anchor(t *testing.T, rec *database.AnchorQuorumRecord, leafCount int, height uint64) {
	t.Helper()
	var root, opID [32]byte
	copy(root[:], rec.Root)
	copy(opID[:], common.FromHex(rec.BatchOperationID))
	setRoot := [32]byte{0x5e}
	bundle := contracts.DeriveV8_2BatchBundleID(rec.ChainID, root, uint64(leafCount), opID, height, testAccSet, testIncarnation)
	msg := contracts.ComputeEvmMessageHashV8_2_Pre(rec.ChainID, bundle, root, opID, setRoot, testAccSet, testIncarnation)
	rec.AnchorVersion, rec.BundleID, rec.MessageHash = "v8_2", "0x"+hex.EncodeToString(bundle[:]), "0x"+hex.EncodeToString(msg[:])
	rec.BatchLeafCount, rec.AccumulateBlockHeight = int64(leafCount), int64(height)
	rec.CertenSetRoot = "0x" + hex.EncodeToString(setRoot[:])
	rec.AccumulateSetRoot, rec.AccumulateIncarnation = "0x"+hex.EncodeToString(testAccSet[:]), "0x"+hex.EncodeToString(testIncarnation[:])
}
