package execution

import (
	"encoding/hex"

	"github.com/certen/independant-validator/pkg/consensus"
	certenproof "github.com/certen/independant-validator/pkg/proof"
	"github.com/ethereum/go-ethereum/common"
)

// testAtt is a round's snapshot as the batch path receives it: carrying the governance decision its member commits
// to, testGov (RB4-F66).
var (
	testGovDecision = []byte("certen:gdr:v1 test decision")
	testAtt         = &consensus.PendingAttestation{GovDecision: testGovDecision}
	testGov         = certenproof.GovernanceCommitment(testGovDecision)
)

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
