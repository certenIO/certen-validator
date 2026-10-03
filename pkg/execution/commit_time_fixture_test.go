package execution

import (
	"github.com/certen/independant-validator/pkg/consensus"
)

// f57AttWithCommitBlock is the round's snapshot of an intent discovery read from BVN `bvn`'s block `index`.
func f57AttWithCommitBlock(bvn string, index int64) *consensus.PendingAttestation {
	att := &consensus.PendingAttestation{GovDecision: testAtt.GovDecision, CertenProof: testAtt.CertenProof}
	att.CertenIntent = &consensus.CertenIntent{ProofPartition: bvn, ProofBlockIndex: index}
	return att
}
