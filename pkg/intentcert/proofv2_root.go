package intentcert

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
	"github.com/certen/independant-validator/pkg/proof"
	proofv2 "github.com/certen/independant-validator/pkg/proof/v2"
)

// ErrBind marks an error of ProofV2Root that is the binding of the report to the intent (BindProofV2, BindProofV21), as
// opposed to the govRoot computation, so a caller can name the two refusals apart.
var ErrBind = errors.New("proof v2 binding")

// ProofV2Root binds a verified proof v2 report to the intent's governance levels and returns the govRoot the intent
// certificate commits: govRoot v3 over evidence 2.0 (BindProofV2, GovRootV3), govRoot v4 over evidence 2.1 (BindProofV21 with
// the facts of the intent's own vote evidence, GovRootV4). Consensus (consensus.VerifyIntentCertificate) and the offline check
// of a stored certificate (execution.CheckIntentCertificate) both call it, so the two cannot bind differently: the version is
// the evidence's, never a caller's choice.
//
// voteEvidence is the intent's govvote.Evidence (IntentCertificateEvidence.VoteEvidence, the G1 level's vote_evidence flag);
// a 2.0 document does not read it, a 2.1 document cannot be bound without it.
func ProofV2Root(rep *proofv2.Report, ev *proofv2.Evidence, g0 *proof.G0Result, g1 *proof.G1Result, g2 *proof.G2Result,
	keyPageURL, keyBookURL string, voteEvidence json.RawMessage, operationID [32]byte) (root [32]byte, v4 bool, err error) {
	if rep == nil || ev == nil {
		return root, false, fmt.Errorf("proof v2 root: the verified report and its evidence are both required")
	}
	switch ev.Version {
	case proofv2.Version:
		if err = BindProofV2(rep, g0, g1, keyPageURL); err != nil {
			return root, false, fmt.Errorf("%w: %w", ErrBind, err)
		}
		root, _, err = GovRootV3(GovRootV3Inputs{Report: rep, Evidence: ev, G0: g0, G1: g1, G2: g2, KeyPageURL: keyPageURL,
			KeyBookURL: keyBookURL, OperationID: operationID})
		return root, false, err
	case proofv2.Version21:
		var gev govvote.Evidence
		if len(voteEvidence) == 0 || json.Unmarshal(voteEvidence, &gev) != nil {
			return root, true, fmt.Errorf("proof v2 root: evidence 2.1 is bound to the intent's vote evidence, which is missing or malformed")
		}
		facts, err := GoverningFactsFromVoteEvidence(&gev)
		if err != nil {
			return root, true, fmt.Errorf("%w: %w", ErrBind, err)
		}
		if err = BindProofV21(rep, g0, g1, keyPageURL, keyBookURL, facts); err != nil {
			return root, true, fmt.Errorf("%w: %w", ErrBind, err)
		}
		root, _, err = GovRootV4(GovRootV4Inputs{Report: rep, Evidence: ev, G0: g0, G1: g1, G2: g2, KeyPageURL: keyPageURL,
			KeyBookURL: keyBookURL, OperationID: operationID})
		return root, true, err
	}
	return root, false, fmt.Errorf("proof v2 root: evidence version %q is neither %s nor %s", ev.Version, proofv2.Version, proofv2.Version21)
}
