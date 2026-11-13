package intentcert

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/govvote"
)

// DAX-1G, DAX-G3: the facts half of the binding for the erp-initiator pattern, over REAL bytes. The vote evidence is what the production
// G1 evidence builder (accumulate-lite-client-2 consolidated_governance-proof, ProveG1 -> buildVoteEvidence) emits for the live Kermit
// transaction acc://488396f1...@dax1-probe-g7.acme/data (DAX-1 probe g7, 2026-11-11): a single-leg intent whose blob 0 declares the erp
// page acc://dax1-probe-g7-erp.acme/book/1 as its signer, so G1 is asked about the erp page. The golden is written from the replay of the
// exchanges recorded off Kermit (testdata/g1_erp_initiator/erp_initiator_g7.json.gz, TestG1ErpInitiator_VoteEvidenceHoldsTheInitiatingSignature
// pins the builder's output to it). The binding's own reader must find the initiating signature in it, or a second defect sits behind
// G-83 (the verifier half): GoverningFactsFromVoteEvidence refuses evidence that holds none with g1_initiator_page_unproven.
const erpG7VoteEvidence = "../../accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/testdata/g1_erp_initiator/erp_initiator_g7.vote_evidence.json"

func TestGoverningFactsOfTheLiveErpInitiatedIntentNameTheInitiatingPage(t *testing.T) {
	raw, err := os.ReadFile(erpG7VoteEvidence)
	if err != nil {
		t.Fatal(err)
	}
	var ev govvote.Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	facts, err := GoverningFactsFromVoteEvidence(&ev)
	if err != nil {
		t.Fatalf("the vote evidence of a live erp-initiated intent does not name its initiator: %v", err)
	}
	const erp = "acc://dax1-probe-g7-erp.acme/book/1"
	if len(facts.Initiators) != 1 || facts.Initiators[0] != govvote.CanonicalAccSpelling(erp) {
		t.Fatalf("the binding reads the initiating pages %v, want [%s]", facts.Initiators, erp)
	}
	if len(facts.InitiatorPath) != 0 {
		t.Fatalf("a non-delegated initiator has no delegator path: %v", facts.InitiatorPath)
	}
	signers := map[string]bool{}
	for _, s := range facts.Signatures {
		signers[s.Signer] = true
	}
	for _, want := range []string{erp, "acc://dax1-probe-g7.acme/book/1"} {
		if !signers[govvote.CanonicalAccSpelling(want)] {
			t.Fatalf("the facts hold no signature of %s: %v", want, signers)
		}
	}
	if !strings.EqualFold(facts.Principal, govvote.CanonicalAccSpelling("acc://dax1-probe-g7.acme/data")) {
		t.Fatalf("principal %s", facts.Principal)
	}
}
