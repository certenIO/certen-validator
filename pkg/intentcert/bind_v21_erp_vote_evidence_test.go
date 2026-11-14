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

// DAX-1G-R2 (G-85): the same for the live intent the validators refused on 2026-11-13, acc://e965cf4c...@dax1-r6a.acme/data (DAX-1 round 6): the erp
// page acc://dax1-r6a-erp.acme/book/1 is on ANOTHER partition (bvn2) than the principal (bvn3), so the proof of it only exists since the key page is
// judged in its own partition's block numbers (accumulate-lite-client-2 g1_frame.go).
const erpR6aVoteEvidence = "../../accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/testdata/g1_erp_initiator/erp_initiator_r6a.vote_evidence.json"

func TestGoverningFactsOfTheLiveErpInitiatedIntentNameTheInitiatingPage(t *testing.T) {
	for _, c := range []struct{ name, file, erp, authority, principal string }{
		{"g7 (the erp page and the principal share a partition)", erpG7VoteEvidence, "acc://dax1-probe-g7-erp.acme/book/1", "acc://dax1-probe-g7.acme/book/1", "acc://dax1-probe-g7.acme/data"},
		{"r6a (the erp page is on another partition than the principal)", erpR6aVoteEvidence, "acc://dax1-r6a-erp.acme/book/1", "acc://dax1-r6a.acme/book/1", "acc://dax1-r6a.acme/data"},
	} {
		t.Run(c.name, func(t *testing.T) { governingFactsOfAnErpEvidence(t, c.file, c.erp, c.authority, c.principal) })
	}
}

func governingFactsOfAnErpEvidence(t *testing.T, file, erp, authority, principal string) {
	raw, err := os.ReadFile(file)
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
	for _, want := range []string{erp, authority} {
		if !signers[govvote.CanonicalAccSpelling(want)] {
			t.Fatalf("the facts hold no signature of %s: %v", want, signers)
		}
	}
	if !strings.EqualFold(facts.Principal, govvote.CanonicalAccSpelling(principal)) {
		t.Fatalf("principal %s", facts.Principal)
	}
}
