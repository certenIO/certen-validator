package execution

import (
	"encoding/json"
	"testing"

	"github.com/certen/independant-validator/pkg/consensus"
	certenproof "github.com/certen/independant-validator/pkg/proof"
)

// RB4-F69. On its way from the proof cycle to governance_proof_levels the governance evidence met four silent
// fallbacks: receipts or a timing basis that did not parse were skipped, a result that was not valid JSON was left
// out, and a level that did not marshal was stored as its verdict flags alone. Each wrote a weaker record than the
// proof had - and one that read as "the generator recorded nothing" rather than "the evidence was broken". They are
// errors now.

func TestF69_MalformedReceiptsInTheCommitmentAreAnError(t *testing.T) {
	cm := map[string]interface{}{
		consensus.G1ProofCommitmentKey:     `{"threshold_satisfied":true}`,
		consensus.GovReceiptsCommitmentKey: `{"not":"a list"}`,
	}
	if in, err := GovernanceInputsFromCommitment(cm); err == nil {
		t.Fatalf("malformed receipts were skipped: %+v", in)
	}
}

func TestF69_MalformedTimingBasisInTheCommitmentIsAnError(t *testing.T) {
	cm := map[string]interface{}{
		consensus.G1ProofCommitmentKey:        `{"threshold_satisfied":true}`,
		consensus.GovTimingBasisCommitmentKey: `[{"level": 7}]`,
	}
	if in, err := GovernanceInputsFromCommitment(cm); err == nil {
		t.Fatalf("a malformed timing basis was skipped: %+v", in)
	}
}

func TestF69_AnInvalidResultIsAnError(t *testing.T) {
	if out, err := BuildGovernanceLevelJSON("G1", json.RawMessage(`{"broken"`), nil, nil, s2Flags()); err == nil {
		t.Fatalf("an invalid result was left out: %s", out)
	}
}

func TestF69_NothingToAddIsNotAnError(t *testing.T) {
	in, err := GovernanceInputsFromCommitment(map[string]interface{}{"bundleID": "x"})
	if err != nil || in != nil {
		t.Fatalf("a commitment with no governance data: %+v %v", in, err)
	}
	out, err := BuildGovernanceLevelJSON("G0", nil, nil, nil, s2Flags())
	if err != nil || len(out) == 0 {
		t.Fatalf("flags alone: %s %v", out, err)
	}
}

// mustLevelJSON is BuildGovernanceLevelJSON for inputs a test expects to encode.
func mustLevelJSON(t *testing.T, level string, result json.RawMessage, ev *certenproof.GovReceiptEvidence,
	tb []certenproof.SignatureTimingBasis, existing map[string]interface{}) json.RawMessage {
	t.Helper()
	out, err := BuildGovernanceLevelJSON(level, result, ev, tb, existing)
	if err != nil {
		t.Fatalf("level_json: %v", err)
	}
	return out
}

// Evidence the round could not carry refuses the levels, rather than storing them without it.
func TestF69_EvidenceTheRoundCouldNotCarryRefusesTheLevels(t *testing.T) {
	cm := map[string]interface{}{
		consensus.G1ProofCommitmentKey:       `{"threshold_satisfied":true}`,
		consensus.EvidenceErrorCommitmentKey: "att.GovReceipts: json: unsupported value",
	}
	if in, err := GovernanceInputsFromCommitment(cm); err == nil {
		t.Fatalf("levels were built without the evidence the round lost: %+v", in)
	}
}
