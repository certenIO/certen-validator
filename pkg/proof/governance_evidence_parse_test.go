package proof

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"testing"
)

// A receipt that is present but does not parse was logged as "carries NO receipt merkle path" and the level stored
// summary-only - a defect in the evidence recorded as an honest absence of it. It is an error.
func TestAMalformedReceiptIsNotAnAbsence(t *testing.T) {
	pretty, _ := loadG1Output(t, "gdr_g1_delegated_case_c.json")
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(pretty, &fields); err != nil {
		t.Fatal(err)
	}
	var receipt map[string]json.RawMessage
	if err := json.Unmarshal(fields["receipt"], &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["entries"] = json.RawMessage(`"not a path"`)
	fields["receipt"], _ = json.Marshal(receipt)
	broken, _ := json.Marshal(fields)
	var compact bytes.Buffer
	_ = json.Compact(&compact, broken)
	g := &CLIGovernanceProofGenerator{logger: log.New(io.Discard, "", 0)}
	if gp, err := g.parseOutput(GovLevelG1, compact.Bytes(), kermitRouter(t)); err == nil {
		t.Fatalf("a malformed receipt was accepted (receipts %d)", len(gp.Receipts))
	}
}
