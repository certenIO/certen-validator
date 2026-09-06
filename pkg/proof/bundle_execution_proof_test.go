package proof

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Component 5 carries the receipt AND the verified inclusion proof, or nothing at all: a receipt the
// bundle cannot prove is a claim, and a stranger must be able to tell the two apart.
func TestExecutionProofRoundTripsAndRefusesUnprovenReceipts(t *testing.T) {
	b := NewCertenProofBundle("bundle-1")
	b.SetTransactionRef("6eb645aa", "acc://insurer-81497.acme/data", "on_demand")
	b.SetAnchorReference("84532", "0x591707dd", 46437431, 32)

	// Without a receipt proof nothing is attached.
	b.SetExecutionProof(&ExecutionProof{ChainID: "84532", TxHash: "0x591707dd", RawReceipt: "0x02f9"})
	if b.ProofComponents.ExecutionProof != nil {
		t.Fatal("a receipt without its inclusion proof must not become component 5")
	}

	rcProof := json.RawMessage(`{"leaf_hash":"ba94","leaf_index":23,"expected_root":"e9a2","proof_nodes":["f871","f851"],"leaf_value":"02f9","verified":true}`)
	b.SetExecutionProof(&ExecutionProof{
		ChainID: "84532", TxHash: "0x591707dd", BlockNumber: 46437431, BlockHash: "0xabc", Status: 1,
		ReceiptsRoot: "0xe9a2", RawReceipt: "0x02f9",
		Logs:             []ExecutionLog{{Address: "0x41bc4283", Topics: []string{"0x81eb79ac", "0xc4991b4a"}, Data: "0x16e360", LogIndex: 0}},
		ReceiptInclusion: rcProof, VerifiedBy: "validator-1",
	})
	if b.ProofComponents.ExecutionProof == nil || b.ProofComponents.ExecutionProof.VerifiedAt.IsZero() {
		t.Fatal("component 5 should be attached with a verified_at")
	}

	raw, err := b.ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"5_execution_proof"`) || !strings.Contains(string(raw), `f871`) || !strings.Contains(string(raw), `f851`) {
		t.Fatalf("the JSON must carry component 5 with the raw proof nodes: %s", raw)
	}
	back, err := BundleFromJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	ep := back.ProofComponents.ExecutionProof
	if ep == nil || ep.TxHash != "0x591707dd" || ep.ReceiptsRoot != "0xe9a2" || len(ep.Logs) != 1 || ep.Logs[0].Topics[1] != "0xc4991b4a" {
		t.Fatalf("component 5 did not round-trip: %+v", ep)
	}
	var want, got bytes.Buffer
	if err := json.Compact(&want, rcProof); err != nil {
		t.Fatal(err)
	}
	if err := json.Compact(&got, ep.ReceiptInclusion); err != nil {
		t.Fatal(err)
	}
	if got.String() != want.String() {
		t.Fatalf("the receipt inclusion proof must pass through unchanged: %s", got.String())
	}
	// Component 2 still names the same transaction — the two must agree.
	if back.ProofComponents.AnchorReference.AnchorTxHash != ep.TxHash {
		t.Fatal("component 2 and component 5 disagree on the transaction")
	}
}
