//go:build integration

package chained_proof

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

func Test_ExamineArtifacts(t *testing.T) {
	// Use same defaults as integration test
	v3URL := getenv("CERTEN_V3", defaultV3Endpoint)
	account := getenv("CERTEN_ACCOUNT", "acc://carp-buyer-62431.acme/data")
	txhash := getenv("CERTEN_TXHASH", "51b0ba6abf413762fd3db7bcb12a2c56ee2806fcd8405640537f92b791aedcf0")
	bvn := getenv("CERTEN_BVN", "")
	if bvn == "" {
		bvn = calculateBVNFromKermitRouting(account)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// L4 replaced the CometBFT binds, so no consensus client is needed.
	v3c := jsonrpc.NewClient(v3URL)

	// Build proof with artifacts
	builder := NewProofBuilder(v3c, true)
	builder.WithArtifacts = true

	proof, err := builder.BuildProof(ctx, ProofInput{
		Account: account,
		TxHash:  txhash,
		BVN:     bvn,
	})
	if err != nil {
		t.Fatalf("Proof build failed: %v", err)
	}

	t.Logf("=== PROOF ARTIFACTS ANALYSIS ===")
	t.Logf("📋 Generated %d artifact files", len(proof.Artifacts))

	for filename, content := range proof.Artifacts {
		t.Logf("\n📁 %s (%d bytes)", filename, len(content))

		// Pretty print first section to see structure
		var prettyJSON map[string]interface{}
		if err := json.Unmarshal(content, &prettyJSON); err == nil {
			prettyBytes, _ := json.MarshalIndent(prettyJSON, "", "  ")
			preview := string(prettyBytes)
			if len(preview) > 1000 {
				preview = preview[:1000] + "\n... [truncated]"
			}
			t.Logf("Content Preview:\n%s", preview)
		} else {
			t.Logf("[Could not parse as JSON: %v]", err)
		}
	}

	t.Logf("\n=== ARTIFACT VALUE ANALYSIS ===")
	t.Logf("🔍 These artifacts contain the RAW v3 API responses for each layer")
	t.Logf("✅ They enable OFFLINE proof verification without re-querying the blockchain")
	t.Logf("✅ They provide complete auditability - anyone can verify our proof construction")
	t.Logf("✅ They preserve the exact data used for proof generation (forensic value)")
	t.Logf("Note: artifacts are an audit trail, not the trust root. The proof's")
	t.Logf("trust comes from L1-L3 merkle recomputation and L4 validator")
	t.Logf("signatures, both of which are checked offline from the proof object")
	t.Logf("itself - not from these files.")
}