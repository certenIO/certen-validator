//go:build integration

package chained_proof

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/cometbft/cometbft/rpc/client/http"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

func Test_ExamineArtifacts(t *testing.T) {
	// Use same defaults as integration test
	v3URL := getenv("CERTEN_V3", "http://127.0.0.1:26660/v3")
	dnComet := getenv("CERTEN_DN_COMET", "http://127.0.0.1:26657")
	bvnComet := getenv("CERTEN_BVN_COMET", "http://127.0.0.1:26757")

	account := getenv("CERTEN_ACCOUNT", "acc://testtesttest10.acme/data1")
	txhash := getenv("CERTEN_TXHASH", "057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116")
	bvn := getenv("CERTEN_BVN", "bvn1")

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Initialize clients
	v3c := jsonrpc.NewClient(v3URL)
	dnClient, err := http.New(dnComet, "/websocket")
	if err != nil {
		t.Fatalf("DN client failed: %v", err)
	}
	bvnClient, err := http.New(bvnComet, "/websocket")
	if err != nil {
		t.Fatalf("BVN client failed: %v", err)
	}

	// Build proof with artifacts
	builder := NewProofBuilder(v3c, dnClient, bvnClient, true)
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
	t.Logf("⚠️  But they require trusting the artifact provider - not zero-trust verification")
}