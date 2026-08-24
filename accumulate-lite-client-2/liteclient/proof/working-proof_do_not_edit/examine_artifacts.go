// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package chained_proof

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
)

// ExamineArtifacts runs a quick proof and shows what artifacts contain
func ExamineArtifacts() error {
	// Use same defaults as integration test
	v3URL := getenvOrDefault("CERTEN_V3", "http://127.0.0.1:26660/v3")

	account := getenvOrDefault("CERTEN_ACCOUNT", "acc://testtesttest10.acme/data1")
	txhash := getenvOrDefault("CERTEN_TXHASH", "057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116")
	bvn := getenvOrDefault("CERTEN_BVN", "bvn1")

	ctx := context.Background()

	// Initialize client. L4 replaced the CometBFT binds, so no consensus
	// client is needed.
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
		return err
	}

	fmt.Printf("=== PROOF ARTIFACTS ANALYSIS ===\n\n")

	for filename, content := range proof.Artifacts {
		fmt.Printf("📁 %s (%d bytes)\n", filename, len(content))

		// Pretty print first 500 chars to see structure
		var prettyJSON map[string]interface{}
		if err := json.Unmarshal(content, &prettyJSON); err == nil {
			prettyBytes, _ := json.MarshalIndent(prettyJSON, "   ", "  ")
			preview := string(prettyBytes)
			if len(preview) > 800 {
				preview = preview[:800] + "\n   ... [truncated]"
			}
			fmt.Printf("   Content Preview:\n   %s\n\n", preview)
		} else {
			fmt.Printf("   [Could not parse as JSON: %v]\n\n", err)
		}
	}

	return nil
}

func getenvOrDefault(key, defaultValue string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultValue
}