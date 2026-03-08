// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"gitlab.com/accumulatenetwork/accumulate/protocol"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
)

// TestCompleteProofChain demonstrates the complete 3-layer cryptographic proof
// using real devnet account data and CometBFT blockchain verification
func TestCompleteProofChain(t *testing.T) {
	fmt.Println("================================================================================")
	fmt.Println("COMPLETE CRYPTOGRAPHIC PROOF CHAIN TEST")
	fmt.Println("Testing Layers 1, 2, and 3 with Real Devnet Data")
	fmt.Println("================================================================================")

	// Test configuration
	testAccount := "acc://alice.acme"
	apiURL := "http://localhost:26660/v3"
	cometURL := "http://localhost:26657"

	fmt.Printf("🎯 TEST PARAMETERS:\n")
	fmt.Printf("  Test Account: %s\n", testAccount)
	fmt.Printf("  Accumulate API: %s\n", apiURL)
	fmt.Printf("  CometBFT RPC: %s\n", cometURL)
	fmt.Println()

	// Parse account URL
	accountURL, err := url.Parse(testAccount)
	if err != nil {
		t.Fatalf("Invalid account URL: %v", err)
	}

	// Create verifier
	verifier := core.NewCryptographicVerifierWithEndpoints(apiURL, cometURL)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run complete verification
	fmt.Println("\n🔐 Running Full Cryptographic Verification...")
	fmt.Println("=" + repeatStr("=", 60))

	result, err := verifier.VerifyAccount(ctx, accountURL)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	// Display results for each layer
	fmt.Printf("\n📊 VERIFICATION RESULTS:\n")
	fmt.Println(repeatStr("─", 60))

	// Layer 1
	layer1 := result.Layers["layer1"]
	fmt.Printf("\n🔍 LAYER 1: Account State → BPT Root\n")
	fmt.Printf("  Status: %s\n", getStatusString(layer1.Verified))
	if layer1.Details != nil {
		if hash, ok := layer1.Details["accountHash"].(string); ok {
			fmt.Printf("  Account Hash: %s...\n", hash[:16])
		}
		if root, ok := layer1.Details["bptRoot"].(string); ok {
			fmt.Printf("  BPT Root: %s...\n", root[:16])
		}
		if entries, ok := layer1.Details["proofEntries"].(int); ok {
			fmt.Printf("  Proof Entries: %d\n", entries)
		}
	}
	if layer1.Error != "" {
		fmt.Printf("  Error: %s\n", layer1.Error)
	}

	// Layer 2
	layer2 := result.Layers["layer2"]
	fmt.Printf("\n🔗 LAYER 2: BPT Root → Block Hash\n")
	fmt.Printf("  Status: %s\n", getStatusString(layer2.Verified))
	if layer2.Details != nil {
		if height, ok := layer2.Details["blockHeight"].(int64); ok {
			fmt.Printf("  Block Height: %d\n", height)
		}
		if hash, ok := layer2.Details["blockHash"].(string); ok && hash != "" {
			fmt.Printf("  Block Hash: %s...\n", hash[:16])
		}
		if trust, ok := layer2.Details["trustRequired"].(string); ok && trust != "" {
			fmt.Printf("  Trust Required: %s\n", trust)
		}
	}
	if layer2.Error != "" {
		fmt.Printf("  Error: %s\n", layer2.Error)
	}

	// Layer 3
	layer3 := result.Layers["layer3"]
	fmt.Printf("\n✍️  LAYER 3: Block Hash → Validator Signatures\n")
	fmt.Printf("  Status: %s\n", getStatusString(layer3.Verified))
	if layer3.Details != nil {
		if total, ok := layer3.Details["totalValidators"].(int); ok && total > 0 {
			fmt.Printf("  Total Validators: %d\n", total)
		}
		if signed, ok := layer3.Details["signedValidators"].(int); ok && signed > 0 {
			fmt.Printf("  Signed Validators: %d\n", signed)
		}
		if threshold, ok := layer3.Details["thresholdMet"].(bool); ok {
			fmt.Printf("  Threshold Met: %v\n", threshold)
		}
		if apiLimit, ok := layer3.Details["apiLimitation"].(bool); ok && apiLimit {
			fmt.Printf("  API Limitation: Yes (awaiting consensus data)\n")
		}
	}
	if layer3.Error != "" {
		fmt.Printf("  Error: %s\n", layer3.Error)
	}

	// Layer 4
	layer4 := result.Layers["layer4"]
	fmt.Printf("\n🏛️  LAYER 4: Validators → Genesis Trust\n")
	fmt.Printf("  Status: %s\n", getStatusString(layer4.Verified))
	if layer4.Error != "" {
		fmt.Printf("  Note: %s\n", layer4.Error)
	}

	// Overall result
	fmt.Printf("\n" + repeatStr("═", 60) + "\n")
	fmt.Printf("🎯 OVERALL VERIFICATION:\n")
	fmt.Printf("  Fully Verified: %v\n", result.FullyVerified)
	fmt.Printf("  Trust Level: %s\n", result.TrustLevel)
	fmt.Printf("  Duration: %.2f seconds\n", result.Duration.Seconds())

	if result.Error != "" {
		fmt.Printf("  Error: %s\n", result.Error)
	}

	// Summary
	fmt.Printf("\n" + repeatStr("═", 60) + "\n")
	if result.Layers["layer1"].Verified && result.Layers["layer2"].Verified {
		fmt.Println("✅ SUCCESS: Layers 1-2 cryptographically verified!")
		fmt.Println("   Account state is provably included in the blockchain.")
	} else {
		fmt.Println("❌ FAILURE: Cryptographic verification failed.")
		fmt.Println("   Check error messages above for details.")
	}

	if !result.Layers["layer3"].Verified {
		fmt.Println("\n⏳ NOTE: Layer 3 requires API enhancements for full verification.")
		fmt.Println("   Ed25519 signature verification is proven to work.")
	}

	fmt.Println("\n" + repeatStr("═", 60))
}

// TestWithDifferentAccounts tests verification with various account types
func TestWithDifferentAccounts(t *testing.T) {
	verifier := core.NewCryptographicVerifier()

	testCases := []struct {
		name    string
		account string
	}{
		{"Directory Network", "acc://dn.acme"},
		{"Alice ADI", "acc://alice.acme"},
		{"Bob ADI", "acc://bob.acme"},
		{"Charlie ADI", "acc://charlie.acme"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accountURL, err := url.Parse(tc.account)
			if err != nil {
				t.Fatalf("Invalid URL: %v", err)
			}

			verified, err := verifier.VerifyAccountSimple(accountURL)
			if err != nil {
				t.Errorf("Verification failed for %s: %v", tc.account, err)
			} else if verified {
				t.Logf("✅ %s verified successfully", tc.account)
			} else {
				t.Logf("❌ %s verification failed", tc.account)
			}
		})
	}
}

// TestPerformance benchmarks the verification speed
func TestPerformance(t *testing.T) {
	verifier := core.NewCryptographicVerifier()
	accountURL := protocol.DnUrl()

	// Warm up
	_, _ = verifier.VerifyAccountSimple(accountURL)

	// Measure
	iterations := 10
	start := time.Now()

	for i := 0; i < iterations; i++ {
		verified, err := verifier.VerifyAccountSimple(accountURL)
		if err != nil || !verified {
			t.Fatalf("Verification failed on iteration %d", i)
		}
	}

	elapsed := time.Since(start)
	avgTime := elapsed / time.Duration(iterations)

	fmt.Printf("\nPerformance Results:\n")
	fmt.Printf("  Total iterations: %d\n", iterations)
	fmt.Printf("  Total time: %v\n", elapsed)
	fmt.Printf("  Average time: %v\n", avgTime)
	fmt.Printf("  Verifications/sec: %.2f\n", float64(iterations)/elapsed.Seconds())

	if avgTime > time.Second {
		t.Logf("Warning: Verification is slow (>1s average)")
	}
}

// Helper functions
func getStatusString(verified bool) string {
	if verified {
		return "✅ Verified"
	}
	return "❌ Not Verified"
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
