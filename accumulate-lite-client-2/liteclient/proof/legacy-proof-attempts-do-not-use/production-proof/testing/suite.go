// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package testing

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
)

// Testing interface wraps testing.T methods we use
type Testing interface {
	Logf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Skip(args ...interface{})
}

// TestSuite manages comprehensive testing across all proof layers
type TestSuite struct {
	client        *jsonrpc.Client
	verifier      *core.CryptographicVerifier
	accounts      []string
	createdCount  atomic.Int32
	verifiedCount atomic.Int32
	layer1Pass    atomic.Int32
	layer2Pass    atomic.Int32
	layer3Pass    atomic.Int32
	errors        []string
	mu            sync.Mutex

	// Configuration
	apiEndpoint   string
	cometEndpoint string
	concurrency   int
	timeout       time.Duration
}

// NewTestSuite creates a new test suite
func NewTestSuite(apiEndpoint string) *TestSuite {
	return &TestSuite{
		client:        jsonrpc.NewClient(apiEndpoint),
		verifier:      core.NewCryptographicVerifierWithEndpoints(apiEndpoint, ""),
		accounts:      make([]string, 0),
		errors:        make([]string, 0),
		apiEndpoint:   apiEndpoint,
		cometEndpoint: "",
		concurrency:   10,
		timeout:       30 * time.Second,
	}
}

// WithCometEndpoint sets the CometBFT endpoint
func (ts *TestSuite) WithCometEndpoint(endpoint string) *TestSuite {
	ts.cometEndpoint = endpoint
	ts.verifier = core.NewCryptographicVerifierWithEndpoints(ts.apiEndpoint, endpoint)
	return ts
}

// WithConcurrency sets the concurrency level
func (ts *TestSuite) WithConcurrency(n int) *TestSuite {
	ts.concurrency = n
	return ts
}

// WithTimeout sets the operation timeout
func (ts *TestSuite) WithTimeout(d time.Duration) *TestSuite {
	ts.timeout = d
	return ts
}

// TestAllLayers performs comprehensive testing of all proof layers
func (ts *TestSuite) TestAllLayers(t Testing) {
	fmt.Printf("\n🔬 Testing All Proof Layers with %d accounts\n", len(ts.accounts))
	fmt.Println(strings.Repeat("═", 80))

	if len(ts.accounts) == 0 {
		// Use default accounts
		ts.accounts = []string{
			"acc://dn.acme",
			"acc://alice.acme",
			"acc://bob.acme",
		}
	}

	// Test each account
	for i, account := range ts.accounts {
		fmt.Printf("\n[%d/%d] Testing: %s\n", i+1, len(ts.accounts), account)
		ts.testSingleAccount(t, account)
	}

	// Display results
	ts.DisplayResults()
}

// testSingleAccount tests all layers for a single account
func (ts *TestSuite) testSingleAccount(t Testing, accountStr string) {
	accountURL, err := url.Parse(accountStr)
	if err != nil {
		ts.addError(fmt.Sprintf("Invalid URL %s: %v", accountStr, err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), ts.timeout)
	defer cancel()

	// Perform full verification
	result, err := ts.verifier.VerifyAccount(ctx, accountURL)
	if err != nil {
		ts.addError(fmt.Sprintf("Verification error for %s: %v", accountStr, err))
		return
	}

	// Update counters
	ts.verifiedCount.Add(1)

	if result.Layers["layer1"].Verified {
		ts.layer1Pass.Add(1)
	}
	if result.Layers["layer2"].Verified {
		ts.layer2Pass.Add(1)
	}
	if result.Layers["layer3"].Verified {
		ts.layer3Pass.Add(1)
	}

	// Display inline results
	status := "❌"
	if result.Layers["layer1"].Verified && result.Layers["layer2"].Verified {
		status = "✅"
	} else if result.Layers["layer1"].Verified || result.Layers["layer2"].Verified {
		status = "⚠️"
	}

	fmt.Printf("  %s L1: %s | L2: %s | L3: %s | Trust: %s\n",
		status,
		formatLayerStatus(result.Layers["layer1"]),
		formatLayerStatus(result.Layers["layer2"]),
		formatLayerStatus(result.Layers["layer3"]),
		result.TrustLevel)
}

// DisplayResults shows comprehensive test results
func (ts *TestSuite) DisplayResults() {
	fmt.Println("\n" + strings.Repeat("═", 80))
	fmt.Println("                          TEST RESULTS SUMMARY")
	fmt.Println(strings.Repeat("═", 80))

	total := ts.verifiedCount.Load()
	if total == 0 {
		fmt.Println("❌ No accounts were tested")
		return
	}

	l1Pass := ts.layer1Pass.Load()
	l2Pass := ts.layer2Pass.Load()
	l3Pass := ts.layer3Pass.Load()

	// Calculate percentages
	l1Percent := float64(l1Pass) / float64(total) * 100
	l2Percent := float64(l2Pass) / float64(total) * 100
	l3Percent := float64(l3Pass) / float64(total) * 100

	fmt.Printf("\n📊 Overall Statistics:\n")
	fmt.Printf("  • Total Accounts Tested: %d\n", total)
	fmt.Printf("  • Accounts Created: %d\n", ts.createdCount.Load())
	fmt.Printf("\n")

	fmt.Printf("🔬 Layer Verification Results:\n")
	fmt.Printf("\n")
	fmt.Printf("  Layer 1 (Account → BPT Root):\n")
	fmt.Printf("    %s Passed: %d/%d (%.1f%%)\n", getStatusIcon(l1Percent), l1Pass, total, l1Percent)
	fmt.Printf("\n")

	fmt.Printf("  Layer 2 (BPT Root → Block Hash):\n")
	fmt.Printf("    %s Passed: %d/%d (%.1f%%)\n", getStatusIcon(l2Percent), l2Pass, total, l2Percent)
	fmt.Printf("\n")

	fmt.Printf("  Layer 3 (Block → Validator Signatures):\n")
	fmt.Printf("    %s Passed: %d/%d (%.1f%%)\n", getStatusIcon(l3Percent), l3Pass, total, l3Percent)
	if l3Percent == 0 {
		fmt.Printf("    • Status: ⏳ Awaiting API support\n")
	}
	fmt.Printf("\n")

	// Overall assessment
	fmt.Printf("🎯 System Health:\n")
	overallScore := (l1Percent + l2Percent) / 2

	if overallScore >= 95 {
		fmt.Printf("  ✅ EXCELLENT - Production ready for Layers 1-2\n")
	} else if overallScore >= 80 {
		fmt.Printf("  ⚠️ GOOD - Minor issues to address\n")
	} else if overallScore >= 60 {
		fmt.Printf("  ⚠️ FAIR - Significant testing needed\n")
	} else {
		fmt.Printf("  ❌ POOR - Critical issues detected\n")
	}

	if len(ts.errors) > 0 {
		fmt.Printf("\n⚠️ Errors: %d (use -v for details)\n", len(ts.errors))
	}

	fmt.Println("\n" + strings.Repeat("═", 80))
}

// Helper functions
func (ts *TestSuite) addError(err string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.errors = append(ts.errors, err)
}

func formatLayerStatus(layer core.LayerStatus) string {
	if layer.Verified {
		return "✅"
	}
	return "❌"
}

func getStatusIcon(percentage float64) string {
	if percentage >= 95 {
		return "✅"
	} else if percentage >= 70 {
		return "⚠️"
	}
	return "❌"
}
