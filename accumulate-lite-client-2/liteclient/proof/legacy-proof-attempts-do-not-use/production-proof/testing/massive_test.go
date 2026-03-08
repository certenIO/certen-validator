// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package testing

import (
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/protocol"
)

// TestMassiveDevnet is the main test function for massive testing
func TestMassiveDevnet(t *testing.T) {
	// Skip if not explicitly enabled
	if testing.Short() {
		t.Skip("Skipping massive test in short mode")
	}

	// Configuration
	apiEndpoint := "http://localhost:26660/v3"
	accountPrefix := "testacct"
	accountCount := 100 // Create 100 test accounts

	// Create test suite
	suite := NewTestSuite(apiEndpoint)

	// Phase 1: Create test accounts
	err := suite.CreateTestAccounts(t, accountCount, accountPrefix)
	if err != nil {
		t.Fatalf("Failed to create test accounts: %v", err)
	}

	// Phase 2: Test all layers with created accounts
	suite.TestAllLayers(t)
}

// TestQuickVerification tests with existing accounts only
func TestQuickVerification(t *testing.T) {
	apiEndpoint := "http://localhost:26660/v3"

	// Create test suite
	suite := NewTestSuite(apiEndpoint)

	// Use existing well-known accounts
	suite.accounts = []string{
		"acc://dn.acme",
		"acc://alice.acme",
		"acc://bob.acme",
		"acc://charlie.acme",
	}

	// Test all layers
	suite.TestAllLayers(t)
}

// TestStressMode runs stress testing
func TestStressMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	apiEndpoint := "http://localhost:26660/v3"
	suite := NewTestSuite(apiEndpoint)

	// Use existing accounts for stress testing
	suite.accounts = []string{
		"acc://dn.acme",
		"acc://alice.acme",
		"acc://bob.acme",
	}

	// Run stress test: 20 concurrent workers for 30 seconds
	suite.StressTest(t, 20, 30*time.Second)
}

// BenchmarkLayer1Verification benchmarks Layer 1
func BenchmarkLayer1Verification(b *testing.B) {
	suite := NewTestSuite("http://localhost:26660/v3")
	accountURL := protocol.DnUrl()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = suite.verifier.VerifyAccountSimple(accountURL)
	}
}

// BenchmarkLayer2Verification benchmarks Layer 2
func BenchmarkLayer2Verification(b *testing.B) {
	suite := NewTestSuite("http://localhost:26660/v3")
	accountURL := protocol.DnUrl()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = suite.verifier.VerifyAccountSimple(accountURL)
	}
}
