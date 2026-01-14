// verifier_test.go
//
// Tests for the cryptographic verification layer of the Accumulate Lite Client.
// Focuses on local verification logic, receipt validation, and proof chain analysis.

package verifier

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/database/merkle"
)

// TestVerifierCreation tests verifier initialization
func TestVerifierCreation(t *testing.T) {
	t.Run("Create verifier with debug disabled", func(t *testing.T) {
		v := NewVerifier("https://testnet.accumulatenetwork.io/v3", false)
		if v == nil {
			t.Fatal("Expected non-nil verifier")
		}
		if v.debug {
			t.Error("Expected debug to be disabled")
		}
	})

	t.Run("Create verifier with debug enabled", func(t *testing.T) {
		v := NewVerifier("https://testnet.accumulatenetwork.io/v3", true)
		if v == nil {
			t.Fatal("Expected non-nil verifier")
		}
		if !v.debug {
			t.Error("Expected debug to be enabled")
		}
	})
}

// TestReceiptValidation tests local cryptographic receipt verification
func TestReceiptValidation(t *testing.T) {
	verifier := NewVerifier("https://testnet.accumulatenetwork.io/v3", false)

	t.Run("Valid receipt verification", func(t *testing.T) {
		// Create a simple receipt for testing
		start := []byte("test-start-hash")
		intermediate := []byte("test-intermediate")

		// Hash1: start + intermediate
		h1 := sha256.New()
		h1.Write(start)
		h1.Write(intermediate)
		hash1 := h1.Sum(nil)

		// Create receipt entry
		entry := merkle.ReceiptEntry{
			Hash:  intermediate,
			Right: true, // intermediate is on the right
		}

		receipt := &merkle.Receipt{
			Start:   start,
			Anchor:  hash1,
			Entries: []*merkle.ReceiptEntry{&entry},
		}

		// Verify receipt locally
		hop := verifier.verifyReceiptLocally("TestReceipt", receipt)

		if !hop.Ok {
			t.Errorf("Expected valid receipt, got error: %s", hop.Err)
		}

		if hop.Name != "TestReceipt" {
			t.Errorf("Expected hop name 'TestReceipt', got '%s'", hop.Name)
		}

		// Verify inputs and outputs are recorded
		if _, exists := hop.Inputs["start"]; !exists {
			t.Error("Expected start hash in inputs")
		}
		if _, exists := hop.Inputs["anchor"]; !exists {
			t.Error("Expected anchor hash in inputs")
		}
		if _, exists := hop.Outputs["computed"]; !exists {
			t.Error("Expected computed hash in outputs")
		}
		if _, exists := hop.Outputs["expected"]; !exists {
			t.Error("Expected expected hash in outputs")
		}
	})

	t.Run("Invalid receipt verification", func(t *testing.T) {
		// Create a receipt with mismatched anchor
		start := []byte("test-start-hash")
		intermediate := []byte("test-intermediate")
		wrongAnchor := []byte("wrong-anchor-hash")

		entry := merkle.ReceiptEntry{
			Hash:  intermediate,
			Right: true,
		}

		receipt := &merkle.Receipt{
			Start:   start,
			Anchor:  wrongAnchor,
			Entries: []*merkle.ReceiptEntry{&entry},
		}

		// Verify receipt locally
		hop := verifier.verifyReceiptLocally("TestInvalidReceipt", receipt)

		if hop.Ok {
			t.Error("Expected invalid receipt to fail verification")
		}

		if hop.Err == "" {
			t.Error("Expected error message for invalid receipt")
		}
	})

	t.Run("Empty receipt verification", func(t *testing.T) {
		// Receipt with no entries should hash start to itself
		start := []byte("test-start-only")

		receipt := &merkle.Receipt{
			Start:   start,
			Anchor:  start, // Should match start since no entries
			Entries: []*merkle.ReceiptEntry{},
		}

		hop := verifier.verifyReceiptLocally("TestEmptyReceipt", receipt)

		if !hop.Ok {
			t.Errorf("Expected empty receipt to be valid, got error: %s", hop.Err)
		}
	})
}

// TestVerificationStrategies tests the strategy pattern implementation
func TestVerificationStrategies(t *testing.T) {
	verifier := NewVerifier("https://testnet.accumulatenetwork.io/v3", false)

	t.Run("Receipt chaining strategy initialization", func(t *testing.T) {
		ctx := context.Background()
		accountURL := "acc://test.acme"
		at := HeightOrTime{Mode: "latest"}

		// This will fail because we don't have real network access, but we test the structure
		verified, hops := verifier.strategyReceiptChaining(ctx, accountURL, at)

		// Should fail due to network, but we can check the structure
		if verified {
			t.Log("Strategy succeeded (unexpected without network)")
		}

		if len(hops) == 0 {
			t.Error("Expected at least one hop even on failure")
		}

		// First hop should be account chain fetching (ParseURL only happens on URL error)
		if len(hops) > 0 && hops[0].Name != "FetchAccountChain" && hops[0].Name != "ExtractAccountReceipt" {
			t.Errorf("Expected first hop to be 'FetchAccountChain' or 'ExtractAccountReceipt', got '%s'", hops[0].Name)
		}
	})

	t.Run("State reconstruction strategy", func(t *testing.T) {
		ctx := context.Background()
		accountURL := "acc://test.acme"
		at := HeightOrTime{Mode: "latest"}

		verified, hops := verifier.strategyStateReconstruction(ctx, accountURL, at)

		// Should always fail as it's not implemented
		if verified {
			t.Error("State reconstruction should not be implemented yet")
		}

		if len(hops) != 1 {
			t.Errorf("Expected exactly 1 hop for unimplemented strategy, got %d", len(hops))
		}

		if len(hops) > 0 && hops[0].Name != "state-reconstruction" {
			t.Errorf("Expected hop name 'state-reconstruction', got '%s'", hops[0].Name)
		}
	})
}

// TestReportGeneration tests verification report creation
func TestReportGeneration(t *testing.T) {
	verifier := NewVerifier("https://testnet.accumulatenetwork.io/v3", false)

	t.Run("Report structure", func(t *testing.T) {
		ctx := context.Background()
		accountURL := "acc://test.acme"
		at := HeightOrTime{Mode: "latest"}

		report, err := verifier.VerifyAccount(ctx, accountURL, at)

		// Verify report structure regardless of success
		if report.AccountURL != accountURL {
			t.Errorf("Expected AccountURL '%s', got '%s'", accountURL, report.AccountURL)
		}

		if report.At.Mode != at.Mode {
			t.Errorf("Expected At.Mode '%s', got '%s'", at.Mode, report.At.Mode)
		}

		if report.Strategy == "" {
			t.Error("Expected non-empty strategy name")
		}

		// Should have at least some hops even on failure
		if len(report.Hops) == 0 {
			t.Error("Expected at least some hops in report")
		}

		// Error handling
		if err != nil {
			t.Logf("Verification failed as expected without network: %v", err)
		}
	})
}

// TestHeightOrTime tests the time/height specification
func TestHeightOrTime(t *testing.T) {
	testCases := []struct {
		name string
		hot  HeightOrTime
	}{
		{
			name: "Latest mode",
			hot:  HeightOrTime{Mode: "latest"},
		},
		{
			name: "Height mode",
			hot:  HeightOrTime{Height: 12345, Mode: "height"},
		},
		{
			name: "Time mode",
			hot:  HeightOrTime{Time: time.Now(), Mode: "time"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that HeightOrTime structures work as expected
			if tc.hot.Mode == "" {
				t.Error("Mode should not be empty")
			}

			switch tc.hot.Mode {
			case "latest":
				// No additional validation needed
			case "height":
				if tc.hot.Height == 0 {
					t.Error("Height should not be zero for height mode")
				}
			case "time":
				if tc.hot.Time.IsZero() {
					t.Error("Time should not be zero for time mode")
				}
			}
		})
	}
}

// TestHopStructure tests the verification hop data structure
func TestHopStructure(t *testing.T) {
	t.Run("Hop creation and manipulation", func(t *testing.T) {
		hop := Hop{
			Name:    "TestHop",
			Inputs:  make(map[string][]byte),
			Outputs: make(map[string][]byte),
			Ok:      true,
			Err:     "",
		}

		// Add some data
		hop.Inputs["test-input"] = []byte("input-data")
		hop.Outputs["test-output"] = []byte("output-data")

		if hop.Name != "TestHop" {
			t.Errorf("Expected name 'TestHop', got '%s'", hop.Name)
		}

		if !hop.Ok {
			t.Error("Expected Ok to be true")
		}

		if len(hop.Inputs) != 1 {
			t.Errorf("Expected 1 input, got %d", len(hop.Inputs))
		}

		if len(hop.Outputs) != 1 {
			t.Errorf("Expected 1 output, got %d", len(hop.Outputs))
		}

		// Test error state
		hop.Ok = false
		hop.Err = "Test error"

		if hop.Ok {
			t.Error("Expected Ok to be false after setting error")
		}

		if hop.Err != "Test error" {
			t.Errorf("Expected error 'Test error', got '%s'", hop.Err)
		}
	})
}

// TestVerifierDebugOutput tests debug output functionality
func TestVerifierDebugOutput(t *testing.T) {
	t.Run("Debug mode affects behavior", func(t *testing.T) {
		debugVerifier := NewVerifier("https://testnet.accumulatenetwork.io/v3", true)
		normalVerifier := NewVerifier("https://testnet.accumulatenetwork.io/v3", false)

		if !debugVerifier.debug {
			t.Error("Debug verifier should have debug enabled")
		}

		if normalVerifier.debug {
			t.Error("Normal verifier should have debug disabled")
		}

		// Both should function the same way structurally
		// (debug only affects logging, not functionality)
		start := []byte("test")
		receipt := &merkle.Receipt{
			Start:   start,
			Anchor:  start,
			Entries: []*merkle.ReceiptEntry{},
		}

		debugHop := debugVerifier.verifyReceiptLocally("Test", receipt)
		normalHop := normalVerifier.verifyReceiptLocally("Test", receipt)

		if debugHop.Ok != normalHop.Ok {
			t.Error("Debug and normal verifiers should produce same results")
		}
	})
}
