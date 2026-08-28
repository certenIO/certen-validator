// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CERTEN Governance Proof Tests
// Comprehensive test suite for consolidated governance proof system
// Ensures CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0 compliance

// =============================================================================
// Test Fixtures and Mock Data
// =============================================================================

// TestFixtures contains all test data for governance proof testing
type TestFixtures struct {
	SampleTxHash       string
	SampleAccount      string
	SampleKeyPage      string
	SamplePrincipal    string
	SamplePublicKey    string
	SampleSignature    string
	SampleExecMBI      int64
	SampleExecWitness  string
	SampleReceiptData  ReceiptData
	SampleKeyPageState KeyPageState
}

// createTestFixtures creates standardized test fixtures
func createTestFixtures() *TestFixtures {
	return &TestFixtures{
		SampleTxHash:      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		SampleAccount:     "acc://example.acme",
		SampleKeyPage:     "acc://example.acme/page/1",
		SamplePrincipal:   "example.acme",
		SamplePublicKey:   "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		SampleSignature:   "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
		SampleExecMBI:     12345,
		SampleExecWitness: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
		SampleReceiptData: ReceiptData{
			Start:      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			Anchor:     "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
			LocalBlock: 12345,
		},
		SampleKeyPageState: KeyPageState{
			Version:   1,
			Keys:      []string{"hash1", "hash2", "hash3"},
			Threshold: 2,
		},
	}
}

// MockRPCClient provides mock RPC responses for testing
type MockRPCClient struct {
	responses map[string]map[string]interface{}
}

// NewMockRPCClient creates a new mock RPC client
func NewMockRPCClient() *MockRPCClient {
	return &MockRPCClient{
		responses: make(map[string]map[string]interface{}),
	}
}

// AddMockResponse adds a mock response for a specific query
func (m *MockRPCClient) AddMockResponse(scope string, response map[string]interface{}) {
	m.responses[scope] = response
}

// Query returns the recorded response for testing.
func (m *MockRPCClient) Query(ctx context.Context, scope string, query map[string]interface{}) (map[string]interface{}, error) {
	if response, exists := m.responses[normalizeAccURL(scope)]; exists {
		return response, nil
	}
	return nil, ValidationError{Msg: "Mock response not found for scope: " + scope}
}

// QueryRaw and GetEndpoint complete RPCClientInterface.
//
// Without these this type did not satisfy the interface, and the two G0 tests
// worked around that by building a REAL client pointed at the endpoint "test"
// - which cannot resolve - while still populating this one. The recorded
// responses were fed to a client that was never called, so the tests could only
// ever fail with "unsupported protocol scheme". They are the reason those two
// tests were red from the day the layer moved to an interface.
func (m *MockRPCClient) QueryRaw(ctx context.Context, scope string, query map[string]interface{}) ([]byte, error) {
	resp, err := m.Query(ctx, scope, query)
	if err != nil {
		return nil, err
	}
	return json.Marshal(resp)
}

func (m *MockRPCClient) GetEndpoint() string { return "recorded" }

// loadRecordedResponse reads a response captured from the live network.
//
// These fixtures are REAL Kermit bytes for a real transaction
// (1f25bb6ae4cad401… on acc://certen-kermit-12.acme/data, captured 2026-08-28),
// not a hand-written shape. A fixture we invent to match our own parser proves
// only that we agree with ourselves; one recorded off the wire tests the parser
// against what Accumulate actually sends, and does it offline and
// deterministically.
func loadRecordedResponse(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read recorded response %s: %v", name, err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("recorded response %s is not JSON: %v", name, err)
	}
	return out
}

// The transaction the recorded fixtures describe.
const (
	recordedAccount    = "acc://certen-kermit-12.acme/data"
	recordedTxHash     = "1f25bb6ae4cad401ddede00c5711d871b02dd0bae20e027d2194fae5c7f12c5f"
	recordedExecMBI    = int64(10214060)
	recordedMessageID  = "acc://1f25bb6ae4cad401ddede00c5711d871b02dd0bae20e027d2194fae5c7f12c5f@certen-kermit-12.acme/data"
	recordedChainIndex = 291
)

// createTestWorkDir creates temporary working directory for tests
func createTestWorkDir(t *testing.T) string {
	workDir, err := os.MkdirTemp("", "govproof_test_*")
	if err != nil {
		t.Fatalf("Failed to create test work dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(workDir)
	})
	return workDir
}

// =============================================================================
// Unit Tests - Core Components
// =============================================================================

// TestHexValidator tests hex validation functionality
func TestHexValidator(t *testing.T) {
	fixtures := createTestFixtures()
	hv := HexValidator{}

	t.Run("RequireHex32_Valid", func(t *testing.T) {
		result, err := hv.RequireHex32(fixtures.SampleTxHash, "test hash")
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result != fixtures.SampleTxHash {
			t.Errorf("Expected %s, got %s", fixtures.SampleTxHash, result)
		}
	})

	t.Run("RequireHex32_WithPrefix", func(t *testing.T) {
		hashWithPrefix := "0x" + fixtures.SampleTxHash
		result, err := hv.RequireHex32(hashWithPrefix, "test hash")
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result != fixtures.SampleTxHash {
			t.Errorf("Expected %s, got %s", fixtures.SampleTxHash, result)
		}
	})

	t.Run("RequireHex32_Invalid", func(t *testing.T) {
		_, err := hv.RequireHex32("invalid", "test hash")
		if err == nil {
			t.Error("Expected error for invalid hex")
		}
	})

	t.Run("RequireHex64_Valid", func(t *testing.T) {
		result, err := hv.RequireHex64(fixtures.SampleSignature, "test signature")
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if result != fixtures.SampleSignature {
			t.Errorf("Expected %s, got %s", fixtures.SampleSignature, result)
		}
	})

	t.Run("RequireHex64_Invalid", func(t *testing.T) {
		_, err := hv.RequireHex64(fixtures.SampleTxHash, "test signature") // Wrong length
		if err == nil {
			t.Error("Expected error for wrong length hex")
		}
	})
}

// TestProofUtilities tests proof utility functions
func TestProofUtilities(t *testing.T) {
	pu := ProofUtilities{}

	testData := map[string]interface{}{
		"field1": "value1",
		"Field2": "value2",
		"FIELD3": "value3",
		"nested": map[string]interface{}{
			"subfield": "subvalue",
		},
	}

	t.Run("CaseInsensitiveGet", func(t *testing.T) {
		// Test exact match
		result := pu.CaseInsensitiveGet(testData, "field1")
		if result != "value1" {
			t.Errorf("Expected 'value1', got %v", result)
		}

		// Test case insensitive match
		result = pu.CaseInsensitiveGet(testData, "field2")
		if result != "value2" {
			t.Errorf("Expected 'value2', got %v", result)
		}

		// Test uppercase match
		result = pu.CaseInsensitiveGet(testData, "field3")
		if result != "value3" {
			t.Errorf("Expected 'value3', got %v", result)
		}

		// Test nested field
		nested := pu.CaseInsensitiveGet(testData, "nested")
		if nestedMap, ok := nested.(map[string]interface{}); ok {
			subResult := pu.CaseInsensitiveGet(nestedMap, "subfield")
			if subResult != "subvalue" {
				t.Errorf("Expected 'subvalue', got %v", subResult)
			}
		} else {
			t.Error("Expected nested map")
		}

		// Test non-existent field
		result = pu.CaseInsensitiveGet(testData, "nonexistent")
		if result != nil {
			t.Errorf("Expected nil, got %v", result)
		}
	})
}

// TestURLUtils tests URL utility functions
func TestURLUtils(t *testing.T) {
	uu := URLUtils{}

	testCases := []struct {
		input    string
		expected string
	}{
		{"acc://example.acme", "acc://example.acme"},
		{"ACC://EXAMPLE.ACME", "acc://example.acme"},
		{"acc://example.acme/", "acc://example.acme"},
		{"acc://example.acme/page/1", "acc://example.acme/page/1"},
		{"example.acme", "acc://example.acme"},
	}

	for _, tc := range testCases {
		t.Run("NormalizeURL_"+tc.input, func(t *testing.T) {
			result := uu.NormalizeURL(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// =============================================================================
// Unit Tests - Signature Verification
// =============================================================================

// TestSignatureVerifier tests signature verification functionality
func TestSignatureVerifier(t *testing.T) {
	fixtures := createTestFixtures()
	sv := NewSignatureVerifier("")

	t.Run("ComputeKeyHash", func(t *testing.T) {
		hash, err := sv.ComputeKeyHash(fixtures.SamplePublicKey)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if len(hash) != 64 { // SHA256 produces 32 bytes = 64 hex chars
			t.Errorf("Expected 64 character hash, got %d", len(hash))
		}

		// Test same input produces same hash
		hash2, err := sv.ComputeKeyHash(fixtures.SamplePublicKey)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if hash != hash2 {
			t.Error("Expected deterministic hash computation")
		}
	})

	t.Run("ValidateSignatureTiming", func(t *testing.T) {
		receipt := fixtures.SampleReceiptData
		execMBI := fixtures.SampleExecMBI

		// Test valid timing (signature before execution)
		result := sv.ValidateSignatureTiming(receipt, execMBI)
		if !result {
			t.Error("Expected timing validation to pass")
		}

		// Test invalid timing (signature after execution)
		result = sv.ValidateSignatureTiming(receipt, execMBI-100)
		if result {
			t.Error("Expected timing validation to fail")
		}
	})

	t.Run("ValidateTransactionHash", func(t *testing.T) {
		sig := SignatureData{
			TransactionHash: fixtures.SampleTxHash,
		}

		// Test matching hash
		result := sv.ValidateTransactionHash(sig, fixtures.SampleTxHash)
		if !result {
			t.Error("Expected transaction hash validation to pass")
		}

		// Test non-matching hash
		result = sv.ValidateTransactionHash(sig, "different"+fixtures.SampleTxHash[9:])
		if result {
			t.Error("Expected transaction hash validation to fail")
		}
	})
}

// =============================================================================
// Unit Tests - Authority Building
// =============================================================================

// TestAuthorityBuilder tests authority snapshot building
func TestAuthorityBuilder(t *testing.T) {
	workDir := createTestWorkDir(t)
	_ = NewMockRPCClient() // Assigned to _ to avoid unused variable warning
	artifactManager, err := NewArtifactManager(workDir)
	if err != nil {
		t.Fatalf("Failed to create artifact manager: %v", err)
	}
	// Create a real RPC client since builder expects *RPCClient
	rpcConfig := RPCConfig{Endpoint: "test", UseHTTP: true}
	rpcClient := NewRPCClient(rpcConfig)
	builder := NewAuthorityBuilder(rpcClient, artifactManager)

	fixtures := createTestFixtures()

	t.Run("ExtractPrincipal", func(t *testing.T) {
		principal, err := builder.extractPrincipal(fixtures.SampleKeyPage)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
		if principal != fixtures.SamplePrincipal {
			t.Errorf("Expected %s, got %s", fixtures.SamplePrincipal, principal)
		}
	})

	t.Run("ParseKeyPageStateFromDef", func(t *testing.T) {
		keyPageDef := map[string]interface{}{
			"version":   float64(1),
			"threshold": float64(2),
			"keys": []interface{}{
				map[string]interface{}{
					"publicKey": fixtures.SamplePublicKey,
				},
			},
		}

		state, err := builder.parseKeyPageStateFromDef(keyPageDef)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		if state.Version != 1 {
			t.Errorf("Expected version 1, got %d", state.Version)
		}
		if state.Threshold != 2 {
			t.Errorf("Expected threshold 2, got %d", state.Threshold)
		}
		if len(state.Keys) != 1 {
			t.Errorf("Expected 1 key, got %d", len(state.Keys))
		}
	})
}

// =============================================================================
// Integration Tests - G0 Layer
// =============================================================================

// TestG0Layer tests G0 proof generation
func TestG0Layer(t *testing.T) {
	workDir := createTestWorkDir(t)
	artifactManager, err := NewArtifactManager(workDir)
	if err != nil {
		t.Fatalf("Failed to create artifact manager: %v", err)
	}

	// The recorded client, not a real one aimed at an endpoint that cannot
	// resolve. Both G0 queries (inclusion, then the expanded binding) are
	// answered from the same recorded record, which is what the live endpoint
	// returns for both.
	client := NewMockRPCClient()
	client.AddMockResponse(recordedAccount, loadRecordedResponse(t, "g0_inclusion.json"))
	g0Layer := NewG0Layer(client, artifactManager)

	request := G0Request{
		Account: recordedAccount,
		TxHash:  recordedTxHash,
		Chain:   "main",
		WorkDir: workDir,
	}

	t.Run("G0ProofGeneration", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := g0Layer.ProveG0(ctx, request)
		if err != nil {
			t.Fatalf("G0 over a recorded real response failed: %v", err)
		}

		if result.TxHash != recordedTxHash {
			t.Errorf("TxHash = %s, want %s", result.TxHash, recordedTxHash)
		}
		// The execution block comes from the receipt the network actually sent.
		if result.ExecMBI != recordedExecMBI {
			t.Errorf("ExecMBI = %d, want %d (receipt.localBlock in the recording)",
				result.ExecMBI, recordedExecMBI)
		}
		if result.ExpandedMessageID != recordedMessageID {
			t.Errorf("ExpandedMessageID = %s, want %s", result.ExpandedMessageID, recordedMessageID)
		}
		if !result.G0ProofComplete {
			t.Error("G0ProofComplete is false on a proof that returned no error")
		}
		// G0 must carry the transaction forward for G1's authority derivation.
		if g0Layer.Transaction() == nil {
			t.Error("G0 did not carry the transaction forward; G1 cannot derive the " +
				"authorities the body requires")
		}
	})

	// The binding check must be insensitive to how the CALLER spelled the
	// account, since one side of that comparison is built from this string and
	// the other comes off the wire.
	t.Run("G0BindingIsSpellingInsensitive", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		shouty := NewMockRPCClient()
		shouty.AddMockResponse(recordedAccount, loadRecordedResponse(t, "g0_inclusion.json"))
		layer := NewG0Layer(shouty, artifactManager)

		loud := request
		loud.Account = "ACC://Certen-Kermit-12.acme/data/"

		if _, err := layer.ProveG0(ctx, loud); err != nil {
			t.Fatalf("the same account spelled differently failed the message-ID binding: %v", err)
		}
	})
}

func setupMockG0Responses(mockClient *MockRPCClient, fixtures *TestFixtures) {
	// Mock execution inclusion response
	executionResponse := map[string]interface{}{
		"data": map[string]interface{}{
			"chainEntry": map[string]interface{}{
				"entry": fixtures.SampleTxHash,
			},
			"receipt": map[string]interface{}{
				"start":      fixtures.SampleTxHash,
				"anchor":     fixtures.SampleExecWitness,
				"localBlock": float64(fixtures.SampleExecMBI),
			},
			"message": map[string]interface{}{
				"id":   fmt.Sprintf("acc://%s@%s", fixtures.SampleTxHash, fixtures.SampleAccount),
				"type": "transaction",
			},
		},
	}

	mockClient.AddMockResponse(fixtures.SampleAccount, executionResponse)
}

// =============================================================================
// Integration Tests - Complete Workflow
// =============================================================================

// TestCompleteWorkflow drives G0 over a recorded real response.
//
// The name promises more than it does, and the body now says exactly where the
// promise stops rather than leaving a reader to assume G1 and G2 are covered.
func TestCompleteWorkflow(t *testing.T) {
	workDir := createTestWorkDir(t)

	t.Run("G0_to_G1_to_G2_Progression", func(t *testing.T) {
		artifactManager, err := NewArtifactManager(workDir)
		if err != nil {
			t.Fatalf("Failed to create artifact manager: %v", err)
		}

		client := NewMockRPCClient()
		client.AddMockResponse(recordedAccount, loadRecordedResponse(t, "g0_inclusion.json"))
		g0Layer := NewG0Layer(client, artifactManager)

		ctx := context.Background()
		g0Result, err := g0Layer.ProveG0(ctx, G0Request{
			Account: recordedAccount,
			TxHash:  recordedTxHash,
			Chain:   "main",
			WorkDir: workDir,
		})
		if err != nil {
			t.Fatalf("G0 proof failed: %v", err)
		}
		if !g0Result.G0ProofComplete {
			t.Error("G0 proof should be complete")
		}

		// G1 and G2 are NOT exercised here, and saying so is the point.
		//
		// They need the signature sets, the authority snapshot and the key page
		// history, none of which this single recorded record carries. The real
		// G1/G2 verification is the Phase 7/8 corpus, which runs the actual
		// prover against Kermit over seventeen provisioned key shapes
		// (phase7_corpus_test.go, phase8_*_test.go). A local fixture that
		// pretended to cover them would be the overclaim this package keeps
		// removing.
		if g0Result.ExecMBI != recordedExecMBI {
			t.Errorf("ExecMBI = %d, want %d", g0Result.ExecMBI, recordedExecMBI)
		}
	})
}

// setupCompleteWorkflowMocks sets up comprehensive mock responses
func setupCompleteWorkflowMocks(mockClient *MockRPCClient, fixtures *TestFixtures) {
	setupMockG0Responses(mockClient, fixtures)

	// Additional mocks for G1 and G2 would be added here
	// Including authority snapshots, signature enumerations, etc.
}

// =============================================================================
// Performance and Benchmarks
// =============================================================================

// BenchmarkHexValidation benchmarks hex validation performance
func BenchmarkHexValidation(b *testing.B) {
	hv := HexValidator{}
	fixtures := createTestFixtures()

	b.Run("RequireHex32", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := hv.RequireHex32(fixtures.SampleTxHash, "benchmark")
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})

	b.Run("RequireHex64", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := hv.RequireHex64(fixtures.SampleSignature, "benchmark")
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

// BenchmarkKeyHashing benchmarks key hash computation
func BenchmarkKeyHashing(b *testing.B) {
	sv := NewSignatureVerifier("")
	fixtures := createTestFixtures()

	b.Run("ComputeKeyHash", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := sv.ComputeKeyHash(fixtures.SamplePublicKey)
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

// =============================================================================
// Error Handling and Edge Cases
// =============================================================================

// TestErrorHandling tests error handling and edge cases
func TestErrorHandling(t *testing.T) {
	t.Run("ValidationError", func(t *testing.T) {
		err := ValidationError{Msg: "test validation error"}
		if err.Error() != "test validation error" {
			t.Errorf("Expected 'test validation error', got %s", err.Error())
		}
	})

	t.Run("ProofError", func(t *testing.T) {
		err := ProofError{Msg: "test proof error"}
		if err.Error() != "test proof error" {
			t.Errorf("Expected 'test proof error', got %s", err.Error())
		}
	})

	t.Run("RPCError", func(t *testing.T) {
		err := RPCError{Msg: "test rpc error"}
		if err.Error() != "test rpc error" {
			t.Errorf("Expected 'test rpc error', got %s", err.Error())
		}
	})
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	t.Run("EmptyInputHandling", func(t *testing.T) {
		pu := ProofUtilities{}

		// Test empty data
		result := pu.CaseInsensitiveGet(nil, "field")
		if result != nil {
			t.Error("Expected nil for nil input")
		}

		result = pu.CaseInsensitiveGet(map[string]interface{}{}, "field")
		if result != nil {
			t.Error("Expected nil for empty map")
		}
	})

	t.Run("InvalidHexHandling", func(t *testing.T) {
		hv := HexValidator{}

		// Test invalid characters
		_, err := hv.RequireHex32("invalid_hex_string", "test")
		if err == nil {
			t.Error("Expected error for invalid hex")
		}

		// Test wrong length
		_, err = hv.RequireHex32("abc", "test")
		if err == nil {
			t.Error("Expected error for wrong length")
		}

		// Test empty string
		_, err = hv.RequireHex32("", "test")
		if err == nil {
			t.Error("Expected error for empty string")
		}
	})
}

// =============================================================================
// Test Utilities and Helpers
// =============================================================================

// assertNoError is a helper that fails the test if err is not nil
func assertNoError(t *testing.T, err error, msg string) {
	if err != nil {
		t.Fatalf("%s: %v", msg, err)
	}
}

// assertEquals is a helper for comparing values
func assertEquals(t *testing.T, expected, actual interface{}, msg string) {
	if expected != actual {
		t.Errorf("%s: expected %v, got %v", msg, expected, actual)
	}
}

// createSampleSignatureData creates sample signature data for testing
func createSampleSignatureData(fixtures *TestFixtures) SignatureData {
	return SignatureData{
		Type:            "ed25519",
		PublicKey:       fixtures.SamplePublicKey,
		Signature:       fixtures.SampleSignature,
		Signer:          fixtures.SampleKeyPage,
		SignerVersion:   1,
		Timestamp:       func() *int64 { ts := time.Now().Unix(); return &ts }(),
		TransactionHash: fixtures.SampleTxHash,
		TXID:            fixtures.SampleTxHash,
	}
}

// validateJSONSerialization tests JSON serialization for all major types
func TestJSONSerialization(t *testing.T) {
	fixtures := createTestFixtures()

	testTypes := []interface{}{
		fixtures.SampleReceiptData,
		fixtures.SampleKeyPageState,
		createSampleSignatureData(fixtures),
		G0Result{
			TXID:            fixtures.SampleTxHash,
			TxHash:          fixtures.SampleTxHash,
			G0ProofComplete: true,
		},
	}

	for i, testType := range testTypes {
		t.Run(fmt.Sprintf("JSONSerialization_%d", i), func(t *testing.T) {
			// Test serialization
			jsonData, err := json.Marshal(testType)
			if err != nil {
				t.Errorf("Failed to marshal JSON: %v", err)
				return
			}

			// Test deserialization
			var result interface{}
			err = json.Unmarshal(jsonData, &result)
			if err != nil {
				t.Errorf("Failed to unmarshal JSON: %v", err)
			}
		})
	}
}
