// test_tags.go
//
// Build tag definitions for test normalization in the Accumulate Lite Client.
// This file defines the test categories and build tags used throughout the codebase.
//
// Test Categories:
// - Default (no tags): Unit tests that run offline without network access
// - integration: Tests that require real network access to Accumulate
// - proofs_pending: Tests for proof functionality that is pending API availability
// - mock_disabled: Tests that should only run when anti-mock guardrails are disabled
//
// Usage:
//   go test ./...                           # Run unit tests only
//   go test -tags=integration ./...         # Run integration tests
//   go test -tags=proofs_pending ./...      # Run pending proof tests
//   go test -tags=all ./...                 # Run all tests
//
// Anti-Mock Guardrails:
// The codebase has been cleaned of mocks. Any test file containing mocks
// must be tagged with 'mock_disabled' and will not run by default.

package liteclient

// TestCategories defines the available test categories
type TestCategories struct {
	Unit          string // Default, no tag needed
	Integration   string // Requires 'integration' tag
	ProofsPending string // Requires 'proofs_pending' tag
	MockDisabled  string // Requires 'mock_disabled' tag
}

// Categories provides the standard test categories
var Categories = TestCategories{
	Unit:          "",
	Integration:   "integration",
	ProofsPending: "proofs_pending",
	MockDisabled:  "mock_disabled",
}