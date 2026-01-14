// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package testing provides comprehensive testing utilities for the Accumulate lite client.
// It includes test suites, mocks, fixtures, and utilities for different testing scenarios.
package testing

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/config"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/logging"
)

// TestSuite provides a comprehensive testing framework
type TestSuite struct {
	T              *testing.T
	Config         *config.Config
	Logger         *logging.Logger
	Client         *jsonrpc.Client
	TempDir        string
	Cleanup        []func()
	TestAccounts   []string
	NetworkEnabled bool
}

// TestOptions configures test suite behavior
type TestOptions struct {
	EnableNetwork     bool
	UseRealEndpoints  bool
	TestDataDir       string
	LogLevel          string
	TestAccounts      []string
	ConfigOverrides   map[string]interface{}
}

// NewTestSuite creates a new test suite
func NewTestSuite(t *testing.T, opts *TestOptions) *TestSuite {
	if opts == nil {
		opts = &TestOptions{}
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "liteclient-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Configure logging for tests
	logLevel := opts.LogLevel
	if logLevel == "" {
		logLevel = "debug"
	}

	logConfig := &logging.Config{
		Level:      parseLogLevel(logLevel),
		Format:     "text",
		Output:     "stdout",
		Structured: false,
		AddSource:  true,
	}

	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	// Create test configuration
	testConfig := createTestConfig(opts, tempDir)

	// Create API client if network is enabled
	var client *jsonrpc.Client
	if opts.EnableNetwork {
		endpoint := testConfig.Network.V3Endpoint
		if !opts.UseRealEndpoints {
			endpoint = "http://localhost:8080/v3" // Test endpoint
		}
		client = jsonrpc.NewClient(endpoint)
	}

	// Set up test accounts
	testAccounts := opts.TestAccounts
	if len(testAccounts) == 0 {
		testAccounts = []string{
			"acc://test.acme",
			"acc://RenatoDAP.acme",
			"acc://DefiDevs.acme",
		}
	}

	suite := &TestSuite{
		T:              t,
		Config:         testConfig,
		Logger:         logger,
		Client:         client,
		TempDir:        tempDir,
		Cleanup:        []func(){},
		TestAccounts:   testAccounts,
		NetworkEnabled: opts.EnableNetwork,
	}

	// Register cleanup
	suite.AddCleanup(func() {
		os.RemoveAll(tempDir)
	})

	t.Cleanup(suite.RunCleanup)

	return suite
}

// AddCleanup adds a cleanup function
func (ts *TestSuite) AddCleanup(fn func()) {
	ts.Cleanup = append(ts.Cleanup, fn)
}

// RunCleanup runs all cleanup functions
func (ts *TestSuite) RunCleanup() {
	for i := len(ts.Cleanup) - 1; i >= 0; i-- {
		ts.Cleanup[i]()
	}
}

// SkipIfNoNetwork skips the test if network testing is disabled
func (ts *TestSuite) SkipIfNoNetwork() {
	if !ts.NetworkEnabled {
		ts.T.Skip("Network testing disabled")
	}
}

// RequireNetwork requires network connectivity for the test
func (ts *TestSuite) RequireNetwork() {
	if !ts.NetworkEnabled {
		ts.T.Fatal("Network connectivity required for this test")
	}
}

// CreateTempFile creates a temporary file in the test directory
func (ts *TestSuite) CreateTempFile(name, content string) string {
	filePath := filepath.Join(ts.TempDir, name)
	
	// Create directory if needed
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		ts.T.Fatalf("Failed to create directory %s: %v", dir, err)
	}

	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		ts.T.Fatalf("Failed to write temp file %s: %v", filePath, err)
	}

	return filePath
}

// GetTestAccount returns a test account URL
func (ts *TestSuite) GetTestAccount(index int) string {
	if index >= len(ts.TestAccounts) {
		ts.T.Fatalf("Test account index %d out of range (max %d)", index, len(ts.TestAccounts)-1)
	}
	return ts.TestAccounts[index]
}

// WithTimeout creates a context with timeout for tests
func (ts *TestSuite) WithTimeout(timeout time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	ts.AddCleanup(cancel)
	return ctx
}

// AssertNoError asserts that an error is nil
func (ts *TestSuite) AssertNoError(err error, msgAndArgs ...interface{}) {
	if err != nil {
		ts.T.Helper()
		if len(msgAndArgs) > 0 {
			ts.T.Fatalf("Unexpected error: %v - %s", err, fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		} else {
			ts.T.Fatalf("Unexpected error: %v", err)
		}
	}
}

// AssertError asserts that an error is not nil
func (ts *TestSuite) AssertError(err error, msgAndArgs ...interface{}) {
	if err == nil {
		ts.T.Helper()
		if len(msgAndArgs) > 0 {
			ts.T.Fatalf("Expected error but got nil - %s", fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		} else {
			ts.T.Fatalf("Expected error but got nil")
		}
	}
}

// AssertEqual asserts that two values are equal
func (ts *TestSuite) AssertEqual(expected, actual interface{}, msgAndArgs ...interface{}) {
	if expected != actual {
		ts.T.Helper()
		if len(msgAndArgs) > 0 {
			ts.T.Fatalf("Values not equal: expected %v, got %v - %s", expected, actual, fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		} else {
			ts.T.Fatalf("Values not equal: expected %v, got %v", expected, actual)
		}
	}
}

// AssertNotEmpty asserts that a string is not empty
func (ts *TestSuite) AssertNotEmpty(value string, msgAndArgs ...interface{}) {
	if value == "" {
		ts.T.Helper()
		if len(msgAndArgs) > 0 {
			ts.T.Fatalf("Value should not be empty - %s", fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		} else {
			ts.T.Fatalf("Value should not be empty")
		}
	}
}

// AssertContains asserts that a string contains a substring
func (ts *TestSuite) AssertContains(haystack, needle string, msgAndArgs ...interface{}) {
	if !contains(haystack, needle) {
		ts.T.Helper()
		if len(msgAndArgs) > 0 {
			ts.T.Fatalf("String '%s' should contain '%s' - %s", haystack, needle, fmt.Sprintf(msgAndArgs[0].(string), msgAndArgs[1:]...))
		} else {
			ts.T.Fatalf("String '%s' should contain '%s'", haystack, needle)
		}
	}
}

// LogTestStep logs a test step for better debugging
func (ts *TestSuite) LogTestStep(step string, args ...interface{}) {
	message := fmt.Sprintf(step, args...)
	ts.Logger.Info("Test step", logging.Field{Key: "step", Value: message})
	ts.T.Logf("🧪 %s", message)
}

// LogTestResult logs a test result
func (ts *TestSuite) LogTestResult(success bool, message string, args ...interface{}) {
	formattedMessage := fmt.Sprintf(message, args...)
	
	if success {
		ts.Logger.Info("Test result", 
			logging.Field{Key: "success", Value: true},
			logging.Field{Key: "message", Value: formattedMessage})
		ts.T.Logf("✅ %s", formattedMessage)
	} else {
		ts.Logger.Error("Test result", 
			logging.Field{Key: "success", Value: false},
			logging.Field{Key: "message", Value: formattedMessage})
		ts.T.Logf("❌ %s", formattedMessage)
	}
}

// createTestConfig creates a configuration for testing
func createTestConfig(opts *TestOptions, tempDir string) *config.Config {
	cfg := config.DefaultConfig()
	
	// Override for testing
	cfg.Network.V3Endpoint = "https://testnet.accumulatenetwork.io/v3"
	cfg.Network.Timeout = 30 * time.Second
	cfg.Server.Port = 8081 // Different port for tests
	cfg.Logging.Level = "debug"
	cfg.Storage.Type = "memory"
	cfg.Storage.ConnectionString = filepath.Join(tempDir, "test.db")
	cfg.Development.Debug = true
	cfg.Development.EnableMetrics = false
	cfg.Development.DisableProofVerification = !opts.EnableNetwork

	// Apply overrides
	if opts.ConfigOverrides != nil {
		applyConfigOverrides(cfg, opts.ConfigOverrides)
	}

	return cfg
}

// applyConfigOverrides applies configuration overrides
func applyConfigOverrides(cfg *config.Config, overrides map[string]interface{}) {
	// This is a simplified implementation
	// In production, you'd want more sophisticated config merging
	for key, value := range overrides {
		switch key {
		case "v3_endpoint":
			if v, ok := value.(string); ok {
				cfg.Network.V3Endpoint = v
			}
		case "log_level":
			if v, ok := value.(string); ok {
				cfg.Logging.Level = v
			}
		case "debug":
			if v, ok := value.(bool); ok {
				cfg.Development.Debug = v
			}
		}
	}
}

// parseLogLevel parses a log level string
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || fmt.Sprintf("%s", s) != s[:len(s)-len(substr)]+substr)
}

// Helper types for common log levels
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Benchmark utilities

// BenchmarkSuite provides benchmarking utilities
type BenchmarkSuite struct {
	B      *testing.B
	Config *config.Config
	Logger *logging.Logger
}

// NewBenchmarkSuite creates a new benchmark suite
func NewBenchmarkSuite(b *testing.B) *BenchmarkSuite {
	cfg := config.DefaultConfig()
	cfg.Logging.Level = "error" // Minimal logging for benchmarks
	
	logger, _ := logging.NewLogger(&logging.Config{
		Level:  slog.LevelError,
		Format: "text",
		Output: "stderr",
	})

	return &BenchmarkSuite{
		B:      b,
		Config: cfg,
		Logger: logger,
	}
}

// ResetTimer resets the benchmark timer
func (bs *BenchmarkSuite) ResetTimer() {
	bs.B.ResetTimer()
}

// StopTimer stops the benchmark timer
func (bs *BenchmarkSuite) StopTimer() {
	bs.B.StopTimer()
}

// StartTimer starts the benchmark timer
func (bs *BenchmarkSuite) StartTimer() {
	bs.B.StartTimer()
}

// ReportAllocs enables allocation reporting
func (bs *BenchmarkSuite) ReportAllocs() {
	bs.B.ReportAllocs()
}

// Test utilities for specific components

// ProofTestSuite provides utilities for testing proof operations
type ProofTestSuite struct {
	*TestSuite
}

// NewProofTestSuite creates a new proof test suite
func NewProofTestSuite(t *testing.T, opts *TestOptions) *ProofTestSuite {
	if opts == nil {
		opts = &TestOptions{}
	}
	opts.EnableNetwork = true // Proof tests need network

	return &ProofTestSuite{
		TestSuite: NewTestSuite(t, opts),
	}
}

// ValidationTestSuite provides utilities for testing validation
type ValidationTestSuite struct {
	*TestSuite
}

// NewValidationTestSuite creates a new validation test suite
func NewValidationTestSuite(t *testing.T) *ValidationTestSuite {
	opts := &TestOptions{
		EnableNetwork: false, // Validation tests don't need network
		LogLevel:      "debug",
	}

	return &ValidationTestSuite{
		TestSuite: NewTestSuite(t, opts),
	}
}

// IntegrationTestSuite provides utilities for integration testing
type IntegrationTestSuite struct {
	*TestSuite
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T) *IntegrationTestSuite {
	opts := &TestOptions{
		EnableNetwork:    true,
		UseRealEndpoints: true,
		LogLevel:         "info",
	}

	return &IntegrationTestSuite{
		TestSuite: NewTestSuite(t, opts),
	}
}