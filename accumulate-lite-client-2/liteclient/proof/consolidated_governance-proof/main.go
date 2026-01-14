// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// CERTEN Governance Proof CLI
// Production-ready command line interface for consolidated governance proof system
// Implements CERTEN Governance Proof Specification v3-governance-kpsw-exec-4.0

const (
	AppName    = "govproof"
	AppVersion = "v3-governance-kpsw-exec-4.0"
	AppUsage   = `CERTEN Governance Proof Generator

USAGE:
  govproof [OPTIONS] <account> <txhash>

PROOF LEVELS:
  G0  Inclusion and Finality Only (No Governance)
  G1  Governance Correctness (Default)
  G2  Governance Correctness + Outcome Binding

EXAMPLES:
  # G0 proof (inclusion only)
  govproof --level G0 acc://example.acme main 1234567890abcdef...

  # G1 proof (governance correctness)
  govproof --level G1 --keypage acc://example.acme/page/1 acc://example.acme main 1234567890abcdef...

  # G2 proof (governance + outcome binding)
  govproof --level G2 --keypage acc://example.acme/page/1 --gomoddir ./verifier --goverify ./verify.go acc://example.acme main 1234567890abcdef...

OPTIONS:`
)

// CLIConfig holds command line configuration
type CLIConfig struct {
	// Required arguments
	Account string
	Chain   string
	TxHash  string

	// Proof level
	Level string

	// G1+ options
	KeyPage       string
	SigningDomain string

	// G2+ options
	GoModDir        string
	GoVerifyPath    string
	TxHashPath      string // Path to txhash tool for G2 payload verification
	SigbytesPath    string
	ExpectEntryHash string

	// RPC configuration
	V3Endpoint string
	UseHTTP    bool
	UseCurl    bool

	// Output configuration
	WorkDir    string
	OutputJSON bool
	Quiet      bool
	Verbose    bool

	// Performance options
	Timeout int

	// Test runner options
	TestMode     bool
	TestNetwork  string
	TestPrincipal string
	TestTxID     string
	TestKeyPage  string
	TestRunMode  string // "chained" or "step"
	TestWorkDir  string
}

// main is the entry point for the governance proof CLI
func main() {
	// Initialize performance optimization systems
	InitLogger()
	InitPools()
	InitRPCCache()

	// Log startup message with performance features enabled
	LogInfo("MAIN", "CERTEN Governance Proof %s starting with performance optimizations", AppVersion)

	config, err := parseFlags()
	if err != nil {
		LogError("MAIN", "Configuration error: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Set log level based on configuration
	logger := GetLogger()
	if config.Quiet {
		logger.SetLogLevel(LogLevelError)
	} else if config.Verbose {
		logger.SetLogLevel(LogLevelDebug)
	}

	// Handle test mode
	if config.TestMode {
		LogInfo("MAIN", "Running in test mode: %s", config.TestRunMode)
		if err := runTestMode(config); err != nil {
			LogError("MAIN", "Test execution failed: %v", err)
			if !config.Quiet {
				fmt.Fprintf(os.Stderr, "Test Error: %v\n", err)
			}
			os.Exit(1)
		}

		// Print cache statistics if debug is enabled
		if IsDebugEnabled() {
			hits, misses, size, hitRate := GetRPCCache().GetStats()
			LogInfo("CACHE", "Session stats - Hits: %d, Misses: %d, Size: %d, Hit Rate: %.1f%%", hits, misses, size, hitRate)
		}
		return
	}

	// Handle normal proof mode
	LogInfo("MAIN", "Running governance proof for level: %s", config.Level)
	if err := runGovernanceProof(config); err != nil {
		LogError("MAIN", "Governance proof failed: %v", err)
		if !config.Quiet {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}

	LogInfo("MAIN", "Governance proof completed successfully")
}

// parseFlags parses command line flags and arguments
func parseFlags() (*CLIConfig, error) {
	config := &CLIConfig{
		Level:         "G1",
		Chain:         "main",
		SigningDomain: "accumulate_ed25519",
		V3Endpoint:    "http://127.0.0.1:26660/v3",
		UseHTTP:       true,
		UseCurl:       false,
		Timeout:       30,
	}

	// Define flags
	flag.StringVar(&config.Level, "level", config.Level, "Proof level: G0, G1, G2")
	flag.StringVar(&config.KeyPage, "keypage", "", "Key page URL (required for G1+)")
	flag.StringVar(&config.KeyPage, "page", "", "Key page URL (alias for --keypage)")
	flag.StringVar(&config.SigningDomain, "signing-domain", config.SigningDomain, "Signing domain for signature verification")
	flag.StringVar(&config.GoModDir, "gomoddir", "", "Go module directory for G2 verifier")
	flag.StringVar(&config.GoVerifyPath, "goverify", "", "Path to Go verifier tool/source (deprecated, use --txhash)")
	flag.StringVar(&config.TxHashPath, "txhash", "", "Path to txhash tool for G2 payload verification")
	flag.StringVar(&config.SigbytesPath, "sigbytes", "", "Path to sigbytes tool")
	flag.StringVar(&config.ExpectEntryHash, "expect-entry", "", "Expected entry hash for effect verification")
	flag.StringVar(&config.V3Endpoint, "endpoint", config.V3Endpoint, "Accumulate v3 RPC endpoint")
	flag.StringVar(&config.TestNetwork, "v3", "", "Test network: devnet, testnet, mainnet")
	flag.BoolVar(&config.UseHTTP, "http", config.UseHTTP, "Use HTTP client")
	flag.BoolVar(&config.UseCurl, "curl", config.UseCurl, "Use curl client")
	flag.StringVar(&config.WorkDir, "workdir", "", "Working directory for artifacts")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output result as JSON")
	flag.BoolVar(&config.Quiet, "quiet", false, "Suppress progress output")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.IntVar(&config.Timeout, "timeout", config.Timeout, "Request timeout in seconds")

	// Test runner flags
	flag.BoolVar(&config.TestMode, "test", false, "Run in test/integration mode")
	flag.StringVar(&config.TestRunMode, "mode", "chained", "Test execution mode: chained or step")
	flag.StringVar(&config.TestPrincipal, "principal", "", "Test principal (account)")
	flag.StringVar(&config.TestTxID, "txid", "", "Test transaction ID")
	flag.StringVar(&config.TestKeyPage, "testpage", "", "Test key page (overrides --page in test mode)")
	flag.StringVar(&config.TestWorkDir, "testworkdir", "", "Test working directory")

	// Custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", AppUsage)
		flag.PrintDefaults()
	}

	flag.Parse()

	// Handle test mode flag detection
	if config.TestMode {
		// In test mode, use flags instead of positional arguments
		if config.TestNetwork == "" {
			return nil, fmt.Errorf("test mode requires --v3 <network>")
		}
		if config.TestPrincipal == "" {
			return nil, fmt.Errorf("test mode requires --principal <account>")
		}
		if config.TestTxID == "" {
			return nil, fmt.Errorf("test mode requires --txid <txhash>")
		}
		if config.KeyPage == "" && config.TestKeyPage == "" {
			return nil, fmt.Errorf("test mode requires --page <keypage>")
		}
		// Override keypage with test-specific if provided
		if config.TestKeyPage != "" {
			config.KeyPage = config.TestKeyPage
		}
	} else {
		// Normal mode: parse positional arguments
		args := flag.Args()
		if len(args) < 2 {
			return nil, fmt.Errorf("missing required arguments: <account> <txhash>")
		}

		config.Account = args[0]
		if len(args) == 2 {
			config.TxHash = args[1]
		} else if len(args) == 3 {
			config.Chain = args[1]
			config.TxHash = args[2]
		} else {
			return nil, fmt.Errorf("too many arguments")
		}
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Handle test help request
	if config.TestMode && config.TestNetwork == "help" {
		PrintTestHelp()
		os.Exit(0)
	}

	return config, nil
}

// validateConfig validates CLI configuration
func validateConfig(config *CLIConfig) error {
	// Validate proof level
	level := strings.ToUpper(config.Level)
	if level != "G0" && level != "G1" && level != "G2" {
		return fmt.Errorf("invalid proof level: %s (must be G0, G1, or G2)", config.Level)
	}
	config.Level = level

	// Validate G1+ requirements
	if (level == "G1" || level == "G2") && config.KeyPage == "" {
		return fmt.Errorf("G1+ proofs require --keypage")
	}

	// Validate working directory
	if config.WorkDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %v", err)
		}
		config.WorkDir = wd
	}

	// Ensure working directory exists
	if err := os.MkdirAll(config.WorkDir, 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %v", err)
	}

	// Validate RPC configuration
	if config.UseCurl && config.UseHTTP {
		config.UseHTTP = false // Curl takes precedence
	}

	return nil
}

// runGovernanceProof executes the governance proof generation
func runGovernanceProof(config *CLIConfig) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
	defer cancel()

	if !config.Quiet {
		fmt.Printf("[GOVPROOF] %s %s\n", AppName, AppVersion)
		fmt.Printf("[GOVPROOF] Starting %s proof for %s\n", config.Level, SafeTruncate(config.TxHash, 16))
	}

	// Initialize components
	rpcClient, artifactManager, err := initializeComponents(config)
	if err != nil {
		return fmt.Errorf("initialization failed: %v", err)
	}

	// Generate proof based on level
	var result interface{}
	var proofErr error

	switch config.Level {
	case "G0":
		result, proofErr = generateG0Proof(ctx, config, rpcClient, artifactManager)
	case "G1":
		result, proofErr = generateG1Proof(ctx, config, rpcClient, artifactManager)
	case "G2":
		result, proofErr = generateG2Proof(ctx, config, rpcClient, artifactManager)
	default:
		return fmt.Errorf("unsupported proof level: %s", config.Level)
	}

	if proofErr != nil {
		return fmt.Errorf("proof generation failed: %v", proofErr)
	}

	// Output result
	if err := outputResult(config, result); err != nil {
		return fmt.Errorf("output failed: %v", err)
	}

	if !config.Quiet {
		fmt.Printf("[GOVPROOF] %s proof complete\n", config.Level)
	}

	return nil
}

// initializeComponents initializes RPC client and artifact manager
func initializeComponents(config *CLIConfig) (RPCClientInterface, *ArtifactManager, error) {
	// Initialize RPC client
	rpcConfig := RPCConfig{
		Endpoint:  config.V3Endpoint,
		UseHTTP:   config.UseHTTP,
		UseCurl:   config.UseCurl,
		UserAgent: fmt.Sprintf("%s/%s", AppName, AppVersion),
	}

	baseClient := NewRPCClient(rpcConfig)
	rpcClient := NewCachedRPCClient(baseClient)

	// Initialize artifact manager
	artifactManager, err := NewArtifactManager(config.WorkDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create artifact manager: %v", err)
	}

	if config.Verbose {
		fmt.Printf("[INIT] RPC endpoint: %s\n", config.V3Endpoint)
		fmt.Printf("[INIT] Working directory: %s\n", config.WorkDir)
	}

	return rpcClient, artifactManager, nil
}

// generateG0Proof generates G0 proof (Inclusion and Finality Only)
func generateG0Proof(ctx context.Context, config *CLIConfig, client RPCClientInterface, am *ArtifactManager) (*G0Result, error) {
	g0Layer := NewG0Layer(client, am)

	request := G0Request{
		Account:    config.Account,
		TxHash:     config.TxHash,
		Chain:      config.Chain,
		V3Endpoint: config.V3Endpoint,
		WorkDir:    config.WorkDir,
	}

	result, err := g0Layer.ProveG0(ctx, request)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		fmt.Printf("[G0] Execution MBI: %d\n", result.ExecMBI)
		fmt.Printf("[G0] Execution witness: %s\n", result.ExecWitness[:16])
		fmt.Printf("[G0] Principal: %s\n", result.Principal)
	}

	return result, nil
}

// generateG1Proof generates G1 proof (Governance Correctness)
func generateG1Proof(ctx context.Context, config *CLIConfig, client RPCClientInterface, am *ArtifactManager) (*G1Result, error) {
	g1Layer := NewG1Layer(client, am, config.SigbytesPath)

	request := G1Request{
		G0Request: G0Request{
			Account:    config.Account,
			TxHash:     config.TxHash,
			Chain:      config.Chain,
			V3Endpoint: config.V3Endpoint,
			WorkDir:    config.WorkDir,
		},
		KeyPage:       config.KeyPage,
		SigningDomain: config.SigningDomain,
	}

	result, err := g1Layer.ProveG1(ctx, request)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		fmt.Printf("[G1] Authority version: %d\n", result.AuthoritySnapshot.StateExec.Version)
		fmt.Printf("[G1] Authority threshold: %d\n", result.AuthoritySnapshot.StateExec.Threshold)
		fmt.Printf("[G1] Valid signatures: %d\n", len(result.ValidatedSignatures))
		fmt.Printf("[G1] Unique valid keys: %d\n", result.UniqueValidKeys)
		fmt.Printf("[G1] Authorization verified: %t\n", result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess)
	}

	return result, nil
}

// generateG2Proof generates G2 proof (Governance + Outcome Binding)
func generateG2Proof(ctx context.Context, config *CLIConfig, client RPCClientInterface, am *ArtifactManager) (*G2Result, error) {
	// Use TxHashPath for G2 payload verification, fallback to GoVerifyPath for backwards compatibility
	txHashToolPath := config.TxHashPath
	if txHashToolPath == "" {
		txHashToolPath = config.GoVerifyPath
	}
	g2Layer := NewG2Layer(client, am, config.SigbytesPath, config.GoModDir, txHashToolPath)

	var expectEntryHash *string
	if config.ExpectEntryHash != "" {
		expectEntryHash = &config.ExpectEntryHash
	}

	var goModDir *string
	if config.GoModDir != "" {
		goModDir = &config.GoModDir
	}

	var sigbytesPath *string
	if config.SigbytesPath != "" {
		sigbytesPath = &config.SigbytesPath
	}

	request := G2Request{
		G1Request: G1Request{
			G0Request: G0Request{
				Account:    config.Account,
				TxHash:     config.TxHash,
				Chain:      config.Chain,
				V3Endpoint: config.V3Endpoint,
				WorkDir:    config.WorkDir,
			},
			KeyPage:       config.KeyPage,
			SigningDomain: config.SigningDomain,
		},
		GoModDir:        goModDir,
		SigbytesPath:    sigbytesPath,
		ExpectEntryHash: expectEntryHash,
	}

	result, err := g2Layer.ProveG2(ctx, request)
	if err != nil {
		return nil, err
	}

	if config.Verbose {
		fmt.Printf("[G2] Payload verified: %t\n", result.PayloadVerified)
		fmt.Printf("[G2] Effect verified: %t\n", result.EffectVerified)
		fmt.Printf("[G2] G2 complete: %t\n", result.G2ProofComplete)
		fmt.Printf("[G2] Security level: %s\n", result.SecurityLevel)
	}

	return result, nil
}

// outputResult outputs the proof result
func outputResult(config *CLIConfig, result interface{}) error {
	if config.OutputJSON {
		// JSON output using pooled marshaling for better performance
		jsonData, err := JSONMarshalPooled(result)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	} else {
		// Human-readable output
		switch r := result.(type) {
		case *G0Result:
			printG0Result(config, r)
		case *G1Result:
			printG1Result(config, r)
		case *G2Result:
			printG2Result(config, r)
		default:
			return fmt.Errorf("unknown result type: %T", result)
		}
	}

	return nil
}

// printG0Result prints G0 result in human-readable format
func printG0Result(config *CLIConfig, result *G0Result) {
	if !config.Quiet {
		fmt.Printf("\n=== G0 PROOF RESULT ===\n")
		fmt.Printf("Proof Level: G0 (Inclusion and Finality Only)\n")
		fmt.Printf("TXID: %s\n", result.TXID)
		fmt.Printf("TX_HASH: %s\n", result.TxHash)
		fmt.Printf("Execution MBI: %d\n", result.ExecMBI)
		fmt.Printf("Execution Witness: %s\n", result.ExecWitness)
		fmt.Printf("Scope: %s\n", result.Scope)
		fmt.Printf("Principal: %s\n", result.Principal)
		fmt.Printf("Chain: %s\n", result.Chain)
		fmt.Printf("G0 Complete: %t\n", result.G0ProofComplete)
		fmt.Printf("========================\n")
	}
}

// printG1Result prints G1 result in human-readable format
func printG1Result(config *CLIConfig, result *G1Result) {
	if !config.Quiet {
		fmt.Printf("\n=== G1 PROOF RESULT ===\n")
		fmt.Printf("Proof Level: G1 (Governance Correctness)\n")
		fmt.Printf("TX_HASH: %s\n", result.TxHash)
		fmt.Printf("Principal: %s\n", result.Principal)
		fmt.Printf("Key Page: %s\n", result.AuthoritySnapshot.Page)
		fmt.Printf("Authority Version: %d\n", result.AuthoritySnapshot.StateExec.Version)
		fmt.Printf("Authority Threshold: %d\n", result.AuthoritySnapshot.StateExec.Threshold)
		fmt.Printf("Authority Keys: %d\n", len(result.AuthoritySnapshot.StateExec.Keys))
		fmt.Printf("Valid Signatures: %d\n", len(result.ValidatedSignatures))
		fmt.Printf("Unique Valid Keys: %d\n", result.UniqueValidKeys)
		fmt.Printf("Required Threshold: %d\n", result.RequiredThreshold)
		fmt.Printf("Threshold Satisfied: %t\n", result.ThresholdSatisfied)
		fmt.Printf("Timing Valid: %t\n", result.TimingValid)
		fmt.Printf("Authorization Verified: %t\n", result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess)
		fmt.Printf("G1 Complete: %t\n", result.G1ProofComplete)
		fmt.Printf("========================\n")
	}
}

// printG2Result prints G2 result in human-readable format
func printG2Result(config *CLIConfig, result *G2Result) {
	if !config.Quiet {
		fmt.Printf("\n=== G2 PROOF RESULT ===\n")
		fmt.Printf("Proof Level: G2 (Governance + Outcome Binding)\n")
		fmt.Printf("TX_HASH: %s\n", result.TxHash)
		fmt.Printf("Principal: %s\n", result.Principal)
		fmt.Printf("Authorization Verified: %t\n", result.ThresholdSatisfied && result.TimingValid && result.ExecutionSuccess)
		fmt.Printf("Payload Verified: %t\n", result.PayloadVerified)
		fmt.Printf("Effect Verified: %t\n", result.EffectVerified)
		fmt.Printf("Receipt Binding: %t\n", result.OutcomeLeaf.ReceiptBinding.Verified)
		fmt.Printf("Witness Consistency: %t\n", result.OutcomeLeaf.WitnessConsistency.Verified)
		fmt.Printf("G2 Complete: %t\n", result.G2ProofComplete)
		fmt.Printf("Security Level: %s\n", result.SecurityLevel)

		if result.OutcomeLeaf.PayloadBinding.ComputedTxHash != "" {
			fmt.Printf("Computed Hash: %s\n", result.OutcomeLeaf.PayloadBinding.ComputedTxHash)
			fmt.Printf("Expected Hash: %s\n", result.OutcomeLeaf.PayloadBinding.ExpectedTxHash)
		}
		fmt.Printf("========================\n")
	}
}

// printVersion prints version information
func printVersion() {
	fmt.Printf("%s %s\n", AppName, AppVersion)
	fmt.Printf("CERTEN Governance Proof Specification %s\n", SpecVersion)
}