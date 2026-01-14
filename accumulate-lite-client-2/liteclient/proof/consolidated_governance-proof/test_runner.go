// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// =============================================================================
// Test Runner Configuration
// =============================================================================

// TestEndpoints maps network names to RPC endpoints
// Updated to match working Python configuration using local endpoints
var TestEndpoints = map[string]string{
	"devnet":  "http://127.0.0.1:26660/v3",        // Local devnet - matches Python success
	"testnet": "https://testnet.accumulate.io/v3",  // External testnet
	"mainnet": "https://mainnet.accumulate.io/v3",  // External mainnet
}

// TestConfig holds test execution configuration
// SECURITY WARNING: Contains hardcoded test values - DO NOT use in production
type TestConfig struct {
	Network   string // devnet, testnet, mainnet
	Principal string // TESTING ONLY: acc://testtesttest10.acme/data1
	TxID      string // TESTING ONLY: 057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116
	KeyPage   string // TESTING ONLY: acc://testtesttest10.acme/book0/1
	Mode      string // "chained" or "step"
	WorkDir   string // Working directory for artifacts
}

// TestRunner manages governance proof test execution
type TestRunner struct {
	config   TestConfig
	client   *RPCClient
	g0Layer  *G0Layer
	g1Layer  *G1Layer
	g2Layer  *G2Layer
	workDir  string
}

// =============================================================================
// Test Execution Methods
// =============================================================================

// NewTestRunner creates a new test runner with the specified configuration
func NewTestRunner(config TestConfig) (*TestRunner, error) {
	endpoint, exists := TestEndpoints[config.Network]
	if !exists {
		return nil, fmt.Errorf("unknown network: %s (available: devnet, testnet, mainnet)", config.Network)
	}

	// Create working directory
	workDir := fmt.Sprintf("test_results_%s_%d", config.Network, time.Now().Unix())
	if config.WorkDir != "" {
		workDir = config.WorkDir
	}

	// Initialize RPC client
	rpcConfig := RPCConfig{
		Endpoint: endpoint,
		Timeout:  60 * time.Second,
		Backend:  "http",
	}
	client := NewRPCClient(rpcConfig)

	// Initialize artifact manager with enhanced security
	artifactManager, err := NewArtifactManager(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create artifact manager: %v", err)
	}

	// Initialize proof layers with proper sigbytes path (same as Python)
	// Point to the main.go file so it can be run with "go run"
	sigbytesPath := "C:\\Accumulate_Stuff\\accumulate_3695-eliminate-need-for-observer\\accumulate\\tools\\sigbytes\\main.go"
	g0Layer := NewG0Layer(client, artifactManager)
	g1Layer := NewG1Layer(client, artifactManager, sigbytesPath)
	g2Layer := NewG2Layer(client, artifactManager, sigbytesPath, "", "")

	return &TestRunner{
		config:  config,
		client:  client,
		g0Layer: g0Layer,
		g1Layer: g1Layer,
		g2Layer: g2Layer,
		workDir: workDir,
	}, nil
}

// RunChainedExecution runs all proof levels in sequence without pausing
func (tr *TestRunner) RunChainedExecution(ctx context.Context) error {
	fmt.Printf("🔗 CHAINED EXECUTION MODE\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Network: %s\n", tr.config.Network)
	fmt.Printf("Principal: %s\n", tr.config.Principal)
	fmt.Printf("TxID: %s\n", tr.config.TxID)
	fmt.Printf("KeyPage: %s\n", tr.config.KeyPage)
	fmt.Printf("Working Directory: %s\n", tr.workDir)
	fmt.Printf("==========================================\n\n")

	startTime := time.Now()

	// Step 1: Run G0 Proof
	fmt.Printf("🔍 STEP 1: G0 PROOF (Inclusion & Finality)\n")
	g0Result, err := tr.executeG0(ctx)
	if err != nil {
		return fmt.Errorf("G0 proof failed: %v", err)
	}
	fmt.Printf("✅ G0 PROOF COMPLETE\n\n")

	// Step 2: Run G1 Proof
	fmt.Printf("🔐 STEP 2: G1 PROOF (Governance Correctness)\n")
	g1Result, err := tr.executeG1(ctx, g0Result)
	if err != nil {
		return fmt.Errorf("G1 proof failed: %v", err)
	}
	fmt.Printf("✅ G1 PROOF COMPLETE\n\n")

	// Step 3: Run G2 Proof
	fmt.Printf("📋 STEP 3: G2 PROOF (Outcome Binding)\n")
	g2Result, err := tr.executeG2(ctx, g1Result)
	if err != nil {
		return fmt.Errorf("G2 proof failed: %v", err)
	}
	fmt.Printf("✅ G2 PROOF COMPLETE\n\n")

	totalTime := time.Since(startTime)
	tr.printChainedSummary(g0Result, g1Result, g2Result, totalTime)

	return nil
}

// RunStepByStepExecution runs each proof level with user confirmation
func (tr *TestRunner) RunStepByStepExecution(ctx context.Context) error {
	fmt.Printf("⏸️  STEP-BY-STEP EXECUTION MODE\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Network: %s\n", tr.config.Network)
	fmt.Printf("Principal: %s\n", tr.config.Principal)
	fmt.Printf("TxID: %s\n", tr.config.TxID)
	fmt.Printf("KeyPage: %s\n", tr.config.KeyPage)
	fmt.Printf("Working Directory: %s\n", tr.workDir)
	fmt.Printf("==========================================\n\n")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: G0 Proof with pause
	fmt.Printf("🔍 READY FOR STEP 1: G0 PROOF (Inclusion & Finality)\n")
	fmt.Printf("Press Enter to execute G0 proof, or 'q' to quit: ")
	input, _ := reader.ReadString('\n')
	if strings.TrimSpace(input) == "q" {
		fmt.Printf("Test execution cancelled.\n")
		return nil
	}

	g0Start := time.Now()
	g0Result, err := tr.executeG0(ctx)
	if err != nil {
		return fmt.Errorf("G0 proof failed: %v", err)
	}
	g0Duration := time.Since(g0Start)
	fmt.Printf("✅ G0 PROOF COMPLETE (took %v)\n\n", g0Duration)

	// Step 2: G1 Proof with pause
	fmt.Printf("🔐 READY FOR STEP 2: G1 PROOF (Governance Correctness)\n")
	fmt.Printf("G0 Results Summary: TXID=%s, ExecMBI=%d, Principal=%s\n",
		g0Result.TXID[:16], g0Result.ExecMBI, g0Result.Principal)
	fmt.Printf("Press Enter to execute G1 proof, or 'q' to quit: ")
	input, _ = reader.ReadString('\n')
	if strings.TrimSpace(input) == "q" {
		fmt.Printf("Test execution cancelled after G0.\n")
		tr.printPartialSummary("G0", g0Result, nil, nil, g0Duration)
		return nil
	}

	g1Start := time.Now()
	g1Result, err := tr.executeG1(ctx, g0Result)
	if err != nil {
		return fmt.Errorf("G1 proof failed: %v", err)
	}
	g1Duration := time.Since(g1Start)
	fmt.Printf("✅ G1 PROOF COMPLETE (took %v)\n\n", g1Duration)

	// Step 3: G2 Proof with pause
	fmt.Printf("📋 READY FOR STEP 3: G2 PROOF (Outcome Binding)\n")
	fmt.Printf("G1 Results Summary: Signatures=%d, Threshold=%d/%d, Authorization=%v\n",
		len(g1Result.ValidatedSignatures), g1Result.UniqueValidKeys, g1Result.RequiredThreshold, g1Result.ThresholdSatisfied)
	fmt.Printf("Press Enter to execute G2 proof, or 'q' to quit: ")
	input, _ = reader.ReadString('\n')
	if strings.TrimSpace(input) == "q" {
		fmt.Printf("Test execution cancelled after G1.\n")
		tr.printPartialSummary("G1", g0Result, g1Result, nil, g0Duration+g1Duration)
		return nil
	}

	g2Start := time.Now()
	g2Result, err := tr.executeG2(ctx, g1Result)
	if err != nil {
		return fmt.Errorf("G2 proof failed: %v", err)
	}
	g2Duration := time.Since(g2Start)
	fmt.Printf("✅ G2 PROOF COMPLETE (took %v)\n\n", g2Duration)

	totalTime := g0Duration + g1Duration + g2Duration
	tr.printStepSummary(g0Result, g1Result, g2Result, g0Duration, g1Duration, g2Duration, totalTime)

	return nil
}

// =============================================================================
// Individual Proof Level Execution
// =============================================================================

// executeG0 runs G0 proof level
func (tr *TestRunner) executeG0(ctx context.Context) (*G0Result, error) {
	request := G0Request{
		Account:           tr.config.Principal,
		TxHash:            tr.config.TxID,
		Chain:             "main",
		CanonicalTxHash:   &tr.config.TxID,
	}

	return tr.g0Layer.ProveG0(ctx, request)
}

// executeG1 runs G1 proof level
func (tr *TestRunner) executeG1(ctx context.Context, g0Result *G0Result) (*G1Result, error) {
	request := G1Request{
		G0Request: G0Request{
			Account:           tr.config.Principal,
			TxHash:            tr.config.TxID,
			Chain:             "main",
			CanonicalTxHash:   &tr.config.TxID,
		},
		KeyPage: tr.config.KeyPage,
	}

	return tr.g1Layer.ProveG1(ctx, request)
}

// executeG2 runs G2 proof level
func (tr *TestRunner) executeG2(ctx context.Context, g1Result *G1Result) (*G2Result, error) {
	request := G2Request{
		G1Request: G1Request{
			G0Request: G0Request{
				Account:           tr.config.Principal,
				TxHash:            g1Result.TxHash,
				Chain:             "main",
				CanonicalTxHash:   &g1Result.TxHash,
			},
			KeyPage: tr.config.KeyPage,
		},
	}

	return tr.g2Layer.ProveG2(ctx, request)
}

// =============================================================================
// Summary and Reporting
// =============================================================================

// printChainedSummary prints results for chained execution
func (tr *TestRunner) printChainedSummary(g0 *G0Result, g1 *G1Result, g2 *G2Result, totalTime time.Duration) {
	fmt.Printf("🎉 CHAINED EXECUTION COMPLETE\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Network: %s\n", tr.config.Network)
	fmt.Printf("Total Execution Time: %v\n", totalTime)
	fmt.Printf("Working Directory: %s\n", tr.workDir)
	fmt.Printf("==========================================\n\n")

	fmt.Printf("📊 PROOF RESULTS SUMMARY:\n")
	fmt.Printf("┌─────────────────────────────────────┐\n")
	fmt.Printf("│ G0 (Inclusion & Finality)           │\n")
	fmt.Printf("├─────────────────────────────────────┤\n")
	fmt.Printf("│ TXID: %s...             │\n", g0.TXID[:16])
	fmt.Printf("│ Exec MBI: %-25d │\n", g0.ExecMBI)
	fmt.Printf("│ Principal: %s...        │\n", g0.Principal[:16])
	fmt.Printf("│ Status: ✅ COMPLETE                  │\n")
	fmt.Printf("├─────────────────────────────────────┤\n")
	fmt.Printf("│ G1 (Governance Correctness)        │\n")
	fmt.Printf("├─────────────────────────────────────┤\n")
	fmt.Printf("│ Signatures: %-23d │\n", len(g1.ValidatedSignatures))
	fmt.Printf("│ Unique Keys: %d/%-18d │\n", g1.UniqueValidKeys, g1.RequiredThreshold)
	fmt.Printf("│ Threshold: %-24v │\n", g1.ThresholdSatisfied)
	fmt.Printf("│ Cryptographic: %-18v │\n", g1.CryptographicSecurity)
	fmt.Printf("│ Status: ✅ COMPLETE                  │\n")
	fmt.Printf("├─────────────────────────────────────┤\n")
	fmt.Printf("│ G2 (Outcome Binding)                │\n")
	fmt.Printf("├─────────────────────────────────────┤\n")
	fmt.Printf("│ Payload Verified: %-17v │\n", g2.PayloadVerified)
	fmt.Printf("│ Effect Verified: %-18v │\n", g2.EffectVerified)
	fmt.Printf("│ Receipt Binding: %-18v │\n", g2.G2ProofComplete)
	fmt.Printf("│ Status: ✅ COMPLETE                  │\n")
	fmt.Printf("└─────────────────────────────────────┘\n\n")

	fmt.Printf("📁 Artifacts saved to: %s\n", tr.workDir)
	fmt.Printf("🔒 Security Level: ENHANCED_CRYPTOGRAPHIC\n")
}

// printStepSummary prints results for step-by-step execution
func (tr *TestRunner) printStepSummary(g0 *G0Result, g1 *G1Result, g2 *G2Result,
	g0Time, g1Time, g2Time, totalTime time.Duration) {
	fmt.Printf("🎉 STEP-BY-STEP EXECUTION COMPLETE\n")
	fmt.Printf("==========================================\n")
	fmt.Printf("Network: %s\n", tr.config.Network)
	fmt.Printf("G0 Time: %v\n", g0Time)
	fmt.Printf("G1 Time: %v\n", g1Time)
	fmt.Printf("G2 Time: %v\n", g2Time)
	fmt.Printf("Total Time: %v\n", totalTime)
	fmt.Printf("Working Directory: %s\n", tr.workDir)
	fmt.Printf("==========================================\n\n")

	// Same detailed summary as chained
	tr.printChainedSummary(g0, g1, g2, totalTime)
}

// printPartialSummary prints results for incomplete execution
func (tr *TestRunner) printPartialSummary(lastLevel string, g0 *G0Result, g1 *G1Result, g2 *G2Result, totalTime time.Duration) {
	fmt.Printf("⚠️  PARTIAL EXECUTION COMPLETE (stopped at %s)\n", lastLevel)
	fmt.Printf("==========================================\n")
	fmt.Printf("Network: %s\n", tr.config.Network)
	fmt.Printf("Execution Time: %v\n", totalTime)
	fmt.Printf("Working Directory: %s\n", tr.workDir)
	fmt.Printf("==========================================\n\n")

	if g0 != nil {
		fmt.Printf("✅ G0 COMPLETE: TXID=%s..., ExecMBI=%d\n", g0.TXID[:16], g0.ExecMBI)
	}
	if g1 != nil {
		fmt.Printf("✅ G1 COMPLETE: %d signatures, %d/%d keys, threshold=%v\n",
			len(g1.ValidatedSignatures), g1.UniqueValidKeys, g1.RequiredThreshold, g1.ThresholdSatisfied)
	}
	if g2 != nil {
		fmt.Printf("✅ G2 COMPLETE: Payload=%v, Effect=%v\n",
			g2.PayloadVerified, g2.EffectVerified)
	}

	fmt.Printf("\n📁 Partial artifacts saved to: %s\n", tr.workDir)
}

// =============================================================================
// Test Validation and Utilities
// =============================================================================

// ValidateTestConfig validates the test configuration parameters
func ValidateTestConfig(config TestConfig) error {
	// Validate network
	if _, exists := TestEndpoints[config.Network]; !exists {
		return fmt.Errorf("invalid network '%s'. Available: devnet, testnet, mainnet", config.Network)
	}

	// Validate TxID format (should be 64-char hex)
	if len(config.TxID) != 64 {
		return fmt.Errorf("invalid TxID length: %d (expected 64)", len(config.TxID))
	}

	// Validate principal format (should start with acc://)
	if !strings.HasPrefix(config.Principal, "acc://") {
		return fmt.Errorf("invalid principal format: %s (should start with acc://)", config.Principal)
	}

	// Validate key page format (should start with acc://)
	if !strings.HasPrefix(config.KeyPage, "acc://") {
		return fmt.Errorf("invalid key page format: %s (should start with acc://)", config.KeyPage)
	}

	// Validate mode
	if config.Mode != "chained" && config.Mode != "step" {
		return fmt.Errorf("invalid mode '%s'. Available: chained, step", config.Mode)
	}

	return nil
}

// PrintTestHelp prints usage information for the test runner
func PrintTestHelp() {
	fmt.Printf("🧪 GOVERNANCE PROOF TEST RUNNER\n")
	fmt.Printf("===============================================\n")
	fmt.Printf("Usage examples:\n\n")
	fmt.Printf("Chained execution (all levels):\n")
	fmt.Printf("  --test --mode chained --v3 devnet --principal acc://testtesttest10.acme/data1 --txid 057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116 --page acc://testtesttest10.acme/book0/1\n\n")
	fmt.Printf("Step-by-step execution (with pauses):\n")
	fmt.Printf("  --test --mode step --v3 devnet --principal acc://testtesttest10.acme/data1 --txid 057c2fc6ae1b8793a3f259705ee1b26f44e4ffed26ac0b897dc0fb733a19f116 --page acc://testtesttest10.acme/book0/1\n\n")
	fmt.Printf("Available networks: devnet, testnet, mainnet\n")
	fmt.Printf("Available modes: chained, step\n\n")
	fmt.Printf("Test Parameters:\n")
	fmt.Printf("  --v3        Network endpoint (devnet/testnet/mainnet)\n")
	fmt.Printf("  --principal Transaction principal (acc://...)\n")
	fmt.Printf("  --txid      Transaction ID (64-char hex)\n")
	fmt.Printf("  --page      Key page for authorization (acc://...)\n")
	fmt.Printf("  --mode      Execution mode (chained/step)\n")
	fmt.Printf("  --workdir   Custom working directory (optional)\n")
	fmt.Printf("===============================================\n")
}