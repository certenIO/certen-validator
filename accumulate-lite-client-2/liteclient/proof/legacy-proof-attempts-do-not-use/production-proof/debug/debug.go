// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package debug provides comprehensive debug and verbose output for proof verification
package debug

import (
	"context"
	"fmt"
	"strings"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/interfaces"
)

// DebugVerifier wraps the CryptographicVerifier with rich debug output
type DebugVerifier struct {
	verifier    *core.CryptographicVerifier
	verboseMode bool
	logLevel    DebugLevel
	output      DebugOutput
}

// DebugLevel defines the level of debug output
type DebugLevel int

const (
	DebugLevelNone DebugLevel = iota
	DebugLevelBasic
	DebugLevelDetailed
	DebugLevelVerbose
	DebugLevelTrace
)

// DebugOutput handles where debug output goes
type DebugOutput interface {
	Printf(format string, args ...interface{})
	Print(args ...interface{})
	Println(args ...interface{})
}

// ConsoleOutput implements DebugOutput for console output
type ConsoleOutput struct{}

func (c *ConsoleOutput) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (c *ConsoleOutput) Print(args ...interface{}) {
	fmt.Print(args...)
}

func (c *ConsoleOutput) Println(args ...interface{}) {
	fmt.Println(args...)
}

// NewDebugVerifier creates a new debug-enabled verifier
func NewDebugVerifier(verifier *core.CryptographicVerifier, level DebugLevel, verbose bool) *DebugVerifier {
	return &DebugVerifier{
		verifier:    verifier,
		verboseMode: verbose,
		logLevel:    level,
		output:      &ConsoleOutput{},
	}
}

// SetOutput sets the debug output destination
func (d *DebugVerifier) SetOutput(output DebugOutput) {
	d.output = output
}

// SetLogLevel sets the debug log level
func (d *DebugVerifier) SetLogLevel(level DebugLevel) {
	d.logLevel = level
}

// SetVerboseMode enables or disables verbose mode
func (d *DebugVerifier) SetVerboseMode(verbose bool) {
	d.verboseMode = verbose
}

// VerifyAccountWithDebug performs account verification with comprehensive debug output
func (d *DebugVerifier) VerifyAccountWithDebug(accountURL string) (*core.VerificationResult, *interfaces.DebugInfo, error) {
	startTime := time.Now()
	debugInfo := &interfaces.DebugInfo{
		AccountURL:        accountURL,
		LayerTimes:        make(map[string]time.Duration),
		CacheHits:         make(map[string]bool),
		Errors:            []string{},
		Warnings:          []string{},
		VerificationSteps: []interfaces.VerificationStep{},
	}

	if d.logLevel >= DebugLevelBasic {
		d.printVerificationHeader(accountURL)
	}

	// Parse URL and perform verification
	parsedURL, err := url.Parse(accountURL)
	if err != nil {
		debugInfo.Errors = append(debugInfo.Errors, fmt.Sprintf("URL parsing failed: %v", err))
		d.logError("URL parsing failed", err)
		return nil, debugInfo, err
	}

	if d.logLevel >= DebugLevelDetailed {
		d.output.Printf("📋 Parsed Account URL: %s\n", parsedURL.String())
		d.output.Printf("   Authority: %s\n", parsedURL.Authority)
		d.output.Printf("   Path: %s\n", parsedURL.Path)
	}

	// Perform verification with timing
	result, err := d.verifier.VerifyAccount(context.Background(), parsedURL)
	if err != nil {
		debugInfo.Errors = append(debugInfo.Errors, fmt.Sprintf("Verification failed: %v", err))
		d.logError("Verification failed", err)
		return nil, debugInfo, err
	}

	debugInfo.GenerationTime = time.Since(startTime)

	// Analyze and report on each layer
	d.analyzeVerificationResult(result, debugInfo)

	if d.logLevel >= DebugLevelBasic {
		d.printVerificationSummary(result, debugInfo)
	}

	return result, debugInfo, nil
}

// analyzeVerificationResult provides detailed analysis of verification results
func (d *DebugVerifier) analyzeVerificationResult(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n========================================")
		d.output.Println("Layer-by-Layer Verification Analysis")
		d.output.Println("========================================")
	}

	// Analyze Layer 1
	d.analyzeLayer1(result, debugInfo)

	// Analyze Layer 2
	d.analyzeLayer2(result, debugInfo)

	// Analyze Layer 3
	d.analyzeLayer3(result, debugInfo)

	// Analyze Layer 4
	d.analyzeLayer4(result, debugInfo)

	// Overall analysis
	d.analyzeOverall(result, debugInfo)
}

// analyzeLayer1 analyzes Layer 1 verification results
func (d *DebugVerifier) analyzeLayer1(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	layerStartTime := time.Now()

	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n🔍 Layer 1: Account State → BPT Root")
		d.output.Println("----------------------------------------")
	}

	layer1, exists := result.Layers["layer1"]
	if !exists {
		d.logWarning("Layer 1 results not found")
		debugInfo.Warnings = append(debugInfo.Warnings, "Layer 1 results not found")
		return
	}

	step := interfaces.VerificationStep{
		Layer:       "Layer 1",
		Description: "Account State → BPT Root",
		Duration:    time.Since(layerStartTime),
		Success:     layer1.Verified,
		Details:     make(map[string]interface{}),
	}

	if layer1.Error != "" {
		step.Error = fmt.Errorf("%s", layer1.Error)
		d.logError("Layer 1 failed", step.Error)
	}

	if result.Layer1Result != nil {
		l1 := result.Layer1Result
		step.Details["accountHash"] = l1.AccountHash
		step.Details["bptRoot"] = l1.BPTRoot
		step.Details["proofEntries"] = l1.ProofEntries
		step.Details["blockIndex"] = l1.BlockIndex
		step.Details["blockTime"] = l1.BlockTime

		if d.logLevel >= DebugLevelVerbose {
			d.output.Printf("   Account Hash: %s\n", d.formatHash(l1.AccountHash))
			d.output.Printf("   BPT Root: %s\n", d.formatHash(l1.BPTRoot))
			d.output.Printf("   Proof Entries: %d\n", l1.ProofEntries)
			d.output.Printf("   Block Index: %d\n", l1.BlockIndex)
			d.output.Printf("   Block Time: %d\n", l1.BlockTime)
		}
	}

	if layer1.Verified {
		if d.logLevel >= DebugLevelBasic {
			d.output.Println("   ✅ Layer 1 Verified: Account merkle proof valid")
		}
	} else {
		if d.logLevel >= DebugLevelBasic {
			d.output.Printf("   ❌ Layer 1 Failed: %s\n", layer1.Error)
		}
		debugInfo.Errors = append(debugInfo.Errors, fmt.Sprintf("Layer 1: %s", layer1.Error))
	}

	debugInfo.LayerTimes["layer1"] = step.Duration
	debugInfo.VerificationSteps = append(debugInfo.VerificationSteps, step)
}

// analyzeLayer2 analyzes Layer 2 verification results
func (d *DebugVerifier) analyzeLayer2(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	layerStartTime := time.Now()

	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n🔗 Layer 2: BPT Root → Block Hash")
		d.output.Println("----------------------------------------")
	}

	layer2, exists := result.Layers["layer2"]
	if !exists {
		d.logWarning("Layer 2 results not found")
		debugInfo.Warnings = append(debugInfo.Warnings, "Layer 2 results not found")
		return
	}

	step := interfaces.VerificationStep{
		Layer:       "Layer 2",
		Description: "BPT Root → Block Hash",
		Duration:    time.Since(layerStartTime),
		Success:     layer2.Verified,
		Details:     make(map[string]interface{}),
	}

	if layer2.Error != "" {
		step.Error = fmt.Errorf("%s", layer2.Error)
		d.logError("Layer 2 failed", step.Error)
	}

	if result.Layer2Result != nil {
		l2 := result.Layer2Result
		step.Details["blockHeight"] = l2.BlockHeight
		step.Details["blockHash"] = l2.BlockHash
		step.Details["appHash"] = l2.AppHash
		step.Details["trustRequired"] = l2.TrustRequired

		if d.logLevel >= DebugLevelVerbose {
			d.output.Printf("   Block Height: %d\n", l2.BlockHeight)
			d.output.Printf("   Block Hash: %s\n", d.formatHash(l2.BlockHash))
			d.output.Printf("   App Hash: %s\n", d.formatHash(l2.AppHash))
			if l2.TrustRequired != "" {
				d.output.Printf("   Trust Required: %s\n", l2.TrustRequired)
			}
		}
	}

	if layer2.Verified {
		if d.logLevel >= DebugLevelBasic {
			d.output.Println("   ✅ Layer 2 Verified: BPT root committed in block")
		}
	} else {
		if d.logLevel >= DebugLevelBasic {
			d.output.Printf("   ❌ Layer 2 Failed: %s\n", layer2.Error)
		}
		debugInfo.Errors = append(debugInfo.Errors, fmt.Sprintf("Layer 2: %s", layer2.Error))
	}

	debugInfo.LayerTimes["layer2"] = step.Duration
	debugInfo.VerificationSteps = append(debugInfo.VerificationSteps, step)
}

// analyzeLayer3 analyzes Layer 3 verification results
func (d *DebugVerifier) analyzeLayer3(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	layerStartTime := time.Now()

	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n✍️ Layer 3: Block Hash → Validator Signatures")
		d.output.Println("----------------------------------------")
	}

	layer3, exists := result.Layers["layer3"]
	if !exists {
		d.logWarning("Layer 3 results not found")
		debugInfo.Warnings = append(debugInfo.Warnings, "Layer 3 results not found")
		return
	}

	step := interfaces.VerificationStep{
		Layer:       "Layer 3",
		Description: "Block Hash → Validator Signatures",
		Duration:    time.Since(layerStartTime),
		Success:     layer3.Verified,
		Details:     make(map[string]interface{}),
	}

	if layer3.Error != "" {
		step.Error = fmt.Errorf("%s", layer3.Error)
		d.logError("Layer 3 failed", step.Error)
	}

	if result.Layer3Result != nil {
		l3 := result.Layer3Result
		step.Details["totalValidators"] = l3.TotalValidators
		step.Details["signedValidators"] = l3.SignedValidators
		step.Details["totalPower"] = l3.TotalPower
		step.Details["signedPower"] = l3.SignedPower
		step.Details["thresholdMet"] = l3.ThresholdMet
		step.Details["chainID"] = l3.ChainID
		step.Details["round"] = l3.Round
		step.Details["apiLimitation"] = l3.APILimitation

		if d.logLevel >= DebugLevelVerbose {
			d.output.Printf("   Chain ID: %s\n", l3.ChainID)
			d.output.Printf("   Round: %d\n", l3.Round)
			d.output.Printf("   Total Validators: %d\n", l3.TotalValidators)
			d.output.Printf("   Signed Validators: %d\n", l3.SignedValidators)
			d.output.Printf("   Total Power: %d\n", l3.TotalPower)
			d.output.Printf("   Signed Power: %d\n", l3.SignedPower)
			d.output.Printf("   Threshold Met: %t\n", l3.ThresholdMet)

			if l3.APILimitation {
				d.output.Println("   🚨 API Limitation: CometBFT not available")
			}

			if d.logLevel >= DebugLevelTrace && len(l3.ValidatorSignatures) > 0 {
				d.output.Println("\n   Validator Signatures:")
				for i, valSig := range l3.ValidatorSignatures {
					d.output.Printf("     [%d] Address: %s\n", i, d.formatHash(valSig.Address))
					d.output.Printf("         Power: %d, Verified: %t\n", valSig.VotingPower, valSig.Verified)
				}
			}
		}
	}

	if layer3.Verified {
		if d.logLevel >= DebugLevelBasic {
			d.output.Println("   ✅ Layer 3 Verified: 2/3+ validator signatures confirmed")
		}
	} else {
		if d.logLevel >= DebugLevelBasic {
			d.output.Printf("   ❌ Layer 3 Failed: %s\n", layer3.Error)
		}
		debugInfo.Errors = append(debugInfo.Errors, fmt.Sprintf("Layer 3: %s", layer3.Error))
	}

	debugInfo.LayerTimes["layer3"] = step.Duration
	debugInfo.VerificationSteps = append(debugInfo.VerificationSteps, step)
}

// analyzeLayer4 analyzes Layer 4 verification results
func (d *DebugVerifier) analyzeLayer4(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	layerStartTime := time.Now()

	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n🌱 Layer 4: Validators → Genesis Trust")
		d.output.Println("----------------------------------------")
	}

	layer4, exists := result.Layers["layer4"]
	if !exists {
		d.logWarning("Layer 4 results not found")
		debugInfo.Warnings = append(debugInfo.Warnings, "Layer 4 results not found")
		return
	}

	step := interfaces.VerificationStep{
		Layer:       "Layer 4",
		Description: "Validators → Genesis Trust",
		Duration:    time.Since(layerStartTime),
		Success:     layer4.Verified,
		Details:     make(map[string]interface{}),
	}

	if layer4.Error != "" {
		step.Error = fmt.Errorf("%s", layer4.Error)
	}

	step.Details["status"] = "Not yet implemented"

	if d.logLevel >= DebugLevelBasic {
		d.output.Println("   ⏳ Layer 4 Skipped: Not yet implemented")
	}

	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("   📋 Layer 4 will verify validator set changes back to genesis")
		d.output.Println("      when API provides validator transition history")
	}

	debugInfo.LayerTimes["layer4"] = step.Duration
	debugInfo.VerificationSteps = append(debugInfo.VerificationSteps, step)
}

// analyzeOverall provides overall verification analysis
func (d *DebugVerifier) analyzeOverall(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	if d.logLevel >= DebugLevelDetailed {
		d.output.Println("\n📊 Overall Analysis")
		d.output.Println("----------------------------------------")
	}

	if result.FullyVerified {
		if d.logLevel >= DebugLevelBasic {
			d.output.Println("   🎉 FULLY VERIFIED: All implemented layers passed")
		}
	} else {
		if d.logLevel >= DebugLevelBasic {
			d.output.Println("   ⚠️  PARTIALLY VERIFIED: Some layers failed or unavailable")
		}
	}

	if d.logLevel >= DebugLevelDetailed {
		d.output.Printf("   Trust Level: %s\n", result.TrustLevel)
		d.output.Printf("   Verification Duration: %v\n", debugInfo.GenerationTime)

		if len(debugInfo.Errors) > 0 {
			d.output.Println("\n❌ Errors encountered:")
			for _, err := range debugInfo.Errors {
				d.output.Printf("   • %s\n", err)
			}
		}

		if len(debugInfo.Warnings) > 0 {
			d.output.Println("\n⚠️  Warnings:")
			for _, warning := range debugInfo.Warnings {
				d.output.Printf("   • %s\n", warning)
			}
		}
	}
}

// Helper methods

func (d *DebugVerifier) printVerificationHeader(accountURL string) {
	d.output.Println("\n========================================")
	d.output.Printf("🔍 Proof Verification: %s\n", accountURL)
	d.output.Println("========================================")
}

func (d *DebugVerifier) printVerificationSummary(result *core.VerificationResult, debugInfo *interfaces.DebugInfo) {
	d.output.Println("\n========================================")
	d.output.Println("Verification Summary")
	d.output.Println("========================================")

	status := func(verified bool) string {
		if verified {
			return "✅ VERIFIED"
		}
		return "❌ NOT VERIFIED"
	}

	d.output.Printf("Layer 1 (Merkle Proof):     %s\n", status(result.Layers["layer1"].Verified))
	d.output.Printf("Layer 2 (Block Commitment): %s\n", status(result.Layers["layer2"].Verified))
	d.output.Printf("Layer 3 (Signatures):       %s\n", status(result.Layers["layer3"].Verified))
	d.output.Printf("Layer 4 (Genesis Chain):    %s\n", status(result.Layers["layer4"].Verified))
	d.output.Println("----------------------------------------")

	if result.FullyVerified {
		d.output.Println("Overall Status:              ✅ VALID")
	} else {
		d.output.Println("Overall Status:              ⚠️  PARTIAL")
	}

	d.output.Printf("Trust Level:                 %s\n", result.TrustLevel)
	d.output.Printf("Verification Time:           %v\n", debugInfo.GenerationTime)

	if result.Error != "" {
		d.output.Printf("Error: %s\n", result.Error)
	}

	d.output.Println("========================================\n")
}

func (d *DebugVerifier) logError(context string, err error) {
	if d.logLevel >= DebugLevelBasic {
		d.output.Printf("❌ ERROR [%s]: %v\n", context, err)
	}
}

func (d *DebugVerifier) logWarning(message string) {
	if d.logLevel >= DebugLevelDetailed {
		d.output.Printf("⚠️  WARNING: %s\n", message)
	}
}

func (d *DebugVerifier) formatHash(hashStr string) string {
	if hashStr == "" {
		return "<empty>"
	}

	// Truncate long hashes for readability
	if len(hashStr) > 16 {
		return hashStr[:16] + "..."
	}

	return hashStr
}


// GetDebugLevelFromString converts string to DebugLevel
func GetDebugLevelFromString(level string) DebugLevel {
	switch strings.ToLower(level) {
	case "none":
		return DebugLevelNone
	case "basic":
		return DebugLevelBasic
	case "detailed":
		return DebugLevelDetailed
	case "verbose":
		return DebugLevelVerbose
	case "trace":
		return DebugLevelTrace
	default:
		return DebugLevelBasic
	}
}