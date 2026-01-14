// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// CERTEN Governance Proof - Go Verifier Integration
// This file provides Go verifier integration for payload authenticity verification
// Required for G2-level governance proofs with outcome binding

// =============================================================================
// Go Verifier
// =============================================================================

// GoVerifier handles external Go verifier integration for payload verification
type GoVerifier struct {
	goModDir     string // Go module directory containing verifier
	goVerifyPath string // Path to go-verify tool or Go source
}

// NewGoVerifier creates a new Go verifier
func NewGoVerifier(goModDir string, goVerifyPath string) *GoVerifier {
	return &GoVerifier{
		goModDir:     goModDir,
		goVerifyPath: goVerifyPath,
	}
}

// VerifyPayload verifies transaction payload authenticity using Go verifier
// Direct translation of Python verify_payload_with_go_verifier
func (gv *GoVerifier) VerifyPayload(ctx context.Context, txData map[string]interface{}, expectedTxHash string) (*PayloadVerification, error) {
	fmt.Printf("[GO_VERIFIER] Verifying payload authenticity (expected: %s)\n", SafeTruncate(expectedTxHash, 16))

	// Serialize transaction data for Go verifier
	txJSON, err := json.Marshal(txData)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize transaction data: %v", err)
	}

	return gv.VerifyPayloadWithRawJSON(ctx, txJSON, expectedTxHash)
}

// VerifyPayloadWithRawJSON verifies transaction payload using raw JSON bytes
// This is the primary method used by G2 - it receives the raw transaction JSON
// from the API and passes it to the txhash tool for canonical hash computation
func (gv *GoVerifier) VerifyPayloadWithRawJSON(ctx context.Context, txJSON []byte, expectedTxHash string) (*PayloadVerification, error) {
	fmt.Printf("[GO_VERIFIER] Verifying payload with raw JSON (%d bytes, expected: %s)\n", len(txJSON), SafeTruncate(expectedTxHash, 16))

	if gv.goVerifyPath == "" {
		// Return expected hash as computed hash to avoid slice bounds issues
		// This allows G2 to proceed with effect verification using expected hash
		return &PayloadVerification{
			Verified:             false,
			ComputedTxHash:       expectedTxHash, // Use expected hash instead of empty string
			ExpectedTxHash:       expectedTxHash,
			GoVerifierOutput:     "",
			GoVerifierErrors:     "Go verifier path not configured",
			VerificationDetails:  map[string]interface{}{"error": "Go verifier not available"},
		}, nil
	}

	// Execute Go verifier (txhash tool)
	computedHash, stdout, stderr, err := gv.executeGoVerifier(ctx, txJSON)
	if err != nil {
		// Return failed verification result instead of error for controlled failure
		return &PayloadVerification{
			Verified:             false,
			ComputedTxHash:       "",
			ExpectedTxHash:       expectedTxHash,
			GoVerifierOutput:     stdout,
			GoVerifierErrors:     stderr,
			VerificationDetails:  map[string]interface{}{"execution_error": err.Error()},
		}, nil
	}

	// Validate computed hash format
	hv := HexValidator{}
	normalizedComputed, err := hv.RequireHex32(computedHash, "computed transaction hash")
	if err != nil {
		return &PayloadVerification{
			Verified:             false,
			ComputedTxHash:       computedHash,
			ExpectedTxHash:       expectedTxHash,
			GoVerifierOutput:     stdout,
			GoVerifierErrors:     stderr,
			VerificationDetails:  map[string]interface{}{"validation_error": err.Error()},
		}, nil
	}

	// Validate expected hash format
	normalizedExpected, err := hv.RequireHex32(expectedTxHash, "expected transaction hash")
	if err != nil {
		return &PayloadVerification{
			Verified:             false,
			ComputedTxHash:       normalizedComputed,
			ExpectedTxHash:       expectedTxHash,
			GoVerifierOutput:     stdout,
			GoVerifierErrors:     stderr,
			VerificationDetails:  map[string]interface{}{"expected_hash_error": err.Error()},
		}, nil
	}

	// Compare hashes
	verified := normalizedComputed == normalizedExpected

	result := &PayloadVerification{
		Verified:             verified,
		ComputedTxHash:       normalizedComputed,
		ExpectedTxHash:       normalizedExpected,
		GoVerifierOutput:     stdout,
		GoVerifierErrors:     stderr,
		VerificationDetails: map[string]interface{}{
			"hash_match":        verified,
			"computed_length":   len(normalizedComputed),
			"expected_length":   len(normalizedExpected),
		},
	}

	if verified {
		fmt.Printf("[GO_VERIFIER] [OK] Payload verification successful\n")
	} else {
		fmt.Printf("[GO_VERIFIER] [FAIL] Hash mismatch: computed=%s, expected=%s\n",
			normalizedComputed[:16], normalizedExpected[:16])
	}

	return result, nil
}

// executeGoVerifier executes the Go verifier tool with transaction data
func (gv *GoVerifier) executeGoVerifier(ctx context.Context, txJSON []byte) (string, string, string, error) {
	var cmd *exec.Cmd

	// Build command based on verifier path type
	if strings.HasSuffix(gv.goVerifyPath, ".go") {
		// Go source file - run with "go run"
		if gv.goModDir != "" {
			// Use go module directory
			cmd = exec.CommandContext(ctx, "go", "run", gv.goVerifyPath)
			cmd.Dir = gv.goModDir
		} else {
			cmd = exec.CommandContext(ctx, "go", "run", gv.goVerifyPath)
		}
	} else {
		// Executable binary
		cmd = exec.CommandContext(ctx, gv.goVerifyPath)
	}

	// Pass transaction JSON via stdin
	cmd.Stdin = strings.NewReader(string(txJSON))

	// Execute command
	output, err := cmd.Output()
	stdout := string(output)
	stderr := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
			return "", stdout, stderr, fmt.Errorf("go verifier failed (exit %d): %s", exitErr.ExitCode(), stderr)
		}
		return "", stdout, stderr, fmt.Errorf("go verifier execution failed: %v", err)
	}

	// Parse output to extract transaction hash
	computedHash, parseErr := gv.parseGoVerifierOutput(stdout)
	if parseErr != nil {
		return "", stdout, stderr, parseErr
	}

	return computedHash, stdout, stderr, nil
}

// parseGoVerifierOutput parses Go verifier output to extract computed transaction hash
func (gv *GoVerifier) parseGoVerifierOutput(output string) (string, error) {
	lines := strings.Split(output, "\n")

	// Look for hash output patterns
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Pattern: "hash=<HASH>"
		if strings.HasPrefix(line, "hash=") {
			hash := strings.TrimPrefix(line, "hash=")
			return strings.TrimSpace(hash), nil
		}

		// Pattern: "transaction_hash=<HASH>"
		if strings.HasPrefix(line, "transaction_hash=") {
			hash := strings.TrimPrefix(line, "transaction_hash=")
			return strings.TrimSpace(hash), nil
		}

		// Pattern: "tx_hash=<HASH>"
		if strings.HasPrefix(line, "tx_hash=") {
			hash := strings.TrimPrefix(line, "tx_hash=")
			return strings.TrimSpace(hash), nil
		}

		// Pattern: "computed=<HASH>"
		if strings.HasPrefix(line, "computed=") {
			hash := strings.TrimPrefix(line, "computed=")
			return strings.TrimSpace(hash), nil
		}

		// Pattern: JSON output with "hash" field
		if strings.HasPrefix(line, "{") {
			var jsonOutput map[string]interface{}
			if err := json.Unmarshal([]byte(line), &jsonOutput); err == nil {
				if hash, ok := jsonOutput["hash"].(string); ok {
					return strings.TrimSpace(hash), nil
				}
				if hash, ok := jsonOutput["transaction_hash"].(string); ok {
					return strings.TrimSpace(hash), nil
				}
				if hash, ok := jsonOutput["tx_hash"].(string); ok {
					return strings.TrimSpace(hash), nil
				}
			}
		}

		// Pattern: Bare hex string (if line looks like a hex hash)
		if len(line) == 64 && isHexString(line) {
			return line, nil
		}
	}

	return "", fmt.Errorf("could not parse transaction hash from go verifier output")
}

// isHexString checks if string is valid hex
func isHexString(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// =============================================================================
// Payload Extraction and Preparation
// =============================================================================

// ExtractTransactionPayload extracts transaction payload from execution message
// Direct translation of Python extract_transaction_payload
func (gv *GoVerifier) ExtractTransactionPayload(msgResult map[string]interface{}) (map[string]interface{}, error) {
	pu := ProofUtilities{}

	// Extract message object
	msg := pu.CaseInsensitiveGet(msgResult, "message")
	if msg == nil {
		return nil, ValidationError{Msg: "Message result missing message{}"}
	}

	msgMap, ok := msg.(map[string]interface{})
	if !ok {
		return nil, ValidationError{Msg: "Message is not an object"}
	}

	// Extract transaction type
	txType := pu.CaseInsensitiveGet(msgMap, "type")
	txTypeStr, ok := txType.(string)
	if !ok || txTypeStr == "" {
		return nil, ValidationError{Msg: "Message missing type"}
	}

	// For G2 verification, we need the complete transaction payload
	// This includes all fields required for canonical hash computation
	payload := make(map[string]interface{})

	// Copy message fields needed for hash computation
	payload["type"] = txTypeStr

	// Extract transaction-specific fields based on type
	switch strings.ToLower(txTypeStr) {
	case "createtoken", "createidentity", "createkeypage", "createkeybook":
		// Creation transactions
		return gv.extractCreationPayload(msgMap)

	case "updatekeypage":
		// Key page updates
		return gv.extractUpdatePayload(msgMap)

	case "sendtokens", "transfertokens":
		// Token transactions
		return gv.extractTokenPayload(msgMap)

	case "burnTokens":
		// Burn transactions
		return gv.extractBurnPayload(msgMap)

	default:
		// Generic extraction - copy all fields
		return gv.extractGenericPayload(msgMap)
	}
}

// extractCreationPayload extracts payload from creation transactions
func (gv *GoVerifier) extractCreationPayload(msg map[string]interface{}) (map[string]interface{}, error) {
	pu := ProofUtilities{}
	payload := make(map[string]interface{})

	// Copy standard fields
	if txType := pu.CaseInsensitiveGet(msg, "type"); txType != nil {
		payload["type"] = txType
	}
	if url := pu.CaseInsensitiveGet(msg, "url"); url != nil {
		payload["url"] = url
	}

	// Copy creation-specific fields
	for _, field := range []string{"keyPage", "account", "manager", "description", "properties", "keybook"} {
		if value := pu.CaseInsensitiveGet(msg, field); value != nil {
			payload[strings.ToLower(field)] = value
		}
	}

	return payload, nil
}

// extractUpdatePayload extracts payload from update transactions
func (gv *GoVerifier) extractUpdatePayload(msg map[string]interface{}) (map[string]interface{}, error) {
	pu := ProofUtilities{}
	payload := make(map[string]interface{})

	// Copy standard fields
	if txType := pu.CaseInsensitiveGet(msg, "type"); txType != nil {
		payload["type"] = txType
	}

	// Copy update-specific fields
	for _, field := range []string{"operation", "oldState", "newState", "updates"} {
		if value := pu.CaseInsensitiveGet(msg, field); value != nil {
			payload[strings.ToLower(field)] = value
		}
	}

	return payload, nil
}

// extractTokenPayload extracts payload from token transactions
func (gv *GoVerifier) extractTokenPayload(msg map[string]interface{}) (map[string]interface{}, error) {
	pu := ProofUtilities{}
	payload := make(map[string]interface{})

	// Copy standard fields
	if txType := pu.CaseInsensitiveGet(msg, "type"); txType != nil {
		payload["type"] = txType
	}

	// Copy token-specific fields
	for _, field := range []string{"to", "amount", "token", "memo", "metadata"} {
		if value := pu.CaseInsensitiveGet(msg, field); value != nil {
			payload[strings.ToLower(field)] = value
		}
	}

	return payload, nil
}

// extractBurnPayload extracts payload from burn transactions
func (gv *GoVerifier) extractBurnPayload(msg map[string]interface{}) (map[string]interface{}, error) {
	pu := ProofUtilities{}
	payload := make(map[string]interface{})

	// Copy standard fields
	if txType := pu.CaseInsensitiveGet(msg, "type"); txType != nil {
		payload["type"] = txType
	}

	// Copy burn-specific fields
	for _, field := range []string{"amount", "token"} {
		if value := pu.CaseInsensitiveGet(msg, field); value != nil {
			payload[strings.ToLower(field)] = value
		}
	}

	return payload, nil
}

// extractGenericPayload extracts generic payload (all fields)
func (gv *GoVerifier) extractGenericPayload(msg map[string]interface{}) (map[string]interface{}, error) {
	// For unknown transaction types, copy all fields
	// This is fail-safe but may include extra fields
	payload := make(map[string]interface{})

	for key, value := range msg {
		// Skip meta fields that shouldn't be in payload
		if strings.ToLower(key) == "id" || strings.ToLower(key) == "hash" {
			continue
		}
		payload[key] = value
	}

	return payload, nil
}

// =============================================================================
// Effect Verification for G2 Proofs
// =============================================================================

// VerifyTransactionEffect verifies transaction effects for G2 outcome binding
func (gv *GoVerifier) VerifyTransactionEffect(expectedEffect string, computedEffect string) *EffectVerification {
	verified := expectedEffect == computedEffect

	result := &EffectVerification{
		EffectType:     "hash_comparison", // Could be extended for other effect types
		Verified:       verified,
		ExpectedValue:  &expectedEffect,
		ComputedValue:  &computedEffect,
		Details: map[string]interface{}{
			"effect_match":      verified,
			"expected_length":   len(expectedEffect),
			"computed_length":   len(computedEffect),
		},
	}

	if verified {
		fmt.Printf("[GO_VERIFIER] [OK] Effect verification successful\n")
	} else {
		fmt.Printf("[GO_VERIFIER] [FAIL] Effect mismatch: expected=%s, computed=%s\n",
			SafeTruncate(expectedEffect, 16), SafeTruncate(computedEffect, 16))
	}

	return result
}

// BuildOutcomeLeaf constructs G2 outcome leaf with all verification results
func (gv *GoVerifier) BuildOutcomeLeaf(payloadVerification PayloadVerification, effectVerification EffectVerification, receiptVerified bool, witnessVerified bool) OutcomeLeaf {
	return OutcomeLeaf{
		PayloadBinding: payloadVerification,
		ReceiptBinding: VerificationResult{
			Verified: receiptVerified,
			Details:  fmt.Sprintf("Receipt binding verification: %t", receiptVerified),
		},
		WitnessConsistency: VerificationResult{
			Verified: witnessVerified,
			Details:  fmt.Sprintf("Witness consistency verification: %t", witnessVerified),
		},
		Effect: effectVerification,
	}
}