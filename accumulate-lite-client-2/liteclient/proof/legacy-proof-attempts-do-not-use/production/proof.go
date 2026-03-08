// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

// Package production provides the production-ready cryptographic proof
// implementation with working Layer 1-3 verification.
package production

import (
	"context"
	"encoding/hex"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production-proof/core"
)

// ProofResult contains the detailed results of proof verification
type ProofResult struct {
	// Layer 1: Account → BPT
	AccountHash     []byte `json:"accountHash"`
	BPTRoot         []byte `json:"bptRoot"`
	Layer1Verified  bool   `json:"layer1Verified"`
	
	// Layer 2: BPT → Block
	BlockHeight     uint64 `json:"blockHeight"`
	BlockHash       []byte `json:"blockHash"`
	Layer2Verified  bool   `json:"layer2Verified"`
	
	// Layer 3: Block → Validators (when available)
	ValidatorCount  int    `json:"validatorCount"`
	SignatureCount  int    `json:"signatureCount"`
	Layer3Available bool   `json:"layer3Available"`
	Layer3Verified  bool   `json:"layer3Verified"`
	
	// Overall status
	FullyVerified   bool   `json:"fullyVerified"`
	TrustRequired   string `json:"trustRequired"` // "none" | "api" | "validators"
	ErrorMessage    string `json:"errorMessage,omitempty"`
}

// VerifyAccountWithDetails performs complete verification and returns detailed results
func VerifyAccountWithDetails(cv *core.CryptographicVerifier, accountURL *url.URL) (*ProofResult, error) {
	ctx := context.Background()

	result := &ProofResult{
		TrustRequired: "api", // Default until we verify more layers
	}

	// Use the core verifier to perform verification
	verificationResult, err := cv.VerifyAccount(ctx, accountURL)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("verification failed: %v", err)
		return result, err
	}

	// Map verification results from layers map (using correct lowercase keys)
	if layer1, ok := verificationResult.Layers["layer1"]; ok {
		result.Layer1Verified = layer1.Verified

		// Extract rich Layer 1 details from typed result
		if verificationResult.Layer1Result != nil {
			l1 := verificationResult.Layer1Result
			if l1.AccountHash != "" {
				if hash, err := parseHexToBytes(l1.AccountHash); err == nil {
					result.AccountHash = hash
				}
			}
			if l1.BPTRoot != "" {
				if root, err := parseHexToBytes(l1.BPTRoot); err == nil {
					result.BPTRoot = root
				}
			}
		}
	}

	if layer2, ok := verificationResult.Layers["layer2"]; ok {
		result.Layer2Verified = layer2.Verified

		// Extract rich Layer 2 details from typed result
		if verificationResult.Layer2Result != nil {
			l2 := verificationResult.Layer2Result
			result.BlockHeight = uint64(l2.BlockHeight)
			if l2.BlockHash != "" {
				if hash, err := parseHexToBytes(l2.BlockHash); err == nil {
					result.BlockHash = hash
				}
			}
		}
	}

	if layer3, ok := verificationResult.Layers["layer3"]; ok {
		result.Layer3Verified = layer3.Verified

		// Extract rich Layer 3 details from typed result
		if verificationResult.Layer3Result != nil {
			l3 := verificationResult.Layer3Result
			result.ValidatorCount = l3.TotalValidators
			result.SignatureCount = l3.SignedValidators

			// Layer 3 is available if we have CometBFT access and no API limitations
			result.Layer3Available = !l3.APILimitation
		}
	}

	result.FullyVerified = verificationResult.FullyVerified
	result.TrustRequired = verificationResult.TrustLevel

	return result, nil
}

// ConfigurableVerifier allows customization of the verification endpoint
type ConfigurableVerifier struct {
	*core.CryptographicVerifier
	apiEndpoint   string
	cometEndpoint string
}

// NewConfigurableVerifier creates a verifier with custom endpoints
func NewConfigurableVerifier(apiEndpoint, cometEndpoint string) *ConfigurableVerifier {
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:26660/v3"
	}
	if cometEndpoint == "" {
		cometEndpoint = "http://127.0.0.2:26657"
	}
	
	return &ConfigurableVerifier{
		CryptographicVerifier: core.NewCryptographicVerifierWithEndpoints(apiEndpoint, cometEndpoint),
		apiEndpoint:   apiEndpoint,
		cometEndpoint: cometEndpoint,
	}
}

// parseHexToBytes safely converts hex string to bytes
func parseHexToBytes(hexStr string) ([]byte, error) {
	// Remove 0x prefix if present
	if len(hexStr) > 2 && hexStr[0:2] == "0x" {
		hexStr = hexStr[2:]
	}
	return hex.DecodeString(hexStr)
}