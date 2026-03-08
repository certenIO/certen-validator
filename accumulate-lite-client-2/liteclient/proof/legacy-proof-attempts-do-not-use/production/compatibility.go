// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package production

import (
	"context"
	"fmt"

	"gitlab.com/accumulatenetwork/accumulate/pkg/url"
)

// DevnetProof provides backwards compatibility with old devnet proof interface
type DevnetProof struct {
	verifier *ConfigurableVerifier
	endpoint string
}

// ProofResult represents the result of proof generation (compatibility)
type FullProofResult struct {
	Complete        bool                   `json:"complete"`
	Step1BPTHash    string                 `json:"step1BPTHash,omitempty"`
	Step2BPTLookup  *BPTLookupResult      `json:"step2BPTLookup,omitempty"`
	Step3BVNReceipt interface{}           `json:"step3BVNReceipt,omitempty"`
	Step4DNAnchor   interface{}           `json:"step4DNAnchor,omitempty"`
	Step5Consensus  *ConsensusResult      `json:"step5Consensus,omitempty"`
	Errors          []string              `json:"errors,omitempty"`
}

type BPTLookupResult struct {
	Found bool `json:"found"`
}

type ConsensusResult struct {
	Threshold bool `json:"threshold"`
}

// NewDevnetProof creates a devnet proof client (compatibility wrapper)
func NewDevnetProof(endpoint string) *DevnetProof {
	return &DevnetProof{
		verifier: NewConfigurableVerifier(endpoint+"/v3", ""),
		endpoint: endpoint,
	}
}

// TestObserverStatus checks if observer mode is enabled
func (d *DevnetProof) TestObserverStatus(ctx context.Context) (bool, error) {
	// Try to verify a known account to test if receipts work
	testURL, _ := url.Parse("acc://dn.acme")
	result, err := VerifyAccountWithDetails(d.verifier.CryptographicVerifier, testURL)
	if err != nil {
		// If we get an error, observer is likely not enabled
		return false, nil
	}
	// If Layer1 is verified, receipts are working (observer enabled)
	return result.Layer1Verified, nil
}

// GenerateFullProof generates a complete proof for an account
func (d *DevnetProof) GenerateFullProof(ctx context.Context, accountURL string) (*FullProofResult, error) {
	accURL, err := url.Parse(accountURL)
	if err != nil {
		return nil, fmt.Errorf("invalid account URL: %w", err)
	}
	
	proofDetails, err := VerifyAccountWithDetails(d.verifier.CryptographicVerifier, accURL)
	if err != nil {
		return &FullProofResult{
			Complete: false,
			Errors:   []string{err.Error()},
		}, nil
	}
	
	result := &FullProofResult{
		Complete: proofDetails.FullyVerified,
	}
	
	// Map new proof results to old structure
	if proofDetails.Layer1Verified {
		result.Step1BPTHash = fmt.Sprintf("%x", proofDetails.AccountHash)
		result.Step2BPTLookup = &BPTLookupResult{Found: true}
	}
	
	if proofDetails.Layer2Verified {
		result.Step3BVNReceipt = map[string]interface{}{
			"blockHeight": proofDetails.BlockHeight,
			"blockHash":   fmt.Sprintf("%x", proofDetails.BlockHash),
		}
		result.Step4DNAnchor = map[string]interface{}{
			"verified": true,
		}
	}
	
	if proofDetails.Layer3Verified {
		result.Step5Consensus = &ConsensusResult{
			Threshold: true,
		}
	}
	
	if proofDetails.ErrorMessage != "" {
		result.Errors = append(result.Errors, proofDetails.ErrorMessage)
	}
	
	return result, nil
}

// RunAccountTests runs basic account tests (compatibility function)
func RunAccountTests() {
	fmt.Println("=== Production Proof Test Suite ===")
	fmt.Println("\nThis functionality has been moved to the production proof system.")
	fmt.Println("Use test-devnet command instead for comprehensive testing.")
}