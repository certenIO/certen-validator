// Copyright 2025 The Accumulate Authors
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package core

import (
	"context"
	"fmt"
	"time"

	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3"
	"gitlab.com/accumulatenetwork/accumulate/pkg/api/v3/jsonrpc"
	"gitlab.com/accumulatenetwork/accumulate/pkg/url"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/types"
)

// APIClient defines the interface for API communication
type APIClient interface {
	Query(ctx context.Context, scope *url.URL, query api.Query) (api.Record, error)
	NetworkStatus(ctx context.Context, opts api.NetworkStatusOptions) (*api.NetworkStatus, error)
}

// CryptographicVerifier orchestrates all layers of proof verification
type CryptographicVerifier struct {
	layer1 *Layer1Verifier
	layer2 *Layer2Verifier
	layer3 *Layer3Verifier
	layer4 *types.Layer4Verifier

	apiEndpoint   string
	cometEndpoint string
	chainID       string
}

// NewCryptographicVerifier creates a new verifier with default endpoints
func NewCryptographicVerifier() *CryptographicVerifier {
	return NewCryptographicVerifierWithEndpoints(
		"http://localhost:26660/v3",
		"http://localhost:26657",
	)
}

// NewCryptographicVerifierWithEndpoints creates a verifier with custom endpoints
func NewCryptographicVerifierWithEndpoints(apiEndpoint, cometEndpoint string) *CryptographicVerifier {
	client := jsonrpc.NewClient(apiEndpoint)

	// Create Layer 4 with placeholder genesis data (to be set from network)
	// In a full implementation, genesis hash and validators would be obtained from network configuration
	layer4 := types.NewLayer4Verifier(
		[]byte{}, // Placeholder genesis hash - should be set from network config
		[]types.Validator{}, // Placeholder genesis validators - should be set from network config
		false, // Debug mode
	)

	return &CryptographicVerifier{
		layer1:        NewLayer1Verifier(client),
		layer2:        NewLayer2Verifier(client, cometEndpoint),
		layer3:        NewLayer3Verifier(cometEndpoint),
		layer4:        layer4,
		apiEndpoint:   apiEndpoint,
		cometEndpoint: cometEndpoint,
		chainID:       "", // Will be determined dynamically from block headers
	}
}

// VerifyAccount performs complete verification of an account through all layers
func (v *CryptographicVerifier) VerifyAccount(ctx context.Context, accountURL *url.URL) (*VerificationResult, error) {
	result := &VerificationResult{
		AccountURL: accountURL.String(),
		Timestamp:  time.Now().UTC(),
		Layers:     make(map[string]LayerStatus),
	}

	// Layer 1: Account State → BPT Root
	layer1Result, err := v.layer1.VerifyAccountToBPT(ctx, accountURL)
	if err != nil {
		result.Layers["layer1"] = LayerStatus{
			Name:     "Account → BPT Root",
			Verified: false,
			Error:    err.Error(),
		}
		result.Error = fmt.Sprintf("Layer 1 failed: %v", err)
		return result, nil
	}
	result.Layer1Result = layer1Result

	result.Layers["layer1"] = LayerStatus{
		Name:     "Account → BPT Root",
		Verified: layer1Result.Verified,
		Details: map[string]interface{}{
			"accountHash":  layer1Result.AccountHash,
			"bptRoot":      layer1Result.BPTRoot,
			"proofEntries": layer1Result.ProofEntries,
			"blockIndex":   layer1Result.BlockIndex,
			"blockTime":    layer1Result.BlockTime,
		},
	}

	if !layer1Result.Verified {
		result.Error = "Layer 1 verification failed"
		return result, nil
	}

	// Layer 2: BPT Root → Block Hash
	layer2Result, err := v.layer2.VerifyBPTToBlock(ctx, layer1Result.BPTRoot, int64(layer1Result.BlockIndex))
	if err != nil {
		// Layer 2 error is not fatal if Layer 1 passed
		result.Layers["layer2"] = LayerStatus{
			Name:     "BPT Root → Block Hash",
			Verified: false,
			Error:    err.Error(),
		}
	} else {
		result.Layer2Result = layer2Result
		result.Layers["layer2"] = LayerStatus{
			Name:     "BPT Root → Block Hash",
			Verified: layer2Result.Verified,
			Details: map[string]interface{}{
				"blockHeight":   layer2Result.BlockHeight,
				"blockHash":     layer2Result.BlockHash,
				"appHash":       layer2Result.AppHash,
				"trustRequired": layer2Result.TrustRequired,
			},
		}
	}

	// Layer 3: Block Hash → Validator Signatures (if Layer 2 succeeded)
	if layer2Result != nil && layer2Result.Verified && layer2Result.BlockHash != "" {
		layer3Result, err := v.layer3.VerifyBlockToValidators(ctx, layer2Result.BlockHash, layer2Result.BlockHeight)
		if err != nil {
			result.Layers["layer3"] = LayerStatus{
				Name:     "Block → Validator Signatures",
				Verified: false,
				Error:    err.Error(),
			}
		} else {
			result.Layer3Result = layer3Result
			result.Layers["layer3"] = LayerStatus{
				Name:     "Block → Validator Signatures",
				Verified: layer3Result.Verified,
				Details: map[string]interface{}{
					"totalValidators":  layer3Result.TotalValidators,
					"signedValidators": layer3Result.SignedValidators,
					"thresholdMet":     layer3Result.ThresholdMet,
					"apiLimitation":    layer3Result.APILimitation,
					"status":           layer3Result.Status,
					"chainID":          layer3Result.ChainID,
					"round":            layer3Result.Round,
					"totalPower":       layer3Result.TotalPower,
					"signedPower":      layer3Result.SignedPower,
				},
			}
		}
	} else {
		result.Layers["layer3"] = LayerStatus{
			Name:     "Block → Validator Signatures",
			Verified: false,
			Error:    "Layer 2 incomplete, cannot verify Layer 3",
		}
	}

	// Layer 4: Validators → Genesis Trust
	if result.Layers["layer3"].Verified {
		// For Layer 4 to work, we need genesis configuration and validator transitions
		// This is a functional implementation but requires genesis data to be configured

		// Example validator transitions (in reality this would come from API)
		transitions := []types.ValidatorTransition{} // Empty for now - would be populated from network

		// Mock current validators (in reality this would come from Layer 3)
		currentValidators := []types.Validator{} // Empty for now - would be populated from consensus

		// Verify the validator chain if we have data
		if len(v.layer4.GetTrustRoot()) > 0 && len(currentValidators) > 0 {
			verified, err := v.layer4.VerifyValidatorChain(currentValidators, 12345, transitions)
			if err != nil {
				result.Layers["layer4"] = LayerStatus{
					Name:     "Validators → Genesis Trust",
					Verified: false,
					Error:    fmt.Sprintf("Layer 4 verification failed: %v", err),
				}
			} else {
				result.Layers["layer4"] = LayerStatus{
					Name:     "Validators → Genesis Trust",
					Verified: verified,
					Error:    "",
				}
			}
		} else {
			result.Layers["layer4"] = LayerStatus{
				Name:     "Validators → Genesis Trust",
				Verified: false,
				Error:    "Genesis configuration not set - need genesis hash and validators",
			}
		}
	} else {
		result.Layers["layer4"] = LayerStatus{
			Name:     "Validators → Genesis Trust",
			Verified: false,
			Error:    "Layer 3 incomplete, cannot verify Layer 4",
		}
	}

	// Determine overall verification status
	result.FullyVerified = result.Layers["layer1"].Verified &&
		result.Layers["layer2"].Verified &&
		result.Layers["layer3"].Verified &&
		result.Layers["layer4"].Verified

	// Calculate trust level
	verifiedLayers := 0
	for _, layer := range result.Layers {
		if layer.Verified {
			verifiedLayers++
		}
	}

	switch verifiedLayers {
	case 4:
		result.TrustLevel = "Zero Trust (Full Cryptographic Proof)"
	case 3:
		result.TrustLevel = "Minimal Trust (Validator Set)"
	case 2:
		result.TrustLevel = "Blockchain Trust (Block Commitment)"
	case 1:
		result.TrustLevel = "API Trust (Merkle Proof Only)"
	default:
		result.TrustLevel = "No Verification"
	}

	result.Duration = time.Since(result.Timestamp)

	return result, nil
}

// SetGenesisConfiguration configures the Layer 4 verifier with genesis data
func (v *CryptographicVerifier) SetGenesisConfiguration(genesisHash []byte, genesisValidators []types.Validator) {
	v.layer4 = types.NewLayer4Verifier(genesisHash, genesisValidators, false)
}

// GetLayer4Verifier returns the Layer 4 verifier for advanced configuration
func (v *CryptographicVerifier) GetLayer4Verifier() *types.Layer4Verifier {
	return v.layer4
}

// VerifyAccountSimple performs basic verification (Layers 1-2 only)
func (v *CryptographicVerifier) VerifyAccountSimple(accountURL *url.URL) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := v.VerifyAccount(ctx, accountURL)
	if err != nil {
		return false, err
	}

	// Consider it verified if at least Layers 1-2 pass
	return result.Layers["layer1"].Verified && result.Layers["layer2"].Verified, nil
}

// VerificationResult contains the complete verification results
type VerificationResult struct {
	AccountURL    string                 `json:"accountUrl"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	FullyVerified bool                   `json:"fullyVerified"`
	TrustLevel    string                 `json:"trustLevel"`
	Layers        map[string]LayerStatus `json:"layers"`
	Error         string                 `json:"error,omitempty"`

	// Typed layer outputs for downstream proof composition
	Layer1Result *Layer1Result `json:"layer1Result,omitempty"`
	Layer2Result *Layer2Result `json:"layer2Result,omitempty"`
	Layer3Result *Layer3Result `json:"layer3Result,omitempty"`
}

// LayerStatus represents the verification status of a single layer
type LayerStatus struct {
	Name     string                 `json:"name"`
	Verified bool                   `json:"verified"`
	Details  map[string]interface{} `json:"details,omitempty"`
	Error    string                 `json:"error,omitempty"`
}

// SetDebug enables or disables debug output across all layers
// This implements the unified debug toggle that "percolates down to all layers"
// as described in Paul Snow's design
func (v *CryptographicVerifier) SetDebug(debug bool) {
	v.layer1.SetDebug(debug)
	v.layer2.SetDebug(debug)
	v.layer3.SetDebug(debug)
}
