// Copyright 2025 Certen Protocol
//
// Proof Generator Adapter
// Adapts LiteClientProofGenerator to ChainedProofGenerator interface
// for use with UnifiedOrchestrator

package execution

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/certen/independant-validator/pkg/proof"
)

// LiteClientProofGeneratorAdapter adapts LiteClientProofGenerator to ChainedProofGenerator
type LiteClientProofGeneratorAdapter struct {
	generator *proof.LiteClientProofGenerator
}

// NewLiteClientProofGeneratorAdapter creates a new adapter
func NewLiteClientProofGeneratorAdapter(gen *proof.LiteClientProofGenerator) *LiteClientProofGeneratorAdapter {
	return &LiteClientProofGeneratorAdapter{
		generator: gen,
	}
}

// GenerateChainedProofForTx implements ChainedProofGenerator interface
// Generates L1/L2/L3 chained proof for a transaction
// Parameters:
//   - accountURL: The Accumulate account URL (e.g., "acc://certen.acme/intent-data")
//   - txHash: The Accumulate transaction hash (64-char hex)
//   - bvn: The BVN partition name (e.g., "bvn1", "bvn2", "bvn3")
func (a *LiteClientProofGeneratorAdapter) GenerateChainedProofForTx(ctx context.Context, accountURL, txHash, bvn string) (*ChainedProofResult, error) {
	if a.generator == nil {
		return nil, fmt.Errorf("proof generator not initialized")
	}

	// Try to generate chained proof - this requires the real proof builder
	if !a.generator.HasRealProofBuilder() {
		return nil, fmt.Errorf("real proof builder not available - CometBFT endpoints required")
	}

	// Validate inputs
	if accountURL == "" {
		return nil, fmt.Errorf("accountURL is required for chained proof generation")
	}
	if txHash == "" {
		return nil, fmt.Errorf("txHash is required for chained proof generation")
	}

	// Calculate BVN from account URL using deterministic routing algorithm
	// This uses SHA256-based prefix matching per Accumulate's routing spec
	// For Kermit testnet: returns "bvn1", "bvn2", or "bvn3"
	if bvn == "" || bvn == "bvn0" {
		calculatedBVN := proof.CalculateBVNFromAccountURL(accountURL)
		if calculatedBVN != "" {
			fmt.Printf("Calculated BVN from account URL routing: %s -> %s\n", accountURL, calculatedBVN)
			bvn = calculatedBVN
		} else {
			// Fallback to bvn1 if calculation fails (should be rare)
			bvn = "bvn1"
			fmt.Printf("Could not calculate BVN from account URL, defaulting to %s\n", bvn)
		}
	}

	fmt.Printf("Generating chained proof: accountURL=%s, txHash=%s, bvn=%s\n", accountURL, txHash, bvn)

	// Generate chained proof for the transaction
	// The liteclient_adapter.GenerateChainedProof will also normalize and validate the BVN
	chainedProof, err := a.generator.GenerateChainedProofForIntent(ctx, accountURL, txHash, bvn)
	if err != nil {
		return nil, fmt.Errorf("generate chained proof for bvn=%s: %w", bvn, err)
	}

	if chainedProof == nil {
		return nil, fmt.Errorf("chained proof is nil")
	}

	// Convert to ChainedProofResult
	result := &ChainedProofResult{
		CompleteProof: chainedProof,
	}

	// Extract L1 data
	if chainedProof.Layer1.BVNRootChainAnchor != "" {
		result.L1ReceiptAnchor = hexToBytes(chainedProof.Layer1.Receipt.Anchor)
		result.L1BVNRoot = hexToBytes(chainedProof.Layer1.BVNRootChainAnchor)
		result.L1BVNPartition = chainedProof.Input.BVN
	}

	// Extract L2 data
	if chainedProof.Layer2.DNRootChainAnchor != "" {
		result.L2DNRoot = hexToBytes(chainedProof.Layer2.DNRootChainAnchor)
		result.L2AnchorSeq = int64(chainedProof.Layer2.DNIndex)
		result.L2DNBlockHash = hexToBytes(chainedProof.Layer2.BVNStateTreeAnchor)
	}

	// Extract L3 data
	if chainedProof.Layer3.DNConsensusHeight > 0 {
		result.L3DNBlockHeight = int64(chainedProof.Layer3.DNConsensusHeight)
		// Consensus timestamp is approximately now since we just fetched it
		result.L3ConsensusTimestamp = time.Now().UTC()
	}

	return result, nil
}

// hexToBytes converts a hex string to bytes, handling "0x" prefix
func hexToBytes(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, _ := hex.DecodeString(s)
	return b
}
