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
func (a *LiteClientProofGeneratorAdapter) GenerateChainedProofForTx(ctx context.Context, txHash string) (*ChainedProofResult, error) {
	if a.generator == nil {
		return nil, fmt.Errorf("proof generator not initialized")
	}

	// The LiteClientProofGenerator needs account URL, tx hash, and BVN name
	// For now, we'll try to generate proof using the tx hash as the account URL
	// In a full implementation, we'd need to look up the account URL from the intent

	// Try to generate chained proof - this requires the real proof builder
	if !a.generator.HasRealProofBuilder() {
		return nil, fmt.Errorf("real proof builder not available")
	}

	// Generate chained proof for the transaction
	// We need to determine the BVN - for now use "bvn0" as default
	// In production, this would be determined from the transaction's routing
	chainedProof, err := a.generator.GenerateChainedProofForIntent(ctx, txHash, txHash, "bvn0")
	if err != nil {
		// Try with different BVNs if the first fails
		chainedProof, err = a.generator.GenerateChainedProofForIntent(ctx, txHash, txHash, "bvn1")
		if err != nil {
			chainedProof, err = a.generator.GenerateChainedProofForIntent(ctx, txHash, txHash, "bvn2")
			if err != nil {
				return nil, fmt.Errorf("generate chained proof: %w", err)
			}
		}
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
