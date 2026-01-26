// Copyright 2025 Certen Protocol
//
// Unified Orchestrator Adapter
// Provides adapter implementations to integrate UnifiedOrchestrator with
// legacy interfaces (ProofCycleOrchestratorInterface and batch OnAnchorCallback)
//
// Per Unified Multi-Chain Architecture:
// - Enables gradual migration from legacy to unified orchestrator
// - Feature flag controlled (FF_UNIFIED_ORCHESTRATOR)
// - Backward compatible with existing code paths

package execution

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

// =============================================================================
// UNIFIED ORCHESTRATOR ADAPTER
// =============================================================================

// UnifiedOrchestratorAdapter wraps UnifiedOrchestrator to implement
// the ProofCycleOrchestratorInterface expected by consensus/bft_integration.go
type UnifiedOrchestratorAdapter struct {
	unified *UnifiedOrchestrator
	legacy  *ProofCycleOrchestrator // Fallback to legacy if unified fails

	// Feature flags
	useUnified       bool
	fallbackToLegacy bool
}

// NewUnifiedOrchestratorAdapter creates a new adapter
func NewUnifiedOrchestratorAdapter(
	unified *UnifiedOrchestrator,
	legacy *ProofCycleOrchestrator,
	useUnified bool,
	fallbackToLegacy bool,
) *UnifiedOrchestratorAdapter {
	return &UnifiedOrchestratorAdapter{
		unified:          unified,
		legacy:           legacy,
		useUnified:       useUnified,
		fallbackToLegacy: fallbackToLegacy,
	}
}

// StartProofCycle implements ProofCycleOrchestratorInterface
func (a *UnifiedOrchestratorAdapter) StartProofCycle(
	ctx context.Context,
	intentID string,
	bundleID [32]byte,
	executionTxHash common.Hash,
	commitment interface{},
) error {
	if a.useUnified && a.unified != nil {
		// Create unified request
		req := &UnifiedProofCycleRequest{
			IntentID:    intentID,
			BundleID:    bundleID,
			TxHashes:    []string{executionTxHash.Hex()},
			ProofClass:  "on_demand",
			TargetChain: a.unified.config.DefaultChainID,
		}

		// Start cycle asynchronously
		go func() {
			result, err := a.unified.StartProofCycle(ctx, req)
			if err != nil {
				fmt.Printf("Unified proof cycle failed: %v\n", err)
			} else if result != nil {
				fmt.Printf("Unified proof cycle completed: success=%v\n", result.Success)
			}
		}()
		return nil
	}

	// Use legacy orchestrator
	if a.legacy != nil {
		return a.legacy.StartProofCycle(ctx, intentID, bundleID, executionTxHash, commitment)
	}

	return nil
}

// StartProofCycleWithAllTxs implements the enhanced ProofCycleOrchestratorInterface
func (a *UnifiedOrchestratorAdapter) StartProofCycleWithAllTxs(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashes interface{},
	commitment interface{},
) error {
	fmt.Printf("[UnifiedAdapter] StartProofCycleWithAllTxs called: intent=%s, useUnified=%v, unified=%v\n",
		intentID, a.useUnified, a.unified != nil)

	if a.useUnified && a.unified != nil {
		// Extract tx hashes from the interface
		var txHashStrs []string
		switch hashes := txHashes.(type) {
		case []string:
			txHashStrs = hashes
		case *AnchorWorkflowTxHashes:
			txHashStrs = []string{
				hashes.CreateTxHash.Hex(),
				hashes.VerifyTxHash.Hex(),
				hashes.GovernanceTxHash.Hex(),
			}
		default:
			// Handle AnchorWorkflowTxHashes from consensus package (different type due to package boundary)
			// Use reflection to extract the hash fields
			if extracted := extractTxHashesViaReflection(txHashes); extracted != nil {
				txHashStrs = []string{
					extracted.CreateTxHash.Hex(),
					extracted.VerifyTxHash.Hex(),
					extracted.GovernanceTxHash.Hex(),
				}
			} else {
				txHashStrs = []string{fmt.Sprintf("%v", txHashes)}
			}
		}

		fmt.Printf("[UnifiedAdapter] Extracted %d tx hashes for intent %s: %v\n", len(txHashStrs), intentID, txHashStrs)

		// Create unified request
		var userIDPtr *string
		if userID != "" {
			userIDPtr = &userID
		}

		req := &UnifiedProofCycleRequest{
			IntentID:    intentID,
			BundleID:    bundleID,
			TxHashes:    txHashStrs,
			ProofClass:  "on_demand",
			TargetChain: a.unified.config.DefaultChainID,
			UserID:      userIDPtr,
		}

		fmt.Printf("[UnifiedAdapter] Starting unified proof cycle for intent %s with target chain %s\n",
			intentID, a.unified.config.DefaultChainID)

		// Start cycle asynchronously
		go func() {
			fmt.Printf("[UnifiedAdapter] Goroutine started for intent %s\n", intentID)
			result, err := a.unified.StartProofCycle(context.Background(), req)
			if err != nil {
				fmt.Printf("[UnifiedAdapter] Unified proof cycle FAILED for %s: %v\n", intentID, err)
			} else if result != nil {
				fmt.Printf("[UnifiedAdapter] Unified proof cycle COMPLETED for %s: success=%v, phase=%d\n",
					intentID, result.Success, result.FailPhase)
			}
		}()
		return nil
	}

	// Use legacy orchestrator
	if a.legacy != nil {
		return a.legacy.StartProofCycleWithAllTxs(ctx, intentID, userID, bundleID, txHashes, commitment)
	}

	return nil
}

// StartProofCycleWithAccumulateRef implements the enhanced ProofCycleOrchestratorInterface with Accumulate reference data
func (a *UnifiedOrchestratorAdapter) StartProofCycleWithAccumulateRef(
	ctx context.Context,
	intentID string,
	userID string,
	bundleID [32]byte,
	txHashes interface{},
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	fmt.Printf("[UnifiedAdapter] StartProofCycleWithAccumulateRef: intent=%s, accountURL=%s, txHash=%s, bvn=%s\n",
		intentID, accumulateAccountURL, accumulateTxHash, bvn)

	if a.useUnified && a.unified != nil {
		// Extract tx hashes from the interface
		var txHashStrs []string
		switch hashes := txHashes.(type) {
		case []string:
			txHashStrs = hashes
		case *AnchorWorkflowTxHashes:
			txHashStrs = []string{
				hashes.CreateTxHash.Hex(),
				hashes.VerifyTxHash.Hex(),
				hashes.GovernanceTxHash.Hex(),
			}
		default:
			// Handle AnchorWorkflowTxHashes from consensus package (different type due to package boundary)
			if extracted := extractTxHashesViaReflection(txHashes); extracted != nil {
				txHashStrs = []string{
					extracted.CreateTxHash.Hex(),
					extracted.VerifyTxHash.Hex(),
					extracted.GovernanceTxHash.Hex(),
				}
			} else {
				txHashStrs = []string{fmt.Sprintf("%v", txHashes)}
			}
		}

		// Create unified request with Accumulate reference data
		var userIDPtr *string
		if userID != "" {
			userIDPtr = &userID
		}

		req := &UnifiedProofCycleRequest{
			IntentID:             intentID,
			BundleID:             bundleID,
			TxHashes:             txHashStrs,
			ProofClass:           "on_demand",
			TargetChain:          a.unified.config.DefaultChainID,
			UserID:               userIDPtr,
			AccumulateAccountURL: accumulateAccountURL,
			AccumulateTxHash:     accumulateTxHash,
			AccumulateBVN:        bvn,
		}

		fmt.Printf("[UnifiedAdapter] Starting unified proof cycle with Accumulate ref for intent %s\n", intentID)

		// Start cycle asynchronously
		go func() {
			result, err := a.unified.StartProofCycle(context.Background(), req)
			if err != nil {
				fmt.Printf("[UnifiedAdapter] Unified proof cycle FAILED for %s: %v\n", intentID, err)
			} else if result != nil {
				fmt.Printf("[UnifiedAdapter] Unified proof cycle COMPLETED for %s: success=%v\n", intentID, result.Success)
			}
		}()
		return nil
	}

	// Fall back to legacy method without Accumulate ref
	if a.legacy != nil {
		return a.legacy.StartProofCycleWithAllTxs(ctx, intentID, userID, bundleID, txHashes, commitment)
	}

	return nil
}

// =============================================================================
// BATCH PROCESSOR CALLBACK ADAPTER
// =============================================================================

// BatchAnchorCallbackAdapter creates an OnAnchorCallback that routes to UnifiedOrchestrator
// This connects the on_cadence batch flow to the unified proof cycle
func BatchAnchorCallbackAdapter(unified *UnifiedOrchestrator) func(
	ctx context.Context,
	batchID uuid.UUID,
	merkleRoot []byte,
	anchorTxHash string,
	txCount int,
	blockNumber int64,
) error {
	if unified == nil {
		return nil
	}

	return func(
		ctx context.Context,
		batchID uuid.UUID,
		merkleRoot []byte,
		anchorTxHash string,
		txCount int,
		blockNumber int64,
	) error {
		// Convert merkle root to [32]byte
		var merkleRootArr [32]byte
		if len(merkleRoot) >= 32 {
			copy(merkleRootArr[:], merkleRoot[:32])
		}

		// Create unified request for on_cadence batch
		req := &UnifiedProofCycleRequest{
			CycleID:     fmt.Sprintf("batch-%s", batchID.String()),
			BatchID:     &batchID,
			TxHashes:    []string{anchorTxHash},
			MerkleRoot:  merkleRootArr,
			ProofClass:  "on_cadence",
			TargetChain: unified.config.DefaultChainID,
			Metadata: map[string]string{
				"tx_count":     fmt.Sprintf("%d", txCount),
				"block_number": fmt.Sprintf("%d", blockNumber),
			},
		}

		// Start cycle asynchronously
		go func() {
			result, err := unified.StartProofCycle(ctx, req)
			if err != nil {
				fmt.Printf("Unified proof cycle for batch %s failed: %v\n", batchID, err)
			} else if result != nil {
				fmt.Printf("Unified proof cycle for batch %s completed: success=%v\n", batchID, result.Success)
			}
		}()

		return nil
	}
}

// =============================================================================
// HELPER: Get Unified if Legacy Adapter
// =============================================================================

// GetUnifiedOrchestrator returns the unified orchestrator if this adapter is using it
func (a *UnifiedOrchestratorAdapter) GetUnifiedOrchestrator() *UnifiedOrchestrator {
	return a.unified
}

// GetLegacyOrchestrator returns the legacy orchestrator
func (a *UnifiedOrchestratorAdapter) GetLegacyOrchestrator() *ProofCycleOrchestrator {
	return a.legacy
}

// IsUsingUnified returns true if the adapter is using the unified orchestrator
func (a *UnifiedOrchestratorAdapter) IsUsingUnified() bool {
	return a.useUnified && a.unified != nil
}
