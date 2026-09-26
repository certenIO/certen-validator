// services/validator/pkg/execution/executor.go
//
// BFT Execution Adapter - Thin integration layer for BFT consensus pipeline
//
// This module provides dependency injection and API endpoints for the canonical
// BFT consensus pipeline. It serves as a bridge between HTTP/gRPC interfaces
// and the core consensus.BFTValidator.
//
// IMPORTANT: All execution logic now runs through consensus.BFTValidator.
// This file only handles wiring and API adaptation.

package execution

import (
	"context"

	"github.com/certen/independant-validator/pkg/anchor"
	"github.com/certen/independant-validator/pkg/consensus"
)

// =====================================
// Adapter wrappers for dependency injection
// =====================================

// AnchorManagerWrapper adapts anchor.AnchorManager to consensus.AnchorManager interface
type AnchorManagerWrapper struct {
	manager *anchor.AnchorManager
}

func NewAnchorManagerWrapper(manager *anchor.AnchorManager) *AnchorManagerWrapper {
	return &AnchorManagerWrapper{manager: manager}
}

func (amw *AnchorManagerWrapper) CreateAnchor(ctx context.Context, req *consensus.AnchorRequest) (*consensus.AnchorResponse, error) {
	// Convert consensus types to anchor types
	anchorReq := &anchor.AnchorRequest{
		RequestID:       req.RequestID,
		TargetChains:    req.TargetChains,
		Priority:        req.Priority,
		TransactionHash: req.TransactionHash,
		AccountURL:      req.AccountURL,
	}

	// Call the actual anchor manager
	resp, err := amw.manager.CreateAnchor(ctx, anchorReq)
	if err != nil {
		return nil, err
	}

	// Convert response back to consensus types
	return &consensus.AnchorResponse{
		AnchorID: resp.AnchorID,
		Success:  resp.Success,
		Message:  resp.Message,
	}, nil
}

// =====================================
// BFT Execution Handler - Thin API adapter
// =====================================

// =====================================
// Legacy support notice
// =====================================

// REMOVED: All legacy queue-based execution architecture has been eliminated.
//
// Legacy components that have been removed:
// - IntentExecutor (queue-based execution manager)
// - ExecutionJob/ExecutionResult processing
// - pendingExecutions tracking
// - executionQueue/resultQueue channels
// - Custom pipeline execution logic
// - ExecutionMetrics (replaced by BFT metrics)
//
// The canonical execution flow is now:
//   Accumulate Blockchain → IntentDiscovery → BFTValidator.ExecuteCanonicalIntentWithBFTConsensus → CometBFT ABCI
//
// NOTE: HTTP API execution is DEPRECATED per E.1 remediation.
// All intents must flow through IntentDiscovery which provides:
// - CertenIntent: canonical 4-blob structure (intentData, crossChainData, governanceData, replayData)
// - CertenProof: cryptographic proof from Accumulate lite client
//
// For migration from legacy IntentExecutor:
// 1. Configure IntentDiscovery to monitor Accumulate for CERTEN_INTENT transactions
// 2. IntentDiscovery automatically calls ExecuteCanonicalIntentWithBFTConsensus with proper artifacts
// 3. Use BFTValidator.GetMetrics() for execution metrics
// 4. Use CometBFT ABCI state for execution tracking instead of custom contexts
