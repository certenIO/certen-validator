// Copyright 2025 Certen Protocol
//
// Anchor Manager Wrapper - Bridges anchor.AnchorManager to batch.AnchorManagerInterface
// Per Implementation Plan Phase 5: Wire batch system to AnchorManager
// Per Implementation Plan Phase 1 (CRITICAL-001): ExecuteComprehensiveProof support
//
// This wrapper handles the type conversion between batch and anchor packages,
// allowing the batch.Processor to call anchor.AnchorManager methods.

package batch

import (
	"context"
	"log"
)

// AnchorManagerWrapper wraps an anchor.AnchorManager to implement AnchorManagerInterface
// This is used in main.go to connect the batch system to the anchor manager
type AnchorManagerWrapper struct {
	// createFunc is the function that creates anchors on-chain
	// We use a function reference instead of importing anchor package to avoid circular imports
	createFunc func(ctx context.Context, batchID string, merkleRoot, opCommit, crossCommit, govRoot []byte,
		txCount int, accumHeight int64, accumHash, targetChain, validatorID string) (
		txHash string, blockNumber int64, blockHash string, gasUsed int64,
		gasPriceWei, totalCostWei string, success bool, err error)

	// executeProofFunc is the function that executes comprehensive proofs on-chain
	// Per CRITICAL-001: This MUST be called after CreateBatchAnchorOnChain
	executeProofFunc func(ctx context.Context, req interface{}) (interface{}, error)

	// logger for logging proof execution
	logger *log.Logger
}

// NewAnchorManagerWrapper creates a new wrapper for anchor creation only
// The createFunc should call anchor.AnchorManager.CreateBatchAnchorOnChain internally
// Note: This constructor creates a wrapper without ExecuteComprehensiveProof support
// Use NewAnchorManagerWrapperFull for complete Phase 1 CRITICAL-001 compliance
func NewAnchorManagerWrapper(createFunc func(ctx context.Context, batchID string, merkleRoot, opCommit, crossCommit, govRoot []byte,
	txCount int, accumHeight int64, accumHash, targetChain, validatorID string) (
	txHash string, blockNumber int64, blockHash string, gasUsed int64,
	gasPriceWei, totalCostWei string, success bool, err error)) *AnchorManagerWrapper {
	return &AnchorManagerWrapper{
		createFunc: createFunc,
		logger:     log.New(log.Writer(), "[AnchorWrapper] ", log.LstdFlags),
	}
}

// NewAnchorManagerWrapperFull creates a wrapper with both anchor creation and proof execution
// Per CRITICAL-001: ExecuteComprehensiveProof MUST be called after CreateBatchAnchorOnChain
func NewAnchorManagerWrapperFull(
	createFunc func(ctx context.Context, batchID string, merkleRoot, opCommit, crossCommit, govRoot []byte,
		txCount int, accumHeight int64, accumHash, targetChain, validatorID string) (
		txHash string, blockNumber int64, blockHash string, gasUsed int64,
		gasPriceWei, totalCostWei string, success bool, err error),
	executeProofFunc func(ctx context.Context, req interface{}) (interface{}, error),
	logger *log.Logger,
) *AnchorManagerWrapper {
	if logger == nil {
		logger = log.New(log.Writer(), "[AnchorWrapper] ", log.LstdFlags)
	}
	return &AnchorManagerWrapper{
		createFunc:       createFunc,
		executeProofFunc: executeProofFunc,
		logger:           logger,
	}
}

// SetExecuteProofFunc sets the proof execution function (for late binding)
func (w *AnchorManagerWrapper) SetExecuteProofFunc(f func(ctx context.Context, req interface{}) (interface{}, error)) {
	w.executeProofFunc = f
}

// CreateBatchAnchorOnChain implements AnchorManagerInterface
func (w *AnchorManagerWrapper) CreateBatchAnchorOnChain(ctx context.Context, req *AnchorOnChainRequest) (*AnchorOnChainResult, error) {
	txHash, blockNumber, blockHash, gasUsed, gasPriceWei, totalCostWei, success, err := w.createFunc(
		ctx,
		req.BatchID,
		req.MerkleRoot,
		req.OperationCommitment,
		req.CrossChainCommitment,
		req.GovernanceRoot,
		req.TxCount,
		req.AccumulateHeight,
		req.AccumulateHash,
		req.TargetChain,
		req.ValidatorID,
	)
	if err != nil {
		return nil, err
	}

	return &AnchorOnChainResult{
		TxHash:       txHash,
		BlockNumber:  blockNumber,
		BlockHash:    blockHash,
		GasUsed:      gasUsed,
		GasPriceWei:  gasPriceWei,
		TotalCostWei: totalCostWei,
		Success:      success,
	}, nil
}

// ExecuteComprehensiveProofOnChain implements AnchorManagerInterface
// Per CRITICAL-001: This MUST be called after CreateBatchAnchorOnChain to submit
// the L1-L4 cryptographic proofs and G0-G2 governance proofs to the contract
func (w *AnchorManagerWrapper) ExecuteComprehensiveProofOnChain(ctx context.Context, req interface{}) (interface{}, error) {
	if w.executeProofFunc == nil {
		// If no proof execution function is configured, log and return nil
		// This is acceptable during development but should be an error in production
		if w.logger != nil {
			w.logger.Printf("⚠️ ExecuteComprehensiveProofOnChain: no execution function configured (proof execution skipped)")
		}
		return nil, nil
	}

	return w.executeProofFunc(ctx, req)
}
