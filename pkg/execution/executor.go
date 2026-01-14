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
    "encoding/json"
    "fmt"
    "log"
    "net/http"

    "github.com/certen/independant-validator/pkg/verification"

    "github.com/certen/independant-validator/pkg/anchor"
    "github.com/certen/independant-validator/pkg/consensus"
    "github.com/certen/independant-validator/pkg/proof"
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

// TargetChainExecutorWrapper adapts BFTTargetChainExecutor to verification.TargetChainExecutor interface
type TargetChainExecutorWrapper struct {
    executor    *BFTTargetChainExecutor
    validatorID string
}

// NewTargetChainExecutorWrapper creates a new wrapper with the given validator ID
func NewTargetChainExecutorWrapper(executor *BFTTargetChainExecutor, validatorID string) *TargetChainExecutorWrapper {
    if validatorID == "" {
        validatorID = "bft-validator" // Fallback default
    }
    return &TargetChainExecutorWrapper{
        executor:    executor,
        validatorID: validatorID,
    }
}

// SubmitAnchorFromValidatorBlock implements verification.TargetChainExecutor
func (tcew *TargetChainExecutorWrapper) SubmitAnchorFromValidatorBlock(
    ctx context.Context,
    vb *verification.ValidatorBlockMetadata,
    bft *verification.BFTExecutionMetadata,
) (*verification.AnchorExecutionResult, error) {
    // Extract data from the sanitized metadata types
    intentID := vb.IntentID
    validatorID := tcew.validatorID // From wrapper configuration
    bundleID := vb.RoundID
    anchorID := fmt.Sprintf("anchor-%d", bft.Height)

    // Create COMPLETE proof structure with all proof data from ValidatorBlockMetadata
    // CRITICAL: The previous "minimal" proof was missing LiteClientProof.BPTRoot and
    // BLSAggregateSignature, causing createAnchor() to receive zeros for crossChainCommitment
    // and governanceRoot. This fix populates all proof data.
    //
    // NOTE: We use vb.SourceBlockHeight (Accumulate block height) NOT bft.Height (CometBFT height).
    // The anchor needs the Accumulate source block for proper chain binding.
    certenProof := &proof.CertenProof{
        ProofID:               fmt.Sprintf("proof-%s", intentID),
        BlockHeight:           vb.SourceBlockHeight, // Accumulate block height, NOT CometBFT height
        TransactionHash:       vb.TransactionHash,
        AccountURL:            vb.AccountURL,
        GeneratedAt:           bft.CommittedAt,
        BLSAggregateSignature: vb.BLSAggregateSignature,
        // LiteClientProof with CompleteProof for Merkle proof extraction
        // CRITICAL: CompleteProof contains the full Merkle receipts (MainChainProof, BPTProof,
        // CombinedReceipt, etc.) which extractMerkleProofHashes() needs to build proofHashes[].
        // Without CompleteProof, the contract's merkleVerified check fails.
        LiteClientProof: &proof.LiteClientProofData{
            CompleteProof:   vb.LiteClientProof, // CRITICAL: Pass complete proof for Merkle verification
            BPTRoot:         vb.BPTRoot,
            ProofValid:      len(vb.BPTRoot) > 0 || vb.LiteClientProof != nil,
            ValidationLevel: "complete_proof",
        },
        // Verification status
        VerificationStatus: &proof.VerificationStatusData{
            OverallValid:      (len(vb.BPTRoot) > 0 || vb.LiteClientProof != nil) && len(vb.GovernanceRoot) > 0,
            Confidence:        1.0,
            VerificationLevel: "complete",
            VerifiedAt:        bft.CommittedAt,
            ComponentStatus: map[string]bool{
                "bpt_root":               len(vb.BPTRoot) > 0,
                "governance_root":        len(vb.GovernanceRoot) > 0,
                "cross_chain_commitment": len(vb.CrossChainCommitment) > 0,
                "bls_signature":          len(vb.BLSAggregateSignature) > 0,
                "complete_proof":         vb.LiteClientProof != nil, // CRITICAL: tracks if Merkle proofs available
            },
        },
    }

    // Log proof data including the critical CompleteProof
    hasCompleteProof := vb.LiteClientProof != nil
    var merkleReceiptCount int
    if hasCompleteProof {
        if vb.LiteClientProof.MainChainProof != nil {
            merkleReceiptCount++
        }
        if vb.LiteClientProof.BPTProof != nil {
            merkleReceiptCount++
        }
        if vb.LiteClientProof.CombinedReceipt != nil {
            merkleReceiptCount++
        }
    }

    log.Printf("📦 [EXECUTOR] Created proof with real data:")
    log.Printf("   BPTRoot: %d bytes", len(vb.BPTRoot))
    log.Printf("   CrossChainCommitment: %d bytes", len(vb.CrossChainCommitment))
    log.Printf("   GovernanceRoot: %d bytes", len(vb.GovernanceRoot))
    log.Printf("   BLSAggregateSignature: %d chars", len(vb.BLSAggregateSignature))
    log.Printf("   SourceBlockHeight: %d (Accumulate)", vb.SourceBlockHeight)
    log.Printf("   CompleteProof present: %v (Merkle receipts: %d)", hasCompleteProof, merkleReceiptCount)

    // Call the legacy ExecuteTargetChainOperations method
    result, err := tcew.executor.ExecuteTargetChainOperations(
        ctx, intentID, string(vb.OperationCommitment), vb.AccountURL,
        validatorID, bundleID, anchorID, certenProof,
    )
    if err != nil {
        return nil, err
    }

    // Convert result to new verification format
    return &verification.AnchorExecutionResult{
        AnchorTxID:  result.TxHash,
        Network:     result.Chain,
        Height:      result.BlockNumber,
        ConfirmedAt: bft.CommittedAt,
    }, nil
}

// =====================================
// BFT Execution Handler - Thin API adapter
// =====================================

// BFTExecutionHandler provides HTTP/API endpoints that delegate to BFTValidator.
// This is a thin adapter - all execution logic is in the consensus package.
type BFTExecutionHandler struct {
    validator *consensus.BFTValidator
    logger    *log.Logger
}

// ExecuteIntentRequest represents an API request to execute an intent
type ExecuteIntentRequest struct {
    IntentID        string                 `json:"intent_id"`
    TransactionHash string                 `json:"transaction_hash"`
    AccountURL      string                 `json:"account_url"`
    BlockHeight     uint64                 `json:"block_height"`
    Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ExecuteIntentResponse represents the API response
type ExecuteIntentResponse struct {
    Success   bool   `json:"success"`
    Message   string `json:"message"`
    RequestID string `json:"request_id,omitempty"`
}

// NewBFTExecutionHandler creates a new BFT execution handler.
// This is the canonical constructor for production intent execution.
func NewBFTExecutionHandler(validator *consensus.BFTValidator, logger *log.Logger) *BFTExecutionHandler {
    return &BFTExecutionHandler{
        validator: validator,
        logger:    logger,
    }
}

// HandleExecuteIntent provides HTTP endpoint for intent execution.
// DEPRECATED: This endpoint is deprecated per E.1 remediation.
// Intents must flow through IntentDiscovery which calls ExecuteCanonicalIntentWithBFTConsensus
// with properly structured CertenIntent (4-blob) and CertenProof from lite client.
// HTTP-triggered execution cannot provide canonical proof artifacts and violates the Golden Spec.
func (h *BFTExecutionHandler) HandleExecuteIntent(w http.ResponseWriter, r *http.Request) {
    h.logger.Printf("⚠️ [BFT-HANDLER] DEPRECATED: HTTP intent execution endpoint called - this path is no longer supported")
    h.logger.Printf("   Intents must flow through IntentDiscovery → ExecuteCanonicalIntentWithBFTConsensus")

    // Return deprecation error
    resp := ExecuteIntentResponse{
        Success: false,
        Message: "DEPRECATED: HTTP intent execution is no longer supported. Intents must be discovered from Accumulate blockchain via IntentDiscovery, which provides canonical CertenIntent (4-blob structure) and CertenProof from lite client. Direct HTTP-triggered execution cannot provide these canonical proof artifacts and violates the Golden Spec.",
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusGone) // 410 Gone - resource no longer available
    json.NewEncoder(w).Encode(resp)
}

// GetMetrics returns BFT execution metrics
func (h *BFTExecutionHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
    // Delegate to BFT validator for metrics
    metrics := h.validator.GetMetrics()

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(metrics)
}

// GetStatus returns BFT execution status
func (h *BFTExecutionHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
    status := map[string]interface{}{
        "status":        "running",
        "pipeline_type": "bft_consensus",
        "validator_id":  h.validator.GetValidatorID(),
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(status)
}

// respondWithError is a helper for consistent error responses
func (h *BFTExecutionHandler) respondWithError(w http.ResponseWriter, statusCode int, message string, err error) {
    resp := ExecuteIntentResponse{
        Success: false,
        Message: message,
    }

    if err != nil {
        h.logger.Printf("❌ [BFT-HANDLER] Error: %s - %v", message, err)
        resp.Message = fmt.Sprintf("%s: %v", message, err)
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(resp)
}

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