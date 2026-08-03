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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

// sortInts sorts a slice of ints in ascending order
func sortInts(s []int) { sort.Ints(s) }

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
		// Extract target chain from commitment if available
		targetChain := a.unified.config.DefaultChainID
		if commitMap, ok := commitment.(map[string]interface{}); ok {
			if tc, ok := commitMap["targetChain"].(string); ok && tc != "" {
				targetChain = tc
			}
		}

		// Create unified request
		req := &UnifiedProofCycleRequest{
			IntentID:    intentID,
			BundleID:    bundleID,
			TxHashes:    []string{executionTxHash.Hex()},
			ProofClass:  "on_demand",
			TargetChain: targetChain,
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
			// Prefer the filtered list, exactly as StartProofCycleWithAccumulateRef does. This is
			// the ON_DEMAND path, and it had the same defect: rebuilding a fixed three-slot list
			// from the typed fields renders unset ones as "0x000…000" via common.Hash.Hex() — a
			// non-empty string that reads as a real hash, so Phase 7 polls for receipts that can
			// never exist and the cycle stalls before Phases 8 and 9.
			if len(hashes.RawTxHashes) > 0 {
				txHashStrs = hashes.RawTxHashes
			} else {
				txHashStrs = []string{
					hashes.CreateTxHash.Hex(),
					hashes.VerifyTxHash.Hex(),
					hashes.GovernanceTxHash.Hex(),
				}
			}
		default:
			// Handle AnchorWorkflowTxHashes from consensus package (different type due to package boundary)
			// Use reflection to extract the hash fields
			if extracted := extractTxHashesViaReflection(txHashes); extracted != nil {
				if len(extracted.RawTxHashes) > 0 {
					txHashStrs = extracted.RawTxHashes
				} else {
					txHashStrs = []string{
						extracted.CreateTxHash.Hex(),
						extracted.VerifyTxHash.Hex(),
						extracted.GovernanceTxHash.Hex(),
					}
				}
			} else {
				txHashStrs = []string{fmt.Sprintf("%v", txHashes)}
			}
		}

		// Same boundary rule as the Accumulate-ref path: a zero hash is indistinguishable from a
		// real one downstream, so it never gets past here.
		txHashStrs = dropUnobservableHashes(txHashStrs)
		if len(txHashStrs) == 0 {
			return fmt.Errorf("intent %s: no observable transaction for Phase 7 (on_demand) — "+
				"refusing to start a proof cycle that cannot complete", intentID)
		}

		fmt.Printf("[UnifiedAdapter] Extracted %d tx hashes for intent %s: %v\n", len(txHashStrs), intentID, txHashStrs)

		// Extract operation commitment and target chain from commitment interface
		var operationCommitment [32]byte
		var targetChainFromCommit string
		if commitMap, ok := commitment.(map[string]interface{}); ok {
			if opCommitStr, ok := commitMap["operationCommitment"].(string); ok && opCommitStr != "" {
				if decoded, err := hexStringToBytes32(opCommitStr); err == nil {
					operationCommitment = decoded
				}
			}
			if tc, ok := commitMap["targetChain"].(string); ok && tc != "" {
				targetChainFromCommit = tc
			}
		}

		// For on-demand proofs (single transaction):
		// LeafIndex = 0, LeafHash = operation commitment
		var leafHash []byte
		var merkleRoot [32]byte
		if operationCommitment != [32]byte{} {
			leafHash = operationCommitment[:]
			merkleRoot = operationCommitment
		}

		// Use target chain from commitment, fall back to default
		targetChain := targetChainFromCommit
		if targetChain == "" {
			targetChain = a.unified.config.DefaultChainID
		}

		// Create unified request
		var userIDPtr *string
		if userID != "" {
			userIDPtr = &userID
		}

		req := &UnifiedProofCycleRequest{
			IntentID:            intentID,
			BundleID:            bundleID,
			TxHashes:            txHashStrs,
			ProofClass:          "on_demand",
			TargetChain:         targetChain,
			UserID:              userIDPtr,
			OperationCommitment: operationCommitment,
			// Merkle inclusion proof data
			LeafHash:   leafHash,
			LeafIndex:  0,
			MerklePath: nil,
			MerkleRoot: merkleRoot,
		}

		fmt.Printf("[UnifiedAdapter] Starting unified proof cycle for intent %s with target chain %q (from commitment: %q)\n",
			intentID, targetChain, targetChainFromCommit)

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
			// Use the filtered list whenever it has ANY entry.
			//
			// This was `== 3`. A batch member has no separate create or verify transaction — the
			// anchor and its quorum attestation are paid ONCE for the whole tree — so its filtered
			// list holds 1 or 2 hashes and ALWAYS fell to the branch below, which rebuilds the
			// fixed three-slot list from the typed fields. common.Hash.Hex() on an unset field
			// yields "0x000…000": a non-empty string that reads as a real hash, so Phase 7 polled
			// for receipts that can never exist and stalled without ever reporting a cause.
			//
			// The length of this list is not a contract — it is however many transactions the
			// intent actually produced.
			if len(hashes.RawTxHashes) > 0 {
				txHashStrs = hashes.RawTxHashes
			} else {
				txHashStrs = []string{
					hashes.CreateTxHash.Hex(),
					hashes.VerifyTxHash.Hex(),
					hashes.GovernanceTxHash.Hex(),
				}
			}
		default:
			// Handle AnchorWorkflowTxHashes from consensus package (different type due to package boundary)
			if extracted := extractTxHashesViaReflection(txHashes); extracted != nil {
				// Same rule as the typed case above: any entry means the list is authoritative.
				if len(extracted.RawTxHashes) > 0 {
					txHashStrs = extracted.RawTxHashes
				} else {
					txHashStrs = []string{
						extracted.CreateTxHash.Hex(),
						extracted.VerifyTxHash.Hex(),
						extracted.GovernanceTxHash.Hex(),
					}
				}
			} else {
				txHashStrs = []string{fmt.Sprintf("%v", txHashes)}
			}
		}

		// Drop anything that is not a real transaction hash.
		//
		// Defence in depth: the branches above should now only ever produce hashes that exist, but
		// a zero hash reaching Phase 7 is indistinguishable from a real one at the observation
		// layer — it simply waits for a receipt that can never arrive and stalls the whole cycle,
		// taking Phases 8 and 9 with it. Nothing downstream can recover from that, so it is
		// rejected here rather than diagnosed later.
		txHashStrs = dropUnobservableHashes(txHashStrs)
		if len(txHashStrs) == 0 {
			return fmt.Errorf("intent %s: no observable transaction for Phase 7 "+
				"(every candidate hash was empty or zero) — refusing to start a proof cycle that "+
				"cannot complete", intentID)
		}
		fmt.Printf("[UnifiedAdapter] Phase 7 will observe %d transaction(s): %v\n", len(txHashStrs), txHashStrs)

		// Extract governance data and target chain from commitment (for G1/G2 proof levels)
		var governanceRoot, operationCommitment [32]byte
		var keyPageThreshold, keyPageKeyCount int
		var targetChainFromCommitment string
		commitMap, _ := commitment.(map[string]interface{})
		if commitMap != nil {
			// Extract targetChain from commitment (set by buildExecutionCommitmentFromIntent)
			if tc, ok := commitMap["targetChain"].(string); ok && tc != "" {
				targetChainFromCommitment = tc
			}
			// Extract governanceRoot (hex string -> [32]byte)
			if govRootStr, ok := commitMap["governanceRoot"].(string); ok && govRootStr != "" {
				if decoded, err := hexStringToBytes32(govRootStr); err == nil {
					governanceRoot = decoded
				}
			}
			// Extract operationCommitment (hex string -> [32]byte)
			if opCommitStr, ok := commitMap["operationCommitment"].(string); ok && opCommitStr != "" {
				if decoded, err := hexStringToBytes32(opCommitStr); err == nil {
					operationCommitment = decoded
				}
			}
			// Extract key page governance threshold (M of N multi-sig)
			if threshold, ok := commitMap["signatureThreshold"].(float64); ok {
				keyPageThreshold = int(threshold)
			}
			if keyCount, ok := commitMap["keyPageKeyCount"].(float64); ok {
				keyPageKeyCount = int(keyCount)
			}
			// Fallback: if not provided, default to 1 of 1 (single sig)
			if keyPageThreshold == 0 {
				keyPageThreshold = 1
			}
			if keyPageKeyCount == 0 {
				keyPageKeyCount = 1
			}
		}

		// Extract multi-leg metadata
		var legCount int
		if commitMap != nil {
			if lc, ok := commitMap["legCount"].(float64); ok {
				legCount = int(lc)
			} else if lc, ok := commitMap["legCount"].(int); ok {
				legCount = lc
			}
		}

		// Create unified request with Accumulate reference data
		var userIDPtr *string
		if userID != "" {
			userIDPtr = &userID
		}

		// For on-demand proofs (single transaction):
		// - LeafIndex = 0 (single transaction in batch)
		// - LeafHash = operation commitment (the leaf hash)
		// - MerklePath = nil (single leaf, leaf is the root)
		// - MerkleRoot = operation commitment (for single leaf, root = leaf)
		var leafHash []byte
		var merkleRoot [32]byte
		if operationCommitment != [32]byte{} {
			leafHash = operationCommitment[:]
			merkleRoot = operationCommitment // For single tx, merkle root = leaf
		}

		// Use target chain from commitment (set by BFT validator from intent's CrossChainData)
		// Fall back to default chain ID only if commitment didn't include it
		targetChain := targetChainFromCommitment
		if targetChain == "" {
			targetChain = a.unified.config.DefaultChainID
		}

		// For multi-chain intents, the tx hashes come from the first successful chain
		// which may differ from the commitment's targetChain (leg 0's chain).
		// Extract the actual chain from the raw create tx hash to ensure consistency.
		if legCount > 1 && commitMap != nil {
			if rawCreate, ok := commitMap["rawCreateTxHashes"].(string); ok && rawCreate != "" {
				// Format: "ChainName:0xhash,ChainName2:0xhash2,...,create_failed_ChainName3"
				// Find the first valid (non-failed) entry
				for _, part := range strings.Split(rawCreate, ",") {
					part = strings.TrimSpace(part)
					if strings.Contains(part, "_failed") {
						continue
					}
					if colonIdx := strings.LastIndex(part, ":"); colonIdx > 0 {
						chainFromTx := strings.TrimSpace(part[:colonIdx])
						// Normalize: "Optimism Sepolia" -> "optimism-sepolia"
						normalized := strings.ToLower(strings.ReplaceAll(chainFromTx, " ", "-"))
						if normalized != "" && normalized != targetChain {
							fmt.Printf("[UnifiedAdapter] Multi-chain: overriding target chain from %q to %q (matching first successful tx)\n",
								targetChain, normalized)
							targetChain = normalized
						}
						break
					}
				}
			}
		}

		fmt.Printf("[UnifiedAdapter] Target chain for Phase 7-9: %q (from commitment: %q, default: %q)\n",
			targetChain, targetChainFromCommitment, a.unified.config.DefaultChainID)

		req := &UnifiedProofCycleRequest{
			IntentID:             intentID,
			BundleID:             bundleID,
			TxHashes:             txHashStrs,
			ProofClass:           "on_demand",
			TargetChain:          targetChain,
			UserID:               userIDPtr,
			AccumulateAccountURL: accumulateAccountURL,
			AccumulateTxHash:     accumulateTxHash,
			AccumulateBVN:        bvn,
			GovernanceRoot:       governanceRoot,
			OperationCommitment:  operationCommitment,
			// Key page governance threshold (M of N)
			KeyPageThreshold: keyPageThreshold,
			KeyPageKeyCount:  keyPageKeyCount,
			// Merkle inclusion proof data (for MerkleTreeVisualization)
			LeafHash:       leafHash,
			LeafIndex:      0,   // Single transaction, always index 0
			MerklePath:     nil, // Empty path for single leaf (leaf = root)
			MerkleRoot:     merkleRoot,
			CommitmentData: commitMap,
		}

		if legCount > 1 {
			fmt.Printf("[UnifiedAdapter] Multi-leg intent detected: %d legs for intent %s\n",
				legCount, intentID)
		}

		fmt.Printf("[UnifiedAdapter] Starting unified proof cycle with Accumulate ref for intent %s\n", intentID)

		// Start cycle asynchronously.
		//
		// Bounded and unconditionally logged. Both were missing, and between them they hid every
		// Phase 7 failure since 2026-07-29:
		//
		//   - context.Background() carries no deadline, so a Phase 7 observation that never
		//     resolves blocks this goroutine forever. The intent settles on chain and its proof
		//     cycle simply never ends — no error, no completion, no retry.
		//   - The logging had no branch for err == nil && result == nil, so that outcome printed
		//     NOTHING. Silence was indistinguishable from a cycle still in progress.
		//
		// Every path now says what happened.
		go func() {
			cycleCtx, cancel := context.WithTimeout(context.Background(), unifiedProofCycleTimeout)
			defer cancel()

			started := time.Now()
			result, err := a.unified.StartProofCycle(cycleCtx, req)
			elapsed := time.Since(started).Round(time.Second)

			switch {
			case err != nil:
				fmt.Printf("[UnifiedAdapter] Unified proof cycle FAILED for %s after %s: %v\n", intentID, elapsed, err)
			case result == nil:
				fmt.Printf("[UnifiedAdapter] Unified proof cycle returned NO RESULT and NO ERROR for %s after %s "+
					"(ctx=%v) — Phases 8 and 9 will not run for this intent\n", intentID, elapsed, cycleCtx.Err())
			default:
				fmt.Printf("[UnifiedAdapter] Unified proof cycle COMPLETED for %s after %s: success=%v error=%q\n",
					intentID, elapsed, result.Success, result.Error)
			}
			if cycleCtx.Err() != nil {
				fmt.Printf("[UnifiedAdapter] Unified proof cycle for %s hit its %s deadline — Phase 7 did not "+
					"resolve every observation\n", intentID, unifiedProofCycleTimeout)
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
// MULTI-LEG PROOF CYCLE SUPPORT
// =============================================================================

// StartMultiLegProofCycle starts a proof cycle for a chain group that is part of a multi-leg intent.
// Sets multi-leg metadata so Phase 9 defers write-back to the MultiLegAggregator.
func (a *UnifiedOrchestratorAdapter) StartMultiLegProofCycle(
	ctx context.Context,
	intentID string,
	chainKey string,
	totalLegs int,
	bundleID [32]byte,
	txHashes []string,
	targetChain string,
	commitmentData map[string]interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	if !a.useUnified || a.unified == nil {
		return fmt.Errorf("multi-leg proof cycles require unified orchestrator")
	}

	// Build leg_indices metadata: extract leg indices for this chain key from commitmentData
	legIndicesStr := ""
	if liRaw, ok := commitmentData["leg_indices_"+chainKey]; ok {
		if li, ok := liRaw.(string); ok {
			legIndicesStr = li
		}
	}

	// Extract governance and merkle data from commitment (same as single-leg path)
	var governanceRoot, operationCommitment [32]byte
	var keyPageThreshold, keyPageKeyCount int
	if commitmentData != nil {
		if govRootStr, ok := commitmentData["governanceRoot"].(string); ok && govRootStr != "" {
			if decoded, err := hexStringToBytes32(govRootStr); err == nil {
				governanceRoot = decoded
			}
		}
		if opCommitStr, ok := commitmentData["operationCommitment"].(string); ok && opCommitStr != "" {
			if decoded, err := hexStringToBytes32(opCommitStr); err == nil {
				operationCommitment = decoded
			}
		}
		if threshold, ok := commitmentData["signatureThreshold"].(float64); ok {
			keyPageThreshold = int(threshold)
		}
		if keyCount, ok := commitmentData["keyPageKeyCount"].(float64); ok {
			keyPageKeyCount = int(keyCount)
		}
		if keyPageThreshold == 0 {
			keyPageThreshold = 1
		}
		if keyPageKeyCount == 0 {
			keyPageKeyCount = 1
		}
	}

	// Compute merkle leaf/root from operation commitment (same as single-leg)
	var leafHash []byte
	var merkleRoot [32]byte
	if operationCommitment != [32]byte{} {
		leafHash = operationCommitment[:]
		merkleRoot = operationCommitment
	}

	req := &UnifiedProofCycleRequest{
		IntentID:             intentID,
		BundleID:             bundleID,
		TxHashes:             txHashes,
		ProofClass:           "on_demand",
		TargetChain:          targetChain,
		CommitmentData:       commitmentData,
		AccumulateAccountURL: accumulateAccountURL,
		AccumulateTxHash:     accumulateTxHash,
		AccumulateBVN:        bvn,
		GovernanceRoot:       governanceRoot,
		OperationCommitment:  operationCommitment,
		KeyPageThreshold:     keyPageThreshold,
		KeyPageKeyCount:      keyPageKeyCount,
		LeafHash:             leafHash,
		LeafIndex:            0,
		MerkleRoot:           merkleRoot,
		Metadata: map[string]string{
			"multi_leg":   "true",
			"chain_key":   chainKey,
			"total_legs":  fmt.Sprintf("%d", totalLegs),
			"intent_id":   intentID,
			"leg_indices": legIndicesStr,
		},
	}

	go func() {
		result, err := a.unified.StartProofCycle(context.Background(), req)
		if err != nil {
			fmt.Printf("[UnifiedAdapter] Multi-leg proof cycle FAILED for %s chain %s: %v\n",
				intentID, chainKey, err)
		} else if result != nil {
			fmt.Printf("[UnifiedAdapter] Multi-leg proof cycle COMPLETED for %s chain %s: success=%v\n",
				intentID, chainKey, result.Success)
		}
	}()

	return nil
}

// RegisterMultiLegIntent registers a multi-leg intent with the aggregator for unified write-back
func (a *UnifiedOrchestratorAdapter) RegisterMultiLegIntent(
	intentID string,
	operationID string,
	totalLegs int,
	executionMode string,
	legMapping map[int]LegChainInfo,
) {
	if a.unified != nil && a.unified.multiLegAggregator != nil {
		a.unified.multiLegAggregator.RegisterMultiLegIntent(
			intentID, operationID, totalLegs, executionMode, legMapping)
	}
}

// StartPerChainProofCycles implements per-chain Phase 7-9 proof cycles for multi-leg intents.
// It registers the intent with the MultiLegAggregator, then starts a separate proof cycle
// for each chain group. The aggregator collects results and produces a unified write-back.
func (a *UnifiedOrchestratorAdapter) StartPerChainProofCycles(
	ctx context.Context,
	intentID string,
	operationID string,
	bundleID [32]byte,
	chainTxHashes map[string][]string,
	legs interface{},
	executionMode string,
	commitment interface{},
	accumulateAccountURL string,
	accumulateTxHash string,
	bvn string,
) error {
	if !a.useUnified || a.unified == nil {
		return fmt.Errorf("per-chain proof cycles require unified orchestrator")
	}

	if a.unified.multiLegAggregator == nil {
		return fmt.Errorf("multi-leg aggregator not initialized")
	}

	// Extract legs via JSON roundtrip to bridge consensus.ChainLegInfo → local struct.
	// Both types have identical fields so JSON marshal/unmarshal maps cleanly.
	type chainLegInfo struct {
		LegIndex  int    `json:"LegIndex"`
		LegID     string `json:"LegID"`
		ChainKey  string `json:"ChainKey"`
		ChainName string `json:"ChainName"`
		ChainID   int64  `json:"ChainID"`
	}

	var legInfos []chainLegInfo
	legsJSON, err := json.Marshal(legs)
	if err != nil {
		return fmt.Errorf("marshal legs: %w", err)
	}
	if err := json.Unmarshal(legsJSON, &legInfos); err != nil {
		return fmt.Errorf("unmarshal legs: %w", err)
	}

	if len(legInfos) == 0 {
		return fmt.Errorf("no leg info provided for multi-leg proof cycles")
	}

	// Build leg mapping for the aggregator
	legMapping := make(map[int]LegChainInfo)
	for _, leg := range legInfos {
		legMapping[leg.LegIndex] = LegChainInfo{
			ChainKey:  leg.ChainKey,
			ChainName: leg.ChainName,
			ChainID:   leg.ChainID,
			LegID:     leg.LegID,
		}
	}

	// Register intent with the aggregator
	a.unified.multiLegAggregator.RegisterMultiLegIntent(
		intentID, operationID, len(legInfos), executionMode, legMapping)

	fmt.Printf("[UnifiedAdapter] Registered multi-leg intent %s with %d legs (mode=%s), starting per-chain proof cycles\n",
		intentID, len(legInfos), executionMode)

	// Build leg indices per chain key for positional observation matching (Workstream 1.1)
	legIndicesByChain := make(map[string][]int)
	for _, leg := range legInfos {
		legIndicesByChain[leg.ChainKey] = append(legIndicesByChain[leg.ChainKey], leg.LegIndex)
	}
	// Sort for determinism
	for ck := range legIndicesByChain {
		sortInts(legIndicesByChain[ck])
	}

	// For sequential mode, build dependency info to determine which chain groups
	// can start immediately vs which must wait (Workstream 2.4: GAP 6)
	readyChainKeys := make(map[string]bool)
	if executionMode == "sequential" {
		// Extract DependsOnLegs from commitment data
		type legDep struct {
			LegIndex      int
			ChainKey      string
			SequenceOrder int
			DependsOn     []string
		}
		var legDeps []legDep
		if cm, ok := commitment.(map[string]interface{}); ok {
			if legsRaw, ok := cm["legs_dependency_info"]; ok {
				if depsJSON, err := json.Marshal(legsRaw); err == nil {
					json.Unmarshal(depsJSON, &legDeps)
				}
			}
		}

		// Determine which chain groups have legs with no dependencies (can start immediately)
		if len(legDeps) > 0 {
			for _, dep := range legDeps {
				if len(dep.DependsOn) == 0 && dep.SequenceOrder == 0 {
					readyChainKeys[dep.ChainKey] = true
				}
			}
		} else {
			// No explicit dependency info - find chain groups containing sequence_order=0 legs
			for _, leg := range legInfos {
				// Without explicit deps, start all groups (parallel fallback)
				readyChainKeys[leg.ChainKey] = true
			}
		}

		if len(readyChainKeys) == 0 {
			// Safety: if nothing is ready, start all (avoid deadlock)
			for ck := range chainTxHashes {
				readyChainKeys[ck] = true
			}
		}
	} else {
		// parallel or atomic mode: all chain groups start immediately
		for ck := range chainTxHashes {
			readyChainKeys[ck] = true
		}
	}

	// Start a proof cycle for each ready chain group
	for chainKey, txHashes := range chainTxHashes {
		if len(txHashes) == 0 {
			continue
		}

		// For sequential mode, skip chain groups that aren't ready yet
		if !readyChainKeys[chainKey] {
			fmt.Printf("[UnifiedAdapter] Deferring chain group %s (sequential mode, dependencies not met)\n", chainKey)
			continue
		}

		// Determine target chain for strategy resolution
		targetChain := chainKey

		fmt.Printf("[UnifiedAdapter] Starting proof cycle for chain group %s (intent %s, %d tx hashes)\n",
			chainKey, intentID, len(txHashes))

		commitData := make(map[string]interface{})
		if cm, ok := commitment.(map[string]interface{}); ok {
			for k, v := range cm {
				commitData[k] = v
			}
		}
		commitData["chain_key"] = chainKey

		// Embed leg indices for this chain group into commitment data
		// so StartMultiLegProofCycle can pass them as metadata
		if indices, ok := legIndicesByChain[chainKey]; ok {
			parts := make([]string, len(indices))
			for i, idx := range indices {
				parts[i] = fmt.Sprintf("%d", idx)
			}
			commitData["leg_indices_"+chainKey] = strings.Join(parts, ",")
		}

		if err := a.StartMultiLegProofCycle(
			ctx, intentID, chainKey, len(legInfos), bundleID,
			txHashes, targetChain, commitData,
			accumulateAccountURL, accumulateTxHash, bvn,
		); err != nil {
			fmt.Printf("[UnifiedAdapter] WARNING: Failed to start proof cycle for chain %s: %v\n", chainKey, err)
			// Continue with other chains - partial results are better than none
		}
	}

	return nil
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

// =============================================================================
// HELPER: Hex String to Bytes32
// =============================================================================

// hexStringToBytes32 converts a hex string (with or without 0x prefix) to [32]byte
func hexStringToBytes32(hexStr string) ([32]byte, error) {
	var result [32]byte

	// Remove 0x prefix if present
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Decode hex string
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return result, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Copy to fixed-size array (pad or truncate as needed)
	if len(decoded) > 32 {
		copy(result[:], decoded[:32])
	} else {
		copy(result[32-len(decoded):], decoded)
	}

	return result, nil
}

// dropUnobservableHashes removes empty and all-zero hashes.
//
// common.Hash.Hex() renders an unset field as "0x000…000", which is a non-empty string that reads
// as a valid hash everywhere downstream. Phase 7 cannot tell it apart from a real one and will
// poll for its receipt until the observation deadline expires.
func dropUnobservableHashes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		t := strings.TrimSpace(h)
		if t == "" {
			continue
		}
		// Must be a real 32-byte hash. The executor records FAILURE MARKERS in the same fields —
		// "create_failed_Ethereum Sepolia", "execution_failed_leg-...", "verify_failed_..." — and
		// Phase 7 cannot tell those from a hash: it just polls for a receipt that will never
		// exist and burns the entire observation deadline. That is what stopped multi-leg
		// write-backs on 2026-08-03: the legs SETTLED on chain, then the proof cycle sat for
		// 10 minutes on "observe transaction 0 (create_failed_Ethereum Sepolia)" and the
		// aggregator never saw its chain group complete.
		if !isHash32(t) {
			continue
		}
		if strings.Trim(strings.TrimPrefix(strings.ToLower(t), "0x"), "0") == "" {
			continue // all zeroes
		}
		out = append(out, t)
	}
	return out
}

// unifiedProofCycleTimeout bounds one intent's Phase 7-9 run.
//
// Phase 7 waits on external-chain receipts, so it is legitimately slow — but never unbounded. An
// unbounded wait is indistinguishable from a hang and leaves the intent settled on chain with no
// record written back to acc://certen-protocol.acme/execution-results.
var unifiedProofCycleTimeout = 10 * time.Minute

// isHash32 reports whether s is a 0x-prefixed 32-byte hex string.
//
// Deliberately strict: anything else in a transaction-hash field is a marker or a mistake, and
// treating it as a hash costs a full observation timeout per entry.
func isHash32(s string) bool {
	h := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
