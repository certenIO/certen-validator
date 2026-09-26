// Copyright 2025 Certen Protocol
//
// Unified Orchestrator Adapter
// Implements consensus's ProofCycleOrchestratorInterface on the UnifiedOrchestrator, the only
// proof-cycle orchestrator. There is no legacy fallback: the legacy orchestrator ran with a
// one-member validator set and could not produce a quorum attestation, and a proof cycle requested
// with no orchestrator is refused by name (ErrProofCycleUnavailable), never skipped.

package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// =============================================================================
// UNIFIED ORCHESTRATOR ADAPTER
// =============================================================================

// ErrProofCycleUnavailable is a proof cycle requested where no orchestrator can run it.
var ErrProofCycleUnavailable = errors.New("proof cycle unavailable")

// UnifiedOrchestratorAdapter wraps UnifiedOrchestrator to implement
// the ProofCycleOrchestratorInterface expected by consensus/bft_integration.go
type UnifiedOrchestratorAdapter struct {
	unified *UnifiedOrchestrator
}

// NewUnifiedOrchestratorAdapter creates the adapter over the unified orchestrator.
func NewUnifiedOrchestratorAdapter(unified *UnifiedOrchestrator) *UnifiedOrchestratorAdapter {
	return &UnifiedOrchestratorAdapter{unified: unified}
}

// unavailable is the refusal every entry point gives when there is no orchestrator.
func (a *UnifiedOrchestratorAdapter) unavailable(intentID string) error {
	return fmt.Errorf("%w: no unified orchestrator for intent %s", ErrProofCycleUnavailable, intentID)
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

	if a.unified != nil {
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

		// The chain the member settled on, stamped by consensus from the chain its batch was flushed
		// on. There is no default to fall back to: a cycle that names no chain is refused rather
		// than observed somewhere guessed (RB3-F45).
		commitMap, _ := commitment.(map[string]interface{})
		targetChain, _ := commitMap["targetChain"].(string)
		if targetChain == "" {
			return fmt.Errorf("intent %s: the proof cycle names no target chain - refusing rather than guessing one", intentID)
		}

		// Extract governance data from commitment (for G1/G2 proof levels)
		var governanceRoot, operationCommitment [32]byte
		var keyPageThreshold, keyPageKeyCount int
		if commitMap != nil {
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

		fmt.Printf("[UnifiedAdapter] Target chain for Phase 7-9: %s\n", targetChain)

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

	return a.unavailable(intentID)
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
