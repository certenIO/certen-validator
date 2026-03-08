// Copyright 2025 Certen Protocol
//
// Multi-Leg Aggregator - Aggregates per-chain proof cycle results into unified write-back
// For multi-leg cross-chain intents, each chain group runs its own proof cycle.
// This component collects all per-chain results and produces a single unified
// Accumulate write-back entry containing per-leg proof summaries for ALL legs.

package execution

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
)

// =============================================================================
// MULTI-LEG AGGREGATOR
// =============================================================================

// MultiLegAggregator collects per-chain proof cycle results and produces
// a unified write-back for multi-leg cross-chain intents.
type MultiLegAggregator struct {
	mu sync.Mutex

	// Dependencies
	txBuilder *SyntheticTxBuilder
	submitter AccumulateSubmitter

	// Pending multi-leg intents waiting for all chain groups to complete
	pending map[string]*PendingMultiLeg // intentID -> pending

	// Result hash chains (shared from orchestrator)
	resultChains     map[string]*ResultHashChain
	resultChainsLock *sync.RWMutex

	// Configuration
	writeBackTimeout time.Duration
	validatorID      string

	// Callbacks
	onUnifiedWriteBack func(intentID string, txHash string)

	logger *log.Logger
}

// PendingMultiLeg tracks a multi-leg intent waiting for all chain groups to complete
type PendingMultiLeg struct {
	IntentID        string
	OperationID     string
	TotalLegs       int
	ExecutionMode   string
	CompletedCycles map[string]*UnifiedProofCycleResult // chainKey -> result
	LegMapping      map[int]LegChainInfo                // legIndex -> chain info
	CreatedAt       time.Time
}

// LegChainInfo maps a leg index to its chain information
type LegChainInfo struct {
	ChainKey  string
	ChainName string
	ChainID   int64
	LegID     string
}

// MultiLegAggregatorConfig holds configuration for the aggregator
type MultiLegAggregatorConfig struct {
	TxBuilder        *SyntheticTxBuilder
	Submitter        AccumulateSubmitter
	ResultChains     map[string]*ResultHashChain
	ResultChainsLock *sync.RWMutex
	WriteBackTimeout time.Duration
	ValidatorID      string
	Logger           *log.Logger
}

// NewMultiLegAggregator creates a new multi-leg aggregator
func NewMultiLegAggregator(cfg *MultiLegAggregatorConfig) *MultiLegAggregator {
	logger := cfg.Logger
	if logger == nil {
		logger = log.New(log.Writer(), "[MULTI-LEG-AGG] ", log.LstdFlags)
	}

	writeBackTimeout := cfg.WriteBackTimeout
	if writeBackTimeout == 0 {
		writeBackTimeout = 2 * time.Minute
	}

	return &MultiLegAggregator{
		txBuilder:        cfg.TxBuilder,
		submitter:        cfg.Submitter,
		pending:          make(map[string]*PendingMultiLeg),
		resultChains:     cfg.ResultChains,
		resultChainsLock: cfg.ResultChainsLock,
		writeBackTimeout: writeBackTimeout,
		validatorID:      cfg.ValidatorID,
		logger:           logger,
	}
}

// RegisterMultiLegIntent registers a new multi-leg intent for aggregation
func (a *MultiLegAggregator) RegisterMultiLegIntent(
	intentID string,
	operationID string,
	totalLegs int,
	executionMode string,
	legMapping map[int]LegChainInfo,
) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, exists := a.pending[intentID]; exists {
		return // Already registered
	}

	a.pending[intentID] = &PendingMultiLeg{
		IntentID:        intentID,
		OperationID:     operationID,
		TotalLegs:       totalLegs,
		ExecutionMode:   executionMode,
		CompletedCycles: make(map[string]*UnifiedProofCycleResult),
		LegMapping:      legMapping,
		CreatedAt:       time.Now(),
	}

	a.logger.Printf("Registered multi-leg intent %s with %d legs", intentID, totalLegs)
}

// OnChainGroupCycleComplete is called when a chain group's proof cycle finishes.
// When all chain groups are complete, triggers buildUnifiedWriteBack.
func (a *MultiLegAggregator) OnChainGroupCycleComplete(
	intentID string,
	chainKey string,
	result *UnifiedProofCycleResult,
) error {
	a.mu.Lock()

	pending, ok := a.pending[intentID]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("intent %s not registered for multi-leg aggregation", intentID)
	}

	// Store this chain group's result
	pending.CompletedCycles[chainKey] = result
	a.logger.Printf("Chain group %s completed for intent %s (%d/%d chain groups)",
		chainKey, intentID, len(pending.CompletedCycles), countUniqueChainKeys(pending.LegMapping))

	// Check if all chain groups are complete
	requiredChainKeys := getUniqueChainKeys(pending.LegMapping)
	allComplete := true
	for _, ck := range requiredChainKeys {
		if _, done := pending.CompletedCycles[ck]; !done {
			allComplete = false
			break
		}
	}

	if !allComplete {
		a.mu.Unlock()
		return nil
	}

	// All chain groups complete - build unified write-back
	a.logger.Printf("All chain groups complete for intent %s, building unified write-back", intentID)

	// Copy pending data and remove from map before releasing lock
	pendingCopy := *pending
	delete(a.pending, intentID)
	a.mu.Unlock()

	// Build and submit unified write-back
	return a.buildUnifiedWriteBack(&pendingCopy)
}

// buildUnifiedWriteBack collects all per-chain observation results,
// builds a unified AttestationBundle with LegResults for every leg,
// creates the CertenDataEntry with per-leg proof summaries, and submits to Accumulate.
func (a *MultiLegAggregator) buildUnifiedWriteBack(pending *PendingMultiLeg) error {
	// Build LegResults from all chain group observation results
	var legResults []LegResult

	// Sort leg indices for determinism
	legIndices := make([]int, 0, len(pending.LegMapping))
	for idx := range pending.LegMapping {
		legIndices = append(legIndices, idx)
	}
	sort.Ints(legIndices)

	for _, legIdx := range legIndices {
		legInfo := pending.LegMapping[legIdx]
		cycleResult, ok := pending.CompletedCycles[legInfo.ChainKey]
		if !ok {
			a.logger.Printf("WARNING: No cycle result for chain key %s (leg %d)", legInfo.ChainKey, legIdx)
			continue
		}

		// Find the observation result for this leg within the chain group's results
		obs := findObservationForLeg(cycleResult, legIdx, legInfo)

		legResult := LegResult{
			LegIndex:    legIdx,
			LegID:       legInfo.LegID,
			Chain:       legInfo.ChainName,
			ChainID:     legInfo.ChainID,
			IsFinalized: obs != nil && obs.IsFinalized,
		}

		if obs != nil {
			legResult.TxHash = obs.TxHash
			legResult.BlockNumber = obs.BlockNumber
			legResult.BlockHash = obs.BlockHash
			legResult.Status = uint64(obs.Status)
			legResult.GasUsed = obs.GasUsed
			legResult.TxFrom = obs.TxFrom
			legResult.EventCount = len(obs.Logs)
			legResult.Confirmations = obs.Confirmations
			legResult.EventsHash = computeObservationEventsHash(obs.Logs)
		}

		legResults = append(legResults, legResult)
	}

	// Compute multi-leg result hash
	multiLegHash := ComputeMultiLegResultHash(legResults)

	// Build the unified attestation bundle using the primary chain's result
	bundle := a.buildUnifiedAttestationBundle(pending, legResults, multiLegHash)
	if bundle == nil {
		return fmt.Errorf("failed to build unified attestation bundle for intent %s", pending.IntentID)
	}

	// Build the synthetic transaction
	if a.txBuilder == nil || a.submitter == nil {
		a.logger.Printf("Write-back skipped (not configured) for multi-leg intent %s", pending.IntentID)
		return nil
	}

	// Build comprehensive proof context from multi-leg data
	proofCtx := a.buildMultiLegProofContext(pending, legResults, multiLegHash)

	tx, err := a.txBuilder.BuildFromBundleWithContext(bundle, proofCtx)
	if err != nil {
		return fmt.Errorf("build synthetic tx for multi-leg intent %s: %w", pending.IntentID, err)
	}

	// Add signature
	if err := a.txBuilder.AddSignature(tx); err != nil {
		return fmt.Errorf("add signature for multi-leg intent %s: %w", pending.IntentID, err)
	}

	// Submit to Accumulate
	ctx, cancel := context.WithTimeout(context.Background(), a.writeBackTimeout)
	defer cancel()

	receipt, err := a.submitter.SubmitTransaction(ctx, tx)
	if err != nil {
		return fmt.Errorf("submit multi-leg write-back for intent %s: %w", pending.IntentID, err)
	}

	a.logger.Printf("Multi-leg unified write-back submitted: intent=%s, legs=%d, receipt=%s",
		pending.IntentID, len(legResults), receipt)

	if a.onUnifiedWriteBack != nil {
		a.onUnifiedWriteBack(pending.IntentID, receipt)
	}

	return nil
}

// buildUnifiedAttestationBundle creates an AttestationBundle from multiple chain group results
func (a *MultiLegAggregator) buildUnifiedAttestationBundle(
	pending *PendingMultiLeg,
	legResults []LegResult,
	multiLegHash [32]byte,
) *AttestationBundle {
	// Use the first chain group's result as the primary for backward compatibility
	var primaryResult *UnifiedProofCycleResult
	var primaryChainKey string

	// Find primary chain (leg 0's chain)
	if legInfo, ok := pending.LegMapping[0]; ok {
		primaryChainKey = legInfo.ChainKey
		primaryResult = pending.CompletedCycles[primaryChainKey]
	}

	// Fallback: use first available result
	if primaryResult == nil {
		for ck, r := range pending.CompletedCycles {
			primaryResult = r
			primaryChainKey = ck
			break
		}
	}

	if primaryResult == nil || len(primaryResult.ObservationResults) == 0 {
		return nil
	}

	obs := primaryResult.ObservationResults[0]

	// Build ExternalChainResult from primary observation (backward compatibility)
	extResult := &ExternalChainResult{
		Chain:               getNetworkName(primaryResult.ChainID),
		ChainID:             parseChainIDInt(primaryResult.ChainID),
		TxHash:              parseHash(obs.TxHash),
		BlockNumber:         parseBigInt(obs.BlockNumber),
		BlockHash:           parseHash(obs.BlockHash),
		Status:              uint64(obs.Status),
		StateRoot:           obs.StateRoot,
		TransactionsRoot:    obs.TransactionsRoot,
		ReceiptsRoot:        obs.ReceiptsRoot,
		ConfirmationBlocks:  obs.Confirmations,
		FinalizedAt:         time.Now().UTC(),
		TxGasUsed:           obs.GasUsed,
		ObservedByValidator: obs.ObserverValidatorID,
		TxFrom:              common.HexToAddress(obs.TxFrom),
		NativeTxHash:        obs.TxHash,
		NativeBlockHash:     obs.BlockHash,
		NativeTxFrom:        obs.TxFrom,
	}

	// Collect logs from ALL chain groups
	for _, cycleResult := range pending.CompletedCycles {
		for _, obsResult := range cycleResult.ObservationResults {
			for _, l := range obsResult.Logs {
				extResult.Logs = append(extResult.Logs, LogEntry{
					Address: common.HexToAddress(l.Address),
					Topics:  parseTopics(l.Topics),
					Data:    l.Data,
					Index:   l.LogIndex,
				})
			}
		}
	}

	// Apply result hash chain using primary chain
	if a.resultChainsLock != nil {
		a.resultChainsLock.Lock()
		chainKey := primaryResult.ChainID
		if chainKey == "" {
			chainKey = "default"
		}
		hashChain, exists := a.resultChains[chainKey]
		if !exists {
			hashChain = NewResultHashChain(chainKey, [32]byte{})
			a.resultChains[chainKey] = hashChain
		}
		_ = hashChain.AddResult(extResult)
		a.resultChainsLock.Unlock()
	}

	// Build aggregated attestation from primary result
	var agg *AggregatedAttestation
	if primaryResult.AggregatedAttestation != nil {
		validatorCount := primaryResult.AggregatedAttestation.ParticipantCount
		if primaryResult.AggregatedAttestation.TotalWeight > 0 {
			validatorCount = int(primaryResult.AggregatedAttestation.TotalWeight)
		}
		achievedWeight := int64(primaryResult.AggregatedAttestation.AchievedWeight)
		if achievedWeight == 0 {
			achievedWeight = int64(primaryResult.AggregatedAttestation.ParticipantCount)
		}
		agg = &AggregatedAttestation{
			MessageHash:        primaryResult.AggregatedAttestation.MessageHash,
			AggregateSignature: primaryResult.AggregatedAttestation.AggregatedSignature,
			ValidatorCount:     validatorCount,
			SignedVotingPower:  big.NewInt(achievedWeight),
			ThresholdMet:       primaryResult.AggregatedAttestation.ThresholdMet,
			Finalized:          primaryResult.AggregatedAttestation.ThresholdMet && primaryResult.AggregatedAttestation.Verified,
			FinalizedAt:        time.Now().UTC(),
		}
	}

	// Compute bundle ID from intent
	bundleID := sha256.Sum256([]byte("CERTEN_MULTI_LEG_BUNDLE:" + pending.IntentID))

	return &AttestationBundle{
		BundleID:           bundleID,
		ResultHash:         obs.ResultHash,
		Result:             extResult,
		Aggregated:         agg,
		LegResults:         legResults,
		MultiLegResultHash: multiLegHash,
	}
}

// buildMultiLegProofContext creates a ComprehensiveProofContext for multi-leg write-back
func (a *MultiLegAggregator) buildMultiLegProofContext(
	pending *PendingMultiLeg,
	legResults []LegResult,
	multiLegHash [32]byte,
) *ComprehensiveProofContext {
	ctx := &ComprehensiveProofContext{
		IntentID: pending.IntentID,
	}

	// Extract data from primary chain group's request if available
	if legInfo, ok := pending.LegMapping[0]; ok {
		if cycleResult, ok := pending.CompletedCycles[legInfo.ChainKey]; ok {
			ctx.ProofArtifactID = cycleResult.ProofID.String()
		}
	}

	return ctx
}

// SetOnUnifiedWriteBack sets the callback for unified write-back completion
func (a *MultiLegAggregator) SetOnUnifiedWriteBack(fn func(intentID string, txHash string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onUnifiedWriteBack = fn
}

// GetPendingCount returns the number of pending multi-leg intents
func (a *MultiLegAggregator) GetPendingCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.pending)
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// findObservationForLeg finds the observation result for a specific leg
// within a chain group's cycle result
func findObservationForLeg(
	cycleResult *UnifiedProofCycleResult,
	legIdx int,
	legInfo LegChainInfo,
) *chain.ObservationResult {
	if cycleResult == nil || len(cycleResult.ObservationResults) == 0 {
		return nil
	}

	// If chain group has multiple observations, try to match by chain metadata
	for _, obs := range cycleResult.ObservationResults {
		if obs.ChainName == legInfo.ChainName && obs.ChainIDNumeric == legInfo.ChainID {
			return obs
		}
	}

	// Fallback: use first observation (single-leg chain group)
	return cycleResult.ObservationResults[0]
}

// computeObservationEventsHash computes a hash of observation event logs
func computeObservationEventsHash(logs []chain.EventLog) [32]byte {
	if len(logs) == 0 {
		return [32]byte{}
	}

	data := make([]byte, 0, 256)
	data = append(data, []byte("CERTEN_OBS_EVENTS_V1")...)
	for _, l := range logs {
		data = append(data, []byte(l.Address)...)
		for _, topic := range l.Topics {
			data = append(data, []byte(topic)...)
		}
		data = append(data, l.Data...)
	}

	return sha256.Sum256(data)
}

// getUniqueChainKeys returns unique chain keys from leg mapping
func getUniqueChainKeys(legMapping map[int]LegChainInfo) []string {
	seen := make(map[string]bool)
	var keys []string
	for _, info := range legMapping {
		if !seen[info.ChainKey] {
			seen[info.ChainKey] = true
			keys = append(keys, info.ChainKey)
		}
	}
	sort.Strings(keys)
	return keys
}

// countUniqueChainKeys returns the number of unique chain keys
func countUniqueChainKeys(legMapping map[int]LegChainInfo) int {
	return len(getUniqueChainKeys(legMapping))
}

// Note: parseTopics, getNetworkName, parseChainIDInt, parseHash, parseBigInt
// are defined in unified_orchestrator.go (same package)
