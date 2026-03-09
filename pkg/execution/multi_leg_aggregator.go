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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"

	chain "github.com/certen/independant-validator/pkg/chain/strategy"
	"github.com/certen/independant-validator/pkg/database"
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

	// Persistence store for crash recovery (GAP 4)
	persistenceRepo *database.MultiLegRepository

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

	// LegIndicesPerChain maps chainKey -> ordered list of leg indices in that chain group.
	// The order matches the txHashes array order in the proof cycle request,
	// enabling positional matching of observations to legs for same-chain multi-leg intents.
	LegIndicesPerChain map[string][]int
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

	// PersistenceRepo enables crash recovery for multi-leg aggregation (GAP 4).
	// If nil, aggregation state is in-memory only (original behavior).
	PersistenceRepo *database.MultiLegRepository
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
		persistenceRepo:  cfg.PersistenceRepo,
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

	// Build leg indices per chain from leg mapping
	legIndicesPerChain := make(map[string][]int)
	for legIdx, info := range legMapping {
		legIndicesPerChain[info.ChainKey] = append(legIndicesPerChain[info.ChainKey], legIdx)
	}
	// Sort each chain's leg indices for deterministic ordering
	for ck := range legIndicesPerChain {
		sort.Ints(legIndicesPerChain[ck])
	}

	a.pending[intentID] = &PendingMultiLeg{
		IntentID:           intentID,
		OperationID:        operationID,
		TotalLegs:          totalLegs,
		ExecutionMode:      executionMode,
		CompletedCycles:    make(map[string]*UnifiedProofCycleResult),
		LegMapping:         legMapping,
		CreatedAt:          time.Now(),
		LegIndicesPerChain: legIndicesPerChain,
	}

	a.logger.Printf("Registered multi-leg intent %s with %d legs", intentID, totalLegs)

	// Persist to database for crash recovery
	a.persistPendingState(a.pending[intentID])
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

	// Persist updated completion state for crash recovery
	a.persistCompletedCycleUpdate(intentID, pending.CompletedCycles)

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

		// Find the observation result for this leg within the chain group's results.
		// Pass the sorted leg indices for this chain group to enable positional matching.
		legIndicesForChain := pending.LegIndicesPerChain[legInfo.ChainKey]
		obs := findObservationForLeg(cycleResult, legIdx, legInfo, legIndicesForChain)

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

	// Clean up persisted state after successful write-back
	a.deletePendingState(pending.IntentID)

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

	// Fallback: use the lexicographically first chain key for determinism across validators.
	// Non-deterministic map iteration (GAP 12) could cause validators to pick different
	// primary results, leading to divergent write-backs.
	if primaryResult == nil {
		chainKeys := make([]string, 0, len(pending.CompletedCycles))
		for ck := range pending.CompletedCycles {
			chainKeys = append(chainKeys, ck)
		}
		sort.Strings(chainKeys)
		if len(chainKeys) > 0 {
			primaryChainKey = chainKeys[0]
			primaryResult = pending.CompletedCycles[primaryChainKey]
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

	// Collect logs from ALL chain groups in deterministic order (sorted chain keys)
	sortedChainKeys := make([]string, 0, len(pending.CompletedCycles))
	for ck := range pending.CompletedCycles {
		sortedChainKeys = append(sortedChainKeys, ck)
	}
	sort.Strings(sortedChainKeys)
	for _, ck := range sortedChainKeys {
		cycleResult := pending.CompletedCycles[ck]
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
// PERSISTENCE (GAP 4: Crash Recovery)
// =============================================================================

// persistPendingState saves the pending multi-leg state to database
func (a *MultiLegAggregator) persistPendingState(pending *PendingMultiLeg) {
	if a.persistenceRepo == nil {
		return
	}

	legMappingJSON, err := json.Marshal(pending.LegMapping)
	if err != nil {
		a.logger.Printf("WARNING: Failed to marshal leg mapping for %s: %v", pending.IntentID, err)
		return
	}

	legIndicesJSON, err := json.Marshal(pending.LegIndicesPerChain)
	if err != nil {
		a.logger.Printf("WARNING: Failed to marshal leg indices for %s: %v", pending.IntentID, err)
		return
	}

	state := &database.MultiLegPendingState{
		IntentID:           pending.IntentID,
		OperationID:        pending.OperationID,
		TotalLegs:          pending.TotalLegs,
		ExecutionMode:      pending.ExecutionMode,
		LegMapping:         legMappingJSON,
		LegIndicesPerChain: legIndicesJSON,
		CompletedCycles:    json.RawMessage("{}"),
		CreatedAt:          pending.CreatedAt,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.persistenceRepo.UpsertPendingState(ctx, state); err != nil {
		a.logger.Printf("WARNING: Failed to persist pending state for %s: %v", pending.IntentID, err)
	}
}

// persistCompletedCycleUpdate saves updated completion state to database.
// We store a summary (chainKey -> {success, chainID, proofID}) rather than
// the full UnifiedProofCycleResult to keep the JSONB manageable.
func (a *MultiLegAggregator) persistCompletedCycleUpdate(intentID string, cycles map[string]*UnifiedProofCycleResult) {
	if a.persistenceRepo == nil {
		return
	}

	// Build a serializable summary of completed cycles
	type cycleSummary struct {
		Success       bool   `json:"success"`
		ChainID       string `json:"chain_id"`
		ChainPlatform string `json:"chain_platform"`
		CycleID       string `json:"cycle_id"`
	}

	summary := make(map[string]*cycleSummary)
	for ck, r := range cycles {
		summary[ck] = &cycleSummary{
			Success:       r.Success,
			ChainID:       r.ChainID,
			ChainPlatform: r.ChainPlatform,
			CycleID:       r.CycleID,
		}
	}

	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		a.logger.Printf("WARNING: Failed to marshal completed cycles for %s: %v", intentID, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.persistenceRepo.UpdateCompletedCycles(ctx, intentID, summaryJSON); err != nil {
		a.logger.Printf("WARNING: Failed to persist completed cycles for %s: %v", intentID, err)
	}
}

// deletePendingState removes the pending state from database after successful write-back
func (a *MultiLegAggregator) deletePendingState(intentID string) {
	if a.persistenceRepo == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := a.persistenceRepo.DeletePendingState(ctx, intentID); err != nil {
		a.logger.Printf("WARNING: Failed to delete pending state for %s: %v", intentID, err)
	}
}

// LoadPendingFromDB reloads incomplete multi-leg aggregation state from the database.
// Called on validator startup to resume aggregation that was in-flight when the process
// crashed or was restarted.
func (a *MultiLegAggregator) LoadPendingFromDB() error {
	if a.persistenceRepo == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	states, err := a.persistenceRepo.LoadAllPending(ctx)
	if err != nil {
		return fmt.Errorf("load pending multi-leg states: %w", err)
	}

	if len(states) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	loaded := 0
	for _, state := range states {
		if _, exists := a.pending[state.IntentID]; exists {
			continue // Already registered in memory
		}

		var legMapping map[int]LegChainInfo
		if err := json.Unmarshal(state.LegMapping, &legMapping); err != nil {
			a.logger.Printf("WARNING: Failed to unmarshal leg mapping for %s: %v", state.IntentID, err)
			continue
		}

		var legIndicesPerChain map[string][]int
		if err := json.Unmarshal(state.LegIndicesPerChain, &legIndicesPerChain); err != nil {
			a.logger.Printf("WARNING: Failed to unmarshal leg indices for %s: %v", state.IntentID, err)
			continue
		}

		a.pending[state.IntentID] = &PendingMultiLeg{
			IntentID:           state.IntentID,
			OperationID:        state.OperationID,
			TotalLegs:          state.TotalLegs,
			ExecutionMode:      state.ExecutionMode,
			CompletedCycles:    make(map[string]*UnifiedProofCycleResult),
			LegMapping:         legMapping,
			CreatedAt:          state.CreatedAt,
			LegIndicesPerChain: legIndicesPerChain,
		}
		loaded++
	}

	if loaded > 0 {
		a.logger.Printf("Loaded %d pending multi-leg intents from database", loaded)
	}

	// Cleanup expired entries
	go func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		if n, err := a.persistenceRepo.CleanupExpired(cleanCtx); err == nil && n > 0 {
			a.logger.Printf("Cleaned up %d expired multi-leg pending entries", n)
		}
	}()

	return nil
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// findObservationForLeg finds the observation result for a specific leg
// within a chain group's cycle result.
//
// For same-chain multi-leg intents (multiple legs on the same chain), the chain group
// has multiple tx hashes and thus multiple observations. We use positional matching:
// the leg indices in the chain group are sorted, and the observation at position N
// corresponds to the leg at position N in the sorted leg indices list.
//
// This fixes GAP 1 where all legs in a same-chain group would incorrectly receive
// the same observation (observation[0]) because chain name/ID matching is ambiguous.
func findObservationForLeg(
	cycleResult *UnifiedProofCycleResult,
	legIdx int,
	legInfo LegChainInfo,
	legIndicesForChain []int,
) *chain.ObservationResult {
	if cycleResult == nil || len(cycleResult.ObservationResults) == 0 {
		return nil
	}

	// Positional matching: find this leg's position within the chain group's sorted leg indices
	if len(legIndicesForChain) > 1 && len(cycleResult.ObservationResults) > 1 {
		for pos, idx := range legIndicesForChain {
			if idx == legIdx && pos < len(cycleResult.ObservationResults) {
				return cycleResult.ObservationResults[pos]
			}
		}
	}

	// Also try metadata-based leg_indices matching (from proof cycle result metadata)
	if cycleResult.Metadata != nil {
		if legIndicesStr, ok := cycleResult.Metadata["leg_indices"]; ok && legIndicesStr != "" {
			indices := parseCommaSeparatedInts(legIndicesStr)
			for pos, idx := range indices {
				if idx == legIdx && pos < len(cycleResult.ObservationResults) {
					return cycleResult.ObservationResults[pos]
				}
			}
		}
	}

	// Single-leg chain group or fallback: use first observation
	return cycleResult.ObservationResults[0]
}

// parseCommaSeparatedInts parses a comma-separated string of integers (e.g., "0,3,5")
func parseCommaSeparatedInts(s string) []int {
	parts := strings.Split(s, ",")
	var result []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			result = append(result, n)
		}
	}
	return result
}

// computeObservationEventsHash computes a deterministic hash of observation event logs.
// Logs are sorted by (Address, Topics[0], LogIndex) before hashing to ensure
// determinism across validators that may receive logs in different orders (GAP 13).
func computeObservationEventsHash(logs []chain.EventLog) [32]byte {
	if len(logs) == 0 {
		return [32]byte{}
	}

	// Sort logs deterministically before hashing
	sorted := make([]chain.EventLog, len(logs))
	copy(sorted, logs)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Address != sorted[j].Address {
			return sorted[i].Address < sorted[j].Address
		}
		ti, tj := "", ""
		if len(sorted[i].Topics) > 0 {
			ti = sorted[i].Topics[0]
		}
		if len(sorted[j].Topics) > 0 {
			tj = sorted[j].Topics[0]
		}
		if ti != tj {
			return ti < tj
		}
		return sorted[i].LogIndex < sorted[j].LogIndex
	})

	data := make([]byte, 0, 256)
	data = append(data, []byte("CERTEN_OBS_EVENTS_V1")...)
	for _, l := range sorted {
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
