# Multi-Leg Write-Back Fix: Implementation Plan

## Context

For multi-leg cross-chain intents (e.g., 4 legs across ethereum-sepolia, base-sepolia, aptos-testnet, solana-devnet), the validator's Phase 9 write-back to Accumulate only captures proof data from the **primary chain** (`ObservationResults[0]`). The on-chain Accumulate record has no proof that legs 1-N executed on their respective chains. Event logs are partially aggregated from all legs but chain metadata (tx_hash, block_number, chain_name, gas_used, success) only reflects leg 0.

**Two architectural gaps identified:**

1. **Single-cycle gap**: `buildAttestationBundleFromCycle()` at line 1325 of `unified_orchestrator.go` uses `obs := result.ObservationResults[0]`, discarding all other observation results when building the write-back `ExternalChainResult`.

2. **Multi-chain cycle gap**: `ExecuteProofCycle()` resolves a single `chainStrategy` from `req.TargetChain` (line 384). Phase 7 uses that one strategy for all `req.TxHashes`. For multi-chain intents, each chain group produces its own proof cycle, but there is no final aggregation step that ties all per-chain proof cycle results into a single unified write-back.

**Goal**: Produce a single Accumulate write-back entry per multi-leg intent that includes per-leg proof summaries for ALL legs, regardless of which chains they span.

---

## Phase 1: Data Model Extensions

### 1A. Add `LegResult` struct

**File**: `pkg/execution/external_chain_result.go` (after line 131)

Add a lightweight per-leg proof summary struct. Uses string types (not `common.Hash`) for chain-agnostic compatibility (EVM hex, Solana base58, NEAR accounts, Aptos hex).

```go
type LegResult struct {
    LegIndex      int      `json:"leg_index"`
    LegID         string   `json:"leg_id,omitempty"`
    Chain         string   `json:"chain"`
    ChainID       int64    `json:"chain_id"`
    TxHash        string   `json:"tx_hash"`
    BlockNumber   uint64   `json:"block_number"`
    BlockHash     string   `json:"block_hash"`
    Status        uint64   `json:"status"`         // 1=success, 0=revert
    GasUsed       uint64   `json:"gas_used"`
    TxFrom        string   `json:"tx_from"`
    EventsHash    [32]byte `json:"events_hash"`
    EventCount    int      `json:"event_count"`
    IsFinalized   bool     `json:"is_finalized"`
    Confirmations int      `json:"confirmations"`
}
```

Add `ComputeMultiLegResultHash(legs []LegResult) [32]byte` — deterministic hash over sorted legs using RFC8785 canonical JSON with domain separator `"CERTEN_MULTI_LEG_RESULT_V1"`.

### 1B. Add chain metadata to `ObservationResult`

**File**: `pkg/chain/strategy/interface.go` (after line 375, inside `ObservationResult`)

```go
    // Chain identification (populated by each strategy)
    ChainName     string `json:"chain_name,omitempty"`
    ChainIDNumeric int64 `json:"chain_id_numeric,omitempty"`
```

Each chain strategy (`evm_strategy.go`, `solana_strategy.go`, `move_strategy.go`, `cosmwasm_strategy.go`) must populate these in their `ObserveTransaction()` methods. This makes each observation self-describing — critical for multi-chain proof cycles.

### 1C. Extend `AttestationBundle`

**File**: `pkg/execution/result_attestation.go` (line 881, `AttestationBundle` struct)

Add fields:

```go
    LegResults         []LegResult `json:"leg_results,omitempty"`
    MultiLegResultHash [32]byte    `json:"multi_leg_result_hash,omitempty"`
```

Update `ComputeBundleHash()` (line 918) to include `MultiLegResultHash` when `len(LegResults) > 1`.

### 1D. Extend `CertenDataEntry`

**File**: `pkg/execution/synthetic_transaction.go` (after line 229)

Add fields:

```go
    LegCount           int             `json:"leg_count"`
    MultiLegResultHash string          `json:"multi_leg_result_hash,omitempty"`
    LegProofs          []LegProofEntry `json:"leg_proofs,omitempty"`
```

New supporting struct:

```go
type LegProofEntry struct {
    LegIndex    int    `json:"leg_index"`
    ChainName   string `json:"chain_name"`
    ChainID     int64  `json:"chain_id"`
    TxHash      string `json:"tx_hash"`
    BlockNumber uint64 `json:"block_number"`
    BlockHash   string `json:"block_hash"`
    Success     bool   `json:"success"`
    GasUsed     uint64 `json:"gas_used"`
    EventsHash  string `json:"events_hash"`
    EventCount  int    `json:"event_count"`
}
```

---

## Phase 2: Multi-Chain Proof Cycle Aggregation

This is the most architecturally significant change. Currently each chain group runs its own proof cycle and writes back independently. We need a **final aggregation step** after all chain groups complete.

### 2A. Add `MultiLegAggregator`

**New file**: `pkg/execution/multi_leg_aggregator.go`

This component collects per-chain proof cycle results and produces a unified write-back.

```go
type MultiLegAggregator struct {
    orchestrator *UnifiedOrchestrator
    txBuilder    *SyntheticTxBuilder
    submitter    *AccumulateSubmitter
}

type PendingMultiLeg struct {
    IntentID        string
    OperationID     string
    TotalLegs       int
    ExecutionMode   string
    CompletedCycles map[string]*UnifiedProofCycleResult // chainKey -> result
    LegMapping      map[int]string                       // legIndex -> chainKey
    CreatedAt       time.Time
}
```

Key methods:
- `OnChainGroupCycleComplete(intentID, chainKey string, result *UnifiedProofCycleResult)` — called by `LegCompletionHandler` when a chain group's proof cycle finishes. Stores the result. When all chain groups are complete, triggers `buildUnifiedWriteBack()`.
- `buildUnifiedWriteBack(pending *PendingMultiLeg) error` — collects all per-chain observation results, builds a unified `AttestationBundle` with `LegResults` for every leg, creates the `CertenDataEntry` with per-leg proof summaries, and submits to Accumulate.

### 2B. Wire into `LegCompletionHandler`

**File**: `pkg/intent/leg_completion.go`

In `OnLegCompleted()` (line 245), after checking if the full intent is complete (all legs completed), call `multiLegAggregator.OnChainGroupCycleComplete()`. The aggregator triggers the unified write-back when all chain groups report in.

### 2C. Suppress per-chain-group write-backs for multi-leg intents

**File**: `pkg/execution/unified_orchestrator.go`, Phase 9 (`executePhase9`, line 1091)

Add a check: if the proof cycle request is for a chain group that's part of a multi-leg intent (`req.Metadata["multi_leg"] == "true"`), skip the per-chain write-back. Instead, store the cycle result for the aggregator.

```go
func (o *UnifiedOrchestrator) executePhase9(ctx context.Context, cycle *activeCycle) error {
    // For multi-leg chain groups, defer write-back to aggregator
    if cycle.Request.Metadata != nil && cycle.Request.Metadata["multi_leg"] == "true" {
        // Store observation results for unified write-back
        if o.multiLegAggregator != nil {
            chainKey := cycle.Request.Metadata["chain_key"]
            o.multiLegAggregator.OnChainGroupCycleComplete(
                cycle.Request.IntentID, chainKey, cycle.Result)
        }
        return nil // Skip per-chain write-back
    }

    // ... existing Phase 9 code for single-leg intents (unchanged)
}
```

---

## Phase 3: Fix `buildAttestationBundleFromCycle` for Unified Write-Back

**File**: `pkg/execution/unified_orchestrator.go`, lines 1316-1406

### 3A. Add `buildUnifiedAttestationBundle` method

New method that accepts observation results from multiple chain groups:

```go
func (o *UnifiedOrchestrator) buildUnifiedAttestationBundle(
    intentID string,
    bundleID [32]byte,
    allResults map[string]*UnifiedProofCycleResult, // chainKey -> result
    legMapping map[int]LegChainInfo,                 // legIndex -> chain info
) *AttestationBundle {
```

This method:
1. Iterates all chain group results in leg order
2. Builds a `LegResult` for each observation across all chains
3. Uses primary chain's `ExternalChainResult` for backward-compatible `Result` field
4. Computes `MultiLegResultHash` covering all legs
5. Computes per-leg `EventsHash` from each observation's logs separately (not merged)

### 3B. Keep existing `buildAttestationBundleFromCycle` for single-leg

The existing method remains unchanged for single-leg intents and single-chain-group cycles. The new `buildUnifiedAttestationBundle` is only called by the `MultiLegAggregator` for multi-chain intents.

---

## Phase 4: Write-Back Format Extension

**File**: `pkg/execution/accumulate_submitter.go`, `ToDoubleHashFormat()` (lines 370-474)

### 4A. Append per-leg entries after existing 51 entries

After line 471 (`finalized_at` entry), add:

```go
    if e.LegCount > 1 {
        entries = append(entries, labeled("leg_count", fmt.Sprintf("%d", e.LegCount)))
        entries = append(entries, labeled("multi_leg_result_hash", e.MultiLegResultHash))

        for i, leg := range e.LegProofs {
            prefix := fmt.Sprintf("leg_%d", i)
            entries = append(entries, labeled(prefix+"_chain_name", leg.ChainName))
            entries = append(entries, labeled(prefix+"_chain_id", fmt.Sprintf("%d", leg.ChainID)))
            entries = append(entries, labeled(prefix+"_tx_hash", leg.TxHash))
            entries = append(entries, labeled(prefix+"_block_number", fmt.Sprintf("%d", leg.BlockNumber)))
            entries = append(entries, labeled(prefix+"_block_hash", leg.BlockHash))
            entries = append(entries, labeled(prefix+"_success", fmt.Sprintf("%t", leg.Success)))
            entries = append(entries, labeled(prefix+"_gas_used", fmt.Sprintf("%d", leg.GasUsed)))
            entries = append(entries, labeled(prefix+"_events_hash", leg.EventsHash))
            entries = append(entries, labeled(prefix+"_event_count", fmt.Sprintf("%d", leg.EventCount)))
        }
    }
```

### 4B. Version bump for multi-leg

- `version` (entry 1): `"2.1"` when `LegCount > 1`
- `schema_version` (entry 47): `"2.1"` when `LegCount > 1`
- Entries 22-29 remain populated with primary leg data for backward compatibility

### 4C. Entry layout for 4-leg intent

| Entries | Content |
|---------|---------|
| 0-50 | Existing v2.0 format (primary leg in 22-29) |
| 51 | `leg_count=4` |
| 52 | `multi_leg_result_hash=<hex>` |
| 53-61 | `leg_0_*` (9 entries) |
| 62-70 | `leg_1_*` (9 entries) |
| 71-79 | `leg_2_*` (9 entries) |
| 80-88 | `leg_3_*` (9 entries) |

Total: 89 entries. Each entry is ~100-200 bytes, well within Accumulate data entry limits.

---

## Phase 5: Attestation Message Update

**File**: `pkg/attestation/strategy/interface.go`, `AttestationMessage` struct

### 5A. Extend AttestationMessage

Add:

```go
    LegCount           int      `json:"leg_count,omitempty"`
    MultiLegResultHash [32]byte `json:"multi_leg_result_hash,omitempty"`
```

### 5B. Update message hash computation

When `LegCount > 1`, include `MultiLegResultHash` in the hash. This ensures validators attest to all legs collectively.

**Note**: This is a consensus-affecting change. All validators must upgrade simultaneously. On testnet this is fine. For mainnet, use a protocol version flag or activation height.

---

## Phase 6: Integration Wiring

### 6A. Route multi-leg metadata through proof cycle requests

**File**: `pkg/intent/discovery.go`, `routeChainLegsToBatchSystem()` (line 1427)

When creating proof cycle requests for chain groups that are part of multi-leg intents, set metadata:

```go
req.Metadata["multi_leg"] = "true"
req.Metadata["chain_key"] = chainGroup.ChainKey
req.Metadata["total_legs"] = fmt.Sprintf("%d", intentRecord.LegCount)
req.Metadata["intent_id"] = intentRecord.IntentID
```

### 6B. Initialize MultiLegAggregator in orchestrator

**File**: `pkg/execution/unified_orchestrator.go`

Add `multiLegAggregator *MultiLegAggregator` field to `UnifiedOrchestrator`. Initialize in constructor.

### 6C. Populate chain metadata in each strategy

**Files to modify** (small change in each `ObserveTransaction()` return):
- `pkg/chain/strategy/evm_strategy.go` — set `ChainName`, `ChainIDNumeric`
- `pkg/chain/strategy/solana_strategy.go` — set `ChainName`, `ChainIDNumeric`
- `pkg/chain/strategy/move_strategy.go` — set `ChainName`, `ChainIDNumeric`
- `pkg/chain/strategy/cosmwasm_strategy.go` — set `ChainName`, `ChainIDNumeric`

### 6D. Wire `BuildFromBundleWithContext` for multi-leg

**File**: `pkg/execution/synthetic_transaction.go`, `BuildFromBundleWithContext()` (around line 448)

After existing `CertenDataEntry` population, populate multi-leg fields from `bundle.LegResults`:

```go
    if len(bundle.LegResults) > 1 {
        dataEntry.LegCount = len(bundle.LegResults)
        dataEntry.MultiLegResultHash = hex.EncodeToString(bundle.MultiLegResultHash[:])
        for _, leg := range bundle.LegResults {
            dataEntry.LegProofs = append(dataEntry.LegProofs, LegProofEntry{...})
        }
    }
```

---

## Phase 7: Testing Strategy

### 7A. Unit tests

**New file**: `pkg/execution/multi_leg_result_test.go`
- `TestComputeMultiLegResultHash_Deterministic` — same legs produce same hash regardless of input order
- `TestComputeMultiLegResultHash_Empty` — returns zero hash
- `TestComputeMultiLegResultHash_DifferentLegs_DifferentHash`

**New file**: `pkg/execution/multi_leg_writeback_test.go`
- `TestToDoubleHashFormat_SingleLeg_BackwardCompatible` — exactly 51 entries, unchanged
- `TestToDoubleHashFormat_MultiLeg_4Legs` — 89 entries, correct key names and values
- `TestToDoubleHashFormat_MultiLeg_VersionBump` — version is "2.1"

### 7B. Integration test

**New file**: `pkg/execution/multi_leg_aggregator_test.go`
- Simulate 4-chain intent: construct mock `UnifiedProofCycleResult` per chain with mock `ObservationResult`
- Feed to `MultiLegAggregator` sequentially
- Verify unified write-back contains all 4 legs
- Verify primary chain data (entries 22-29) matches leg 0
- Verify `multi_leg_result_hash` is deterministic

### 7C. End-to-end scenario

- Submit a multi-leg intent on Kermit testnet (4 legs: ethereum-sepolia, base-sepolia, aptos-testnet, solana-devnet)
- Verify each chain group's proof cycle completes
- Verify the aggregator produces a unified write-back
- Query the Accumulate data account and confirm per-leg entries are present
- Verify `leg_0_tx_hash` through `leg_3_tx_hash` match actual on-chain tx hashes

### 7D. Regression

- Run existing test suite to confirm single-leg intents are unaffected
- Verify `crypto_verification_test.go` still passes
- Verify existing write-back format (v2.0) unchanged for single-leg

---

## Risk Areas

1. **Consensus break (Phase 5)**: Changing attestation message hash requires synchronized validator upgrade. Mitigate with protocol version flag.

2. **Accumulate entry limits**: 89 entries for 4 legs is fine. For 20+ legs, validate Accumulate `WriteData` supports 200+ entries per transaction.

3. **Timing**: The aggregator must handle chain groups completing at different times (especially for sequential execution mode where groups complete minutes apart). Use timeouts aligned with `timeout_policy.total_timeout_seconds`.

4. **Partial failures**: If one chain group's proof cycle fails, the aggregator should still write back partial results with per-leg success/failure status for audit trail.

5. **Hash chain binding**: Each chain group currently advances its own chain's result hash chain (line 1366). The unified write-back creates a new entry that spans multiple chains. The primary chain's hash chain is used for the unified entry; other chains' hash chains continue independently via their per-chain proof cycles.

---

## Implementation Order

```
Phase 1B (ObservationResult chain metadata) — independent, do first
Phase 6C (populate in each strategy) — depends on 1B
Phase 1A (LegResult struct) — independent
Phase 1C (AttestationBundle extension) — depends on 1A
Phase 1D (CertenDataEntry extension) — depends on 1A
Phase 4  (ToDoubleHashFormat) — depends on 1D
Phase 2  (MultiLegAggregator) — depends on 1A, 1C
Phase 3  (buildUnifiedAttestationBundle) — depends on 1A, 1C, 2
Phase 5  (AttestationMessage update) — depends on 1A
Phase 6A,B,D (wiring) — depends on 2, 3, 4
Phase 7  (testing) — after all phases
```

---

## Critical Files Summary

| File | Changes |
|------|---------|
| `pkg/execution/external_chain_result.go` | Add `LegResult`, `ComputeMultiLegResultHash` |
| `pkg/chain/strategy/interface.go` | Add `ChainName`, `ChainIDNumeric` to `ObservationResult` |
| `pkg/chain/strategy/evm_strategy.go` | Populate chain metadata in `ObserveTransaction` |
| `pkg/chain/strategy/solana_strategy.go` | Populate chain metadata in `ObserveTransaction` |
| `pkg/chain/strategy/move_strategy.go` | Populate chain metadata in `ObserveTransaction` |
| `pkg/chain/strategy/cosmwasm_strategy.go` | Populate chain metadata in `ObserveTransaction` |
| `pkg/execution/result_attestation.go` | Extend `AttestationBundle` with `LegResults` |
| `pkg/execution/synthetic_transaction.go` | Extend `CertenDataEntry`, `LegProofEntry`, update `BuildFromBundleWithContext` |
| `pkg/execution/accumulate_submitter.go` | Extend `ToDoubleHashFormat` with per-leg entries |
| `pkg/execution/unified_orchestrator.go` | Phase 9 multi-leg bypass, `buildUnifiedAttestationBundle`, aggregator init |
| `pkg/execution/multi_leg_aggregator.go` | **NEW** — aggregation of per-chain proof cycles into unified write-back |
| `pkg/intent/leg_completion.go` | Wire aggregator callback on all-legs-complete |
| `pkg/intent/discovery.go` | Set multi-leg metadata on proof cycle requests |
| `pkg/attestation/strategy/interface.go` | Extend `AttestationMessage` with multi-leg fields |
