// Copyright 2025 Certen Protocol
//
// Production ABCI Application for Validator CometBFT Chain
// Implements ValidatorBlock processing with canonical JSON validation

package consensus

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/certen/independant-validator/pkg/ledger"
)

// ValidatorApp implements the ABCI interface for validator consensus
type ValidatorApp struct {
	logger          *log.Logger
	latestHeight    int64
	lastCommitHash  []byte
	validatorBlocks map[string]*ValidatorBlock // Store by bundle_id
	mu              sync.RWMutex

	// Ledger integration
	ledgerStore *ledger.LedgerStore
	chainID     string

	// Current block tracking for ledger updates
	currentBlockHeight uint64
	currentBlockHash   string
	currentBlockTime   time.Time
	currentAccAnchor   *ledger.SystemAccumulateAnchorRef
}

// NewValidatorApp creates a new ABCI application for validator consensus.
// It automatically restores state from the ledger if available, ensuring
// CometBFT can sync properly after restart.
func NewValidatorApp(ledgerStore *ledger.LedgerStore, chainID string) *ValidatorApp {
	app := &ValidatorApp{
		logger:          log.New(log.Writer(), "[ValidatorApp] ", log.LstdFlags),
		latestHeight:    0,
		validatorBlocks: make(map[string]*ValidatorBlock),
		ledgerStore:     ledgerStore,
		chainID:         chainID,
	}

	// Restore persisted ABCI state for CometBFT recovery
	if ledgerStore != nil {
		if state, err := ledgerStore.LoadABCIState(); err != nil {
			app.logger.Printf("⚠️ Failed to load ABCI state: %v (starting fresh)", err)
		} else if state != nil {
			app.latestHeight = state.LastBlockHeight
			app.lastCommitHash = state.LastBlockAppHash
			app.logger.Printf("✅ Restored ABCI state: height=%d, appHash=%x",
				app.latestHeight, app.lastCommitHash[:min(8, len(app.lastCommitHash))])
		}
	}

	return app
}

// GetLedgerStore returns the ledger store for compatibility with anchor manager
func (app *ValidatorApp) GetLedgerStore() *ledger.LedgerStore {
	return app.ledgerStore
}

// GetChainID returns the chain ID for compatibility with anchor manager
func (app *ValidatorApp) GetChainID() string {
	return app.chainID
}

// Info returns application information
func (app *ValidatorApp) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	return &abcitypes.ResponseInfo{
		Data:             "Certen Validator Consensus Application",
		Version:          "1.0.0",
		AppVersion:       1,
		LastBlockHeight:  app.latestHeight,
		LastBlockAppHash: app.lastCommitHash,
	}, nil
}

// CheckTx validates incoming ValidatorBlock transactions
func (app *ValidatorApp) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	// Parse ValidatorBlock from transaction bytes
	var vb ValidatorBlock
	if err := json.Unmarshal(req.Tx, &vb); err != nil {
		return &abcitypes.ResponseCheckTx{
			Code: 1,
			Log:  "invalid ValidatorBlock JSON: " + err.Error(),
		}, nil
	}

	// Validate canonical structure and commitments
	if err := app.validateValidatorBlock(&vb); err != nil {
		return &abcitypes.ResponseCheckTx{
			Code: 2,
			Log:  "ValidatorBlock validation failed: " + err.Error(),
		}, nil
	}

	app.logger.Printf("✅ CheckTx: Valid ValidatorBlock - Bundle: %s, Height: %d",
		vb.BundleID, vb.BlockHeight)

	return &abcitypes.ResponseCheckTx{
		Code:      0,
		GasWanted: 1,
		GasUsed:   1,
		Log:       "ValidatorBlock validation passed",
	}, nil
}

// processValidatorTransaction processes ValidatorBlock transactions for FinalizeBlock
func (app *ValidatorApp) processValidatorTransaction(tx []byte) abcitypes.ExecTxResult {
	var vb ValidatorBlock
	if err := json.Unmarshal(tx, &vb); err != nil {
		return abcitypes.ExecTxResult{Code: 1, Log: "invalid ValidatorBlock JSON: " + err.Error()}
	}

	// === ABCI metadata authority ===
	// Override metadata before calling invariants per Golden Spec section 4.1
	vb.BlockHeight = uint64(app.currentBlockHeight)
	vb.Timestamp = app.currentBlockTime.UTC().Format(time.RFC3339)
	if vb.ValidatorID == "" {
		vb.ValidatorID = app.chainID // or from config
	}

	// CRITICAL: Validate ProofClass per FIRST_PRINCIPLES 2.5 before invariant check
	if vb.ExecutionProof.ProofClass != "" {
		if vb.ExecutionProof.ProofClass != "on_demand" && vb.ExecutionProof.ProofClass != "on_cadence" {
			return abcitypes.ExecTxResult{
				Code: 3,
				Log:  fmt.Sprintf("invalid proof class '%s' - must be 'on_demand' or 'on_cadence'", vb.ExecutionProof.ProofClass),
			}
		}
		app.logger.Printf("🎯 [PROOF-CLASS] ValidatorBlock %s has proof class: %s", vb.BundleID, vb.ExecutionProof.ProofClass)
	}

	// Now validate invariants with corrected metadata
	if err := VerifyValidatorBlockInvariants(&vb); err != nil {
		return abcitypes.ExecTxResult{
			Code: 2,
			Log:  "validator block invariant violations: " + err.Error(),
		}
	}

	// Store ValidatorBlock with basic memory retention
	// NOTE: No mutex lock here - FinalizeBlock already holds app.mu.Lock()
	// Adding a lock here would cause a deadlock (sync.Mutex is not reentrant)
	app.validatorBlocks[vb.BundleID] = &vb

	// Height-based VB in-memory cache retention (keep last 1000 blocks)
	const maxCachedBlocks = 1000
	if len(app.validatorBlocks) > maxCachedBlocks {
		// Height-based cleanup: find and remove oldest entries by block height
		minHeightToKeep := vb.BlockHeight - uint64(maxCachedBlocks-100) // Keep margin of 100
		count := 0
		for bundleID, cachedVB := range app.validatorBlocks {
			if cachedVB.BlockHeight < minHeightToKeep {
				delete(app.validatorBlocks, bundleID)
				count++
			}
		}
		if count == 0 {
			// Fallback: if no old entries found (heights too close), remove any 100 entries
			for bundleID := range app.validatorBlocks {
				delete(app.validatorBlocks, bundleID)
				count++
				if count >= 100 {
					break
				}
			}
		}
		app.logger.Printf("🗑️ VB cache cleanup: removed %d old entries (below height %d)", count, minHeightToKeep)
	}

	// Wire AccumulateAnchorReference into current anchor tracking
	anchorRef := vb.AccumulateAnchorReference
	if anchorRef.TxHash != "" && anchorRef.BlockHeight > 0 {
		app.currentAccAnchor = &ledger.SystemAccumulateAnchorRef{
			TxHash:     anchorRef.TxHash,
			AccountURL: anchorRef.AccountURL, // Use AccountURL from the anchor reference
			MinorIndex: anchorRef.BlockHeight, // Use block height as minor index for now
			MajorIndex: 0,                     // Default to 0, can be enhanced later
		}
		app.logger.Printf("📍 Wired AccumulateAnchorReference: TxHash=%s, AccountURL=%s, BlockHeight=%d",
			anchorRef.TxHash, anchorRef.AccountURL, anchorRef.BlockHeight)
	}

	app.logger.Printf("📝 DeliverTx: Stored ValidatorBlock - Bundle: %s, Height: %d, Operations: %d",
		vb.BundleID, vb.BlockHeight, len(vb.SyntheticTransactions))

	// Create events for indexing
	events := []abcitypes.Event{
		{
			Type: "validator_block",
			Attributes: []abcitypes.EventAttribute{
				{Key: "bundle_id", Value: vb.BundleID},
				{Key: "validator_id", Value: vb.ValidatorID},
				{Key: "block_height", Value: fmt.Sprintf("%d", vb.BlockHeight)},
				{Key: "organization_adi", Value: vb.GovernanceProof.OrganizationADI},
			},
		},
		{
			Type: "cross_chain_operations",
			Attributes: []abcitypes.EventAttribute{
				{Key: "operation_id", Value: vb.CrossChainProof.OperationID},
				{Key: "chain_targets", Value: fmt.Sprintf("%d", len(vb.CrossChainProof.ChainTargets))},
				{Key: "execution_stage", Value: vb.ExecutionProof.Stage},
			},
		},
	}

	return abcitypes.ExecTxResult{
		Code:   0,
		Log:    "ValidatorBlock processed successfully",
		Events: events,
	}
}


// FinalizeBlock processes the entire block (CometBFT v0.38+)
func (app *ValidatorApp) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Reset current anchor for this block; it will be set again if any tx wires it
	app.currentAccAnchor = nil

	// Capture block header information for ledger tracking
	app.currentBlockHeight = uint64(req.Height)
	app.currentBlockHash = fmt.Sprintf("%X", req.Hash)
	app.currentBlockTime = req.Time
	// Note: currentAccAnchor is now set per ValidatorBlock transaction in processValidatorTransaction

	app.logger.Printf("🚀 FinalizeBlock: Height %d, Hash: %s, Time: %s",
		app.currentBlockHeight, app.currentBlockHash[:8], app.currentBlockTime.Format(time.RFC3339))

	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))

	for i, tx := range req.Txs {
		// Process each ValidatorBlock transaction
		result := app.processValidatorTransaction(tx)
		txResults[i] = &result
	}

	app.logger.Printf("🔄 Finalized validator block %d with %d ValidatorBlock transactions", req.Height, len(req.Txs))

	return &abcitypes.ResponseFinalizeBlock{
		TxResults: txResults,
	}, nil
}

// Commit finalizes the block and updates application state
func (app *ValidatorApp) Commit(ctx context.Context, req *abcitypes.RequestCommit) (*abcitypes.ResponseCommit, error) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Increment block height
	app.latestHeight++

	// Update system ledger with current block information
	height := app.currentBlockHeight
	hash := app.currentBlockHash
	t := app.currentBlockTime

	// Configure executor version and upstream networks
	executorVersion := "certen-v1" // or from config
	upstream := []ledger.UpstreamExecutor{
		{Partition: "accumulate-dn", Version: "v2-jiuquan"},
		// add others dynamically if needed
	}

	if err := app.ledgerStore.UpdateSystemLedgerOnCommit(
		height, hash, t, app.currentAccAnchor, executorVersion, upstream,
	); err != nil {
		app.logger.Printf("❌ Failed to update system ledger: %v", err)
	} else {
		app.logger.Printf("✅ Updated system ledger for block %d", height)
	}

	// Generate application hash from current state
	appHash := app.generateAppHash()
	app.lastCommitHash = appHash

	// CRITICAL: Persist ABCI state for CometBFT recovery after restart
	// This ensures Info() returns the correct height and appHash so CometBFT
	// can sync properly with the application state.
	if err := app.ledgerStore.SaveABCIState(&ledger.ABCIState{
		LastBlockHeight:  app.latestHeight,
		LastBlockAppHash: appHash,
	}); err != nil {
		app.logger.Printf("❌ Failed to persist ABCI state: %v", err)
	}

	blockCount := len(app.validatorBlocks)
	app.logger.Printf("📦 Committed validator block %d with %d ValidatorBlocks (hash: %x)",
		app.latestHeight, blockCount, appHash[:8])

	// Guard RetainHeight against negative values
	retainHeight := app.latestHeight - 100
	if retainHeight < 0 {
		retainHeight = 0
	}

	return &abcitypes.ResponseCommit{
		RetainHeight: retainHeight, // Keep recent 100 blocks, but guard against negative
	}, nil
}

// Query handles application state queries
func (app *ValidatorApp) Query(ctx context.Context, req *abcitypes.RequestQuery) (*abcitypes.ResponseQuery, error) {
	app.mu.RLock()
	defer app.mu.RUnlock()

	switch req.Path {
	case "/validator_block":
		// Query specific ValidatorBlock by bundle_id
		bundleID := string(req.Data)
		if vb, exists := app.validatorBlocks[bundleID]; exists {
			data, _ := json.Marshal(vb)
			return &abcitypes.ResponseQuery{
				Code:  0,
				Value: data,
				Log:   "ValidatorBlock found",
			}, nil
		}
		return &abcitypes.ResponseQuery{
			Code: 1,
			Log:  "ValidatorBlock not found",
		}, nil

	case "/validator_blocks/count":
		count := len(app.validatorBlocks)
		return &abcitypes.ResponseQuery{
			Code:  0,
			Value: []byte(fmt.Sprintf("%d", count)),
			Log:   "ValidatorBlocks count",
		}, nil

	case "/latest_height":
		return &abcitypes.ResponseQuery{
			Code:  0,
			Value: []byte(fmt.Sprintf("%d", app.latestHeight)),
			Log:   "Latest block height",
		}, nil

	case "/certen/system_ledger":
		resp := app.querySystemLedger(*req)
		return &resp, nil

	case "/certen/anchor_ledger":
		resp := app.queryAnchorLedger(*req)
		return &resp, nil

	default:
		return &abcitypes.ResponseQuery{
			Code: 2,
			Log:  "unknown query path: " + req.Path,
		}, nil
	}
}

// InitChain initializes the application
func (app *ValidatorApp) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) (*abcitypes.ResponseInitChain, error) {
	app.logger.Printf("🚀 Initializing Validator ABCI Application - Chain: %s", req.ChainId)
	return &abcitypes.ResponseInitChain{}, nil
}

// ==================================
// Helper Methods
// ==================================

// validateValidatorBlock performs validation for CheckTx path
// Per Golden Spec section 4.2: CheckTx doesn't know final block height
func (app *ValidatorApp) validateValidatorBlock(vb *ValidatorBlock) error {
	// Run invariant verification
	if err := VerifyValidatorBlockInvariants(vb); err != nil {
		return fmt.Errorf("validator block invariant violations: %w", err)
	}

	// Structural sanity checks (not strict height equality)
	if vb.BundleID == "" {
		return fmt.Errorf("bundle_id must not be empty")
	}
	if vb.OperationCommitment == "" {
		return fmt.Errorf("operation_commitment must not be empty")
	}

	return nil
}


// generateAppHash creates a deterministic hash of current application state
func (app *ValidatorApp) generateAppHash() []byte {
	if len(app.validatorBlocks) == 0 {
		return []byte("empty_validator_state")
	}

	// Sort bundleID keys for deterministic iteration
	bundleIDs := make([]string, 0, len(app.validatorBlocks))
	for bundleID := range app.validatorBlocks {
		bundleIDs = append(bundleIDs, bundleID)
	}
	sort.Strings(bundleIDs)

	// Create deterministic hash from ValidatorBlocks in sorted order
	hash := [32]byte{}
	for _, bundleID := range bundleIDs {
		vb := app.validatorBlocks[bundleID]
		// XOR bundleID bytes into hash in deterministic order
		bundleBytes := []byte(vb.BundleID)
		for i, b := range bundleBytes {
			if i < 32 {
				hash[i] ^= b
			}
		}
	}

	return hash[:]
}

// querySystemLedger handles system ledger query requests
func (app *ValidatorApp) querySystemLedger(req abcitypes.RequestQuery) abcitypes.ResponseQuery {
	var params ledger.SystemLedgerQueryParams
	if len(req.Data) > 0 {
		if err := json.Unmarshal(req.Data, &params); err != nil {
			return abcitypes.ResponseQuery{
				Code: 1,
				Log:  fmt.Sprintf("invalid system_ledger params: %v", err),
			}
		}
	}

	state, err := app.ledgerStore.GetSystemLedgerLatest(app.chainID)
	// If height-specific queries are needed, add GetSystemLedgerAt(height) and branch here

	if err != nil || state == nil {
		return abcitypes.ResponseQuery{
			Code: 1,
			Log:  fmt.Sprintf("failed to load system ledger: %v", err),
		}
	}

	b, err := json.Marshal(state)
	if err != nil {
		return abcitypes.ResponseQuery{
			Code: 1,
			Log:  fmt.Sprintf("failed to marshal system ledger: %v", err),
		}
	}

	return abcitypes.ResponseQuery{
		Code:  0,
		Value: b,
		Log:   "System ledger retrieved successfully",
	}
}

// queryAnchorLedger handles anchor ledger query requests
func (app *ValidatorApp) queryAnchorLedger(req abcitypes.RequestQuery) abcitypes.ResponseQuery {
	state, err := app.ledgerStore.GetAnchorLedger(app.chainID)
	if err != nil || state == nil {
		return abcitypes.ResponseQuery{
			Code: 1,
			Log:  fmt.Sprintf("failed to load anchor ledger: %v", err),
		}
	}

	b, err := json.Marshal(state)
	if err != nil {
		return abcitypes.ResponseQuery{
			Code: 1,
			Log:  fmt.Sprintf("failed to marshal anchor ledger: %v", err),
		}
	}

	return abcitypes.ResponseQuery{
		Code:  0,
		Value: b,
		Log:   "Anchor ledger retrieved successfully",
	}
}

// ==============================================
// Additional ABCI methods for complete interface
// ==============================================

// PrepareProposal processes incoming proposals
func (app *ValidatorApp) PrepareProposal(ctx context.Context, req *abcitypes.RequestPrepareProposal) (*abcitypes.ResponsePrepareProposal, error) {
	// For ValidatorBlock chain, we accept all ValidatorBlock transactions as-is
	return &abcitypes.ResponsePrepareProposal{Txs: req.Txs}, nil
}

// ProcessProposal validates a proposed block
func (app *ValidatorApp) ProcessProposal(ctx context.Context, req *abcitypes.RequestProcessProposal) (*abcitypes.ResponseProcessProposal, error) {
	// Basic validation - all ValidatorBlock transactions should be valid JSON
	for _, tx := range req.Txs {
		var vb ValidatorBlock
		if err := json.Unmarshal(tx, &vb); err != nil {
			return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_REJECT}, nil
		}
	}
	return &abcitypes.ResponseProcessProposal{Status: abcitypes.ResponseProcessProposal_ACCEPT}, nil
}

// ExtendVote extends validator votes
func (app *ValidatorApp) ExtendVote(ctx context.Context, req *abcitypes.RequestExtendVote) (*abcitypes.ResponseExtendVote, error) {
	return &abcitypes.ResponseExtendVote{}, nil
}

// VerifyVoteExtension verifies vote extensions
func (app *ValidatorApp) VerifyVoteExtension(ctx context.Context, req *abcitypes.RequestVerifyVoteExtension) (*abcitypes.ResponseVerifyVoteExtension, error) {
	return &abcitypes.ResponseVerifyVoteExtension{Status: abcitypes.ResponseVerifyVoteExtension_ACCEPT}, nil
}

// ListSnapshots returns available snapshots
func (app *ValidatorApp) ListSnapshots(ctx context.Context, req *abcitypes.RequestListSnapshots) (*abcitypes.ResponseListSnapshots, error) {
	return &abcitypes.ResponseListSnapshots{}, nil
}

// OfferSnapshot handles snapshot offers
func (app *ValidatorApp) OfferSnapshot(ctx context.Context, req *abcitypes.RequestOfferSnapshot) (*abcitypes.ResponseOfferSnapshot, error) {
	return &abcitypes.ResponseOfferSnapshot{Result: abcitypes.ResponseOfferSnapshot_ABORT}, nil
}

// LoadSnapshotChunk loads snapshot chunks
func (app *ValidatorApp) LoadSnapshotChunk(ctx context.Context, req *abcitypes.RequestLoadSnapshotChunk) (*abcitypes.ResponseLoadSnapshotChunk, error) {
	return &abcitypes.ResponseLoadSnapshotChunk{}, nil
}

// ApplySnapshotChunk applies snapshot chunks
func (app *ValidatorApp) ApplySnapshotChunk(ctx context.Context, req *abcitypes.RequestApplySnapshotChunk) (*abcitypes.ResponseApplySnapshotChunk, error) {
	return &abcitypes.ResponseApplySnapshotChunk{Result: abcitypes.ResponseApplySnapshotChunk_ABORT}, nil
}
