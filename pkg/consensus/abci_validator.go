// Copyright 2025 Certen Protocol
//
// Production ABCI Application for Validator CometBFT Chain
// Implements ValidatorBlock processing with canonical JSON validation

package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/metrics"
	abcitypes "github.com/cometbft/cometbft/abci/types"
)

// ValidatorApp implements the ABCI interface for validator consensus
type ValidatorApp struct {
	logger          *log.Logger
	latestHeight    int64
	lastCommitHash  []byte
	pendingAppHash  []byte                     // app-hash computed in FinalizeBlock, persisted verbatim in Commit so CometBFT and the app agree
	validatorBlocks map[string]*ValidatorBlock // Store by bundle_id
	// App-hash: a SHA256 hash chain over committed ValidatorBlocks:
	//     appHash(H) = SHA256( appHash(H-1) || sorted(unique bundle-ids in block H) )
	// (genesis base = nil; an empty block advances the chain as SHA256(prev)). This is collision-
	// resistant and commits to the ORDER and COUNT of committed VBs — unlike the legacy XOR. It is
	// derived from persisted state (committedAppHash is seeded from the persisted app-hash on
	// restart), NOT from the in-memory validatorBlocks map (which is pruned and not restored), so a
	// restarted/catch-up node reproduces correct app-hashes.
	//
	// TRANSACTIONALITY (idempotency): committedAppHash is mutated ONLY by Commit. FinalizeBlock stages
	// its result into pendingAppHash, computed from committedAppHash WITHOUT mutating it. ABCI may
	// call FinalizeBlock without a following Commit (rejected block, blocksync retry) or replay it —
	// this design makes every such call recompute the same result instead of corrupting committed state.
	committedAppHash []byte   // chain head as of the last Commit (nil = genesis); mutated only by Commit
	blockBundles     []string // bundle-ids seen during the current FinalizeBlock (reset each block)
	mu               sync.RWMutex

	// Ledger integration
	ledgerStore *ledger.LedgerStore
	chainID     string

	// Entitlement gate. Read once at construction: a consensus rule must not
	// change under a running node, and re-reading the environment per block
	// would let two validators evaluate the same block differently.
	entitlement EntitlementConfig

	// executionRulesVersion is the rules version that produced the committed
	// state, persisted beside the app hash so a later binary can detect that it
	// would replay history under rules that did not commit it.
	executionRulesVersion uint64

	// Current block tracking for ledger updates
	currentBlockHeight uint64
	currentBlockHash   string
	currentBlockTime   time.Time
	currentAccAnchor   *ledger.SystemAccumulateAnchorRef

	// Database repositories for consensus persistence
	repos *database.Repositories

	// Background writer for consensus_entries / batch_attestations (consensus_persistence.go). Commit
	// only hands it this block's accepted ValidatorBlocks; nil when no database is wired.
	persister *consensusPersister
	// Accepted ValidatorBlocks of the block being finalized (reset each FinalizeBlock, handed off by Commit).
	blockValidatorBlocks []ValidatorBlock
	// Height restored from the ledger when this process started (before any handshake replay). Blocks this
	// process commits above it before the persister exists are rebuilt from the block store.
	startHeight    int64
	startHeightSet bool

	// Validator count for quorum calculation
	validatorCount int

	// Optional block-checkpoint hook (P3): invoked non-blocking after each committed block so a
	// single designated writer can mirror block roots to Accumulate. nil unless wired in main.go.
	checkpointHook func(height int64, blockHash string, appHash []byte, ts time.Time)

	// How many blocks of consensus history CometBFT keeps. <= 0 retains all,
	// which is the default; see retainHeightFor for why pruning is opt-in.
	blockRetention int64
}

// LatestHeight returns the height of the last block this app committed.
//
// The batch path derives its period cutoff from this. It must be the CHAIN's height, not a
// count of anything this node happens to be doing: a period closes when the chain passes its
// upper bound, and until then a member could still land in it.
//
// Reading the app rather than counting processed intents is what makes a lone intent settle.
// When the cutoff only advanced as intents arrived, one queued intent could never close its own
// period — it waited for a second intent that might never come.
func (app *ValidatorApp) LatestHeight() int64 {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.latestHeight
}

// SetCheckpointHook installs the (non-blocking) per-commit checkpoint callback. The callback
// MUST NOT block — it is called on the consensus commit path and is expected to enqueue only.
func (app *ValidatorApp) SetCheckpointHook(fn func(height int64, blockHash string, appHash []byte, ts time.Time)) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.checkpointHook = fn
}

// blockRetentionFromEnv reads CERTEN_BLOCK_RETENTION.
//
// Unset, zero or unparseable means retain ALL consensus history — the safe
// default. Pruning is opt-in because losing old blocks both destroys the BFT
// quorum record and makes a mismatched volume reset unrecoverable.
func blockRetentionFromEnv() int64 {
	raw := strings.TrimSpace(os.Getenv("CERTEN_BLOCK_RETENTION"))
	if raw == "" {
		return 0
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return n
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
		blockRetention:  blockRetentionFromEnv(),
	}

	// Entitlement gate. A misconfiguration here is fatal on purpose: starting
	// with a silently-off gate that the operator believes is enforcing is worse
	// than not starting, and starting in enforce mode with a key set that
	// differs from the rest of the fleet would fork the chain.
	envCfg, err := EntitlementConfigFromEnv()
	if err != nil {
		app.logger.Fatalf("invalid entitlement gate configuration: %v", err)
	}

	// The environment is only the GENESIS SEED. On a chain that already sealed a
	// policy, the sealed value wins and the environment is ignored — because the
	// gate's verdict feeds the app hash, and a rule that can change between two
	// runs lets a node disagree with its own committed past. That disagreement
	// is unrecoverable, and it is what took the fleet down on 2026-07-27.
	entCfg, err := ResolveEntitlementPolicy(ledgerStore, envCfg, app.logger)
	if err != nil {
		app.logger.Fatalf("entitlement policy could not be resolved: %v", err)
	}
	app.entitlement = entCfg
	app.logger.Printf("🔐 [ENTITLEMENT] gate mode=%s trusted_keys=%d",
		entCfg.Mode, len(entCfg.Keys))

	// Restore persisted ABCI state for CometBFT recovery
	if ledgerStore != nil {
		if state, err := ledgerStore.LoadABCIState(); err != nil {
			app.logger.Printf("⚠️ Failed to load ABCI state: %v (starting fresh)", err)
		} else if state != nil {
			// Execution-rules check, BEFORE adopting the state.
			//
			// Fatal on purpose. Starting under rules that differ from the ones
			// that committed this state replays history to a different app hash
			// and panics inside CometBFT's handshake — a failure that names
			// nothing and cannot self-recover. Refusing here costs a restart
			// and says exactly what to do.
			ver, err := checkExecutionRulesVersion(state.ExecutionRulesVersion, state.LastBlockHeight)
			if err != nil {
				app.logger.Fatalf("❌ %v", err)
			}
			app.executionRulesVersion = ver

			app.latestHeight = state.LastBlockHeight
			app.lastCommitHash = state.LastBlockAppHash
			app.seedAppHash(state.LastBlockAppHash)
			app.logger.Printf("✅ Restored ABCI state: height=%d, appHash=%x, rules=v%d",
				app.latestHeight, app.lastCommitHash[:min(8, len(app.lastCommitHash))], ver)
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

// SetRepositories sets the database repositories and starts consensus persistence, identified by the
// chain id and with no block source for rebuilding missed heights. Prefer EnableConsensusPersistence,
// which the CometBFT engine calls with the validator id and its block store.
func (app *ValidatorApp) SetRepositories(repos *database.Repositories) {
	app.EnableConsensusPersistence(repos, app.chainID, nil)
}

// EnableConsensusPersistence wires the repositories and starts the background consensus persister.
//
// writerID identifies this node's persisted-height watermark; validators that share a database must use
// distinct ids. source rebuilds heights the persister did not receive (nil disables rebuilding; such
// heights are logged as gaps). Calling it again replaces the source only.
func (app *ValidatorApp) EnableConsensusPersistence(repos *database.Repositories, writerID string, source committedBlockSource) {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.repos = repos
	if repos == nil || repos.Consensus == nil {
		return
	}
	if app.persister != nil {
		if source != nil {
			app.persister.setSource(source)
		}
		return
	}
	if writerID == "" {
		writerID = app.chainID
	}
	// writer_id is VARCHAR(256); a longer id would fail every watermark update and stall the writer.
	if len(writerID) > 256 {
		sum := sha256.Sum256([]byte(writerID))
		writerID = writerID[:190] + "#" + hex.EncodeToString(sum[:])
	}
	p := newConsensusPersister(repos.Consensus, writerID, log.New(log.Writer(), "[ValidatorApp] ", log.LstdFlags))
	p.setSource(source)
	start := app.latestHeight
	if app.startHeightSet {
		start = app.startHeight
	}
	p.seedCommitted(start, app.latestHeight)
	p.start()
	app.persister = p
	app.logger.Printf("✅ [PERSIST] consensus persistence runs off the Commit path (writer=%s, rebuild=%t)", writerID, source != nil)
}

// StopConsensusPersistence stops the background persister (shutdown, tests). Heights still queued are
// rebuilt from the block store on the next start.
func (app *ValidatorApp) StopConsensusPersistence() {
	app.mu.Lock()
	p := app.persister
	app.persister = nil
	app.mu.Unlock()
	if p != nil {
		p.stop()
	}
}

// SetValidatorCount sets the total number of validators for quorum calculation
func (app *ValidatorApp) SetValidatorCount(count int) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.validatorCount = count
}

// applyCommitMetadata stamps the ABCI-authoritative metadata onto a ValidatorBlock: the committing block's
// height and time, and the chain id when the block names no validator. FinalizeBlock and the consensus
// persister's block-store rebuild both use it, so a rebuilt block is identical to the one committed.
func applyCommitMetadata(vb *ValidatorBlock, height int64, blockTime time.Time, chainID string) {
	vb.BlockHeight = uint64(height)
	vb.Timestamp = blockTime.UTC().Format(time.RFC3339)
	if vb.ValidatorID == "" {
		vb.ValidatorID = chainID // or from config
	}
}

// Info returns application information
// Per BFT Resiliency Task 3: Includes height mismatch detection and recovery logging
func (app *ValidatorApp) Info(ctx context.Context, req *abcitypes.RequestInfo) (*abcitypes.ResponseInfo, error) {
	// WRITE lock: Info() is the handshake entry point and is where persisted
	// state must be restored, so it has to be able to mutate.
	app.mu.Lock()
	defer app.mu.Unlock()

	// Restore height and app hash from the ledger before answering.
	//
	// `latestHeight` lives in memory and is therefore 0 in a fresh process. The
	// previous code noticed the mismatch and only logged it ("Can't modify
	// state here (RLock)"), so every restart told CometBFT the app was at
	// height 0 and forced a replay from genesis.
	//
	// That was survivable only while block 1 still existed. Once CometBFT
	// pruned the block store, replay from 0 became impossible and the node
	// could never start again:
	//
	//   error on replay: app block height (0) is too far below block store base (4)
	//
	// which took the whole validator set down on a routine restart. The ledger
	// is the source of truth for what this app has committed, so read it.
	if app.ledgerStore != nil {
		if state, err := app.ledgerStore.LoadABCIState(); err == nil && state != nil {
			// Re-check the execution rules HERE, not only at construction.
			//
			// Info is the handshake entry point and the last moment before
			// CometBFT compares our app hash against its own. The constructor
			// check can be bypassed — a nil ledger store at construction, or
			// state written between construction and handshake — and a bypass
			// costs the outage this whole mechanism exists to prevent.
			if _, err := checkExecutionRulesVersion(state.ExecutionRulesVersion, state.LastBlockHeight); err != nil {
				app.logger.Fatalf("❌ %v", err)
			}
			if state.LastBlockHeight > app.latestHeight {
				app.logger.Printf("🔄 Restoring app state from ledger: height %d -> %d",
					app.latestHeight, state.LastBlockHeight)
				app.latestHeight = state.LastBlockHeight
				if len(state.LastBlockAppHash) > 0 {
					app.lastCommitHash = state.LastBlockAppHash
				}
			}
		} else if err != nil {
			// Do NOT silently answer 0 — that triggers a full replay and, on a
			// pruned store, an unrecoverable node. Surface it loudly instead.
			app.logger.Printf("❌ Could not load persisted ABCI state (%v); "+
				"reporting height %d, which will force a replay", err, app.latestHeight)
		}
	}

	if !app.startHeightSet {
		// The handshake calls Info before replaying any block: this is the height this process started from.
		app.startHeight = app.latestHeight
		app.startHeightSet = true
	}

	app.logger.Printf("📋 Info() called - App height: %d, AppHash: %x",
		app.latestHeight, app.lastCommitHash[:min(8, len(app.lastCommitHash))])

	return &abcitypes.ResponseInfo{
		Data:    "Certen Validator Consensus Application",
		Version: "1.0.0",
		// Report the execution rules this binary implements rather than a
		// hardcoded constant, so "what rules does this node run" has one answer.
		AppVersion:       CurrentExecutionRulesVersion,
		LastBlockHeight:  app.latestHeight,
		LastBlockAppHash: app.lastCommitHash,
	}, nil
}

// CheckTx validates incoming ValidatorBlock transactions
func (app *ValidatorApp) CheckTx(ctx context.Context, req *abcitypes.RequestCheckTx) (*abcitypes.ResponseCheckTx, error) {
	// A policy update is not a ValidatorBlock. Without this branch it is parsed
	// as one, fails every structural invariant, and is refused before it can
	// enter the mempool — so it never reaches FinalizeBlock, and the entitlement
	// rule can never be changed at all. FinalizeBlock has always had the
	// equivalent branch; this is the half that was missing.
	//
	// Only shape is checked here. Signatures, quorum, version and activation
	// height are verified in FinalizeBlock, which is the authority: CheckTx is a
	// mempool filter, and a lenient filter costs a wasted block, while a strict
	// one costs the ability to govern the chain.
	if _, ok := DecodePolicyUpdate(req.Tx); ok {
		return &abcitypes.ResponseCheckTx{Code: 0, GasWanted: 1, GasUsed: 1}, nil
	}

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

	// Entitlement gate — MEMPOOL FILTER, not the authority.
	//
	// CheckTx runs before a block exists, so there is no ABCI block time to
	// judge freshness against. Use the WALL CLOCK. CheckTx is explicitly not
	// consensus — a disagreement here costs a gossip round, not a fork — so it
	// is free to read a non-deterministic clock, and it is the only clock that
	// tracks the publisher's issued_at.
	//
	// This used to read the last committed block time, which DEADLOCKS an idle
	// chain (observed in production 2026-07-27, intent a45ee049): block time
	// only advances when a ValidatorBlock commits, so after ~5 minutes of quiet
	// every freshly published epoch looks future-dated, CheckTx refuses it as
	// ENTITLEMENT_STALE, and the refused block is precisely the one that would
	// have advanced the clock. Nothing recovers on its own.
	//
	// The authoritative, deterministic check stays in
	// processValidatorTransaction, which judges against req.Time — the time of
	// the block BEING finalized, which is current by construction.
	approxNow := time.Now().UTC()
	if reason, err := VerifyEntitlement(&vb, PrincipalOf(&vb), approxNow.Unix(), app.entitlement); err != nil {
		metrics.RecordEntitlementDecision("checktx", "refused", reason, PrincipalOf(&vb))
		app.logger.Printf("🚫 [ENTITLEMENT] CheckTx rejecting bundle=%s principal=%q reason=%s",
			vb.BundleID, PrincipalOf(&vb), reason)
		return &abcitypes.ResponseCheckTx{
			Code: 4,
			Log:  "entitlement check failed: " + err.Error(),
		}, nil
	} else if reason != "" {
		// Observed, not bound. Counted separately so "what would enforcing refuse"
		// is answerable from the same series BEFORE the fleet ever enforces.
		metrics.RecordEntitlementDecision("checktx", "observed", reason, PrincipalOf(&vb))
		app.logger.Printf("👁️ [ENTITLEMENT] OBSERVE CheckTx would reject bundle=%s principal=%q reason=%s",
			vb.BundleID, PrincipalOf(&vb), reason)
	} else {
		metrics.RecordEntitlementDecision("checktx", "admitted", "", "")
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
	applyCommitMetadata(&vb, int64(app.currentBlockHeight), app.currentBlockTime, app.chainID)

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

	// Entitlement gate — THE AUTHORITY.
	//
	// This is the consensus-enforced point: every validator runs it on every
	// ValidatorBlock, so a block rejected here cannot commit anywhere, no matter
	// what any individual node chose to sign earlier.
	//
	// app.currentBlockTime, never time.Now(): ABCI hands every validator the
	// same block time, and freshness judged against wall time would make nodes
	// disagree about expiry and halt the chain.
	principal := PrincipalOf(&vb)
	if reason, err := VerifyEntitlement(&vb, principal, app.currentBlockTime.UTC().Unix(), app.entitlement); err != nil {
		metrics.RecordEntitlementDecision("finalizeblock", "refused", reason, principal)
		app.logger.Printf("🚫 [ENTITLEMENT] REJECTED bundle=%s principal=%q reason=%s height=%d",
			vb.BundleID, principal, reason, app.currentBlockHeight)
		return abcitypes.ExecTxResult{
			Code: 4,
			Log:  "entitlement check failed: " + err.Error(),
		}
	} else if reason != "" {
		metrics.RecordEntitlementDecision("finalizeblock", "observed", reason, principal)
		app.logger.Printf("👁️ [ENTITLEMENT] OBSERVE would reject bundle=%s principal=%q reason=%s height=%d",
			vb.BundleID, principal, reason, app.currentBlockHeight)
	} else {
		metrics.RecordEntitlementDecision("finalizeblock", "admitted", "", "")
	}

	// Store ValidatorBlock with basic memory retention (query cache ONLY — it no longer feeds the
	// app-hash, so its pruning/restart-volatility can't affect consensus).
	// NOTE: No mutex lock here - FinalizeBlock already holds app.mu.Lock().
	// Record this bundle for the block's STAGED app-hash: FinalizeBlock folds it onto the committed
	// accumulator without mutating committed state, and Commit promotes it.
	app.blockBundles = append(app.blockBundles, vb.BundleID)
	app.validatorBlocks[vb.BundleID] = &vb
	// This block's accepted ValidatorBlocks, handed to the consensus persister by Commit. A value copy:
	// nothing mutates a ValidatorBlock after this point, and the persister only reads it.
	app.blockValidatorBlocks = append(app.blockValidatorBlocks, vb)

	// Height-based VB in-memory cache retention (keep last 1000 blocks). This is the Query cache only;
	// Commit never iterates it.
	const maxCachedBlocks = 1000
	if len(app.validatorBlocks) > maxCachedBlocks {
		// Height-based cleanup: find and remove oldest entries by block height.
		// Guard the subtraction: heights are uint64, and below the margin it would wrap to a huge
		// value and evict the entire cache.
		keepMargin := uint64(maxCachedBlocks - 100) // Keep margin of 100
		minHeightToKeep := uint64(0)
		if vb.BlockHeight > keepMargin {
			minHeightToKeep = vb.BlockHeight - keepMargin
		}
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
			AccountURL: anchorRef.AccountURL,  // Use AccountURL from the anchor reference
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

	// Bounded: an empty/short block hash must not panic FinalizeBlock.
	app.logger.Printf("🚀 FinalizeBlock: Height %d, Hash: %s, Time: %s",
		app.currentBlockHeight,
		app.currentBlockHash[:min(8, len(app.currentBlockHash))],
		app.currentBlockTime.Format(time.RFC3339))

	// POLICY ACTIVATION — before any transaction is judged.
	//
	// Keyed on BLOCK TIME, not height: this chain produces blocks only for real
	// work, so a height-based schedule means something different at every
	// throughput. Block time comes from the header and is identical on every
	// node, so it is exactly as deterministic and does not drift in meaning.
	//
	// A scheduled rule change takes effect at its activation height, and it must
	// take effect for the WHOLE block: judging some transactions in a block by
	// the old rule and others by the new one would make the outcome depend on
	// ordering. Promotion is a pure function of committed state and height, so
	// every node does it at the same height and replay reproduces it exactly.
	app.activatePolicyForBlock(req.Height, req.Time.UTC().Unix())

	txResults := make([]*abcitypes.ExecTxResult, len(req.Txs))
	app.blockBundles = app.blockBundles[:0] // reset per-block bundle list; txs append to it
	// A fresh slice, never [:0]: the previous block's slice may already belong to the persister.
	app.blockValidatorBlocks = nil

	for i, tx := range req.Txs {
		// A policy update is not a ValidatorBlock and must not be judged as one.
		if pu, ok := DecodePolicyUpdate(tx); ok {
			result := app.processPolicyUpdate(pu, req.Height)
			txResults[i] = &result
			continue
		}
		result := app.processValidatorTransaction(tx)
		txResults[i] = &result
	}

	// STAGE this block's app-hash: fold the block's unique bundle-ids onto the COMMITTED accumulator
	// WITHOUT mutating it. Because committedAccum is untouched until Commit, calling FinalizeBlock
	// again for the same block (rejected block, blocksync retry, handshake replay) recomputes the
	// identical result instead of corrupting state. In ABCI 0.38 the block's app-hash comes from
	// ResponseFinalizeBlock.AppHash; Commit persists this exact staged value.
	app.pendingAppHash = app.stageAppHash(app.blockBundles)

	// Normalize an empty app hash HERE, not in Commit.
	//
	// CometBFT records the app hash from FinalizeBlock's response and replays
	// against it on restart. Substituting a value later in Commit makes the
	// persisted hash disagree with what CometBFT stored, and the node dies on
	// the next handshake with:
	//
	//   panic: state.AppHash does not match AppHash after replay
	//
	// Doing it here keeps one value flowing through FinalizeBlock -> CometBFT
	// state -> Commit -> ledger, so every party holds the same bytes. The
	// substitution is deterministic, so validators cannot diverge.
	if len(app.pendingAppHash) == 0 {
		app.pendingAppHash = make([]byte, 32)
	}

	app.logger.Printf("🔄 Finalized validator block %d with %d ValidatorBlock transactions (appHash=%x)",
		req.Height, len(req.Txs), app.pendingAppHash[:min(8, len(app.pendingAppHash))])

	return &abcitypes.ResponseFinalizeBlock{
		TxResults: txResults,
		AppHash:   app.pendingAppHash,
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

	// PROMOTE the staged accumulator computed in FinalizeBlock to committed. This is the ONLY place
	// committedAccum is mutated — which is precisely what makes FinalizeBlock idempotent under
	// replay/retry. The persisted app-hash is byte-identical to what CometBFT recorded from
	// FinalizeBlock's ResponseFinalizeBlock.AppHash.
	appHash := app.pendingAppHash
	if appHash != nil {
		app.committedAppHash = appHash // promote staged -> committed (the ONLY mutation of committed)
	} else {
		// Defensive: FinalizeBlock didn't run (should not happen in the normal ABCI flow).
		appHash = app.generateAppHash()
	}

	// Persist EXACTLY what FinalizeBlock reported to CometBFT.
	//
	// Any normalization must happen in FinalizeBlock, because that response is
	// what CometBFT stores and replays against. Changing the value here would
	// make the ledger disagree with CometBFT's state and kill the node on the
	// next handshake ("state.AppHash does not match AppHash after replay").
	//
	// The defensive branch below only covers a path where FinalizeBlock never
	// ran at all; it must not silently rewrite a hash CometBFT already has.
	if len(appHash) == 0 {
		app.logger.Printf("⚠️ Empty app hash at height %d with no FinalizeBlock result — "+
			"using the zero hash to keep Commit from aborting before state is persisted",
			app.latestHeight)
		appHash = make([]byte, 32)
	}
	app.lastCommitHash = appHash

	// CRITICAL: Persist ABCI state for CometBFT recovery after restart
	// This ensures Info() returns the correct height and appHash so CometBFT
	// can sync properly with the application state.
	if err := app.ledgerStore.SaveABCIState(&ledger.ABCIState{
		LastBlockHeight:  app.latestHeight,
		LastBlockAppHash: appHash,
		// Stamp the rules that produced this hash, so a future binary can tell
		// whether it is able to replay this state at all.
		ExecutionRulesVersion: CurrentExecutionRulesVersion,
	}); err != nil {
		app.logger.Printf("❌ Failed to persist ABCI state: %v", err)
	}

	// P3: mirror this committed block's roots to Accumulate (non-blocking; hook only enqueues).
	if app.checkpointHook != nil {
		app.checkpointHook(app.latestHeight, app.currentBlockHash, appHash, app.currentBlockTime)
	}

	// Consensus entries and batch attestations: hand THIS block's accepted ValidatorBlocks to the
	// background persister (non-blocking). Commit must never do database I/O — CometBFT serialises
	// CheckTx with Commit, and a slow Commit turns every concurrent BroadcastTxSync into an RPC timeout
	// (see consensus_persistence.go). Every committed height is handed off, including blocks without
	// ValidatorBlocks, so the persister's watermark advances contiguously.
	blockVBs := app.blockValidatorBlocks
	app.blockValidatorBlocks = nil
	if app.persister != nil && app.currentBlockHeight > 0 {
		app.persister.enqueue(committedBlock{
			height: int64(app.currentBlockHeight),
			time:   app.currentBlockTime,
			blocks: blockVBs,
		}, app.validatorCount)
	}

	// Bounded slice: a log line must never be able to abort a commit.
	app.logger.Printf("📦 Committed validator block %d with %d ValidatorBlocks (cached: %d, hash: %x)",
		app.latestHeight, len(blockVBs), len(app.validatorBlocks), appHash[:min(8, len(appHash))])

	return &abcitypes.ResponseCommit{
		RetainHeight: app.retainHeightFor(app.latestHeight),
	}, nil
}

// retainHeightFor decides how much consensus history CometBFT keeps.
//
// Returning 0 means RETAIN EVERYTHING, and that is the default. The previous
// behaviour — prune everything below `height - 100` — was costly in a way that
// was invisible until it wasn't:
//
//   - Operationally it is a trap. The app's state and CometBFT's blocks live in
//     separate volumes, so resetting one and not the other leaves the app at
//     height 0 against a pruned store. Replay from genesis is then impossible
//     and NO validator can start:
//     "app block height (0) is too far below block store base (4)".
//     That took the whole set down after the chain first passed height 100.
//
//   - Evidentially it discards the BFT precommit history — the proof that a
//     quorum agreed at a given height. Customer-facing evidence lives on
//     Accumulate and the destination chains and is unaffected, but our own
//     ability to re-derive quorum from the chain is not. Until block roots are
//     anchored externally, these blocks are the only copy of that.
//
// Disk is cheap and these blocks are small; keeping them is the safe default.
// Set CERTEN_BLOCK_RETENTION to a positive number of blocks to prune anyway.
func (app *ValidatorApp) retainHeightFor(height int64) int64 {
	if app.blockRetention <= 0 {
		return 0 // retain all history
	}
	retain := height - app.blockRetention
	if retain < 0 {
		return 0
	}
	return retain
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

// seedAppHash initializes the COMMITTED chain head from a persisted app-hash so the app-hash chain
// continues correctly (and identically) after a restart.
func (app *ValidatorApp) seedAppHash(h []byte) {
	if len(h) > 0 {
		app.committedAppHash = append([]byte(nil), h...)
	}
}

// stageAppHash computes this block's app-hash by extending the COMMITTED chain head with the block's
// unique, sorted bundle-ids, WITHOUT mutating committed state:
//
//	appHash(H) = SHA256( appHash(H-1) || sorted(unique bundle-ids in block H) )
//
// Sorting makes it independent of tx order within the block while still committing to the SET; the
// chain over appHash(H-1) commits to order and count ACROSS blocks; SHA256 makes it collision-
// resistant. It is pure w.r.t. committed state, so calling it repeatedly for the same block (rejected
// block, blocksync retry, handshake replay) yields the identical result — the property that makes
// FinalizeBlock idempotent. An empty block advances the chain as SHA256(prev).
func (app *ValidatorApp) stageAppHash(bundles []string) []byte {
	uniq := make([]string, 0, len(bundles))
	seen := make(map[string]struct{}, len(bundles))
	for _, bid := range bundles {
		if _, dup := seen[bid]; dup {
			continue
		}
		seen[bid] = struct{}{}
		uniq = append(uniq, bid)
	}

	// Empty block: NO committed-state change, so the app-hash MUST stay unchanged. Advancing it on
	// empty blocks (e.g. SHA256(prev)) makes the app-hash change every block, and with
	// create_empty_blocks=false CometBFT emits a "proof" block whenever the app-hash changes
	// (needProofBlock) — which changes it again, producing an endless stream of empty timed blocks.
	// Returning the unchanged committed hash keeps the chain event-driven: blocks are produced only
	// for real ValidatorBlock transactions. The chain still commits to the order+count of VB-bearing
	// blocks (each such block advances the hash); empty filler blocks simply don't exist.
	if len(uniq) == 0 {
		return append([]byte(nil), app.committedAppHash...)
	}

	sort.Strings(uniq)
	h := sha256.New()
	h.Write(app.committedAppHash) // nil at genesis writes nothing
	for _, bid := range uniq {
		h.Write([]byte(bid))
	}
	return h.Sum(nil)
}

// generateAppHash returns the COMMITTED app-hash (used by Info() and as a defensive fallback). The
// per-block value comes from stageAppHash via FinalizeBlock.
func (app *ValidatorApp) generateAppHash() []byte {
	if app.committedAppHash == nil {
		return nil
	}
	return append([]byte(nil), app.committedAppHash...)
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

// ==============================================
// State Recovery & Graceful Shutdown Methods
// Per BFT Resiliency Tasks 3 & 6
// ==============================================

// RecoverState attempts to recover from state inconsistency
// Per BFT Resiliency Task 3: Automated State Recovery
func (app *ValidatorApp) RecoverState() error {
	app.mu.Lock()
	defer app.mu.Unlock()

	if app.ledgerStore == nil {
		return fmt.Errorf("ledger store not available for recovery")
	}

	// Load persisted ABCI state
	state, err := app.ledgerStore.LoadABCIState()
	if err != nil {
		return fmt.Errorf("failed to load ABCI state: %w", err)
	}

	if state == nil {
		app.logger.Printf("⚠️ No persisted ABCI state found - starting fresh")
		app.latestHeight = 0
		app.lastCommitHash = nil
		return nil
	}

	// Check for height mismatch
	if state.LastBlockHeight != app.latestHeight {
		app.logger.Printf("🔄 [RECOVERY] Height mismatch: Memory=%d, Ledger=%d",
			app.latestHeight, state.LastBlockHeight)

		// Use ledger state as source of truth
		app.latestHeight = state.LastBlockHeight
		app.lastCommitHash = state.LastBlockAppHash
		app.seedAppHash(state.LastBlockAppHash)

		app.logger.Printf("✅ [RECOVERY] Restored state from ledger: height=%d, hash=%x",
			app.latestHeight, app.lastCommitHash[:min(8, len(app.lastCommitHash))])
	}

	return nil
}

// ForceResetState performs an emergency state reset (use with caution!)
// This should only be used when consensus is completely stuck and manual recovery is needed
func (app *ValidatorApp) ForceResetState(targetHeight int64) error {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.logger.Printf("⚠️ [FORCE-RESET] Resetting state to height %d (was %d)", targetHeight, app.latestHeight)

	// Reset in-memory state
	app.latestHeight = targetHeight
	app.lastCommitHash = []byte("reset_state")
	app.validatorBlocks = make(map[string]*ValidatorBlock)

	// Persist the reset state
	if app.ledgerStore != nil {
		if err := app.ledgerStore.SaveABCIState(&ledger.ABCIState{
			LastBlockHeight:  app.latestHeight,
			LastBlockAppHash: app.lastCommitHash,
		}); err != nil {
			return fmt.Errorf("failed to persist reset state: %w", err)
		}
	}

	app.logger.Printf("✅ [FORCE-RESET] State reset complete")
	return nil
}

// Shutdown performs graceful shutdown with state flush
// Per BFT Resiliency Task 6: Graceful Shutdown with State Flush
func (app *ValidatorApp) Shutdown() error {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.logger.Printf("🛑 Graceful shutdown - flushing state...")

	// Flush current state to ledger
	if app.ledgerStore != nil {
		if err := app.ledgerStore.SaveABCIState(&ledger.ABCIState{
			LastBlockHeight:  app.latestHeight,
			LastBlockAppHash: app.lastCommitHash,
		}); err != nil {
			app.logger.Printf("❌ Failed to save state on shutdown: %v", err)
			return fmt.Errorf("failed to save state on shutdown: %w", err)
		}
		app.logger.Printf("✅ State flushed: height=%d, hash=%x",
			app.latestHeight, app.lastCommitHash[:min(8, len(app.lastCommitHash))])
	}

	app.logger.Printf("✅ Graceful shutdown complete")
	return nil
}

// GetLatestHeight returns the current committed height
func (app *ValidatorApp) GetLatestHeight() int64 {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.latestHeight
}

// GetStateInfo returns current state information for health checks
func (app *ValidatorApp) GetStateInfo() (height int64, appHash []byte, blockCount int) {
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.latestHeight, app.lastCommitHash, len(app.validatorBlocks)
}

// ==============================================
// Consensus Data Persistence
// ==============================================
//
// Commit hands each block's accepted ValidatorBlocks to consensusPersister (consensus_persistence.go),
// which writes them off the consensus path. Phase 5 anchor_batches fields are owned by the batch
// ConsensusCoordinator. The previous in-Commit implementations (persistConsensusData,
// updatePhase5AfterCommit) are removed; see consensus_persistence.go for why.
