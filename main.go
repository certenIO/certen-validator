package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/certen/independant-validator/db"
	"github.com/certen/independant-validator/pkg/accumulate"
	"github.com/certen/independant-validator/pkg/anchor"
	attestationStrategy "github.com/certen/independant-validator/pkg/attestation/strategy"
	"github.com/certen/independant-validator/pkg/config"
	"github.com/certen/independant-validator/pkg/consensus"
	"github.com/certen/independant-validator/pkg/crypto/bls"
	"github.com/certen/independant-validator/pkg/database"
	"github.com/certen/independant-validator/pkg/entitlement"
	"github.com/certen/independant-validator/pkg/envvar"
	"github.com/certen/independant-validator/pkg/ethereum"
	"github.com/certen/independant-validator/pkg/ethrpc"
	"github.com/certen/independant-validator/pkg/execution"
	"github.com/certen/independant-validator/pkg/execution/contracts"
	"github.com/certen/independant-validator/pkg/firestore"
	"github.com/certen/independant-validator/pkg/intent"
	"github.com/certen/independant-validator/pkg/ledger"
	"github.com/certen/independant-validator/pkg/metrics"
	"github.com/certen/independant-validator/pkg/proof"
	"github.com/certen/independant-validator/pkg/proofrequests"
	"github.com/certen/independant-validator/pkg/server"
	"github.com/certen/independant-validator/pkg/strategy"
)

// MemoryKV is a simple in-memory implementation of the KV interface
type MemoryKV struct {
	store map[string][]byte
	mu    sync.RWMutex
}

func (m *MemoryKV) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if value, exists := m.store[string(key)]; exists {
		return value, nil
	}
	return nil, nil
}

func (m *MemoryKV) Set(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.store[string(key)] = value
	return nil
}

// LedgerStoreWrapper adapts LedgerStore to the intent.LedgerStoreInterface
type LedgerStoreWrapper struct {
	store *ledger.LedgerStore
}

func (w *LedgerStoreWrapper) SaveIntentLastBlock(height uint64) error {
	return w.store.SaveIntentLastBlock(height)
}

func (w *LedgerStoreWrapper) LoadIntentLastBlock() (uint64, error) {
	return w.store.LoadIntentLastBlock()
}

// HealthStatus tracks the health of various components for the /health endpoint
// Per E.2 remediation: Proper degradation handling with explicit status tracking
// Per F.2 remediation: Enhanced health check with all component tracking
type HealthStatus struct {
	Status        string `json:"status"` // "ok", "degraded", "error"
	Phase         string `json:"phase"`
	Consensus     string `json:"consensus"`
	Database      string `json:"database"`       // "connected", "disconnected"
	Ethereum      string `json:"ethereum"`       // "connected", "disconnected"
	Accumulate    string `json:"accumulate"`     // "connected", "disconnected"
	BatchSystem   string `json:"batch_system"`   // "active", "disabled"
	ProofCycle    string `json:"proof_cycle"`    // "active", "disabled"
	UptimeSeconds int64  `json:"uptime_seconds"` // Seconds since startup

	// Discovery is "advancing", "stalled", or "starting".
	//
	// CONTINUOUSLY re-evaluated, unlike Accumulate above which is set once at startup and then
	// never revisited. That startup-only check is exactly why the 2026-08-05 outage was
	// invisible: Accumulate was marked "connected" at boot, the endpoint died later, and the
	// field still read "connected" hours after discovery had stopped.
	Discovery     string `json:"discovery"`
	DiscoveryLag  uint64 `json:"discovery_lag_blocks"`
	DiscoveryIdle int64  `json:"discovery_seconds_since_advance"`
	// DiscoveryUnsearched is how many blocks wait to be searched again, and the oldest's age (RB3-F125).
	DiscoveryUnsearched          int   `json:"discovery_unsearched_blocks"`
	DiscoveryUnsearchedOldestAge int64 `json:"discovery_unsearched_oldest_seconds"`
	DiscoveryInProgress          int   `json:"discovery_intents_in_progress"` // zero while "paused" = nothing in flight (RB3-F8)
	startTime                    time.Time
	mu                           sync.RWMutex
}

// Global health status - updated during startup and runtime
var healthStatus = &HealthStatus{
	Status:      "starting",
	Phase:       "5",
	Consensus:   "cometbft",
	Database:    "unknown",
	Ethereum:    "unknown",
	Accumulate:  "unknown",
	BatchSystem: "unknown",
	ProofCycle:  "unknown",
	startTime:   time.Now(),
}

func (h *HealthStatus) SetDatabase(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Database = status
	h.updateOverallStatus()
}

func (h *HealthStatus) SetEthereum(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Ethereum = status
	h.updateOverallStatus()
}

func (h *HealthStatus) SetAccumulate(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Accumulate = status
	h.updateOverallStatus()
}

// SetDiscovery records discovery liveness. Called on a loop, not once at startup.
func (h *HealthStatus) SetDiscovery(status string, lagBlocks uint64, secondsSinceAdvance int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Discovery = status
	h.DiscoveryLag = lagBlocks
	h.DiscoveryIdle = secondsSinceAdvance
	h.updateOverallStatus()
}

// SetDiscoveryInProgress records how many intents are being processed now.
func (h *HealthStatus) SetDiscoveryInProgress(n int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.DiscoveryInProgress = n
}

// SetDiscoveryUnsearched records the blocks waiting to be searched again.
func (h *HealthStatus) SetDiscoveryUnsearched(count int, oldestAgeSeconds int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.DiscoveryUnsearched = count
	h.DiscoveryUnsearchedOldestAge = oldestAgeSeconds
}

func (h *HealthStatus) SetBatchSystem(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.BatchSystem = status
	h.updateOverallStatus()
}

func (h *HealthStatus) SetProofCycle(status string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ProofCycle = status
	h.updateOverallStatus()
}

func (h *HealthStatus) updateOverallStatus() {
	// F.2 remediation: Determine overall status based on all component states
	// Critical components: Database, Ethereum, Accumulate
	// Optional components: BatchSystem, ProofCycle

	// Check for critical failures (error state)
	//
	// A stalled watermark is critical, not degraded: while it is stalled NO intent can be
	// discovered, so the validator contributes nothing to the set even though every other
	// component looks fine. On 2026-08-05 that state persisted for hours behind a "healthy"
	// container because nothing here consulted discovery at all.
	if h.Ethereum == "disconnected" || h.Accumulate == "disconnected" || h.Discovery == "stalled" {
		h.Status = "error"
		return
	}

	// Check for degraded state (non-critical components)
	// A paused intake (RB3-F8) is deliberate: the node is up and takes no new intent.
	if h.Database == "disconnected" || h.BatchSystem == "disabled" || h.ProofCycle == "disabled" || h.Discovery == "paused" {
		h.Status = "degraded"
		return
	}

	// All components healthy
	if h.Database == "connected" && h.Ethereum == "connected" &&
		h.Accumulate == "connected" && h.BatchSystem == "active" {
		h.Status = "ok"
	}
}

func (h *HealthStatus) ToJSON() []byte {
	h.mu.Lock()
	// Update uptime before serializing
	h.UptimeSeconds = int64(time.Since(h.startTime).Seconds())
	h.mu.Unlock()

	h.mu.RLock()
	defer h.mu.RUnlock()
	data, _ := json.Marshal(h)
	return data
}

// unifiedOrchestratorForAttestation bridges the unified orchestrator (created in
// startValidator) to main()'s HTTP mux so the Phase 8 peer-attestation endpoint
// (/api/unified/attestation/request) can route to it. Atomic because the HTTP
// server goroutine and startValidator run concurrently.
var unifiedOrchestratorForAttestation atomic.Pointer[execution.UnifiedOrchestrator]

// batchStackForAttestation bridges the batch stack (built late, in the batching wiring block)
// to the peer attestation HTTP handler (registered early). Same pattern, same reason.
var batchStackForAttestation atomic.Pointer[execution.BatchStack]

// batchQuorumAttestorForEvidence bridges the quorum attestor (built in the batching wiring block, before
// the database exists) to the anchor-evidence hook (wired later, once repositories are available).
//
// Same shape and the same reason as batchStackForAttestation above: the two halves are constructed in
// different phases of startup, and a package-level handle is how this file already joins them.
var batchQuorumAttestorForEvidence atomic.Pointer[execution.BatchQuorumAttestor]

// batchAttesterIdentity is who this validator claims to be when co-signing a peer's batch.
// Its EVM address must match its registry entry on the anchor, or its partial contributes no
// voting power and the aggregate is refused.
var batchAttesterIdentity atomic.Pointer[execution.BatchAttesterIdentity]

// batchPeriodBlocksFromEnv reads BATCH_PERIOD_BLOCKS.
//
// Every validator MUST agree on this value. It buckets BFT heights into periods, the period
// cutoff becomes the batch's accumulateBlockHeight, and that height is hashed into the
// bundleId. A node configured differently derives a different bundleId from identical
// membership, so it can neither propose a batch its peers will co-sign nor co-sign theirs.
//
// A value that is not a positive integer is refused: it used to become the default, so a node with a typo
// silently bucketed on a different period from its peers - the one disagreement this value must never have.
func batchPeriodBlocksFromEnv() (uint64, error) {
	return envvar.Uint64("BATCH_PERIOD_BLOCKS", execution.DefaultBatchPeriodBlocks, 1)
}

// resolveBatchAttesterIdentity determines the EVM address this validator attests as, and
// publishes it to the peer attestation handler.
//
// The address is derived from the CHAIN: read the anchor's validator registry and find the
// entry whose registered BLS public key equals this node's. That cannot be misconfigured, and
// it refuses to publish an identity when this node's key is not registered — precisely the
// case where it must not attest.
//
// The explicit VALIDATOR_EVM_ADDRESS remains as an override for bring-up. It is no longer the
// primary path because the live containers carry only VALIDATOR_ID: requiring it meant
// batchAttesterIdentity was never set, every peer answered 503, and no quorum could form.
//
// Runs in the background with retries because the first RPC call can lose a race with the
// node's own startup; a validator that cannot reach its anchor yet should keep trying rather
// than spend the process lifetime unable to attest.
func resolveBatchAttesterIdentity(resolver *execution.EVMChainResolverImpl, validatorID string) {
	publish := func(addr, how string) {
		// The sending key must be this identity, or the node sends and claims settlements as another
		// validator (RB3-F64). A configuration error that no retry fixes: the validator does not run.
		// Verified here, and only here, is this process allowed to send or claim settlements.
		if err := execution.VerifySendersAreIdentity(resolver, addr); err != nil {
			log.Fatalf("❌ [BATCH] %s: %v", validatorID, err)
		}
		batchAttesterIdentity.Store(&execution.BatchAttesterIdentity{
			ValidatorID: validatorID,
			EVMAddress:  addr,
		})
		log.Printf("🔏 [BATCH] Attesting as %s (%s, %s) on %s",
			validatorID, addr, how, execution.BatchAttestationEndpoint)
	}

	// VALIDATOR_EVM_ADDRESS is an assertion, never a substitute: the identity is always the registry
	// entry matching this node's BLS key, and a configured address that differs stops the validator. It
	// used to be published as-is, so an override equal to a shared key's address passed the sender check
	// without the registry ever being read (RB3-F64).
	override := strings.ToLower(strings.TrimSpace(os.Getenv("VALIDATOR_EVM_ADDRESS")))
	publishResolved := func(addr, how string) {
		if override != "" && !strings.EqualFold(override, addr) {
			log.Fatalf("❌ [BATCH] %s: VALIDATOR_EVM_ADDRESS %s is not this validator's registered identity %s",
				validatorID, override, addr)
		}
		publish(addr, how)
	}

	chains := resolver.Chains()
	if len(chains) == 0 {
		log.Printf("⚠️ [BATCH] No chains configured — cannot resolve this validator's registry identity")
		return
	}

	// Any configured chain's anchor carries the same registry; the first is enough.
	//
	// KEEP TRYING. This used to stop after `attempts` and never look again, so a transient RPC
	// failure during startup permanently demoted the node: it refuses every peer attestation for
	// the rest of its life while still reporting healthy, and quorum silently runs a signer short.
	// Seen live on 2026-08-04 — validator-3 lost DNS for ~75s at boot, exhausted its six tries,
	// and stayed non-attesting until it was restarted by hand.
	//
	// There is no state in which giving up is right: a validator that cannot name itself cannot
	// do its job, and the condition is almost always transient. The first `attempts` stay fast so
	// a healthy boot publishes within seconds; after that it retries indefinitely at a slower
	// cadence, which costs one call a minute and removes the failure mode entirely.
	const attempts = 6
	for i := 1; ; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		ecm, anchorAddr, err := resolver.ManagerForChain(chains[0])
		if err == nil {
			var registry map[string]consensus.ValidatorRegistryEntry
			registry, err = execution.ReadValidatorRegistry(ctx, ecm, anchorAddr)
			if err == nil {
				var addr string
				addr, err = execution.ResolveOwnEVMAddress(registry)
				if err == nil {
					cancel()
					publishResolved(addr, "matched on-chain BLS registry")
					return
				}
			}
		}
		cancel()

		switch {
		case i < attempts:
			log.Printf("⚠️ [BATCH] Attester identity attempt %d/%d failed: %v", i, attempts, err)
			time.Sleep(time.Duration(i) * 5 * time.Second)
		case i == attempts:
			// Say plainly what is wrong NOW, once, rather than burying it in a repeating line.
			log.Printf("❌ [BATCH] Could not resolve this validator's registry identity after %d "+
				"attempts (%v). Until it resolves this node REFUSES every peer attestation request, "+
				"so quorum runs a signer short. Retrying every %s — check that this node's BLS key "+
				"is registered on the anchor.", attempts, err, identityRetryInterval)
			time.Sleep(identityRetryInterval)
		default:
			// Throttled so a long outage does not flood the log, but never silent: an operator
			// grepping for this must be able to see it is still trying.
			if i%identityRetryLogEvery == 0 {
				log.Printf("⚠️ [BATCH] Still cannot resolve attester identity (attempt %d): %v — "+
					"this node is not attesting", i, err)
			}
			time.Sleep(identityRetryInterval)
		}
	}
}

// identityRetryInterval is the steady-state cadence for attester-identity resolution once the
// fast startup attempts are exhausted. One call a minute is negligible next to a node sitting
// non-attesting indefinitely.
// incarnationVerifyTimeout bounds how long startup keeps retrying the derivation of the Accumulate incarnation when
// the network cannot be read; a derived value that differs from the configured one fails at once.
const incarnationVerifyTimeout = 5 * time.Minute

const identityRetryInterval = time.Minute

// identityRetryLogEvery throttles the persistent-failure log to roughly every 10 minutes.
const identityRetryLogEvery = 10

// discoveryStallThreshold is how long the watermark may sit still before the node is declared
// stalled.
//
// Sized against the mechanism, not guessed: the poll runs every 5s and a healthy node advances
// the watermark on essentially every tick. Two minutes is ~24 missed ticks — far beyond any
// transient RPC hiccup, and far short of the hours the 2026-08-05 outage went unnoticed.
//
// It must also tolerate a genuinely idle chain. Accumulate produces blocks continuously and
// independently of Certen traffic, so the watermark advances even when no intent exists; an
// idle network is therefore NOT a stall. If that ever stops being true, this becomes noisy and
// should key on poll failure alone.
const discoveryStallThreshold = 2 * time.Minute

// watchDiscoveryLiveness publishes discovery health to Prometheus and to /health.
//
// Runs for the life of the process. Both destinations matter: the metric is for a scraper that
// may not be configured yet, while the health field takes effect immediately because the
// container healthcheck already consults /health.
func watchDiscoveryLiveness(d *intent.IntentDiscovery) {
	if d == nil {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	wasStalled := false
	for range ticker.C {
		st := d.Status()
		stalled := st.Stalled(discoveryStallThreshold)

		metrics.SetDiscoveryStatus(
			st.Watermark, st.ChainHead, st.LagBlocks,
			st.SecondsSinceAdvance, stalled, st.LastPollError != "",
		)

		state := "advancing"
		switch {
		case st.IntakePaused:
			state = "paused"
		case !st.Started:
			state = "starting"
		case stalled:
			state = "stalled"
		}
		healthStatus.SetDiscovery(state, st.LagBlocks, int64(st.SecondsSinceAdvance))
		healthStatus.SetDiscoveryUnsearched(st.Unsearched, int64(st.OldestUnsearchedSeconds))
		healthStatus.SetDiscoveryInProgress(st.InProgress)
		if st.UnsearchedError != "" {
			log.Printf("🚨 [DISCOVERY] the unsearched-block store cannot be read: %s", st.UnsearchedError)
		} else if st.Unsearched > 0 && st.OldestUnsearchedSeconds > 600 {
			log.Printf("🚨 [DISCOVERY] %d block(s) not yet searched; the oldest, %d, has waited %.0fs. Intents "+
				"anchored in them are not discovered until they are.", st.Unsearched, st.OldestUnsearched, st.OldestUnsearchedSeconds)
		}

		// Log the EDGES only. A per-tick line would be noise nobody reads, which is the
		// failure mode that let the original outage hide in plain sight.
		if stalled && !wasStalled {
			log.Printf("🚨 [DISCOVERY] STALLED: watermark %d has not advanced for %.0fs "+
				"(head %d, lag %d blocks). No intent can be discovered while this persists.%s",
				st.Watermark, st.SecondsSinceAdvance, st.ChainHead, st.LagBlocks,
				pollErrSuffix(st.LastPollError))
		} else if !stalled && wasStalled {
			log.Printf("✅ [DISCOVERY] recovered: watermark advancing again at %d (lag %d blocks)",
				st.Watermark, st.LagBlocks)
		}
		wasStalled = stalled
	}
}

func pollErrSuffix(err string) string {
	if err == "" {
		// No poll error means we CAN reach Accumulate but are not progressing — a different
		// fault from the endpoint being unreachable, and worth distinguishing in the log.
		return " The head poll is succeeding, so this is not an endpoint outage."
	}
	return " Last poll error: " + err
}

// batchConsensusHeightFn returns the height source for batch period cutoffs.
//
// Prefers the ABCI app's committed height — that is the chain's height, and a period is only
// closed once the chain has passed its upper bound. Falls back to the highest height this
// validator has seen a round commit at, which is never ahead of the chain and so can only be
// conservative.
func batchConsensusHeightFn(
	accClient accumulate.Client,
	validator *consensus.BFTValidator,
) func() uint64 {
	var (
		mu     sync.Mutex
		cached uint64
		at     time.Time
	)
	return func() uint64 {
		mu.Lock()
		defer mu.Unlock()
		// One query per flush tick at most; the flush loop sub-ticks far faster than
		// Accumulate produces blocks.
		if time.Since(at) < 20*time.Second && cached > 0 {
			return cached
		}
		if accClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			blk, err := accClient.GetLatestBlock(ctx)
			cancel()
			if err == nil && blk != nil && blk.Height > cached {
				cached = blk.Height
				at = time.Now()
				return cached
			}
		}
		// Fallback: the highest Accumulate height this node has actually seen an intent at.
		// Never ahead of the chain, so it can only be conservative.
		if validator != nil {
			if h := validator.ObservedConsensusHeight(); h > cached {
				cached = h
			}
		}
		at = time.Now()
		return cached
	}
}

func main() {
	// Configure logging
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("🚀 Starting Certen Validator Service with REAL CometBFT Consensus - NO SIMULATION")
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrationCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "repair" {
		os.Exit(runRepairCommand(os.Args[2:]))
	}

	// Parse CLI flags
	var (
		validatorID = flag.String("validator-id", "", "Validator ID (overrides VALIDATOR_ID env var)")
		showHelp    = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	log.Printf("🔄 Parsed command-line flags: validatorID=%s", *validatorID)

	if *showHelp {
		printHelp()
		return
	}

	log.Printf("🚀 Starting Certen BFT Validator with full consensus capabilities...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	// LedgerStore is now created and managed within the ABCI application
	// No need for separate initialization here

	// Override config from CLI (only if explicitly set)
	if *validatorID != "" {
		log.Printf("📋 CLI flag override: using validator ID from command line: %s", *validatorID)
		cfg.ValidatorID = *validatorID
	}
	requireValidatorID(cfg)
	if err := checkEnvironment(); err != nil {
		log.Fatalf("❌ environment values that cannot be used:\n%v", err)
	}
	log.Printf("📋 Validator ID: %s (from %s)", cfg.ValidatorID, func() string {
		if *validatorID != "" {
			return "CLI flag"
		}
		return "VALIDATOR_ID env var"
	}())

	// ==========================================================================
	// PHASE 5: PostgreSQL Database Connection
	//
	// Required. A validator without its database used to start "in DEGRADED mode" unless
	// DATABASE_REQUIRED=true, with the batch system, proof storage, lifecycle tracking and the evidence
	// writers switched off - taking part in consensus and executing intents it could record nothing about.
	// It does not start; the deployment waits for its database (compose: postgres healthy, schema-migrate
	// completed) and restarts it.
	// ==========================================================================
	if v := os.Getenv("REQUIRE_BFT_COMMIT"); v != "" && v != "true" {
		log.Fatalf("❌ REQUIRE_BFT_COMMIT=%s is not supported: nothing acts on a ValidatorBlock consensus has not committed (RB3-F98)", v)
	}
	if v := os.Getenv("DATABASE_REQUIRED"); v != "" && v != "true" {
		log.Fatalf("❌ [Phase 5] DATABASE_REQUIRED=%s is not supported: a validator cannot start without its database", v)
	}
	log.Println("🗄️ [Phase 5] Connecting to PostgreSQL database...")
	dbClient, err := database.NewClient(cfg, database.WithLogger(
		log.New(log.Writer(), "[Database] ", log.LstdFlags),
	))
	if err != nil {
		log.Fatalf("❌ [Phase 5] The validator cannot start without its database: %v", err)
	}
	log.Println("✅ [Phase 5] Connected to PostgreSQL database")
	healthStatus.SetDatabase("connected")

	runner := schema.Runner{DB: dbClient.DB()}
	migrateOnStart, err := envvar.Bool("MIGRATE_ON_START", false)
	if err != nil {
		log.Fatalf("❌ [Phase 5] %v", err)
	}
	if migrateOnStart {
		if err := runner.Up(context.Background(), cfg.ValidatorID); err != nil {
			log.Fatalf("❌ [Phase 5] Database migration failed: %v", err)
		}
	} else {
		required, err := schema.LatestVersion()
		if err != nil {
			log.Fatalf("❌ [Phase 5] Cannot load schema catalog: %v", err)
		}
		if err := runner.Verify(context.Background(), required); err != nil {
			log.Fatalf("❌ [Phase 5] Database schema verification failed: %v", err)
		}
		log.Printf("✅ [Phase 5] Database schema verified through migration %s", required)
	}

	// ==========================================================================
	// HIGH-002: Initialize Persistent Replay Protection Store
	// Uses bbolt (pure Go) for durable nonce tracking that survives restarts.
	// ==========================================================================
	log.Println("🔒 [Phase 5b] Initializing persistent replay store...")
	replayStorePath := filepath.Join("data", "replay_nonces.db")
	replayStore, replayErr := consensus.NewBboltReplayStore(replayStorePath)
	if replayErr != nil {
		log.Printf("⚠️ [Phase 5b] Failed to open replay store: %v", replayErr)
		log.Printf("⚠️ WARNING: Falling back to in-memory nonce tracking (lost on restart)")
	} else {
		consensus.SetReplayStore(replayStore)
		defer replayStore.Close()
		log.Printf("✅ [Phase 5b] Persistent replay store ready at %s", replayStorePath)

		// Periodic cleanup of expired nonces (every hour)
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := replayStore.CleanExpired(ctx, time.Now().Unix()); err != nil {
					log.Printf("⚠️ [REPLAY-STORE] Cleanup error: %v", err)
				}
				cancel()
			}
		}()
	}

	// ==========================================================================
	// Initialize Firestore for Real-Time UI Sync
	// Per Data Collection & Management Plan: Sync proof cycle progress to Firestore
	// ==========================================================================
	var firestoreClient *firestore.Client
	var firestoreSyncService *firestore.SyncService

	if cfg.FirestoreEnabled {
		log.Println("🔥 [Firestore] Initializing Firestore client for real-time UI sync...")
		firestoreCfg := &firestore.ClientConfig{
			ProjectID:       cfg.FirebaseProjectID,
			CredentialsFile: cfg.FirebaseCredentialsFile,
			Enabled:         true,
			Logger:          log.New(log.Writer(), "[Firestore] ", log.LstdFlags),
		}

		var firestoreErr error
		firestoreClient, firestoreErr = firestore.NewClient(context.Background(), firestoreCfg)
		if firestoreErr != nil {
			// Enabled means working or not starting; it used to switch itself off with a warning.
			log.Fatalf("❌ [Firestore] FIRESTORE_ENABLED is set but the client could not be created: %v", firestoreErr)
		} else {
			log.Println("✅ [Firestore] Connected to Firestore")

			// Create sync service
			syncCfg := &firestore.SyncServiceConfig{
				Client:         firestoreClient,
				ValidatorID:    cfg.ValidatorID,
				Logger:         log.New(log.Writer(), "[FirestoreSync] ", log.LstdFlags),
				IntentCacheTTL: 5 * time.Minute,
			}
			firestoreSyncService, firestoreErr = firestore.NewSyncService(syncCfg)
			if firestoreErr != nil {
				log.Printf("⚠️ [Firestore] Failed to create sync service: %v", firestoreErr)
			} else {
				log.Println("✅ [Firestore] Sync service initialized - will sync proof cycle events")
			}
		}
	} else {
		log.Println("⚠️ [Firestore] Firestore sync DISABLED (set FIRESTORE_ENABLED=true to enable)")
	}

	// Initialize Accumulate client using canonical interface
	log.Println("📡 Connecting to Accumulate network...")
	liteClientConfig := &accumulate.LiteClientConfig{
		NetworkURL:     cfg.AccumulateURL,
		EnableCaching:  true,
		RequestTimeout: 30 * time.Second,
	}
	accClient, err := accumulate.NewLiteClientAdapter(liteClientConfig)
	if err != nil {
		healthStatus.SetAccumulate("disconnected")
		log.Fatal("Failed to create Accumulate client:", err)
	}
	healthStatus.SetAccumulate("connected")
	log.Println("✅ Connected to Accumulate network")

	// Initialize Ethereum client
	log.Println("🔗 Connecting to Ethereum network...")
	ethClient, err := ethereum.NewClient(cfg.EthereumURL, cfg.EthChainID)
	if err != nil {
		healthStatus.SetEthereum("disconnected")
		log.Fatal("Failed to connect to Ethereum:", err)
	}
	healthStatus.SetEthereum("connected")
	log.Println("✅ Connected to Ethereum network")

	// Initialize BFT validator node and consensus
	log.Printf("🔐 Initializing BFT Validator Node (%s) with full consensus capabilities...", cfg.ValidatorID)
	validatorNode, batchComponents, err := startValidator(cfg, accClient, ethClient, dbClient, firestoreSyncService)
	if err != nil {
		log.Fatal("Failed to initialize BFT validator node:", err)
	}

	// HTTP server with ledger query endpoints
	mux := http.NewServeMux()

	// Phase 8 unified-orchestrator peer attestation endpoint (registered unconditionally
	// so the multi-validator quorum works regardless of legacy-attestation config). The
	// orchestrator is created later in startValidator and published via the atomic pointer;
	// this closure reads it at request time. Without this route, peers' POSTs to
	// /api/unified/attestation/request 404'd and the cycle fell back to one self-attestation.
	mux.HandleFunc("/api/unified/attestation/request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		uo := unifiedOrchestratorForAttestation.Load()
		if uo == nil {
			http.Error(w, "unified orchestrator not ready", http.StatusServiceUnavailable)
			return
		}
		var par execution.PeerAttestationRequest
		if decErr := json.NewDecoder(r.Body).Decode(&par); decErr != nil {
			http.Error(w, "bad request: "+decErr.Error(), http.StatusBadRequest)
			return
		}
		resp, hErr := uo.HandlePeerAttestationRequest(r.Context(), &par)
		if hErr != nil {
			http.Error(w, "attestation failed: "+hErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Peer batch attestation. A proposer asks this validator to co-sign a batch; the handler
	// rebuilds that batch from THIS validator's own mempool and signs only on an exact
	// bundleId match. The request deliberately carries no member data — see
	// pkg/execution/batch_attestation.go.
	mux.HandleFunc(execution.BatchAttestationEndpoint, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stack := batchStackForAttestation.Load()
		if stack == nil {
			http.Error(w, "batch stack not ready", http.StatusServiceUnavailable)
			return
		}
		me := batchAttesterIdentity.Load()
		if me == nil {
			http.Error(w, "attester identity not configured", http.StatusServiceUnavailable)
			return
		}
		var req execution.BatchAttestationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// A refusal is a normal, expected outcome (the peer simply has a different view), so
		// it returns 200 with Error set rather than an HTTP error status.
		resp := stack.HandleBatchAttestationRequest(&req, *me)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Peer ON-DEMAND attestation. Same security boundary as the period endpoint above — the
	// handler rebuilds the one-member batch from THIS validator's own copy of the member and
	// signs only on an exact bundleId match — but keyed on (chain, operationID) rather than a
	// height window. A SEPARATE route on purpose: a validator that has not been upgraded
	// answers 404 here rather than misreading an on-demand request as a period one.
	mux.HandleFunc(execution.OnDemandAttestationEndpoint, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stack := batchStackForAttestation.Load()
		if stack == nil {
			http.Error(w, "batch stack not ready", http.StatusServiceUnavailable)
			return
		}
		me := batchAttesterIdentity.Load()
		if me == nil {
			http.Error(w, "attester identity not configured", http.StatusServiceUnavailable)
			return
		}
		var req execution.OnDemandAttestationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		// A refusal is a normal, expected outcome — CodeMemberNotHeld especially, for the few
		// seconds before a peer finishes processing the round — so it returns 200 with Error
		// and Code set rather than an HTTP error status.
		resp := stack.HandleOnDemandAttestationRequest(&req, *me)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	// Prometheus metrics.
	//
	// pkg/metrics has existed with ~20 instruments since the BFT resiliency work, but neither
	// RegisterMetrics nor MetricsHandler was ever called, so nothing was exported and the
	// README's "Prometheus Metrics" claim was untrue. Serving it here is what makes the
	// discovery liveness gauges (and everything else already defined) reachable by a scraper.
	metrics.RegisterMetrics()
	mux.Handle("/metrics", metrics.MetricsHandler())

	// Health endpoint - Per E.2 remediation: Shows degraded status if database disconnected
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return appropriate status code based on health
		if healthStatus.Status == "ok" {
			w.WriteHeader(http.StatusOK)
		} else if healthStatus.Status == "degraded" {
			w.WriteHeader(http.StatusOK) // 200 but content indicates degradation
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.Write(healthStatus.ToJSON())
	})

	// Detailed health endpoint - Per Implementation Plan: Batch-aware health status
	// This endpoint provides comprehensive health information including batch system state
	mux.HandleFunc("/health/detailed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Build detailed health response
		detailed := struct {
			Status            string                 `json:"status"`
			Phase             string                 `json:"phase"`
			Consensus         string                 `json:"consensus"`
			Database          string                 `json:"database"`
			Ethereum          string                 `json:"ethereum"`
			Accumulate        string                 `json:"accumulate"`
			BatchSystem       string                 `json:"batch_system"`
			ProofCycle        string                 `json:"proof_cycle"`
			UptimeSeconds     int64                  `json:"uptime_seconds"`
			BatchDetails      map[string]interface{} `json:"batch_details"`
			StatusExplanation string                 `json:"status_explanation"`
		}{
			Status:        healthStatus.Status,
			Phase:         healthStatus.Phase,
			Consensus:     healthStatus.Consensus,
			Database:      healthStatus.Database,
			Ethereum:      healthStatus.Ethereum,
			Accumulate:    healthStatus.Accumulate,
			BatchSystem:   healthStatus.BatchSystem,
			ProofCycle:    healthStatus.ProofCycle,
			UptimeSeconds: int64(time.Since(healthStatus.startTime).Seconds()),
			BatchDetails:  make(map[string]interface{}),
		}

		// Build status explanation
		switch healthStatus.Status {
		case "ok":
			detailed.StatusExplanation = "All systems operational. Batch system is functioning normally."
		case "degraded":
			detailed.StatusExplanation = "System is operational but some components are degraded. " +
				"On-cadence batch delays up to 15 minutes are expected and do not indicate a problem."
		case "error":
			detailed.StatusExplanation = "One or more critical components have failed. Investigation required."
		default:
			detailed.StatusExplanation = "System status is being determined."
		}

		// Return appropriate status code
		if healthStatus.Status == "ok" || healthStatus.Status == "degraded" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(detailed)
	})

	// Ledger query endpoints
	// Use GetLedgerStoreProvider() which works for both CertenApplication and ValidatorApp
	consensusEngine := validatorNode.GetConsensusEngine()
	if consensusEngine == nil {
		log.Printf("⚠️ Ledger endpoints not available - ConsensusEngine is nil")
	} else {
		ledgerProvider := consensusEngine.GetLedgerStoreProvider()
		if ledgerProvider == nil {
			log.Printf("⚠️ Ledger endpoints not available - LedgerStoreProvider is nil")
		} else if ledgerProvider.GetLedgerStore() == nil {
			log.Printf("⚠️ Ledger endpoints not available - LedgerStore is nil (provider exists)")
		} else {
			ledgerHandlers := server.NewLedgerHandlers(ledgerProvider.GetLedgerStore(), ledgerProvider.GetChainID())
			mux.HandleFunc("/api/system-ledger", ledgerHandlers.HandleSystemLedger)
			mux.HandleFunc("/api/anchor-ledger", ledgerHandlers.HandleAnchorLedger)
			mux.HandleFunc("/api/ledger/status", ledgerHandlers.HandleLedgerStatus)
			log.Printf("✅ Ledger query endpoints configured at /api/*")
		}
	}

	// ==========================================================================
	// PHASE 5: Batch and Proof API Endpoints
	// ==========================================================================
	{
		batchHandlers := server.NewBatchHandlers(
			batchComponents.Repos,
			cfg.ValidatorID,
			log.New(log.Writer(), "[BatchAPI] ", log.LstdFlags),
		)

		// Batch status endpoint
		mux.HandleFunc("/api/batches/", batchHandlers.HandleBatchStatus)

		// Proof retrieval endpoints (Priority 3.1)
		mux.HandleFunc("/api/proofs/by-tx/", batchHandlers.HandleGetProofByTxHash)
		mux.HandleFunc("/api/proofs/by-account/", batchHandlers.HandleGetProofsByAccount)
		mux.HandleFunc("/api/proofs/", batchHandlers.HandleGetProof)

		// Four-component Certen anchor proofs (certen_anchor_proofs)
		mux.HandleFunc("/api/certen-proofs/by-artifact/", batchHandlers.HandleGetCertenProofByArtifact)
		mux.HandleFunc("/api/certen-proofs/by-tx/", batchHandlers.HandleGetCertenProofByTxHash)
		mux.HandleFunc("/api/certen-proofs/by-account/", batchHandlers.HandleGetCertenProofsByAccount)
		mux.HandleFunc("/api/certen-proofs/", batchHandlers.HandleGetCertenProof)

		// Anchor retrieval endpoints
		mux.HandleFunc("/api/anchors/by-batch/", batchHandlers.HandleGetAnchorByBatch)
		mux.HandleFunc("/api/anchors/", batchHandlers.HandleGetAnchor)

		// Cost tracking endpoints (Priority 3.2)
		mux.HandleFunc("/api/costs", batchHandlers.HandleGetCostStatistics)
		mux.HandleFunc("/api/costs/estimate", batchHandlers.HandleEstimateCost)

		// NEW: Comprehensive Proof Artifact API (v1 endpoints)
		proofHandlers := server.NewProofHandlers(
			batchComponents.Repos,
			cfg.ValidatorID,
			log.New(log.Writer(), "[ProofAPI] ", log.LstdFlags),
		)

		// Proof discovery endpoints
		mux.HandleFunc("/api/v1/proofs/tx/", proofHandlers.HandleGetProofByTxHash)
		mux.HandleFunc("/api/v1/proofs/account/", proofHandlers.HandleGetProofsByAccount)
		mux.HandleFunc("/api/v1/proofs/batch/", proofHandlers.HandleGetProofsByBatch)
		mux.HandleFunc("/api/v1/proofs/anchor/", proofHandlers.HandleGetProofsByAnchor)
		mux.HandleFunc("/api/v1/proofs/query", proofHandlers.HandleQueryProofs)
		mux.HandleFunc("/api/v1/proofs/sync", proofHandlers.HandleSyncProofs)

		// Proof detail endpoints (must be registered last due to path matching)
		mux.HandleFunc("/api/v1/proofs/", proofHandlers.HandleGetProofByID)

		// Batch statistics endpoint
		mux.HandleFunc("/api/v1/batches/", proofHandlers.HandleGetBatchStats)

		// Intent Lifecycle endpoints
		lifecycleHandlers := server.NewIntentLifecycleHandlers(
			batchComponents.Repos,
			log.New(log.Writer(), "[LifecycleAPI] ", log.LstdFlags),
		)
		mux.HandleFunc("/api/v1/intent/recent", lifecycleHandlers.HandleListRecent)
		mux.HandleFunc("/api/v1/intent/status/", lifecycleHandlers.HandleListByStatus)
		mux.HandleFunc("/api/v1/intent/user/", lifecycleHandlers.HandleListByUser)
		mux.HandleFunc("/api/v1/intent/tx/", lifecycleHandlers.HandleGetByTxHash)
		mux.HandleFunc("/api/v1/intent/", lifecycleHandlers.HandleGetByIntentID)

		log.Printf("✅ Intent lifecycle API endpoints configured:")
		log.Printf("   - GET /api/v1/intent/recent             (recent intents)")
		log.Printf("   - GET /api/v1/intent/status/{status}    (intents by status)")
		log.Printf("   - GET /api/v1/intent/user/{user_id}     (intents by user)")
		log.Printf("   - GET /api/v1/intent/{id}/lifecycle     (lifecycle by intent ID)")
		log.Printf("   - GET /api/v1/intent/tx/{hash}/lifecycle (lifecycle by tx hash)")

		log.Printf("✅ [Phase 5] Comprehensive proof artifact API v1 endpoints configured:")
		log.Printf("   - GET  /api/v1/proofs/tx/:hash      (proof by tx hash)")
		log.Printf("   - GET  /api/v1/proofs/account/:url  (proofs by account)")
		log.Printf("   - GET  /api/v1/proofs/batch/:id     (proofs by batch)")
		log.Printf("   - GET  /api/v1/proofs/anchor/:hash  (proofs by anchor)")
		log.Printf("   - POST /api/v1/proofs/query         (filtered query)")
		log.Printf("   - GET  /api/v1/proofs/sync          (sync for auditing)")
		log.Printf("   - GET  /api/v1/proofs/:id           (full proof details)")
		log.Printf("   - GET  /api/v1/batches/:id/stats    (batch statistics)")

		log.Printf("✅ [Phase 5] Batch and proof API endpoints configured:")
		log.Printf("   - GET  /api/proofs/by-tx/:hash (proof by transaction)")
		log.Printf("   - GET  /api/proofs/by-account/:url (proofs by account)")
		log.Printf("   - GET  /api/costs              (cost structure)")
		log.Printf("   - GET  /api/costs/estimate     (estimate anchoring cost)")
	}

	httpServer := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	// Start CometBFT consensus engine for this validator
	go validatorNode.StartConsensus()

	log.Printf("✅ BFT Validator ready - participating in decentralized consensus network!")

	// Start HTTP API
	go func() {
		log.Printf("🌐 BFT Validator API listening on %s", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start HTTP server:", err)
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Printf("🛑 Shutting down BFT Validator...")

	// Graceful HTTP shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Close Firestore client
	if firestoreClient != nil {
		if err := firestoreClient.Close(); err != nil {
			log.Printf("Firestore client close error: %v", err)
		}
	}

	log.Printf("✅ BFT Validator stopped")
}

// requireValidatorID refuses to run as nobody in particular. An unset VALIDATOR_ID used to become
// "validator-default" - the name signed into blocks, attestations and certen_schema_history, which
// production's history carries once (RB3-F89).
func requireValidatorID(cfg *config.Config) {
	if err := cfg.RequireValidatorID(); err != nil {
		log.Fatal(err)
	}
}

func runMigrationCommand(args []string) {
	if !validMigrationCommand(args) {
		log.Fatal("usage: certen-validator migrate <up|verify [--require VERSION]|fingerprint|catalog|adopt [--dry-run]|data NAME>")
	}
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	requireValidatorID(cfg)
	client, err := database.NewClient(cfg)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer client.Close()
	runner := schema.Runner{DB: client.DB()}
	switch args[0] {
	case "up":
		err = runner.Up(context.Background(), cfg.ValidatorID)
	case "verify":
		var required string
		if len(args) == 3 {
			required = args[2]
		} else {
			required, err = schema.LatestVersion()
		}
		if err == nil {
			err = runner.Verify(context.Background(), required)
		}
	case "fingerprint":
		var fingerprint string
		fingerprint, err = runner.Fingerprint(context.Background())
		if err == nil {
			fmt.Println(fingerprint)
		}
	case "catalog":
		var catalog []string
		catalog, err = runner.Catalog(context.Background())
		if err == nil {
			for _, entry := range catalog {
				fmt.Println(entry)
			}
		}
	case "adopt":
		var fingerprint string
		fingerprint, err = runner.Fingerprint(context.Background())
		if err == nil {
			var approved string
			approved, err = schema.BaselineFingerprint()
			if configured := os.Getenv("SCHEMA_FINGERPRINT"); err == nil && configured != "" && configured != approved {
				err = fmt.Errorf("SCHEMA_FINGERPRINT does not match the reviewed catalog fingerprint")
			}
			if err != nil {
				break
			}
			if len(args) == 2 {
				err = runner.AdoptionPreflight(context.Background(), fingerprint, approved)
			} else {
				err = runner.Adopt(context.Background(), fingerprint, approved, cfg.ValidatorID)
			}
		}
	case "data":
		err = runner.Data(context.Background(), args[1], cfg.ValidatorID)
	}
	if err != nil {
		log.Fatalf("migrate %s: %v", args[0], err)
	}
	log.Printf("schema migration command %q completed", args[0])
}

func validMigrationCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "up", "fingerprint", "catalog":
		return len(args) == 1
	case "verify":
		return len(args) == 1 || len(args) == 3 && args[1] == "--require" && args[2] != ""
	case "adopt":
		return len(args) == 1 || len(args) == 2 && args[1] == "--dry-run"
	case "data":
		return len(args) == 2 && args[1] != ""
	default:
		return false
	}
}

// BatchComponents holds all batch system components for API handlers
type BatchComponents struct {
	Repos                *database.Repositories
	FirestoreSyncService *firestore.SyncService // Real-time UI sync
}

// ed25519KeyPath is where the validator's Ed25519 key lives: ED25519_KEY_PATH, or ed25519_key.hex in the
// data directory.
func ed25519KeyPath(cfg *config.Config) string {
	if cfg.Ed25519KeyPath != "" {
		return cfg.Ed25519KeyPath
	}
	dataDir := cfg.DataDir
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "ed25519_key.hex")
}

// blsKeyPath is where the validator's BLS key lives: BLS_KEY_PATH, or data/bls_key_<id>.hex.
// blsKeySecret is the secret a validator's BLS key is derived from when it has no key file: BLS_KEY_SEED
// (hex) when set, otherwise the validator's ETH_PRIVATE_KEY. Both live in the validator's environment,
// not its data volume, so wiping the volume does not lose them.
func blsKeySecret(cfg *config.Config) ([]byte, error) {
	raw, name := os.Getenv("BLS_KEY_SEED"), "BLS_KEY_SEED"
	if strings.TrimSpace(raw) == "" {
		raw, name = cfg.EthPrivateKey, "ETH_PRIVATE_KEY"
	}
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if raw == "" {
		return nil, fmt.Errorf("no BLS key secret: set BLS_KEY_SEED or ETH_PRIVATE_KEY")
	}
	secret, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not hex: %w", name, err)
	}
	return secret, nil
}

func blsKeyPath(cfg *config.Config) string {
	if path := os.Getenv("BLS_KEY_PATH"); path != "" {
		return path
	}
	return filepath.Join("data", fmt.Sprintf("bls_key_%s.hex", cfg.ValidatorID))
}

// loadOrGenerateEd25519Key securely loads or generates an Ed25519 private key
// E.5 remediation: Never derive keys from validator ID - use proper key management
func loadOrGenerateEd25519Key(cfg *config.Config) (ed25519.PrivateKey, error) {
	keyPath := ed25519KeyPath(cfg)

	// Ensure directory exists
	keyDir := filepath.Dir(keyPath)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("create key directory %s: %w", keyDir, err)
	}

	var privateKey ed25519.PrivateKey

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		// Generate new secure random key
		log.Printf("🔑 Generating new Ed25519 key...")
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}

		// Save to file with restrictive permissions (owner read/write only)
		keyHex := hex.EncodeToString(privateKey)
		if err := os.WriteFile(keyPath, []byte(keyHex), 0600); err != nil {
			return nil, fmt.Errorf("save ed25519 key to %s: %w", keyPath, err)
		}
		log.Printf("✅ Generated and saved new Ed25519 key: %s", keyPath)
	} else {
		// Load existing key
		log.Printf("🔑 Loading existing Ed25519 key from %s...", keyPath)
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read ed25519 key from %s: %w", keyPath, err)
		}

		keyBytes, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("decode ed25519 key from %s: %w", keyPath, err)
		}

		if len(keyBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ed25519 key size: expected %d, got %d", ed25519.PrivateKeySize, len(keyBytes))
		}

		privateKey = ed25519.PrivateKey(keyBytes)
		log.Printf("✅ Loaded existing Ed25519 key from %s", keyPath)
	}

	return privateKey, nil
}

// startValidator wires all components and returns a fully configured BFT validator
// Returns the validator, batch components (if enabled), and any error
func startValidator(
	cfg *config.Config,
	accClient accumulate.Client,
	ethClient *ethereum.Client,
	dbClient *database.Client,
	firestoreSyncService *firestore.SyncService,
) (*consensus.BFTValidator, *BatchComponents, error) {
	// Base validator info used for BFT validator set
	validatorInfo := consensus.BFTValidatorInfo{
		ValidatorID: cfg.ValidatorID,
		PublicKey:   []byte{}, // set below after key generation
		VotingPower: 1,
		IsActive:    true,
		Address:     cfg.ListenAddr,
	}

	// Consensus parameters (used for per-round logic, not raw CometBFT)
	consensusParams := &consensus.ConsensusParams{
		ByzantineFaultTolerance: 0.33,
		ConsensusTimeout:        10 * time.Second,
		MinVotingPower:          1,
		ExecutorSelectionSeed:   []byte(cfg.ValidatorID),
	}

	// E.5 remediation: Secure Ed25519 key loading from file or generation
	// NEVER derive keys from validator ID - that's cryptographically weak
	privateKey, err := loadOrGenerateEd25519Key(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load/generate Ed25519 key: %w", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	validatorInfo.PublicKey = publicKey
	log.Printf("✅ Ed25519 key loaded: public key = %s...", hex.EncodeToString(publicKey)[:16])

	// --- Proof generator wiring (REAL lite client) ---
	// Note: Some legacy components still require the concrete type
	// TODO: Refactor these to use the interface when the API stabilizes
	liteClientAdapter, ok := accClient.(*accumulate.LiteClientAdapter)
	if !ok {
		return nil, nil, fmt.Errorf("accumulate client must be LiteClientAdapter for current proof generator compatibility")
	}

	proofConfig := &proof.ProofConfig{
		EnableRealProofs:  true,
		BatchSize:         5,
		ProcessingTimeout: 30 * time.Second,
		CacheEnabled:      true,
		Environment:       "testnet",
		ValidatorID:       cfg.ValidatorID,
	}

	// Create lite client proof generator with CometBFT endpoints for REAL L1-L3 proofs
	// CometBFT endpoints are required for consensus binding (app_hash validation)
	// Multi-BVN support for Kermit and other networks with multiple BVN partitions
	v3Endpoint := strings.TrimSuffix(cfg.AccumulateURL, "/") + "/v3"
	log.Printf("[PROOF] Creating LiteClientProofGenerator with:")
	log.Printf("   V3 API: %s", v3Endpoint)
	log.Printf("   DN CometBFT: %s", cfg.AccumulateCometDN)
	log.Printf("   BVN0 CometBFT: %s", cfg.AccumulateCometBVN0)
	log.Printf("   BVN1 CometBFT: %s", cfg.AccumulateCometBVN1)
	log.Printf("   BVN2 CometBFT: %s", cfg.AccumulateCometBVN2)
	log.Printf("   BVN3 CometBFT: %s", cfg.AccumulateCometBVN3)

	// Use multi-BVN constructor if specific BVN endpoints are configured, otherwise fall back to legacy
	var liteClientProofGen *proof.LiteClientProofGenerator
	if cfg.AccumulateCometBVN0 != "" || cfg.AccumulateCometBVN1 != "" || cfg.AccumulateCometBVN2 != "" || cfg.AccumulateCometBVN3 != "" {
		// Multi-BVN mode (Kermit has BVN1/BVN2/BVN3, production networks)
		bvn0 := cfg.AccumulateCometBVN0
		if bvn0 == "" {
			bvn0 = cfg.AccumulateCometBVN // Fall back to legacy single BVN
		}
		bvn1 := cfg.AccumulateCometBVN1
		if bvn1 == "" {
			bvn1 = bvn0 // Fall back to BVN0 if not specified
		}
		bvn2 := cfg.AccumulateCometBVN2
		if bvn2 == "" {
			bvn2 = bvn0 // Fall back to BVN0 if not specified
		}
		bvn3 := cfg.AccumulateCometBVN3
		// BVN3 doesn't need fallback - it's optional (only used in Kermit/production)
		liteClientProofGen, err = proof.NewLiteClientProofGeneratorMultiBVN(
			v3Endpoint,
			cfg.AccumulateCometDN,
			bvn0,
			bvn1,
			bvn2,
			bvn3,
			30*time.Second,
		)
	} else {
		// Legacy single-BVN mode (DevNet, backward compatibility)
		liteClientProofGen, err = proof.NewLiteClientProofGeneratorWithComet(
			v3Endpoint,
			cfg.AccumulateCometDN,
			cfg.AccumulateCometBVN,
			30*time.Second,
		)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create lite client proof generator: %w", err)
	}

	// The real L1-L4 proof builder needs only the v3 client and is always constructed; there is no
	// "basic proof mode". Stated as a startup invariant so a regression cannot run a validator that
	// builds proofs without their chained layers.
	if !liteClientProofGen.HasRealProofBuilder() {
		return nil, nil, fmt.Errorf("the real L1-L4 proof builder is not available; a validator does not run without it")
	}
	log.Printf("✅ [PROOF] Real L1-L4 ProofBuilder initialized")

	proofGenerator, err := proof.NewProofGenerator(liteClientProofGen, proofConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof generator: %w", err)
	}

	log.Printf("✅ BFT execution components initialized (legacy IntentExecutor replaced)")

	// --- REAL CometBFT engine wiring (unified engine) ---
	log.Printf("🚀 Initializing unified BFT consensus with real CometBFT networking: %s", cfg.ValidatorID)
	cometEngine, err := consensus.NewUnifiedCometBFTEngine(cfg.ValidatorID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create unified CometBFT engine: %w", err)
	}

	// P3: optional async Accumulate block-checkpoint anchor. Gated OFF by default. A single
	// designated writer validator mirrors each committed block's roots to a Certen data account
	// (e.g. acc://certen-protocol.acme/block-history) for external tamper-evidence / audit.
	checkpointEnabled, err := envvar.Bool("CHECKPOINT_ANCHOR_ENABLED", false)
	if err != nil {
		return nil, nil, err
	}
	if checkpointEnabled {
		// Enabled means configured, whole, or the node does not start (RB3-F89). The writer used to
		// default to "validator-1", a missing account or signer and a missing ValidatorApp each turned
		// the anchor off with a log line, and an invalid or absent write-back key fell back to the
		// validator's own key - which is not on the checkpoint key page, so every write would fail.
		cp, err := checkpointSettingsFromEnv()
		if err != nil {
			return nil, nil, err
		}
		writer, cpAccount, cpSigner := cp.writer, cp.account, cp.signer
		if cfg.ValidatorID != writer {
			log.Printf("ℹ️ [CHECKPOINT] anchor enabled; this node (%s) is not the designated writer (%s)", cfg.ValidatorID, writer)
		} else if va := cometEngine.GetValidatorApp(); va == nil {
			return nil, nil, fmt.Errorf("CHECKPOINT_ANCHOR_ENABLED: this node is the writer but its engine has no ValidatorApp to hook")
		} else {
			// The checkpoint account lives under the same ADI as Phase-9 write-back
			// (acc://certen-protocol.acme), so it is signed with the write-back key authorized on that
			// key page: CHECKPOINT_WRITEBACK_PRIV_KEY when set, else ACCUMULATE_WRITEBACK_PRIV_KEY.
			cpKey := cp.key
			cpSub, cpErr := execution.NewAccumulateSubmitter(&execution.AccumulateSubmitterConfig{
				Client:              liteClientAdapter,
				PrivateKey:          cpKey,
				AccountURL:          cpAccount,
				SignerURL:           cpSigner,
				ConfirmationTimeout: 30 * time.Second,
				MaxRetries:          3,
				RetryDelay:          3 * time.Second,
				Logger:              log.New(log.Writer(), "[CheckpointSubmitter] ", log.LstdFlags),
			})
			if cpErr != nil {
				return nil, nil, fmt.Errorf("CHECKPOINT_ANCHOR_ENABLED: create the checkpoint submitter: %w", cpErr)
			} else {
				cpDataDir := cfg.DataDir
				if cpDataDir == "" {
					cpDataDir = "data"
				}
				cpStateFile := filepath.Join(cpDataDir, "checkpoint_chain_head")
				anchor := execution.NewCheckpointAnchor(cpSub, cfg.ValidatorID, cpStateFile, 256, log.New(log.Writer(), "[CHECKPOINT] ", log.LstdFlags))
				va.SetCheckpointHook(anchor.Enqueue)
				log.Printf("⚓ [CHECKPOINT] block-checkpoint anchor ENABLED: writer=%s account=%s", writer, cpAccount)
			}
		}
	}

	// The validator's BLS key: its key file, or - when there is none - derived from this validator's
	// secret, so a wiped data volume comes back with the same, still-registered key. See
	// bls.InitializeValidatorBLSKey and docs/runbooks/bls-key-rotation.md.
	blsSecret, err := blsKeySecret(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize BLS key: %w", err)
	}
	blsKeyManager, err := bls.InitializeValidatorBLSKey(cfg.ValidatorID, blsKeyPath(cfg), blsSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize BLS key: %w", err)
	}
	blsPubKeyHex := blsKeyManager.GetPublicKeyHex()
	log.Printf("✅ BLS key initialized: %s...%s (path: %s)",
		blsPubKeyHex[:16],
		blsPubKeyHex[len(blsPubKeyHex)-8:],
		blsKeyPath(cfg))
	// Log full BLS public key for contract registration
	log.Printf("📋 BLS PUBLIC KEY FOR CONTRACT REGISTRATION:")
	log.Printf("   0x%s", blsPubKeyHex)
	log.Printf("   (Use this value for VALIDATOR_BLS_PUBKEY when registering on CertenAnchorV3)")

	// Create ValidatorBlockBuilder with real BLS public key
	builderConfig := consensus.BuilderConfig{
		ValidatorID:           cfg.ValidatorID,
		BLSValidatorSetPubKey: blsKeyManager.GetPublicKeyHex(), // Real BLS12-381 public key
	}
	validatorBlockBuilder := consensus.NewValidatorBlockBuilder(builderConfig)

	// Create Governance Proof Generator (G0/G1/G2)
	// Per CERTEN spec v3-governance-kpsw-exec-4.0:
	// - G0/G1/G2 proofs are generated AFTER L1-L4 lite client proof completes
	// - Uses the same v3 endpoint as the lite client
	var governanceProofGen consensus.GovernanceProofGenerator
	// Both are REQUIRED (RB5-F28). Every intent is attested on G0-G2, and G2's payload check needs the txhash tool;
	// a validator without them could only refuse every intent, so it does not start.
	govProofPath := os.Getenv("GOV_PROOF_CLI_PATH")
	txhashPath := os.Getenv("TXHASH_CLI_PATH")
	if err := requireExecutable("GOV_PROOF_CLI_PATH", govProofPath); err != nil {
		return nil, nil, err
	}
	if err := requireExecutable("TXHASH_CLI_PATH", txhashPath); err != nil {
		return nil, nil, err
	}
	govWorkDir := os.Getenv("GOV_PROOF_WORK_DIR")
	if govWorkDir == "" {
		govWorkDir = filepath.Join("data", "gov_proofs")
	}
	cliGovProofGen, govErr := proof.NewCLIGovernanceProofGenerator(
		govProofPath,
		cfg.AccumulateURL,
		govWorkDir,
		// A full G0→G1→G2 chain (authority snapshot via anchored key-page receipts) takes ~55s;
		// 60s cut G2 off, leaving G0-only. Give each CLI level generous headroom.
		120*time.Second,
	)
	if govErr != nil {
		return nil, nil, fmt.Errorf("the governance proof generator cannot be initialized: %w", govErr)
	}
	cliGovProofGen.SetTxHashPath(txhashPath)
	governanceProofGen = cliGovProofGen
	log.Printf("✅ Governance proof generator: %s, G2 payload verifier %s", govProofPath, txhashPath)

	// --- Anchor manager, built from the engine's ledger store before the BFT validator that holds it
	// (RB3-F137: the validator was handed a typed-nil wrapper that was only assigned afterwards) ---
	var anchorWrapper *execution.AnchorManagerWrapper
	var anchorManager *anchor.AnchorManager
	if ledgerProvider := cometEngine.GetLedgerStoreProvider(); ledgerProvider != nil && ledgerProvider.GetLedgerStore() != nil {
		anchorLogger := log.New(log.Writer(), "[AnchorManager] ", log.LstdFlags)
		anchorManager, err = anchor.NewAnchorManager(liteClientAdapter, cfg, proofGenerator, ledgerProvider.GetLedgerStore(), anchorLogger)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create anchor manager: %w", err)
		}
		// Now create the wrapper with the real anchor manager
		anchorWrapper = execution.NewAnchorManagerWrapper(anchorManager)
		log.Printf("✅ AnchorManager created with LedgerStore integration")
	} else {
		return nil, nil, fmt.Errorf("ABCI application or ledger store not available for anchor manager")
	}

	// Create BFT validator with engine injection (NEW SIGNATURE)
	validator := consensus.NewBFTValidator(
		cometEngine, // NEW: injected engine
		[]consensus.BFTValidatorInfo{validatorInfo},
		consensusParams,
		cfg.ValidatorID,
		cfg.ChainID, // CometBFT chain ID from config
		privateKey,
		anchorWrapper,
		proofGenerator,
		governanceProofGen, // G0/G1/G2 governance proof generator (runs AFTER L1-L4)
		validatorBlockBuilder,
		log.New(log.Writer(), "[BFTValidator] ", log.LstdFlags),
	)

	log.Printf("✅ BFT validator created with pure CometBFT consensus architecture")

	// RB5 D3: intent certificates are built against the chain id and BLS registry the chain itself judges them by.
	validatorApp := cometEngine.GetValidatorApp()
	if validatorApp == nil {
		return nil, nil, fmt.Errorf("the CometBFT engine has no ValidatorApp, so intent certificates cannot be built against the chain's state")
	}
	validator.SetIntentCertificateSource(validatorApp)

	// The key page G1 is built against is the page that signed, read from the chain - never a
	// guess. Without a resolver every governance proof fails rather than naming a page.
	// Without it every G1 would fail rather than name a page, so a validator without it does not start (RB5-F28).
	kpResolver, kpErr := proof.NewChainKeyPageResolver(cfg.AccumulateURL, log.Printf)
	if kpErr != nil {
		return nil, nil, fmt.Errorf("the signing key page resolver cannot be initialized: %w", kpErr)
	}
	validator.SetKeyPageResolver(kpResolver)

	// LedgerStore is automatically configured within the ABCI application
	if ledgerProvider := cometEngine.GetLedgerStoreProvider(); ledgerProvider != nil {
		log.Printf("✅ LedgerStore configured in ABCI app for chain: %s", ledgerProvider.GetChainID())
	}

	log.Printf("✅ Unified BFT consensus with real CometBFT networking active for validator: %s", cfg.ValidatorID)

	// ==========================================================================
	// CROSS-ADI BATCH PATH (CertenAnchorV8)
	//
	// Many on_cadence intents share ONE anchor and ONE BLS verification. Measured on live
	// Sepolia, createAnchor + executeComprehensiveProof are 802,128 of the 987,644 gas an
	// intent costs (81.2%), so amortising them across a batch is where the saving is.
	//
	// This batches the ATTESTATION, never the authorization: each member keeps its own
	// operationID and its own executionCommitment as a distinct Merkle leaf, spendable only
	// by the account whose immutable adiURL is hashed into it.
	//
	// ORDER MATTERS. The flush loop is started BEFORE SetBatchEnqueuer, so the mempool can
	// never accept a member while nothing is draining it — a pool that fills and never
	// flushes would strand intents, and there is no other path to settle them.
	//
	// Required: the batch path is the only settlement path. Each piece it needs is a startup error when
	// missing - a validator that ran without it would accept intents it can never settle.
	// ==========================================================================
	anchorCfg, cfgErr := config.LoadAnchorConfigFromEnv()
	if cfgErr != nil {
		return nil, nil, fmt.Errorf("batch path: anchor config: %w", cfgErr)
	}
	// Every settlement carries a BLS ZK proof made with the deployed verifier's keys: a node without them
	// would pay for anchors whose verification can only revert (RB3-F36), so it does not start.
	if _, zkErr := execution.GetBLSZKProver(); zkErr != nil {
		return nil, nil, fmt.Errorf("batch path: %w", zkErr)
	}
	// The chains CERTEN settles on now, of those this build supports (sepolia, base-sepolia, arbitrum-sepolia):
	// named, never defaulted, and each one's anchor read back as a CertenAnchorV8_2 before anything starts (RB5-F33).
	batchChains, scErr := execution.SettlementChainsFromEnv(strategy.SupportedChainIDs)
	if scErr != nil {
		return nil, nil, fmt.Errorf("batch path: %w", scErr)
	}
	// The chain resolver is shared with Phase 8, which counts its post-execution quorum against the
	// same on-chain validator registry the batch quorum does.
	resolver, rErr := execution.NewEVMChainResolverFromEnv(anchorCfg, batchChains)
	if rErr != nil {
		return nil, nil, fmt.Errorf("batch path: chain resolver: %w", rErr)
	}
	anchorCtx, anchorCancel := context.WithTimeout(context.Background(), 60*time.Second)
	gErr := execution.VerifySettlementAnchors(anchorCtx, resolver, batchChains)
	anchorCancel()
	if gErr != nil {
		return nil, nil, fmt.Errorf("batch path: %w", gErr)
	}
	log.Printf("✅ [BATCH] settling on chains %v, each on a CertenAnchorV8_2", batchChains)
	submitter := execution.NewBatchProofSubmitter(resolver, log.Printf)
	peers := execution.BatchAttestationPeersFromEnv()
	if len(peers) == 0 {
		return nil, nil, fmt.Errorf("batch path: ATTESTATION_PEERS unset - no quorum can form without peers")
	}
	prover, pErr := execution.NewBatchQuorumAttestor(
		resolver, submitter, peers, cfg.ValidatorID, 0, log.Printf)
	if pErr != nil {
		return nil, nil, fmt.Errorf("batch path: quorum attestor: %w", pErr)
	}
	batchQuorumAttestorForEvidence.Store(prover)
	mempoolCfg := execution.DefaultBatchMempoolConfig()
	// Every V8.2 anchor commits the Accumulate incarnation: the configured value must be the chain this validator
	// actually reads, derived here with every check cmd/incarnation makes (docs/l4/INCARNATION_ANCHOR.md).
	incarnation, incErr := consensus.AccumulateIncarnation()
	if incErr != nil {
		return nil, nil, fmt.Errorf("batch path: %w", incErr)
	}
	incCtx, incCancel := context.WithTimeout(context.Background(), incarnationVerifyTimeout)
	incRep, incVErr := proof.VerifyConfiguredIncarnation(incCtx, strings.TrimSuffix(cfg.AccumulateURL, "/")+"/v3", incarnation, 10*time.Second)
	incCancel()
	if incVErr != nil {
		return nil, nil, fmt.Errorf("batch path: Accumulate incarnation: %w", incVErr)
	}
	log.Printf("🧬 [INCARNATION] 0x%x verified against %s: network %s, genesis %s, %d genesis validators, genesis anchor signed %d/%d",
		incarnation, cfg.AccumulateURL, incRep.NetworkName, incRep.GenesisTime, len(incRep.Validators), incRep.GenesisSigners, incRep.GenesisThreshold)
	stack, sErr := execution.NewBatchStack(resolver, prover, mempoolCfg, incarnation, log.Printf)
	if sErr != nil {
		return nil, nil, fmt.Errorf("batch path: stack assembly: %w", sErr)
	}
	// Members with a certified intent are placed by their quorum certificate's height (RB5 D3) - installed before
	// the persisted queue is restored, so a restored certified member is placed rather than refused.
	stack.Mempool.SetIntentCertificates(validatorApp)
	// A member with a recorded outcome is never queued again (RB3-F141).
	if dbClient == nil {
		return nil, nil, fmt.Errorf("the validator cannot start without its database")
	}
	stack.MemberOutcomes = database.NewIntentLifecycleRepository(dbClient)
	// Every batch tree this validator signs or proves is kept on its own disk before it is signed, so it can state and
	// certify what the members did once the batch settles (RB5 D4). A store that cannot be opened stops the start.
	outcomeTrees, otErr := execution.NewOutcomeTreeStore(execution.OutcomeTreeDir())
	if otErr != nil {
		return nil, nil, fmt.Errorf("batch path: %w (the files are left in place; resolve them before restarting)", otErr)
	}
	stack.OutcomeTrees = outcomeTrees
	prover.SetOutcomeTreeRetainer(stack)
	log.Printf("🌳 [OUTCOME] batch trees kept at %s", outcomeTrees.Dir())
	// The attester compares an incoming request's period width against this and
	// refuses a mismatch, so a proposer cannot widen what this node selects.
	periodBlocks, err := batchPeriodBlocksFromEnv()
	if err != nil {
		return nil, nil, err
	}
	stack.PeriodBlocks = periodBlocks

	// DURABILITY. Restore anything queued before a restart, BEFORE the enqueuer
	// is published below, so a restored member cannot race a freshly discovered
	// one. Without this the round has already reported batch_queued while the
	// member is gone: neither settled, failed, nor retried.
	storePath := strings.TrimSpace(os.Getenv("BATCH_MEMPOOL_PATH"))
	if storePath == "" {
		storePath = "data/batch_mempool.json"
	}
	mstore, mErr := execution.NewBatchMempoolStore(storePath, consensus.PendingAttestationCodec{}, log.Printf)
	if mErr != nil {
		return nil, nil, fmt.Errorf("batch path: mempool persistence at %s unavailable - a restart would lose queued members: %w", storePath, mErr)
	}
	if err := stack.Mempool.SetStore(mstore, log.Printf); err != nil {
		return nil, nil, fmt.Errorf("batch path: %w (the file is left in place; resolve it before restarting)", err)
	}
	log.Printf("💾 [BATCH] Mempool persisted at %s", storePath)
	// Drain first, enqueue second.
	go stack.RunFlushLoop(
		context.Background(),
		execution.BatchFlushConfig{
			Interval:     mempoolCfg.FlushInterval,
			PeriodBlocks: periodBlocks,
			// The ACCUMULATE chain height — the same units member CommitHeights
			// are keyed in, and the only height every validator agrees on.
			//
			// Not the CometBFT height: each validator broadcasts its own
			// ValidatorBlock, so one intent commits at a different height on
			// every node. Accumulate also advances on its own, so a period
			// closes without needing more Certen traffic — a lone queued intent
			// no longer waits for a second one to arrive.
			ConsensusHeightFn: batchConsensusHeightFn(accClient, validator),
			// Only the elected submitter for the period forms a batch. Without
			// this all seven race to anchor the same period and six revert with
			// AnchorAlreadyExists after paying gas.
			IsLeaderFn: validator.IsBatchPeriodLeader,
			Attest: func(ctx context.Context, att interface{}, txHash string, chainID int64, ok bool) {
				// Replay the captured Phase 7-9 snapshot so each settled member
				// closes its own proof cycle back to Accumulate.
				validator.RunBatchMemberAttestation(ctx, att, txHash, chainID, ok, string(execution.LaneOnCadence))
			},
			// Members that leave the batch path for good are recorded as FAILED
			// with the cause they were dropped for; there is no other path to
			// settle them (owner decision 2026-09-26).
			OnDropped: func(ctx context.Context, m *execution.PendingBatchIntent, cause string) {
				if m == nil {
					return
				}
				validator.RunBatchMemberRefusal(ctx, m.Attestation, m.ChainID, cause, string(execution.LaneOnCadence))
			},
		},
		log.Printf,
	)
	validator.SetBatchEnqueuer(stack)

	// ON-DEMAND LANE. Intent-keyed settlement: one intent, one anchor, no
	// period, no settle grace — see docs/ON_DEMAND_LANE_BUILD_PLAN.md.
	//
	// The submitter is started whenever batching is active. It settles the later
	// members of every sequential cross-chain intent (EnqueueAfter, RB3-F52), and
	// on_demand intents too once ON_DEMAND_INTENT_KEYED=true routes them to
	// EnqueueOnDemand.
	odSubmitter, odErr := execution.NewOnDemandSubmitter(execution.OnDemandSubmitterConfig{
		Stack:       stack,
		Prover:      prover,
		ValidatorID: cfg.ValidatorID,
		Roster:      consensus.BatchLeaderRoster,
		Attest: func(ctx context.Context, att interface{}, txHash string, chainID int64, ok bool) {
			validator.RunBatchMemberAttestation(ctx, att, txHash, chainID, ok, string(execution.LaneOnDemand))
		},
		OnDropped: func(ctx context.Context, m *execution.PendingBatchIntent, cause string) {
			if m == nil {
				return
			}
			validator.RunBatchMemberRefusal(ctx, m.Attestation, m.ChainID, cause, string(execution.LaneOnDemand))
		},
		// The Accumulate block time of a member queued without it: the failover clock.
		CommitTime: liteClientAdapter.MinorBlockTime,
		Logf:       log.Printf,
	})
	if odErr != nil {
		return nil, nil, fmt.Errorf("batch path: on-demand submitter unavailable: %w", odErr)
	}
	stack.SetOnDemandWaker(odSubmitter.Wake)
	go odSubmitter.Run(context.Background())
	odLane, err := consensus.OnDemandLaneEnabled()
	if err != nil {
		return nil, nil, err
	}
	if odLane {
		log.Printf("⚡ [OD] intent-keyed on-demand lane ENABLED — on_demand " +
			"intents settle one-per-anchor with no period and no settle grace")
	} else {
		log.Printf("⚡ [OD] on-demand submitter running for the later members of sequential cross-chain " +
			"intents only (ON_DEMAND_INTENT_KEYED is not true; on_demand intents take the period path)")
	}

	// Publish to the peer attestation handler. Without this a proposer's
	// request gets 503 and no quorum can ever form.
	batchStackForAttestation.Store(stack)

	// The EVM address this validator signs as. It MUST match its registry entry
	// on the anchor: the aggregator resolves voting power by address, so a wrong
	// one contributes nothing and the quorum silently runs a signer short.
	//
	// Resolved from the CHAIN by matching this node's BLS public key against the
	// anchor's registry — impossible to misconfigure, and it fails loudly in
	// exactly the case where this node should not be attesting (its key is not
	// registered). VALIDATOR_EVM_ADDRESS remains an explicit override for
	// bring-up, but is no longer required: the live containers only carry
	// VALIDATOR_ID, so requiring it meant no validator could ever attest.
	go resolveBatchAttesterIdentity(resolver, cfg.ValidatorID)

	log.Printf("🌐 [BATCH] Quorum peers: %v", peers)

	log.Printf("✅ [BATCH] Cross-ADI batching ACTIVE on chains %v (flush every %s, "+
		"period %d blocks)",
		resolver.Chains(), mempoolCfg.FlushInterval, periodBlocks)

	// ==========================================================================
	// PHASE 5: Wire Batch System for Real Merkle Roots
	// Per Implementation Plan: Connect batch collector/processor to AnchorManager
	// ==========================================================================
	if dbClient == nil {
		return nil, nil, fmt.Errorf("the validator cannot start without its database")
	}
	var batchComponents *BatchComponents
	{
		log.Println("📦 [Phase 5] Initializing batch system with database storage...")

		// Create database repositories
		repos := database.NewRepositories(dbClient)

		// Wire repositories to ValidatorApp for consensus persistence. Commit hands each block's accepted
		// ValidatorBlocks to a background writer (pkg/consensus/consensus_persistence.go); Commit itself never
		// touches the database.
		cometEngine.SetValidatorRepositories(repos)
		log.Println("✅ [Phase 5] Database repositories wired to ValidatorApp for consensus persistence")

		// Proof requests: the API records them as pending; this works them through to a proof.
		requestFulfiller, err := proofrequests.New(repos, proofrequests.Config{
			Interval:         cfg.ProofRequestInterval,
			OnDemandDeadline: cfg.ProofRequestOnDemandDeadline,
			CadenceDeadline:  cfg.ProofRequestCadenceDeadline,
			MaxRetries:       cfg.ProofRequestMaxRetries,
			ValidatorID:      cfg.ValidatorID,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("proof request fulfiller: %w", err)
		}
		requestFulfiller.Start(context.Background())
		log.Println("✅ [Phase 5] Proof request fulfiller started")

		// The live anchors' events on every supported chain (RB3-F72). This used to watch
		// CERTEN_CONTRACT_ADDRESS - the retired CertenAnchorV5 on Sepolia alone - with a V3 ABI the live
		// anchors no longer emit.
		anchorEvents := &execution.AnchorEventMonitor{Endpoints: resolver, Logf: log.Printf}
		if err := anchorEvents.Start(context.Background()); err != nil {
			return nil, nil, fmt.Errorf("anchor event monitor: %w", err)
		}

		// Package all batch components
		batchComponents = &BatchComponents{
			Repos:                repos,
			FirestoreSyncService: firestoreSyncService,
		}
		// E.2 remediation: Update health status for batch system
		healthStatus.SetBatchSystem("active")

		// Log Firestore sync status
		if firestoreSyncService != nil && firestoreSyncService.IsEnabled() {
			log.Println("✅ [Firestore] Sync service wired to batch system - UI will receive real-time updates")
		} else {
			log.Println("⚠️ [Firestore] Sync service not enabled - web app will not receive real-time status updates")
		}
	}

	// ==========================================================================
	// PHASE 7-9: Proof Cycle Orchestrator for Complete Cryptographic Loop
	// Per COMPREHENSIVE_REMEDIATION_PLAN.md Group A
	// ==========================================================================
	log.Println("🔄 [Phase 7-9] Initializing Proof Cycle Orchestrator...")

	// Phase 9 write-back is part of every proof cycle (RB3-F75): the principal, the signer and the
	// submitter are required, and a validator that cannot build them does not start. There is no
	// disabled mode - it used to run every cycle with its results written nowhere - no null submitter,
	// and no fallback to the validator's key: the write-back key is required (RB4-F50).
	var accSubmitter execution.AccumulateSubmitter

	if v := os.Getenv("FF_UNIFIED_TABLES"); v != "" && v != "true" {
		return nil, nil, fmt.Errorf("FF_UNIFIED_TABLES=%s is not supported: every proof cycle stores its evidence", v)
	}

	wb, err := writebackSettingsFromEnv()
	if err != nil {
		return nil, nil, err
	}
	{
		log.Printf("📝 [Phase 9] Configuring Accumulate write-back:")
		log.Printf("   - Principal: %s", wb.principal)
		log.Printf("   - Signer: %s", wb.signer)
		log.Printf("   - Key: %x", wb.key.Public())

		submitterCfg := &execution.AccumulateSubmitterConfig{
			Client:              liteClientAdapter,
			PrivateKey:          wb.key,
			AccountURL:          wb.principal,
			SignerURL:           wb.signer,
			ConfirmationTimeout: 2 * time.Minute,
			MaxRetries:          3,
			RetryDelay:          5 * time.Second,
			Logger:              log.New(log.Writer(), "[AccSubmitter] ", log.LstdFlags),
		}
		submitter, submitErr := execution.NewAccumulateSubmitter(submitterCfg)
		if submitErr != nil {
			return nil, nil, fmt.Errorf("write-back: the Accumulate submitter cannot be created: %w", submitErr)
		}
		accSubmitter = submitter
		log.Printf("✅ [Phase 9] Accumulate submitter configured")
	}

	orchestratorRepos := batchComponents.Repos

	// The unified orchestrator is the only proof-cycle orchestrator. The legacy one it used to fall
	// back to ran with a one-member validator set and could not produce a quorum attestation; a
	// validator whose proof cycle cannot be built does not start (it used to run with Phases 7-9
	// silently disabled).
	if !cfg.UseUnifiedOrchestrator {
		return nil, nil, fmt.Errorf("FF_UNIFIED_ORCHESTRATOR=false is not supported: the unified orchestrator is the only " +
			"proof-cycle orchestrator")
	}
	log.Printf("🔄 [Unified] Initializing Unified Multi-Chain Orchestrator...")

	strategyRegistry, registryErr := initializeStrategyRegistry(cfg, blsKeyManager, resolver)
	if registryErr != nil {
		return nil, nil, fmt.Errorf("proof cycle: strategy registry cannot be created: %w", registryErr)
	}

	unifiedRepo := batchComponents.Repos.Unified

	// Chained proofs (L1/L2/L3) come from the real proof builder, required at startup above.
	proofGenAdapter := execution.NewLiteClientProofGeneratorAdapter(liteClientProofGen)

	// Members that never settled are attested and written back (RB3-F49). Their records wait in a
	// durable queue beside the validator's other state until the chain is past their deadline.
	nsDataDir := cfg.DataDir
	if nsDataDir == "" {
		nsDataDir = "data"
	}
	nonSettlements, nsErr := execution.OpenNonSettlementQueue(filepath.Join(nsDataDir, "non_settlement_queue.json"))
	if nsErr != nil {
		return nil, nil, fmt.Errorf("proof cycle: non-settlement queue: %w", nsErr)
	}

	// Member outcomes the lifecycle store refuses wait here until it takes them (RB3-F78): an intent's
	// status is derived from every member's outcome, and each is recorded after its write-back.
	memberOutcomes, moErr := execution.NewFileMemberOutcomeOutbox(filepath.Join(nsDataDir, "member_outcome_outbox"))
	if moErr != nil {
		return nil, nil, fmt.Errorf("proof cycle: member outcome outbox: %w", moErr)
	}
	(&execution.MemberOutcomeReconciler{
		Outbox: memberOutcomes, Store: batchComponents.Repos.IntentLifecycle, ValidatorID: cfg.ValidatorID, Logf: log.Printf,
	}).Start(context.Background())
	log.Printf("✅ [Phase 9] Member outcome outbox at %s; reconciler replaying on startup and every minute", memberOutcomes.Dir())

	// Level-record completions the store fails wait here until it takes them (RB3-F123).
	proofCompletions, pcErr := execution.NewFileProofCompletionOutbox(filepath.Join(nsDataDir, "proof_completion_outbox"))
	if pcErr != nil {
		return nil, nil, fmt.Errorf("proof cycle: proof completion outbox: %w", pcErr)
	}
	(&execution.ProofCompletionReconciler{
		Outbox: proofCompletions, Store: batchComponents.Repos.ProofArtifacts, Logf: log.Printf,
	}).Start(context.Background())
	log.Printf("✅ [Phase 9] Proof completion outbox at %s; reconciler replaying on startup and every minute", proofCompletions.Dir())

	unifiedConfig := &execution.UnifiedOrchestratorConfig{
		ValidatorID:              cfg.ValidatorID,
		ValidatorIndex:           0,
		Registry:                 strategyRegistry,
		Repos:                    orchestratorRepos,
		UnifiedRepo:              unifiedRepo,
		ThresholdConfig:          attestationStrategy.DefaultThresholdConfig(),
		ObservationTimeout:       ethrpc.FinalityBound, // Phase 7 waits for the chain's finalized block (RB5-F49)
		AttestationTimeout:       execution.PeerAttestationRounds,
		WriteBackTimeout:         2 * time.Minute,
		AttestationPeers:         cfg.AttestationPeers,
		AttestationRequiredCount: cfg.AttestationRequiredCount,
		AccumulateClient:         accSubmitter,
		ResultsPrincipal:         wb.principal,
		Ed25519Key:               privateKey,
		EnableMultiChain:         cfg.EnableMultiChain,
		ProofGenerator:           proofGenAdapter,
		AccumulateQueryClient:    liteClientAdapter, // For querying tx governance data (M-of-N threshold)
		ResultQuorumRegistry:     execution.ResultQuorumRegistryFromChains(resolver),
		MemberLookup:             stack.Mempool.FindMember,
		NonSettlementChain:       execution.NonSettlementChainFromResolver(resolver),
		NonSettlements:           nonSettlements,
		MemberOutcomes:           memberOutcomes,
		ProofCompletions:         proofCompletions,
		// The Accumulate validator-set evidence every V8.2 proof carries (RB5-F4): the Directory's set and threshold
		// derived from account bytes under the incarnation this validator verified at boot, rebuilt every 10 minutes.
		ValidatorSetProver: execution.CachedValidatorSetProver(func(ctx context.Context) (*proof.ValidatorSetProof, error) {
			return proof.BuildValidatorSetProof(ctx, proof.NewHTTPQuerier(strings.TrimSuffix(cfg.AccumulateURL, "/")+"/v3"), stack.Incarnation)
		}, 10*time.Minute),
	}

	unifiedOrchestrator, unifiedErr := execution.NewUnifiedOrchestrator(unifiedConfig)
	if unifiedErr != nil {
		return nil, nil, fmt.Errorf("proof cycle: unified orchestrator cannot be created: %w", unifiedErr)
	}
	validator.SetProofCycleOrchestrator(execution.NewUnifiedOrchestratorAdapter(unifiedOrchestrator))
	log.Printf("✅ [Unified] Unified Multi-Chain Orchestrator initialized and wired to validator")

	// Phase 8 quorum: publish the orchestrator so main()'s HTTP mux can route peer attestation
	// requests to it (UnifiedOrchestrator.HandlePeerAttestationRequest).
	unifiedOrchestratorForAttestation.Store(unifiedOrchestrator)
	go unifiedOrchestrator.RunNonSettlements(context.Background(), time.Minute)
	log.Printf("✅ [Unified] Non-settlement attestation running (%d queued)", len(nonSettlements.All()))
	log.Printf("✅ [Unified] Phase 8 peer attestation handler published for HTTP routing")
	log.Printf("   - Strategy Registry: %d attestation schemes, %d chains",
		len(strategyRegistry.ListAttestationSchemes()),
		len(strategyRegistry.ListChainIDs()))
	log.Printf("   - Multi-Chain: %v", cfg.EnableMultiChain)
	healthStatus.SetProofCycle("active")

	// --- Intent discovery wiring ---
	log.Printf("🔍 Starting Certen Intent Discovery Service for validator...")

	// Create IntentDiscovery configuration
	//
	// BFTTimeout bounds the ENTIRE canonical workflow, governance proof generation included.
	// That budget is not small: each of G0/G1/G2 shells out to the govproof CLI, which makes
	// live v3 API round trips. Measured on Sepolia against the Kermit endpoint, G0 ~1s but G1
	// ~27s and G2 a similar order — comfortably past 30s in total.
	//
	// This mattered more than a slow path. exec.CommandContext KILLS the child when the
	// context expires, and a killed process surfaces as an *exec.ExitError with EMPTY stderr,
	// so the failure logged only as "governance proof CLI failed:" with no reason. G2 was
	// killed every time, governance settled at G1, and HIGH-004 then correctly refused every
	// value-moving intent: "G2 governance required for value-moving operations, got G1".
	// The net effect was that NO intent moving value could execute, on_demand or on_cadence,
	// while the CLI itself worked perfectly when run by hand.
	//
	// DefaultIntentDiscoveryConfig already carried 60s ("Increased from 30s for WAN latency");
	// this literal silently reverted it. Keep the two in agreement, and allow an env override
	// so a slow endpoint can be accommodated without a rebuild.
	//
	// Sized to exceed three CLI budgets (the adapter allows 120s per level and passes the CLI
	// 115s of that), so the CLI always reaches its OWN timeout and reports a real reason
	// rather than being SIGKILLed here with empty stderr.
	bftTimeout, err := bftTimeoutFromEnv()
	if err != nil {
		return nil, nil, err
	}
	log.Printf("⏱️  BFT timeout: %v (must cover G0+G1+G2 govproof CLI round trips)", bftTimeout)

	blockWorkers, err := intent.BlockWorkersFromEnv()
	if err != nil {
		return nil, nil, err
	}
	intentConfig := &intent.IntentDiscoveryConfig{
		BlockPollInterval:   5 * time.Second,
		BFTTimeout:          bftTimeout,
		MaxConcurrentBlocks: 2000, // Increased from 10 to handle high block rate
		BlockWorkers:        blockWorkers,
		IntentBatchSize:     100, // Increased from 50 to process more intents per batch
		MinStartHeight:      0,
	}

	// Get LedgerStore from ABCI application and wrap it for IntentDiscovery
	var ledgerWrapper *LedgerStoreWrapper
	if ledgerProvider := cometEngine.GetLedgerStoreProvider(); ledgerProvider != nil && ledgerProvider.GetLedgerStore() != nil {
		ledgerWrapper = &LedgerStoreWrapper{store: ledgerProvider.GetLedgerStore()}
	}

	// Create IntentDiscovery with proper configuration and persistence
	intentDiscovery := intent.NewIntentDiscovery(accClient, cfg.AccumulateURL, intentConfig, ledgerWrapper, liteClientProofGen, cfg.ValidatorID)
	// Blocks whose search fails wait here until they are searched (RB3-F125): the watermark never passes a
	// block that is neither searched nor kept.
	unsearchedBlocks, ubErr := intent.OpenFileUnsearchedBlocks(filepath.Join(nsDataDir, "unsearched_blocks.json"))
	if ubErr != nil {
		return nil, nil, fmt.Errorf("intent discovery: %w", ubErr)
	}
	intentDiscovery.SetUnsearchedBlocks(unsearchedBlocks)
	log.Printf("✅ [DISCOVERY] unsearched blocks kept at %s; searched again every 30s", unsearchedBlocks.Path())

	// This is the critical hook: IntentDiscovery calls the canonical BFT consensus method
	// BFTValidator.ExecuteCanonicalIntentWithBFTConsensus(ctx, certenIntent, certenProof, blockHeight)
	// with properly structured CertenIntent (4-blob canonical) and CertenProof from lite client
	intentDiscovery.SetBFTConsensus(validator)

	// RB4-F55 repair: one decided member's proof cycle is re-driven on request, here, where the orchestrator, its
	// keys, its peers and the committed-operation index are (`validator repair member-proof-cycle`).
	memberRepairs := &execution.MemberRepairRunner{
		Dir: execution.MemberRepairDir(nsDataDir), ValidatorID: cfg.ValidatorID, DB: dbClient.DB(),
		Lifecycle: batchComponents.Repos.IntentLifecycle, Outbox: memberOutcomes,
		Observe: unifiedOrchestrator.ObserveSettlement, Arm: validator.ArmMemberRepair,
		Reprocess: intentDiscovery.ReprocessIntent, Logf: log.Printf,
	}
	if err := memberRepairs.Start(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("member repair runner: %w", err)
	}
	log.Printf("✅ [MEMBER-REPAIR] repair requests served from %s", memberRepairs.Dir)

	// ENTITLEMENT — wire the epoch snapshot to the two places that consume it.
	//
	// The gate inside the ABCI validator only VERIFIES evidence; something has
	// to PRODUCE it. Without this the proposer attaches nothing to every
	// ValidatorBlock, and the gate reports NO_ENTITLEMENT_EVIDENCE for
	// everything — indistinguishable from a genuinely unentitled principal, and
	// in enforce mode it would refuse the entire fleet's work.
	//
	// Mode comes from the SAME parse the gate uses, so the producer and the
	// verifier can never disagree about whether the gate is on.
	if entGateCfg, err := consensus.EntitlementConfigFromEnv(); err != nil {
		log.Fatalf("invalid entitlement configuration: %v", err)
	} else {
		entStoreCfg, err := entitlement.StoreConfigFromEnv()
		if err != nil {
			log.Fatalf("invalid entitlement configuration: %v", err)
		}
		entStore := entitlement.NewStore(
			entStoreCfg,
			entGateCfg.Keys,
			log.New(log.Writer(), "[Entitlement] ", log.LstdFlags),
		)
		// Start is non-blocking and a failed first refresh is not fatal: a
		// validator must boot while the gateway is down. Background context to
		// match the other long-lived services started here (bftScheduler,
		// batchScheduler) — the refresher lives for the process lifetime.
		entStore.Start(context.Background())

		validator.SetEntitlementStore(entStore, entGateCfg.Mode)
		// Pre-screen only declines work when the gate is actually enforcing;
		// in observe mode a decline would drop intents the gate would admit.
		intentDiscovery.SetEntitlementScreen(entStore, entGateCfg.Mode == consensus.EntitlementEnforce)

		// Report the SEALED mode, not the environment's.
		//
		// Policy is sealed into the ledger at genesis and the environment is
		// ignored thereafter, so an operator who edits CERTEN_ENTITLEMENT_MODE
		// and redeploys gets a warning log and no behaviour change. Publishing
		// this as a gauge is how the fleet's ACTUAL mode becomes observable
		// rather than assumed.
		metrics.SetEntitlementMode(string(entGateCfg.Mode))

		// Epoch freshness, sampled independently of refresh success.
		//
		// A refresh that keeps failing leaves the previous snapshot in place —
		// correct, and the reason a single failed poll does not halt admission.
		// But it also means "last refresh succeeded" stays silent while the
		// document underneath expires. Sampling on a timer reports the epoch a
		// validator would ACTUALLY verify against, which is the only thing that
		// predicts a halt under enforce.
		go func() {
			t := time.NewTicker(15 * time.Second)
			defer t.Stop()
			for range t.C {
				h := entStore.Health()
				remaining := float64(0)
				if h.NotAfterUnix > 0 {
					// Deliberately signed: negative means this node is already
					// refusing, and clamping would hide it.
					remaining = float64(h.NotAfterUnix - time.Now().UTC().Unix())
				}
				metrics.SetEntitlementEpoch(h.Epoch, h.Accounts, remaining)
			}
		}()

		log.Printf("✅ [ENTITLEMENT] store wired: mode=%s enabled=%t keys=%d",
			entGateCfg.Mode, entStore.Enabled(), len(entGateCfg.Keys))
	}

	{
		// Wire repositories for intent lifecycle tracking
		intentDiscovery.SetRepositories(batchComponents.Repos)
		log.Printf("✅ Intent lifecycle tracking wired to intent discovery")

		// Leg counts (legs_completed / legs_failed) and the intent's status are derived from each
		// chain member's recorded outcome (IntentLifecycleRepository.RecordMemberOutcome, RB3-F50).
		// The additive per-report counters that used to write them are gone: two writers of one
		// column disagreed, and a member reported twice was counted twice.

		// Anchor quorum evidence. The quorum proven over each anchor — aggregate signature, signer set and
		// voting power — used to be computed and dropped, leaving anchor_batches' Phase 5 columns empty on
		// all 70,236 rows and proofs_service reporting batch_quorum_met=false for every intent. The writer
		// records it off the proving path; see pkg/execution/anchor_quorum_writer.go.
		attestor := batchQuorumAttestorForEvidence.Load()
		if attestor == nil {
			return nil, nil, fmt.Errorf("anchor quorum evidence: the batch quorum attestor was not built")
		}
		{
			// The completion time is the verify block's, read from its chain before any write; a record
			// whose block cannot be read yet waits in the retry and the outbox (RB3-F133).
			anchorQuorumStore := execution.BlockTimedAnchorQuorumStore{Store: batchComponents.Repos.Batches, BlockTime: attestor.VerifyBlockTime}
			anchorQuorumWriter := execution.NewAnchorQuorumWriter(anchorQuorumStore, log.Printf)

			// The durable half. Every way the in-memory hand-off can lose a proven anchor — a saturated
			// queue, a database that is down, a shutdown with records still in flight — is a way the
			// database is unavailable, so the spill store cannot live in that database. It is a directory
			// beside the validator's other state, and the reconciler drains it back once the database
			// answers again, including across a restart.
			aqDataDir := cfg.DataDir
			if aqDataDir == "" {
				aqDataDir = "data"
			}
			outboxDir := filepath.Join(aqDataDir, "anchor_quorum_outbox")
			// Required: without the outbox, evidence the database does not accept at that moment would be
			// recoverable only by someone running `anchorquorumbackfill`.
			outbox, obErr := execution.NewFileAnchorQuorumOutbox(outboxDir)
			if obErr != nil {
				return nil, nil, fmt.Errorf("anchor quorum outbox at %s: %w", outboxDir, obErr)
			}
			anchorQuorumWriter.SetOutbox(outbox)
			reconciler := &execution.AnchorQuorumReconciler{
				Outbox: outbox,
				Store:  anchorQuorumStore,
				Logf:   log.Printf,
			}
			reconciler.Start(context.Background())
			log.Printf("✅ [Phase 5] Anchor quorum outbox at %s; reconciler replaying on startup and every %s",
				outboxDir, 5*time.Minute)

			anchorQuorumWriter.Start()
			attestor.SetAnchorAttestedHook(anchorQuorumWriter.Hook())
			log.Printf("✅ [Phase 5] Anchor quorum evidence hook wired (canonical rows keyed by chain_id + bundle_id)")
		}

		// Standing evidence checks. The counters above report what the writer DID; these report what is
		// WRONG, on a timer, whether or not anything is happening — including whether this database is
		// behind this binary's migration catalog, which is fatal on the NEXT restart and therefore has to
		// be visible before someone rolls the fleet rather than after.
		monitor := &execution.EvidenceMonitor{DB: dbClient.DB(), Logf: log.Printf}
		monitor.Start(context.Background())
		log.Printf("✅ [Phase 5] Standing evidence checks started (settled-without-canonical, " +
			"contradicted layer 5, schema-behind-binary)")
	}

	go intentDiscovery.StartMonitoring()
	go watchDiscoveryLiveness(intentDiscovery)

	// Eager, so an undelivered cost event survives a restart in practice and not just in
	// principle — the WAL is only read when the reporter is constructed.
	execution.StartCostReporter(log.Printf)

	log.Printf("✅ CERTEN Validator initialized with real BFT consensus:")
	log.Printf("   - Validator ID: %s", cfg.ValidatorID)
	log.Printf("   - CometBFT role: Full consensus participant + P2P networking")
	log.Printf("   - Intent discovery: ENABLED (validator discovers and proposes to BFT network)")
	log.Printf("   - Consensus protocol: Real CometBFT Byzantine fault tolerance via P2P validators")
	log.Printf("   - Proof generation: enabled for post-consensus execution")
	log.Printf("   - P2P networking: enabled for BFT cluster formation")
	log.Printf("🎯 Ready for intent discovery → peer proposal → decentralized validator BFT consensus!")

	return validator, batchComponents, nil
}

// initializeStrategyRegistry builds the proof cycle's strategy registry: BLS12-381 attestation and one
// observer per chain CERTEN settles on now - the resolver's chains, CERTEN_SETTLEMENT_CHAINS - each at the RPC and
// anchor the batch path uses (RB3-F44, RB5-F33).
func initializeStrategyRegistry(
	cfg *config.Config,
	blsKeyManager *bls.KeyManager,
	resolver *execution.EVMChainResolverImpl,
) (*strategy.Registry, error) {
	settled := resolver.Chains()
	sort.Slice(settled, func(i, j int) bool { return settled[i] < settled[j] })
	chains := make([]strategy.ChainEndpoint, 0, len(settled))
	for _, id := range settled {
		rpc, anchor, err := resolver.Endpoint(id)
		if err != nil {
			return nil, err
		}
		chains = append(chains, strategy.ChainEndpoint{ChainID: id, RPC: rpc, Anchor: anchor})
	}
	return strategy.InitializeRegistry(&strategy.RegistryConfig{
		ValidatorID:      cfg.ValidatorID,
		BLSPrivateKey:    blsKeyManager.GetPrivateKeyBytes(),
		EthPrivateKey:    cfg.EthPrivateKey,
		SettlementChains: settled,
		Chains:           chains,
		Logger:           log.New(log.Writer(), "[StrategyRegistry] ", log.LstdFlags),
	})
}

func printHelp() {
	fmt.Println("Certen BFT Validator Service")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  validator-service [OPTIONS]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --validator-id=ID        Validator ID (required unless VALIDATOR_ID is set)")
	fmt.Println("  --help                   Show this help message")
	fmt.Println()
	fmt.Println("BFT Consensus Features:")
	fmt.Println("  ✅ Real distributed consensus")
	fmt.Println("  ✅ Byzantine fault tolerance")
	fmt.Println("  ✅ Validator voting on blocks")
	fmt.Println("  ✅ Production-grade cryptographic security")
	fmt.Println("  ✅ Target chain execution capabilities")
	fmt.Println("  ✅ Anchor creation and verification")
	fmt.Println("  ❌ NO SIMULATION, NO SELF-CONSENSUS")
}

// bftTimeoutFromEnv is the time an intent gets through consensus: CERTEN_BFT_TIMEOUT, or 360s.
func bftTimeoutFromEnv() (time.Duration, error) {
	d, err := envvar.Duration("CERTEN_BFT_TIMEOUT", 360*time.Second, time.Second)
	if err == nil && os.Getenv("CERTEN_BFT_TIMEOUT") != "" {
		log.Printf("⏱️  BFT timeout overridden by CERTEN_BFT_TIMEOUT=%v", d)
	}
	return d, err
}

// checkpointSettings is the block-checkpoint anchor's configuration, all of it.
type writebackSettings struct {
	principal, signer string
	key               ed25519.PrivateKey
}

// writebackSettingsFromEnv reads Phase 9 write-back's settings, refusing any that is missing or malformed.
// The key is required: a validator without ACCUMULATE_WRITEBACK_PRIV_KEY used to sign its write-backs with
// its own consensus key, which is not on the signer's key page (RB4-F50).
func writebackSettingsFromEnv() (writebackSettings, error) {
	wb := writebackSettings{
		principal: strings.TrimSpace(os.Getenv("ACCUMULATE_RESULTS_PRINCIPAL")),
		signer:    strings.TrimSpace(os.Getenv("ACCUMULATE_SIGNER_URL")),
	}
	if v := os.Getenv("PROOF_CYCLE_WRITEBACK"); v != "" && v != "true" {
		return wb, fmt.Errorf("PROOF_CYCLE_WRITEBACK=%s is not supported: proof cycles always write their results back", v)
	}
	keyHex := strings.TrimSpace(os.Getenv("ACCUMULATE_WRITEBACK_PRIV_KEY"))
	var missing []string
	for name, v := range map[string]string{
		"ACCUMULATE_RESULTS_PRINCIPAL": wb.principal, "ACCUMULATE_SIGNER_URL": wb.signer,
		"ACCUMULATE_WRITEBACK_PRIV_KEY": keyHex,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return wb, fmt.Errorf("proof cycles always write their results back, but %s is not set", strings.Join(missing, ", "))
	}
	kb, err := hex.DecodeString(keyHex)
	if err != nil || len(kb) != ed25519.PrivateKeySize {
		// The value is a secret: named, never printed.
		return wb, fmt.Errorf("ACCUMULATE_WRITEBACK_PRIV_KEY is not a %d-byte hex ed25519 private key", ed25519.PrivateKeySize)
	}
	wb.key = ed25519.PrivateKey(kb)
	return wb, nil
}

type checkpointSettings struct {
	writer, account, signer string
	key                     ed25519.PrivateKey
}

// checkpointSettingsFromEnv reads the checkpoint anchor's settings, refusing any that is missing or
// malformed. Read on every node, writer or not, so a misconfiguration is found wherever it is deployed.
func checkpointSettingsFromEnv() (checkpointSettings, error) {
	cp := checkpointSettings{
		writer:  strings.TrimSpace(os.Getenv("CHECKPOINT_WRITER_VALIDATOR")),
		account: strings.TrimSpace(os.Getenv("CHECKPOINT_DATA_ACCOUNT")), // acc://certen-protocol.acme/block-history
		signer:  strings.TrimSpace(os.Getenv("CHECKPOINT_SIGNER_URL")),   // acc://certen-protocol.acme/book/1
	}
	var missing []string
	for name, v := range map[string]string{
		"CHECKPOINT_WRITER_VALIDATOR": cp.writer, "CHECKPOINT_DATA_ACCOUNT": cp.account, "CHECKPOINT_SIGNER_URL": cp.signer,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	keyVar := "CHECKPOINT_WRITEBACK_PRIV_KEY"
	keyHex := strings.TrimSpace(os.Getenv(keyVar))
	if keyHex == "" {
		keyVar = "ACCUMULATE_WRITEBACK_PRIV_KEY"
		keyHex = strings.TrimSpace(os.Getenv(keyVar))
	}
	if keyHex == "" {
		missing = append(missing, "CHECKPOINT_WRITEBACK_PRIV_KEY or ACCUMULATE_WRITEBACK_PRIV_KEY")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return cp, fmt.Errorf("CHECKPOINT_ANCHOR_ENABLED is set but %s is not", strings.Join(missing, ", "))
	}
	kb, err := hex.DecodeString(keyHex)
	if err != nil || len(kb) != ed25519.PrivateKeySize {
		// The value is a secret: named, never printed.
		return cp, fmt.Errorf("CHECKPOINT_ANCHOR_ENABLED: %s is not a %d-byte hex ed25519 private key", keyVar, ed25519.PrivateKeySize)
	}
	cp.key = ed25519.PrivateKey(kb)
	return cp, nil
}

// checkEnvironment reads every environment knob the validator consults after boot, so one that does not
// parse stops the node before it does anything, naming each value, rather than refusing work later.
func checkEnvironment() error {
	return envvar.Check(
		consensus.CheckEnv,
		execution.CheckEnv,
		contracts.CheckEnv,
		intent.CheckEnv,
		ethrpc.CheckEnv,
		func() error { _, err := entitlement.StoreConfigFromEnv(); return err },
		func() error { _, err := batchPeriodBlocksFromEnv(); return err },
		func() error { _, err := bftTimeoutFromEnv(); return err },
		func() error { _, err := envvar.Bool("MIGRATE_ON_START", false); return err },
		func() error { _, err := accumulate.LogLevelFromEnv(); return err },
		func() error { _, err := writebackSettingsFromEnv(); return err },
		func() error {
			enabled, err := envvar.Bool("CHECKPOINT_ANCHOR_ENABLED", false)
			if err != nil || !enabled {
				return err
			}
			_, err = checkpointSettingsFromEnv()
			return err
		},
	)
}

// requireExecutable refuses an environment variable that does not name an executable file.
func requireExecutable(name, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is required: it names a tool every intent's governance proof needs", name)
	}
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s=%s: %w", name, path, err)
	}
	if st.IsDir() {
		return fmt.Errorf("%s=%s is a directory, not a tool", name, path)
	}
	if runtime.GOOS != "windows" && st.Mode()&0o111 == 0 {
		return fmt.Errorf("%s=%s is not executable", name, path)
	}
	return nil
}
