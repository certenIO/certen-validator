package main

import (
    "context"
    "crypto/ed25519"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
    "path/filepath"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/google/uuid"

    "github.com/certen/independant-validator/pkg/accumulate"
    "github.com/certen/independant-validator/pkg/anchor"
    "github.com/certen/independant-validator/pkg/attestation"
    attestationStrategy "github.com/certen/independant-validator/pkg/attestation/strategy"
    "github.com/certen/independant-validator/pkg/batch"
    "github.com/certen/independant-validator/pkg/config"
    "github.com/certen/independant-validator/pkg/consensus"
    "github.com/certen/independant-validator/pkg/crypto/bls"
    "github.com/certen/independant-validator/pkg/database"
    "github.com/certen/independant-validator/pkg/ethereum"
    "github.com/certen/independant-validator/pkg/execution"
    "github.com/certen/independant-validator/pkg/firestore"
    "github.com/certen/independant-validator/pkg/intent"
    "github.com/certen/independant-validator/pkg/ledger"
    "github.com/certen/independant-validator/pkg/proof"
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
    Status        string `json:"status"`         // "ok", "degraded", "error"
    Phase         string `json:"phase"`
    Consensus     string `json:"consensus"`
    Database      string `json:"database"`       // "connected", "disconnected"
    Ethereum      string `json:"ethereum"`       // "connected", "disconnected"
    Accumulate    string `json:"accumulate"`     // "connected", "disconnected"
    BatchSystem   string `json:"batch_system"`   // "active", "disabled"
    ProofCycle    string `json:"proof_cycle"`    // "active", "disabled"
    UptimeSeconds int64  `json:"uptime_seconds"` // Seconds since startup
    startTime     time.Time
    mu            sync.RWMutex
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
    if h.Ethereum == "disconnected" || h.Accumulate == "disconnected" {
        h.Status = "error"
        return
    }

    // Check for degraded state (non-critical components)
    if h.Database == "disconnected" || h.BatchSystem == "disabled" || h.ProofCycle == "disabled" {
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

func main() {
    // Configure logging
    log.SetOutput(os.Stdout)
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    log.Printf("🚀 Starting Certen Validator Service with REAL CometBFT Consensus - NO SIMULATION")

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
    log.Printf("📋 Validator ID: %s (from %s)", cfg.ValidatorID, func() string {
        if *validatorID != "" {
            return "CLI flag"
        }
        return "VALIDATOR_ID env var"
    }())

    // ==========================================================================
    // PHASE 5: Initialize PostgreSQL Database Connection
    // Per Implementation Plan: Wire batch system with real Merkle roots
    // Per E.2 remediation: Proper degradation handling with DatabaseRequired flag
    // ==========================================================================
    log.Println("🗄️ [Phase 5] Connecting to PostgreSQL database...")
    dbClient, err := database.NewClient(cfg, database.WithLogger(
        log.New(log.Writer(), "[Database] ", log.LstdFlags),
    ))
    if err != nil {
        // E.2 remediation: Check if database is required
        if cfg.DatabaseRequired {
            log.Fatalf("❌ [Phase 5] Database connection REQUIRED but failed: %v", err)
        }
        // Database is optional in development - log warning with explicit degradation notice
        log.Printf("⚠️ [Phase 5] Database connection failed - running in DEGRADED mode")
        log.Printf("⚠️ WARNING: Batch system, proof storage, and confirmation tracking DISABLED")
        log.Printf("   Error: %v", err)
        dbClient = nil
        healthStatus.SetDatabase("disconnected")
        healthStatus.SetBatchSystem("disabled")
    } else {
        log.Println("✅ [Phase 5] Connected to PostgreSQL database")
        healthStatus.SetDatabase("connected")

        // Run migrations
        if err := dbClient.MigrateUp(context.Background()); err != nil {
            log.Printf("⚠️ [Phase 5] Database migration failed: %v", err)
            // Migration failure is a warning, not a fatal error
        }
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
            log.Printf("⚠️ [Firestore] Failed to create Firestore client: %v", firestoreErr)
            log.Printf("   Real-time UI sync DISABLED - web app will not receive status updates")
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

        // Add batch system details if available
        if batchComponents != nil && batchComponents.Collector != nil {
            batchInterval := 15 * time.Minute

            // Get on-cadence batch info
            onCadenceInfo := batchComponents.Collector.GetOnCadenceBatchInfo()
            if onCadenceInfo != nil {
                expectedCompletion := onCadenceInfo.StartTime.Add(batchInterval)
                remaining := time.Until(expectedCompletion)

                detailed.BatchDetails["on_cadence"] = map[string]interface{}{
                    "batch_id":               onCadenceInfo.BatchID.String(),
                    "transaction_count":      onCadenceInfo.TxCount,
                    "age_seconds":            int64(onCadenceInfo.Age.Seconds()),
                    "start_time":             onCadenceInfo.StartTime.UTC().Format(time.RFC3339),
                    "expected_completion_at": expectedCompletion.UTC().Format(time.RFC3339),
                    "remaining_seconds":      int64(remaining.Seconds()),
                    "is_delay_expected":      true,
                    "price_tier":             "$0.05/proof",
                    "status_message":         "On-cadence batch delays up to 15 minutes are normal operation.",
                }

                // Check if batch is stalled (beyond expected + grace period)
                if onCadenceInfo.Age > (batchInterval + 5*time.Minute) {
                    detailed.BatchDetails["on_cadence_warning"] = "Batch age exceeds expected window. May require investigation."
                }
            }

            // Get on-demand batch info
            onDemandInfo := batchComponents.Collector.GetOnDemandBatchInfo()
            if onDemandInfo != nil {
                detailed.BatchDetails["on_demand"] = map[string]interface{}{
                    "batch_id":          onDemandInfo.BatchID.String(),
                    "transaction_count": onDemandInfo.TxCount,
                    "age_seconds":       int64(onDemandInfo.Age.Seconds()),
                    "start_time":        onDemandInfo.StartTime.UTC().Format(time.RFC3339),
                    "is_delay_expected": false,
                    "price_tier":        "$0.25/proof",
                    "status_message":    "On-demand batches anchor immediately.",
                }

                // Check if on-demand batch is stalled
                if onDemandInfo.Age > 2*time.Minute {
                    detailed.BatchDetails["on_demand_warning"] = "On-demand batch age exceeds expected. May require investigation."
                }
            }

            // Get batch system health status
            batchHealth := batch.GetBatchSystemHealth(onCadenceInfo, onDemandInfo, batchInterval)
            detailed.BatchDetails["system_health"] = map[string]interface{}{
                "overall_status":         batchHealth.OverallStatus,
                "on_cadence_status":      batchHealth.OnCadenceStatus,
                "on_demand_status":       batchHealth.OnDemandStatus,
                "on_cadence_delay_normal": batchHealth.OnCadenceDelayNormal,
                "message":                batchHealth.StatusMessage,
            }
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
    if batchComponents != nil {
        batchHandlers := server.NewBatchHandlers(
            batchComponents.Collector,
            batchComponents.Processor,
            batchComponents.OnDemandHandler,
            batchComponents.Repos,
            cfg.ValidatorID,
            log.New(log.Writer(), "[BatchAPI] ", log.LstdFlags),
        )

        // On-demand anchor endpoint (Priority 2.1)
        mux.HandleFunc("/api/anchors/on-demand", batchHandlers.HandleOnDemandAnchor)

        // Batch status endpoints
        mux.HandleFunc("/api/batches/current", batchHandlers.HandleBatchInfo)
        mux.HandleFunc("/api/batches/", batchHandlers.HandleBatchStatus)

        // Proof retrieval endpoints (Priority 3.1)
        mux.HandleFunc("/api/proofs/by-tx/", batchHandlers.HandleGetProofByTxHash)
        mux.HandleFunc("/api/proofs/by-account/", batchHandlers.HandleGetProofsByAccount)
        mux.HandleFunc("/api/proofs/", batchHandlers.HandleGetProof)

        // Anchor retrieval endpoints
        mux.HandleFunc("/api/anchors/by-batch/", batchHandlers.HandleGetAnchorByBatch)
        mux.HandleFunc("/api/anchors/", batchHandlers.HandleGetAnchor)

        // Cost tracking endpoints (Priority 3.2)
        mux.HandleFunc("/api/costs", batchHandlers.HandleGetCostStatistics)
        mux.HandleFunc("/api/costs/estimate", batchHandlers.HandleEstimateCost)

        // Multi-Validator Attestation endpoints (Priority 3.1)
        if batchComponents.AttestationService != nil {
            attestationHandlers := server.NewAttestationHandlers(
                batchComponents.AttestationService,
                cfg.ValidatorID,
                log.New(log.Writer(), "[AttestationAPI] ", log.LstdFlags),
            )

            // Attestation collection endpoints
            mux.HandleFunc("/api/attestations", attestationHandlers.HandleAttestationInfo)
            mux.HandleFunc("/api/attestations/request", attestationHandlers.HandleAttestationRequest)
            mux.HandleFunc("/api/attestations/status/", attestationHandlers.HandleGetAttestationStatus)
            mux.HandleFunc("/api/attestations/bundle/", attestationHandlers.HandleGetAttestationBundle)
            mux.HandleFunc("/api/attestations/peers", attestationHandlers.HandleGetPeers)

            log.Printf("✅ [Phase 5] Multi-validator attestation endpoints configured:")
            log.Printf("   - POST /api/attestations/request  (receive attestation from peer)")
            log.Printf("   - GET  /api/attestations/status/:id (attestation status)")
            log.Printf("   - GET  /api/attestations/bundle/:id (attestation bundle)")
            log.Printf("   - GET  /api/attestations/peers     (configured peers)")
        }

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
        log.Printf("   - POST /api/anchors/on-demand  (immediate anchoring ~$0.25/proof)")
        log.Printf("   - GET  /api/batches/current    (current batch status)")
        log.Printf("   - GET  /api/proofs/by-tx/:hash (proof by transaction)")
        log.Printf("   - GET  /api/proofs/by-account/:url (proofs by account)")
        log.Printf("   - GET  /api/costs              (cost structure)")
        log.Printf("   - GET  /api/costs/estimate     (estimate anchoring cost)")
    } else {
        log.Printf("⚠️ [Phase 5] Batch API endpoints not available - database not connected")
    }

    httpServer := &http.Server{
        Addr:    cfg.ListenAddr,
        Handler: mux,
    }

    // Context for background tasks
    ctx, cancel := context.WithCancel(context.Background())

    // Start internal validator services (execution queue, etc)
    go validatorNode.Start(ctx)

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

    // Cancel background services
    cancel()

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

// BatchComponents holds all batch system components for API handlers
type BatchComponents struct {
    Scheduler            *batch.Scheduler
    Collector            *batch.Collector
    Processor            *batch.Processor
    OnDemandHandler      *batch.OnDemandHandler
    ConfirmationTracker  *batch.ConfirmationTracker
    AttestationService   *attestation.Service
    Repos                *database.Repositories
    FirestoreSyncService *firestore.SyncService // Real-time UI sync
}

// loadOrGenerateEd25519Key securely loads or generates an Ed25519 private key
// E.5 remediation: Never derive keys from validator ID - use proper key management
func loadOrGenerateEd25519Key(cfg *config.Config) (ed25519.PrivateKey, error) {
    // Determine key file path
    keyPath := cfg.Ed25519KeyPath
    if keyPath == "" {
        // Default to data directory
        dataDir := cfg.DataDir
        if dataDir == "" {
            dataDir = "./data"
        }
        keyPath = filepath.Join(dataDir, "ed25519_key.hex")
    }

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

    if liteClientProofGen.HasRealProofBuilder() {
        log.Printf("✅ [PROOF] Real L1-L3 ProofBuilder initialized with CometBFT consensus binding")
    } else {
        log.Printf("⚠️ [PROOF] Basic proof mode - CometBFT binding not available")
    }

    proofGenerator, err := proof.NewProofGenerator(liteClientProofGen, proofConfig)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create proof generator: %w", err)
    }

    // --- Anchor manager for Ethereum (now uses shared proof generator) ---
    // We'll create the anchor manager after the engine is set up in the validator

    // --- Target chain executor (BFT-aware wrapper) ---
    targetChainExecutor := execution.NewBFTTargetChainExecutor(
        log.New(os.Stdout, "[TARGET-CHAIN] ", log.LstdFlags),
    )
    // Create placeholder anchor wrapper for now - will be updated after engine is configured
    var anchorWrapper *execution.AnchorManagerWrapper
    targetChainWrapper := execution.NewTargetChainExecutorWrapper(targetChainExecutor, cfg.ValidatorID)

    log.Printf("✅ BFT execution components initialized (legacy IntentExecutor replaced)")

    // --- REAL CometBFT engine wiring (unified engine) ---
    log.Printf("🚀 Initializing unified BFT consensus with real CometBFT networking: %s", cfg.ValidatorID)
    cometEngine, err := consensus.NewUnifiedCometBFTEngine(cfg.ValidatorID)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create unified CometBFT engine: %w", err)
    }

    // Initialize BLS key for validator consensus
    // Keys are derived deterministically from validator ID or loaded from file
    // Key storage path can be set via BLS_KEY_PATH env var, defaults to ./data/bls_key.hex
    blsKeyPath := os.Getenv("BLS_KEY_PATH")
    if blsKeyPath == "" {
        blsKeyPath = filepath.Join("data", fmt.Sprintf("bls_key_%s.hex", cfg.ValidatorID))
    }
    blsKeyManager, err := bls.InitializeValidatorBLSKey(cfg.ValidatorID, cfg.ChainID, blsKeyPath)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to initialize BLS key: %w", err)
    }
    blsPubKeyHex := blsKeyManager.GetPublicKeyHex()
    log.Printf("✅ BLS key initialized: %s...%s (path: %s)",
        blsPubKeyHex[:16],
        blsPubKeyHex[len(blsPubKeyHex)-8:],
        blsKeyPath)
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
    govProofPath := os.Getenv("GOV_PROOF_CLI_PATH") // Optional: path to govproof CLI
    txhashPath := os.Getenv("TXHASH_CLI_PATH")       // Optional: path to txhash CLI for G2 payload verification
    govWorkDir := os.Getenv("GOV_PROOF_WORK_DIR")
    if govWorkDir == "" {
        govWorkDir = filepath.Join("data", "gov_proofs")
    }
    cliGovProofGen, govErr := proof.NewCLIGovernanceProofGenerator(
        govProofPath,
        cfg.AccumulateURL,
        govWorkDir,
        60*time.Second,
    )
    if govErr != nil {
        log.Printf("⚠️ [GOV-PROOF] CLI governance proof generator init failed: %v (proofs will be skipped)", govErr)
        // Fall back to in-process generator
        governanceProofGen = proof.NewInProcessGovernanceGenerator(
            cfg.AccumulateURL,
            govWorkDir,
            60*time.Second,
        )
        log.Printf("✅ In-process governance proof generator initialized (G0/G1/G2)")
    } else {
        // Set txhash path for G2 payload verification
        if txhashPath != "" {
            cliGovProofGen.SetTxHashPath(txhashPath)
            log.Printf("✅ TxHash tool configured for G2 payload verification: %s", txhashPath)
        }
        governanceProofGen = cliGovProofGen
        if govProofPath != "" {
            log.Printf("✅ CLI governance proof generator initialized: %s", govProofPath)
        } else {
            log.Printf("✅ Governance proof generator initialized (CLI not configured, using stub)")
        }
    }

    // Create BFT validator with engine injection (NEW SIGNATURE)
    validator := consensus.NewBFTValidator(
        cometEngine,                                                      // NEW: injected engine
        []consensus.BFTValidatorInfo{validatorInfo},
        consensusParams,
        cfg.ValidatorID,
        cfg.ChainID, // CometBFT chain ID from config
        privateKey,
        anchorWrapper,
        proofGenerator,
        governanceProofGen, // G0/G1/G2 governance proof generator (runs AFTER L1-L4)
        targetChainWrapper,
        validatorBlockBuilder,
        log.New(log.Writer(), "[BFTValidator] ", log.LstdFlags),
    )

    log.Printf("✅ BFT validator created with pure CometBFT consensus architecture")

    // LedgerStore is automatically configured within the ABCI application
    if ledgerProvider := cometEngine.GetLedgerStoreProvider(); ledgerProvider != nil {
        log.Printf("✅ LedgerStore configured in ABCI app for chain: %s", ledgerProvider.GetChainID())
    }

    // --- Create anchor manager now that engine is configured ---
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

    log.Printf("✅ Unified BFT consensus with real CometBFT networking active for validator: %s", cfg.ValidatorID)

    // ==========================================================================
    // PHASE 5: Wire Batch System for Real Merkle Roots
    // Per Implementation Plan: Connect batch collector/processor to AnchorManager
    // ==========================================================================
    var batchComponents *BatchComponents
    if dbClient != nil {
        log.Println("📦 [Phase 5] Initializing batch system with database storage...")

        // Create database repositories
        repos := database.NewRepositories(dbClient)

        // Wire repositories to ValidatorApp for consensus persistence
        // This enables the ABCI Commit() function to persist consensus entries and batch attestations
        cometEngine.SetValidatorRepositories(repos)
        cometEngine.SetValidatorCount(7) // 7 validators in the network
        log.Println("✅ [Phase 5] Database repositories wired to ValidatorApp for consensus persistence")

        // Create batch collector configuration
        collectorCfg := &batch.CollectorConfig{
            ValidatorID:  cfg.ValidatorID,
            MaxBatchSize: 1000,             // Max 1000 txs per batch
            BatchTimeout: 15 * time.Minute, // ~15 min batches per whitepaper
            MaxOnDemand:  5,                // Small on-demand batches for immediate anchoring
            Logger:       log.New(log.Writer(), "[BatchCollector] ", log.LstdFlags),
        }

        // Create batch collector
        collector, err := batch.NewCollector(repos, collectorCfg)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to create batch collector: %w", err)
        }
        log.Println("✅ [Phase 5] Batch collector created")

        // Create anchor adapter that bridges batch.Processor to AnchorManager
        // This uses the REAL Merkle roots from closed batches
        anchorManagerWrapper := batch.NewAnchorManagerWrapper(func(ctx context.Context, batchID string, merkleRoot, opCommit, crossCommit, govRoot []byte,
            txCount int, accumHeight int64, accumHash, targetChain, validatorID string) (
            txHash string, blockNumber int64, blockHash string, gasUsed int64,
            gasPriceWei, totalCostWei string, success bool, err error) {

            // Call the real AnchorManager's CreateBatchAnchorOnChain
            req := &anchor.AnchorOnChainRequest{
                BatchID:              batchID,
                MerkleRoot:           merkleRoot,
                OperationCommitment:  opCommit,
                CrossChainCommitment: crossCommit,
                GovernanceRoot:       govRoot,
                TxCount:              txCount,
                AccumulateHeight:     accumHeight,
                AccumulateHash:       accumHash,
                TargetChain:          targetChain,
                ValidatorID:          validatorID,
            }
            result, err := anchorManager.CreateBatchAnchorOnChain(ctx, req)
            if err != nil {
                return "", 0, "", 0, "", "", false, err
            }
            return result.TxHash, result.BlockNumber, result.BlockHash,
                result.GasUsed, result.GasPriceWei, result.TotalCostWei, result.Success, nil
        })

        // Wire the ExecuteComprehensiveProofOnChain function to enable Ethereum proof execution
        // Per CRITICAL-001: This MUST be set for comprehensive proofs to be submitted on-chain
        anchorManagerWrapper.SetExecuteProofFunc(anchorManager.ExecuteComprehensiveProofOnChain)
        log.Println("✅ [Phase 5] ExecuteComprehensiveProofOnChain wired to anchor manager")

        anchorAdapter := batch.NewAnchorAdapter(
            anchorManagerWrapper,
            log.New(log.Writer(), "[AnchorAdapter] ", log.LstdFlags),
        )
        log.Println("✅ [Phase 5] Anchor adapter created for real Merkle root anchoring")

        // Create batch processor configuration
        processorCfg := &batch.ProcessorConfig{
            ValidatorID:     cfg.ValidatorID,
            TargetChain:     "ethereum",
            ChainID:         fmt.Sprintf("%d", cfg.EthChainID),
            NetworkName:     cfg.NetworkName, // From NETWORK_NAME env var, defaults to "devnet"
            ContractAddress: cfg.CertenContractAddress,
            Logger:          log.New(log.Writer(), "[BatchProcessor] ", log.LstdFlags),
        }

        // Create batch processor
        processor, err := batch.NewProcessor(repos, anchorAdapter, processorCfg)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to create batch processor: %w", err)
        }
        log.Println("✅ [Phase 5] Batch processor created")

        // Wire Firestore sync service to batch collector and processor
        if firestoreSyncService != nil {
            collector.SetFirestoreSyncService(firestoreSyncService)
            processor.SetFirestoreSyncService(firestoreSyncService)
            log.Println("✅ [Firestore] Sync service wired to batch collector and processor")
        }

        // PHASE 5: Attestation callback will be wired after attestation service is created
        // See below after attestation service initialization

        // Create scheduler configuration
        schedulerCfg := &batch.SchedulerConfig{
            Interval:      15 * time.Minute, // ~15 min batches per whitepaper
            CheckInterval: 1 * time.Minute,  // Check every minute
            Callback: func(ctx context.Context, result *batch.ClosedBatchResult) error {
                // Process the closed batch (create anchor, store proofs)
                return processor.ProcessClosedBatch(ctx, result)
            },
            GetAccumState: func() (int64, string) {
                // Get current Accumulate state from lite client
                // Uses the LiteClientProofGenerator to query consensus state
                state, err := liteClientProofGen.GetConsensusState(context.Background())
                if err != nil {
                    log.Printf("⚠️ [BatchScheduler] Failed to get Accumulate state: %v", err)
                    return 0, ""
                }
                return state.BlockHeight, state.BlockHash
            },
            Logger: log.New(log.Writer(), "[BatchScheduler] ", log.LstdFlags),
        }

        // Create batch scheduler
        batchScheduler, err := batch.NewScheduler(collector, schedulerCfg)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to create batch scheduler: %w", err)
        }
        log.Println("✅ [Phase 5] Batch scheduler created")

        // Start the batch scheduler
        if err := batchScheduler.Start(context.Background()); err != nil {
            return nil, nil, fmt.Errorf("failed to start batch scheduler: %w", err)
        }
        log.Println("🚀 [Phase 5] Batch scheduler started - processing ~15 min on-cadence batches")

        // Create on-demand handler for immediate anchoring (~$0.25/proof)
        onDemandCfg := &batch.OnDemandConfig{
            MaxBatchSize: 5,
            MaxWaitTime:  30 * time.Second,
            Callback: func(ctx context.Context, result *batch.ClosedBatchResult) error {
                return processor.ProcessClosedBatch(ctx, result)
            },
            GetAccumState: schedulerCfg.GetAccumState,
            Logger:        log.New(log.Writer(), "[OnDemand] ", log.LstdFlags),
        }
        onDemandHandler, err := batch.NewOnDemandHandler(collector, onDemandCfg)
        if err != nil {
            return nil, nil, fmt.Errorf("failed to create on-demand handler: %w", err)
        }
        log.Println("✅ [Phase 5] On-demand handler created for immediate anchoring")

        // Create confirmation tracker for anchor finality monitoring
        confirmationCfg := &batch.ConfirmationTrackerConfig{
            PollInterval:          30 * time.Second,
            RequiredConfirmations: 12, // Standard Ethereum finality
            Logger:                log.New(log.Writer(), "[ConfirmationTracker] ", log.LstdFlags),
        }

        // Create Ethereum block provider using the Ethereum client
        blockProvider := batch.NewEthereumBlockProvider(
            func(ctx context.Context) (int64, error) {
                // Get latest block from Ethereum client
                // Note: ethClient is available in the outer scope
                return ethClient.GetLatestBlockNumber(ctx)
            },
            func(ctx context.Context, blockNumber int64) (string, time.Time, error) {
                // Get block info from Ethereum client
                return ethClient.GetBlockInfo(ctx, blockNumber)
            },
        )

        confirmationTracker, err := batch.NewConfirmationTracker(repos, blockProvider, confirmationCfg)
        if err != nil {
            log.Printf("⚠️ [Phase 5] Failed to create confirmation tracker: %v", err)
            // Continue without confirmation tracking - it's not critical
        } else {
            // Wire Firestore sync service to confirmation tracker
            if firestoreSyncService != nil {
                confirmationTracker.SetFirestoreSyncService(firestoreSyncService)
                log.Println("✅ [Firestore] Sync service wired to confirmation tracker")
            }
            // Start the confirmation tracker
            if err := confirmationTracker.Start(context.Background()); err != nil {
                log.Printf("⚠️ [Phase 5] Failed to start confirmation tracker: %v", err)
            } else {
                log.Println("✅ [Phase 5] Confirmation tracker started - monitoring anchor finality")
            }
        }

        // ==========================================================================
        // PHASE 5: Multi-Validator Attestation Service
        // Per Whitepaper Section 3.4.1 Component 4: Validator attestations
        // ==========================================================================
        var attestationService *attestation.Service
        attestationCfg := &attestation.Config{
            ValidatorID:   cfg.ValidatorID,
            PrivateKey:    privateKey,
            PeerEndpoints: cfg.AttestationPeers,
            RequiredCount: cfg.AttestationRequiredCount,
            Timeout:       30 * time.Second,
            Logger:        log.New(log.Writer(), "[Attestation] ", log.LstdFlags),
        }

        attestationService, err = attestation.NewService(repos, attestationCfg)
        if err != nil {
            log.Printf("⚠️ [Phase 5] Failed to create attestation service: %v", err)
            // Continue without attestation - it's not critical for single-validator testing
        } else {
            log.Printf("✅ [Phase 5] Attestation service created with %d peers", len(cfg.AttestationPeers))

            // Wire attestation callback to batch processor
            // This triggers multi-validator attestation collection when a batch is anchored
            processor.SetOnAnchorCallback(func(ctx context.Context, batchID uuid.UUID, merkleRoot []byte, anchorTxHash string, txCount int, blockNumber int64) error {
                status, err := attestationService.OnBatchAnchored(ctx, batchID, merkleRoot, anchorTxHash, txCount, blockNumber)
                if err != nil {
                    return err
                }
                log.Printf("📜 Attestation status for batch %s: %d/%d validators attested",
                    batchID, status.CollectedCount, status.RequiredCount)
                return nil
            })
            log.Printf("✅ [Phase 5] Attestation callback wired to batch processor")
        }

        // ==========================================================================
        // PHASE 4 Task 4.3: Event Watcher for Contract Event Monitoring
        // Per Implementation Plan: Monitor CertenAnchorV3 contract events
        // This provides visibility into on-chain anchor confirmations and proof executions
        // ==========================================================================
        if cfg.CertenContractAddress != "" && cfg.EthereumURL != "" {
            eventWatcherConfig := &anchor.EventWatcherConfig{
                ContractAddress: common.HexToAddress(cfg.CertenContractAddress),
                EthereumURL:     cfg.EthereumURL,
                ChainID:         cfg.EthChainID,
                PollInterval:    30 * time.Second,
                BlockLookback:   100,
                EventBufferSize: 500,
                RetryAttempts:   3,
                RetryDelay:      5 * time.Second,
            }

            eventWatcher, eventWatcherErr := anchor.NewEventWatcher(
                eventWatcherConfig,
                log.New(log.Writer(), "[EventWatcher] ", log.LstdFlags),
            )

            if eventWatcherErr != nil {
                log.Printf("⚠️ [Phase 4] Failed to create event watcher: %v", eventWatcherErr)
            } else {
                // Register handlers for contract events
                eventWatcher.RegisterHandler(anchor.EventTypeAnchorCreated, func(event anchor.ContractEvent) error {
                    e := event.(*anchor.AnchorCreatedEvent)
                    log.Printf("📡 [EventWatcher] AnchorCreated: bundleId=%x..., block=%d, validator=%s",
                        e.BundleID[:8], e.BlockNumber, e.Validator.Hex()[:10])
                    return nil
                })

                eventWatcher.RegisterHandler(anchor.EventTypeProofExecuted, func(event anchor.ContractEvent) error {
                    e := event.(*anchor.ProofExecutedEvent)
                    log.Printf("📡 [EventWatcher] ProofExecuted: anchorId=%x..., merkle=%v, bls=%v, gov=%v",
                        e.AnchorID[:8], e.MerkleVerified, e.BLSVerified, e.GovernanceVerified)
                    return nil
                })

                eventWatcher.RegisterHandler(anchor.EventTypeProofVerificationFailed, func(event anchor.ContractEvent) error {
                    e := event.(*anchor.ProofVerificationFailedEvent)
                    log.Printf("⚠️ [EventWatcher] ProofVerificationFailed: anchorId=%x..., reason=%s",
                        e.AnchorID[:8], e.Reason)
                    return nil
                })

                // Start the event watcher
                if err := eventWatcher.Start(context.Background()); err != nil {
                    log.Printf("⚠️ [Phase 4] Failed to start event watcher: %v", err)
                } else {
                    log.Printf("✅ [Phase 4] Event watcher started - monitoring contract %s", cfg.CertenContractAddress[:10])
                }
            }
        } else {
            log.Printf("⚠️ [Phase 4] Event watcher not started - contract address or Ethereum URL not configured")
        }

        // Package all batch components
        batchComponents = &BatchComponents{
            Scheduler:            batchScheduler,
            Collector:            collector,
            Processor:            processor,
            OnDemandHandler:      onDemandHandler,
            ConfirmationTracker:  confirmationTracker,
            AttestationService:   attestationService,
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
    } else {
        log.Println("⚠️ [Phase 5] Database not available - batch system disabled")
        // E.2 remediation: Health status already set to disconnected/disabled in main
    }

    // ==========================================================================
    // PHASE 7-9: Proof Cycle Orchestrator for Complete Cryptographic Loop
    // Per COMPREHENSIVE_REMEDIATION_PLAN.md Group A
    // ==========================================================================
    log.Println("🔄 [Phase 7-9] Initializing Proof Cycle Orchestrator...")

    // Create AccumulateSubmitter for proof write-back
    // If Accumulate write-back credentials are configured, use real submitter
    // Otherwise, use null submitter that logs but doesn't submit
    var accSubmitter execution.AccumulateSubmitter

    accWritebackPrincipal := os.Getenv("ACCUMULATE_RESULTS_PRINCIPAL")
    accSignerURL := os.Getenv("ACCUMULATE_SIGNER_URL")
    writebackEnabled := os.Getenv("PROOF_CYCLE_WRITEBACK") == "true"

    if writebackEnabled && accWritebackPrincipal != "" && accSignerURL != "" {
        log.Printf("📝 [Phase 9] Configuring real Accumulate write-back:")
        log.Printf("   - Principal: %s", accWritebackPrincipal)
        log.Printf("   - Signer: %s", accSignerURL)

        // Check for optional separate write-back private key
        // This allows using a different key than the validator's key for signing write-back transactions
        writebackPrivKey := privateKey
        if writebackKeyHex := os.Getenv("ACCUMULATE_WRITEBACK_PRIV_KEY"); writebackKeyHex != "" {
            log.Printf("   - Using dedicated write-back private key from ACCUMULATE_WRITEBACK_PRIV_KEY")
            keyBytes, err := hex.DecodeString(strings.TrimSpace(writebackKeyHex))
            if err != nil {
                log.Printf("⚠️ [Phase 9] Invalid ACCUMULATE_WRITEBACK_PRIV_KEY: %v (falling back to validator key)", err)
            } else if len(keyBytes) != ed25519.PrivateKeySize {
                log.Printf("⚠️ [Phase 9] Invalid ACCUMULATE_WRITEBACK_PRIV_KEY size: expected %d, got %d (falling back to validator key)", ed25519.PrivateKeySize, len(keyBytes))
            } else {
                writebackPrivKey = ed25519.PrivateKey(keyBytes)
                log.Printf("✅ [Phase 9] Loaded dedicated write-back private key")
            }
        }

        submitterCfg := &execution.AccumulateSubmitterConfig{
            Client:              liteClientAdapter,
            PrivateKey:          writebackPrivKey,
            AccountURL:          accWritebackPrincipal,
            SignerURL:           accSignerURL,
            KeyPageIndex:        1,
            KeyIndex:             0,
            ConfirmationTimeout: 2 * time.Minute,
            MaxRetries:          3,
            RetryDelay:          5 * time.Second,
            Logger:              log.New(log.Writer(), "[AccSubmitter] ", log.LstdFlags),
        }

        var submitErr error
        accSubmitter, submitErr = execution.NewAccumulateSubmitter(submitterCfg)
        if submitErr != nil {
            log.Printf("⚠️ [Phase 9] Failed to create Accumulate submitter: %v (using null submitter)", submitErr)
            accSubmitter = execution.NewNullAccumulateSubmitter(log.New(log.Writer(), "[NullSubmitter] ", log.LstdFlags))
        } else {
            log.Printf("✅ [Phase 9] Real Accumulate submitter configured")
        }
    } else {
        log.Printf("⚠️ [Phase 9] Accumulate write-back not configured (PROOF_CYCLE_WRITEBACK=true required)")
        log.Printf("   Using null submitter - proof results will be logged but not written to Accumulate")
        accSubmitter = execution.NewNullAccumulateSubmitter(log.New(log.Writer(), "[NullSubmitter] ", log.LstdFlags))
    }

    // Create Proof Cycle Orchestrator configuration
    orchestratorConfig := &execution.ProofCycleConfig{
        EthereumRPC:           cfg.EthereumURL,
        ChainID:               cfg.EthChainID,
        RequiredConfirmations: 12,
        ObservationTimeout:    10 * time.Minute,
        ThresholdNumerator:    2,
        ThresholdDenominator:  3,
        AccumulatePrincipal:   accWritebackPrincipal,
        WriteBackEnabled:      writebackEnabled,
        BLSPrivateKey:         blsKeyManager.GetPrivateKeyBytes(),
    }

    // Get validator address from BLS public key
    validatorAddress := blsKeyManager.GetAddress()

    // Create validator set (single validator for now, will load from config/contract later)
    validatorSet := execution.NewValidatorSetFromConfig(cfg.ValidatorID, validatorAddress)

    // Create Proof Cycle Orchestrator
    // Pass database repositories for proof artifact persistence (enables web app to track all 9 stages)
    var orchestratorRepos *database.Repositories
    if batchComponents != nil {
        orchestratorRepos = batchComponents.Repos
    }
    orchestrator, orchestratorErr := execution.NewProofCycleOrchestrator(
        cfg.ValidatorID,
        validatorAddress,
        0, // validator index
        validatorSet,
        orchestratorConfig,
        accSubmitter,
        orchestratorRepos,
        log.New(log.Writer(), "[ProofCycle] ", log.LstdFlags),
    )

    if orchestratorErr != nil {
        log.Printf("⚠️ [Phase 7-9] Failed to create proof cycle orchestrator: %v", orchestratorErr)
        log.Printf("   Phase 7-9 disabled - execution will complete without proof write-back")
        // F.2 remediation: Update health status for proof cycle
        healthStatus.SetProofCycle("disabled")
    } else {
        // ==========================================================================
        // UNIFIED MULTI-CHAIN ORCHESTRATOR (Feature Flag Controlled)
        // Per Unified Multi-Chain Architecture plan
        // ==========================================================================
        if cfg.UseUnifiedOrchestrator {
            log.Printf("🔄 [Unified] Initializing Unified Multi-Chain Orchestrator...")

            // Create strategy registry with all attestation and chain strategies
            strategyRegistry, registryErr := initializeStrategyRegistry(cfg, blsKeyManager, privateKey)
            if registryErr != nil {
                log.Printf("⚠️ [Unified] Failed to create strategy registry: %v (falling back to legacy)", registryErr)
            } else {
                // Get unified repository
                var unifiedRepo *database.UnifiedRepository
                if batchComponents != nil && batchComponents.Repos != nil {
                    unifiedRepo = batchComponents.Repos.Unified
                }

                // Create proof generator adapter for chained proofs (L1/L2/L3)
                var proofGenAdapter *execution.LiteClientProofGeneratorAdapter
                if liteClientProofGen != nil && liteClientProofGen.HasRealProofBuilder() {
                    proofGenAdapter = execution.NewLiteClientProofGeneratorAdapter(liteClientProofGen)
                    log.Printf("   - Chained Proof Generator: enabled (L1/L2/L3 proofs)")
                } else {
                    log.Printf("   - Chained Proof Generator: disabled (no real proof builder)")
                }

                // Create unified orchestrator configuration
                unifiedConfig := &execution.UnifiedOrchestratorConfig{
                    ValidatorID:          cfg.ValidatorID,
                    ValidatorIndex:       0,
                    Registry:             strategyRegistry,
                    Repos:                orchestratorRepos,
                    UnifiedRepo:          unifiedRepo,
                    DefaultChainID:       cfg.DefaultTargetChain,
                    ThresholdConfig:      attestationStrategy.DefaultThresholdConfig(),
                    ObservationTimeout:   10 * time.Minute,
                    AttestationTimeout:   5 * time.Minute,
                    WriteBackTimeout:     2 * time.Minute,
                    AttestationPeers:     cfg.AttestationPeers,
                    AttestationRequiredCount: cfg.AttestationRequiredCount,
                    AccumulateClient:     accSubmitter,
                    ResultsPrincipal:     accWritebackPrincipal,
                    Ed25519Key:           privateKey,
                    EnableMultiChain:     cfg.EnableMultiChain,
                    EnableUnifiedTables:  cfg.EnableUnifiedTables,
                    FallbackToLegacy:     cfg.FallbackToLegacy,
                    EnableWriteBack:      writebackEnabled,
                    ProofGenerator:       proofGenAdapter,
                    AccumulateQueryClient: liteClientAdapter, // For querying tx governance data (M-of-N threshold)
                }

                unifiedOrchestrator, unifiedErr := execution.NewUnifiedOrchestrator(unifiedConfig)
                if unifiedErr != nil {
                    log.Printf("⚠️ [Unified] Failed to create unified orchestrator: %v (falling back to legacy)", unifiedErr)
                } else {
                    // Create adapter that implements ProofCycleOrchestratorInterface
                    adapter := execution.NewUnifiedOrchestratorAdapter(
                        unifiedOrchestrator,
                        orchestrator, // Legacy orchestrator for fallback
                        true,         // useUnified = true
                        cfg.FallbackToLegacy,
                    )

                    // Wire adapter to validator (implements same interface as legacy)
                    validator.SetProofCycleOrchestrator(adapter)
                    log.Printf("✅ [Unified] Unified Multi-Chain Orchestrator initialized and wired to validator")
                    log.Printf("   - Strategy Registry: %d attestation schemes, %d chains",
                        len(strategyRegistry.ListAttestationSchemes()),
                        len(strategyRegistry.ListChainIDs()))
                    log.Printf("   - Default Chain: %s", cfg.DefaultTargetChain)
                    log.Printf("   - Multi-Chain: %v", cfg.EnableMultiChain)
                    log.Printf("   - Unified Tables: %v", cfg.EnableUnifiedTables)
                    log.Printf("   - Fallback to Legacy: %v", cfg.FallbackToLegacy)
                    healthStatus.SetProofCycle("active")

                    // Skip wiring legacy orchestrator
                    goto afterOrchestrator
                }
            }
        }

        // Wire legacy orchestrator to BFT validator (default or fallback)
        validator.SetProofCycleOrchestrator(orchestrator)
        log.Printf("✅ [Phase 7-9] Proof Cycle Orchestrator initialized and wired to validator")
        log.Printf("   - Ethereum RPC: %s", cfg.EthereumURL)
        log.Printf("   - Confirmations: %d", orchestratorConfig.RequiredConfirmations)
        log.Printf("   - Write-back: %v", writebackEnabled)
        // F.2 remediation: Update health status for proof cycle
        healthStatus.SetProofCycle("active")

    afterOrchestrator:
    }

    // --- Intent discovery wiring ---
    log.Printf("🔍 Starting Certen Intent Discovery Service for validator...")

    // Create IntentDiscovery configuration
    intentConfig := &intent.IntentDiscoveryConfig{
        BlockPollInterval:   5 * time.Second,
        BFTTimeout:          30 * time.Second,
        MaxConcurrentBlocks: 2000,  // Increased from 10 to handle high block rate
        IntentBatchSize:     100,   // Increased from 50 to process more intents per batch
        MinStartHeight:      0,
    }

    // Get LedgerStore from ABCI application and wrap it for IntentDiscovery
    var ledgerWrapper *LedgerStoreWrapper
    if ledgerProvider := cometEngine.GetLedgerStoreProvider(); ledgerProvider != nil && ledgerProvider.GetLedgerStore() != nil {
        ledgerWrapper = &LedgerStoreWrapper{store: ledgerProvider.GetLedgerStore()}
    }

    // Create IntentDiscovery with proper configuration and persistence
    intentDiscovery := intent.NewIntentDiscovery(accClient, cfg.AccumulateURL, intentConfig, ledgerWrapper, liteClientProofGen, cfg.ValidatorID)

    // This is the critical hook: IntentDiscovery calls the canonical BFT consensus method
    // BFTValidator.ExecuteCanonicalIntentWithBFTConsensus(ctx, certenIntent, certenProof, blockHeight)
    // with properly structured CertenIntent (4-blob canonical) and CertenProof from lite client
    intentDiscovery.SetBFTConsensus(validator)

    // PHASE 5: Wire batch system to intent discovery for PostgreSQL persistence
    // This enables routing intents based on proofClass (on_demand vs on_cadence)
    if batchComponents != nil {
        intentDiscovery.SetBatchSystem(batchComponents.Collector, batchComponents.OnDemandHandler)
        log.Printf("✅ [Phase 5] Batch system wired to intent discovery:")
        log.Printf("   - on_cadence intents → BatchCollector → ~$0.05/proof")
        log.Printf("   - on_demand intents → OnDemandHandler → ~$0.25/proof")
    } else {
        log.Printf("⚠️ [Phase 5] Batch system not available - intents will bypass PostgreSQL")
    }

    // Wire governance proof generator to intent discovery for G0/G1/G2 proof generation
    // This ensures governance proofs are generated BEFORE batch routing, so they are persisted correctly
    if governanceProofGen != nil {
        intentDiscovery.SetGovernanceProofGenerator(governanceProofGen)
        log.Printf("✅ [Phase 5] Governance proof generator wired to intent discovery")
        log.Printf("   - G0/G1/G2 proofs generated before PostgreSQL persistence")
    }

    go intentDiscovery.StartMonitoring()

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

// generateDeterministicValidatorKey remains if you still need it for validator sets elsewhere
func generateDeterministicValidatorKey(validatorID string) ed25519.PrivateKey {
    baseKey := os.Getenv("ACCUM_PRIV_KEY")
    if baseKey == "" {
        baseKey = "833224d93dde732803e77a52d51a1ba5aa0d5f53c105772fe2e42d8b94ff151e2f07a1a5681a8149d38c8fd08b8470dfc9ad87c8bb541ddd74342d088b29fcb7"
    }

    hasher := sha256.New()
    hasher.Write([]byte(baseKey))
    hasher.Write([]byte(validatorID))
    hasher.Write([]byte("CERTEN_VALIDATOR_BFT_CONSENSUS"))
    seed := hasher.Sum(nil)

    privateKeySeed := seed[:32]
    privateKey := ed25519.NewKeyFromSeed(privateKeySeed)
    return privateKey
}

// initializeStrategyRegistry creates and populates the strategy registry
// with all attestation and chain execution strategies
// Per Unified Multi-Chain Architecture plan
func initializeStrategyRegistry(
    cfg *config.Config,
    blsKeyManager *bls.KeyManager,
    ed25519Key ed25519.PrivateKey,
) (*strategy.Registry, error) {
    // Create registry configuration
    regConfig := &strategy.RegistryConfig{
        ValidatorID:       cfg.ValidatorID,
        ValidatorIndex:    0, // Would come from validator set
        BLSPrivateKey:     blsKeyManager.GetPrivateKeyBytes(),
        Ed25519PrivateKey: ed25519Key,
        EthereumRPC:       cfg.EthereumURL,
        EthPrivateKey:     cfg.EthPrivateKey,
        EthChainID:        cfg.EthChainID,
        AnchorContract:    cfg.AnchorContractAddress,
        CertenContract:    cfg.CertenContractAddress,
        NetworkName:       cfg.NetworkName,
        Logger:            log.New(log.Writer(), "[StrategyRegistry] ", log.LstdFlags),
    }

    // Initialize the registry with all strategies
    return strategy.InitializeRegistry(regConfig)
}

func printHelp() {
    fmt.Println("Certen BFT Validator Service")
    fmt.Println()
    fmt.Println("Usage:")
    fmt.Println("  validator-service [OPTIONS]")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  --validator-id=ID        Validator ID (default: validator-1)")
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