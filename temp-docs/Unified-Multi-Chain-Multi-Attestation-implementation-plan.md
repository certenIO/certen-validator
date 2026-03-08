  # Unified Multi-Chain & Multi-Attestation Architecture

  ## Executive Summary

  This plan unifies both **on_demand** and **on_cadence** proof flows through a single orchestrator while supporting:
  - **Multiple Attestation Strategies**: BLS12-381, Ed25519, future schemes (Schnorr, threshold)
  - **Multiple Chain Execution Strategies**: EVM, CosmWasm, Solana, Move (Aptos/Sui), TON, NEAR
  - **Complete Proof Artifact Collection**: All flows populate the same PostgreSQL tables

  ---

  ## 1. Architecture Overview

  ### 1.1 Current Problem

  Two separate flows with different attestation schemes and incomplete data:

  | Flow | Attestation | Tables Used | Orchestrator |
  |------|-------------|-------------|--------------|
  | on_demand (BFT) | BLS12-381 | bls_result_attestations | ProofCycleOrchestrator |
  | on_cadence (Batch) | Ed25519 | validator_attestations | None (direct to DB) |

  ### 1.2 Target Architecture

  ```
  ┌─────────────────────────────────┐
  │      StrategyRegistry           │
  │  ┌─────────────────────────┐    │
  │  │ AttestationStrategies   │    │
  │  │  - BLS12381Strategy     │    │
  │  │  - Ed25519Strategy      │    │
  │  └─────────────────────────┘    │
  │  ┌─────────────────────────┐    │
  │  │ ChainExecutionStrategies│    │
  │  │  - EVMStrategy          │    │
  │  │  - SolanaStrategy       │    │
  │  │  - CosmWasmStrategy     │    │
  │  │  - MoveStrategy         │    │
  │  │  - TONStrategy          │    │
  │  │  - NEARStrategy         │    │
  │  └─────────────────────────┘    │
  └─────────────────────────────────┘
  │
  ┌───────────────────────────────────────────┼───────────────────────────────────────────┐
  │                                           │                                           │
  ▼                                           ▼                                           ▼
  ┌───────────────┐                        ┌─────────────────────┐                     ┌───────────────┐
  │  on_demand    │                        │ UnifiedProofCycle   │                     │  on_cadence   │
  │  (immediate)  │───────────────────────▶│    Orchestrator     │◀────────────────────│  (batched)    │
  └───────────────┘                        └─────────────────────┘                     └───────────────┘
  │
  ┌───────────────┼───────────────┐
  ▼               ▼               ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐
  │ Phase 7  │   │ Phase 8  │   │ Phase 9  │
  │ Observe  │   │ Attest   │   │WriteBack │
  └──────────┘   └──────────┘   └──────────┘
  │               │               │
  ▼               ▼               ▼
  ┌─────────────────────────────────────────────┐
  │         Unified PostgreSQL Tables           │
  │  - proof_artifacts                          │
  │  - unified_attestations                     │
  │  - aggregated_attestations                  │
  │  - chain_execution_results                  │
  └─────────────────────────────────────────────┘
  ```

  ---

  ## 2. Core Interface Definitions

  ### 2.1 AttestationStrategy Interface

  **File:** `pkg/attestation/strategy/interface.go`

  ```go
  // AttestationScheme identifies the cryptographic scheme
  type AttestationScheme string

  const (
  AttestationSchemeBLS12381  AttestationScheme = "bls12-381"
  AttestationSchemeEd25519   AttestationScheme = "ed25519"
  AttestationSchemeSchnorr   AttestationScheme = "schnorr"     // Future
  AttestationSchemeThreshold AttestationScheme = "threshold"   // Future
  )

  // AttestationMessage is the canonical message to be signed
  type AttestationMessage struct {
  IntentID      string   `json:"intent_id"`
  ResultHash    [32]byte `json:"result_hash"`
  AnchorTxHash  string   `json:"anchor_tx_hash"`
  BlockNumber   uint64   `json:"block_number"`
  TargetChain   string   `json:"target_chain"`
  Timestamp     int64    `json:"timestamp"`
  }

  // Attestation represents a single validator's attestation
  type Attestation struct {
  AttestationID uuid.UUID         `json:"attestation_id"`
  Scheme        AttestationScheme `json:"scheme"`
  ValidatorID   string            `json:"validator_id"`
  PublicKey     []byte            `json:"public_key"`
  Signature     []byte            `json:"signature"`
  Message       *AttestationMessage `json:"message"`
  Weight        int64             `json:"weight"` // Voting power
  Timestamp     time.Time         `json:"timestamp"`
  }

  // AggregatedAttestation represents multiple attestations combined
  type AggregatedAttestation struct {
  Scheme              AttestationScheme `json:"scheme"`
  AggregatedSignature []byte            `json:"aggregated_signature,omitempty"` // BLS only
  AggregatedPublicKey []byte            `json:"aggregated_public_key,omitempty"` // BLS only
  Attestations        []*Attestation    `json:"attestations"` // For non-aggregatable schemes
  ParticipantCount    int               `json:"participant_count"`
  TotalWeight         int64             `json:"total_weight"`
  ThresholdWeight     int64             `json:"threshold_weight"`
  ThresholdMet        bool              `json:"threshold_met"`
  }

  // AttestationStrategy defines the interface for all attestation schemes
  type AttestationStrategy interface {
  // Scheme returns the attestation scheme identifier
  Scheme() AttestationScheme

  // Sign creates an attestation for the given message
  Sign(ctx context.Context, message *AttestationMessage) (*Attestation, error)

  // Verify verifies a single attestation
  Verify(ctx context.Context, attestation *Attestation) (bool, error)

  // Aggregate combines multiple attestations (if supported by scheme)
  Aggregate(ctx context.Context, attestations []*Attestation) (*AggregatedAttestation, error)

  // VerifyAggregated verifies an aggregated attestation
  VerifyAggregated(ctx context.Context, agg *AggregatedAttestation) (bool, error)

  // SupportsAggregation returns true if scheme supports signature aggregation
  SupportsAggregation() bool

  // PublicKey returns this validator's public key for the scheme
  PublicKey() []byte

  // ValidatorID returns the validator identifier
  ValidatorID() string
  }
  ```

  ### 2.2 ChainExecutionStrategy Interface

  **File:** `pkg/chain/strategy/interface.go`

  ```go
  // ChainPlatform identifies the blockchain platform
  type ChainPlatform string

  const (
  ChainPlatformEVM      ChainPlatform = "evm"
  ChainPlatformCosmWasm ChainPlatform = "cosmwasm"
  ChainPlatformSolana   ChainPlatform = "solana"
  ChainPlatformMove     ChainPlatform = "move"      // Aptos & Sui
  ChainPlatformTON      ChainPlatform = "ton"
  ChainPlatformNEAR     ChainPlatform = "near"
  )

  // ChainConfig holds configuration for a specific chain
  type ChainConfig struct {
  Platform              ChainPlatform     `json:"platform"`
  ChainID               string            `json:"chain_id"`
  NetworkName           string            `json:"network_name"`
  RPC                   string            `json:"rpc"`
  ContractAddress       string            `json:"contract_address"`
  RequiredConfirmations int               `json:"required_confirmations"`
  AttestationScheme     AttestationScheme `json:"attestation_scheme"`
  PlatformConfig        map[string]interface{} `json:"platform_config,omitempty"`
  }

  // AnchorRequest is the chain-agnostic request to create an anchor
  type AnchorRequest struct {
  IntentID             string   `json:"intent_id"`
  BundleID             [32]byte `json:"bundle_id"`
  MerkleRoot           [32]byte `json:"merkle_root"`
  OperationCommitment  [32]byte `json:"operation_commitment"`
  CrossChainCommitment [32]byte `json:"cross_chain_commitment"`
  GovernanceRoot       [32]byte `json:"governance_root"`
  Timestamp            int64    `json:"timestamp"`
  }

  // AnchorResult is the chain-agnostic anchor result
  type AnchorResult struct {
  TxHash      string    `json:"tx_hash"`
  BlockNumber uint64    `json:"block_number"`
  BlockHash   string    `json:"block_hash"`
  GasUsed     uint64    `json:"gas_used"`
  Status      uint8     `json:"status"` // 0=pending, 1=success, 2=failed
  Timestamp   time.Time `json:"timestamp"`
  }

  // ObservationResult is the chain-agnostic observation result
  type ObservationResult struct {
  TxHash        string    `json:"tx_hash"`
  BlockNumber   uint64    `json:"block_number"`
  BlockHash     string    `json:"block_hash"`
  Status        uint8     `json:"status"`
  Confirmations int       `json:"confirmations"`
  IsFinalized   bool      `json:"is_finalized"`
  ResultHash    [32]byte  `json:"result_hash"`
  MerkleProof   []byte    `json:"merkle_proof,omitempty"` // Chain-specific
  RawReceipt    []byte    `json:"raw_receipt,omitempty"`
  Timestamp     time.Time `json:"timestamp"`
  }

  // ChainExecutionStrategy defines the interface for chain-specific operations
  type ChainExecutionStrategy interface {
  // Platform returns the chain platform identifier
  Platform() ChainPlatform

  // ChainID returns the specific chain ID
  ChainID() string

  // CreateAnchor creates an anchor transaction on the chain
  CreateAnchor(ctx context.Context, req *AnchorRequest) (*AnchorResult, error)

  // SubmitProof submits proof for on-chain verification (Step 2)
  SubmitProof(ctx context.Context, anchorID [32]byte, proof *ProofSubmission) (*AnchorResult, error)

  // ExecuteWithGovernance executes with governance verification (Step 3)
  ExecuteWithGovernance(ctx context.Context, anchorID [32]byte, params *ExecutionParams) (*AnchorResult, error)

  // ObserveTransaction watches a transaction until finalization
  ObserveTransaction(ctx context.Context, txHash string) (*ObservationResult, error)

  // GetRequiredConfirmations returns confirmations needed for finality
  GetRequiredConfirmations() int

  // HealthCheck verifies connectivity to the chain
  HealthCheck(ctx context.Context) error
  }
  ```

  ### 2.3 Strategy Registry

  **File:** `pkg/strategy/registry.go`

  ```go
  // StrategyRegistry manages attestation and chain execution strategies
  type StrategyRegistry struct {
  mu sync.RWMutex

  // Attestation strategies by scheme
  attestationStrategies map[AttestationScheme]AttestationStrategy

  // Chain execution strategies by chainID
  chainStrategies map[string]ChainExecutionStrategy

  // Chain configs
  chainConfigs map[string]*ChainConfig

  // Default attestation scheme per platform
  platformDefaults map[ChainPlatform]AttestationScheme
  }

  // NewStrategyRegistry creates a registry with default mappings
  func NewStrategyRegistry() *StrategyRegistry {
  return &StrategyRegistry{
  attestationStrategies: make(map[AttestationScheme]AttestationStrategy),
  chainStrategies:       make(map[string]ChainExecutionStrategy),
  chainConfigs:          make(map[string]*ChainConfig),
  platformDefaults: map[ChainPlatform]AttestationScheme{
  ChainPlatformEVM:      AttestationSchemeBLS12381, // BLS for EVM (ZK-verified)
  ChainPlatformCosmWasm: AttestationSchemeEd25519,  // Ed25519 native support
  ChainPlatformSolana:   AttestationSchemeEd25519,  // Ed25519 native support
  ChainPlatformMove:     AttestationSchemeEd25519,  // Ed25519 for cost
  ChainPlatformTON:      AttestationSchemeEd25519,  // Ed25519 native support
  ChainPlatformNEAR:     AttestationSchemeEd25519,  // Ed25519 native support
  },
  }
  }

  // Key methods:
  // - RegisterAttestationStrategy(strategy AttestationStrategy)
  // - RegisterChainStrategy(chainID string, config *ChainConfig, strategy ChainExecutionStrategy)
  // - GetAttestationStrategy(scheme AttestationScheme) (AttestationStrategy, error)
  // - GetChainStrategy(chainID string) (ChainExecutionStrategy, error)
  // - GetAttestationSchemeForChain(chainID string) (AttestationScheme, error)
  ```

  ---

  ## 3. Database Schema Updates

  **File:** `pkg/database/migrations/003_unified_multi_chain.sql`

  ```sql
  -- Add columns to proof_artifacts for unified tracking
  ALTER TABLE proof_artifacts ADD COLUMN IF NOT EXISTS attestation_scheme VARCHAR(32) DEFAULT 'ed25519';
  ALTER TABLE proof_artifacts ADD COLUMN IF NOT EXISTS chain_platform VARCHAR(32) DEFAULT 'evm';

  -- Unified attestations table (scheme-agnostic)
  CREATE TABLE IF NOT EXISTS unified_attestations (
  attestation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proof_id UUID REFERENCES proof_artifacts(proof_id),
  cycle_id VARCHAR(255) NOT NULL,

  -- Attestation scheme
  scheme VARCHAR(32) NOT NULL,

  -- Validator identity
  validator_id VARCHAR(255) NOT NULL,
  public_key BYTEA NOT NULL,

  -- Signature data
  signature BYTEA NOT NULL,
  message_hash BYTEA NOT NULL,

  -- Weight for quorum
  weight BIGINT DEFAULT 1,

  -- Verification
  signature_valid BOOLEAN,
  verified_at TIMESTAMPTZ,

  -- Timestamps
  attested_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(proof_id, validator_id, scheme)
  );

  -- Aggregated attestations table (scheme-agnostic)
  CREATE TABLE IF NOT EXISTS aggregated_attestations (
  aggregation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proof_id UUID REFERENCES proof_artifacts(proof_id),
  cycle_id VARCHAR(255) NOT NULL,

  -- Scheme
  scheme VARCHAR(32) NOT NULL,
  message_hash BYTEA NOT NULL,

  -- Aggregated signature (BLS only, NULL for Ed25519)
  aggregated_signature BYTEA,
  aggregated_public_key BYTEA,

  -- Participants
  participant_ids JSONB NOT NULL,
  participant_count INT NOT NULL,

  -- Threshold tracking
  total_weight BIGINT NOT NULL,
  threshold_weight BIGINT NOT NULL,
  achieved_weight BIGINT NOT NULL,
  threshold_met BOOLEAN NOT NULL,

  -- Verification
  aggregation_valid BOOLEAN,
  verified_at TIMESTAMPTZ,

  -- Timestamps
  aggregated_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(proof_id, scheme)
  );

  -- Chain execution results (platform-agnostic)
  CREATE TABLE IF NOT EXISTS chain_execution_results (
  result_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  proof_id UUID REFERENCES proof_artifacts(proof_id),
  cycle_id VARCHAR(255) NOT NULL,

  -- Chain identification
  chain_platform VARCHAR(32) NOT NULL,
  chain_id VARCHAR(64) NOT NULL,
  network_name VARCHAR(64),

  -- Transaction details
  tx_hash VARCHAR(128) NOT NULL,
  block_number BIGINT,
  block_hash VARCHAR(128),

  -- Execution status
  status SMALLINT NOT NULL DEFAULT 0,
  gas_used BIGINT,

  -- Confirmations
  confirmations INT DEFAULT 0,
  required_confirmations INT,
  is_finalized BOOLEAN DEFAULT FALSE,

  -- Platform-specific data
  raw_receipt JSONB,
  merkle_proof BYTEA,
  result_hash BYTEA,

  -- Timestamps
  submitted_at TIMESTAMPTZ,
  confirmed_at TIMESTAMPTZ,
  finalized_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),

  UNIQUE(chain_id, tx_hash)
  );

  -- Indexes
  CREATE INDEX IF NOT EXISTS idx_unified_attestations_proof ON unified_attestations(proof_id);
  CREATE INDEX IF NOT EXISTS idx_unified_attestations_scheme ON unified_attestations(scheme);
  CREATE INDEX IF NOT EXISTS idx_aggregated_attestations_proof ON aggregated_attestations(proof_id);
  CREATE INDEX IF NOT EXISTS idx_chain_execution_proof ON chain_execution_results(proof_id);
  CREATE INDEX IF NOT EXISTS idx_chain_execution_chain ON chain_execution_results(chain_id, tx_hash);
  ```

  ---

  ## 4. Unified Flow Diagrams

  ### 4.1 on_demand Flow (New Architecture)

  ```
  Intent Discovery (CERTEN_INTENT with proof_class="on_demand")
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  Extract target_chain from intent legs[].chain                    │
  │  e.g., "ethereum", "solana", "osmosis"                           │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  BFTValidator.ExecuteCanonicalIntentWithBFTConsensus()           │
  │  - Build ValidatorBlock with proofs                               │
  │  - CometBFT consensus (2/3+1)                                    │
  │  - Elect executor deterministically                               │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  StrategyRegistry.GetChainStrategy(targetChainID)                │
  │  Returns: EVMStrategy | SolanaStrategy | CosmWasmStrategy | etc  │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  ChainStrategy.CreateAnchor() → SubmitProof() → Execute()        │
  │  (3-step anchor workflow, chain-specific implementation)          │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  UnifiedProofCycleOrchestrator.StartUnifiedProofCycle()          │
  │                                                                   │
  │  Phase 7: ChainStrategy.ObserveTransaction()                     │
  │           - Wait for required confirmations                       │
  │           - Extract chain-specific merkle proof                   │
  │           - Persist to chain_execution_results                    │
  │                                                                   │
  │  Phase 8: AttestationStrategy.Sign() + Aggregate()               │
  │           - Get scheme from registry (BLS for EVM, Ed25519 other)│
  │           - Collect attestations from peer validators             │
  │           - Aggregate when threshold met                          │
  │           - Persist to unified_attestations + aggregated_attest. │
  │                                                                   │
  │  Phase 9: ResultWriteBack to Accumulate                          │
  │           - Build ComprehensiveProofContext                       │
  │           - Submit synthetic transaction                          │
  │           - Persist to proof_artifacts                            │
  └───────────────────────────────────────────────────────────────────┘
  ```

  ### 4.2 on_cadence Flow (New Architecture)

  ```
  Intent Discovery (CERTEN_INTENT with proof_class="on_cadence")
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  BatchCollector.AddOnCadenceTransaction()                        │
  │  - Add to batch with target_chain info                            │
  │  - Wait for batch timeout (~15 min) or size limit                │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼ (batch closes)
  ┌───────────────────────────────────────────────────────────────────┐
  │  BatchProcessor.ProcessClosedBatch()                             │
  │  - Build Merkle tree                                              │
  │  - Elect executor deterministically                               │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  StrategyRegistry.GetChainStrategy(batchTargetChain)             │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  ChainStrategy.CreateAnchor() (batch anchor)                     │
  └───────────────────────────────────────────────────────────────────┘
  │
  ▼
  ┌───────────────────────────────────────────────────────────────────┐
  │  OnAnchorCallback → UnifiedProofCycleOrchestrator                │
  │                                                                   │
  │  *** SAME PHASES AS ON_DEMAND ***                                │
  │  Phase 7: Observe                                                 │
  │  Phase 8: Attest (with chain-appropriate scheme)                 │
  │  Phase 9: Write-back                                              │
  │                                                                   │
  │  All data stored to SAME unified tables                          │
  └───────────────────────────────────────────────────────────────────┘
  ```

  ---

  ## 5. Implementation Plan

  ### Phase 1: Core Interfaces (Files 1-3)

  | # | File | Description |
  |---|------|-------------|
  | 1 | `pkg/attestation/strategy/interface.go` | AttestationStrategy interface + types |
  | 2 | `pkg/chain/strategy/interface.go` | ChainExecutionStrategy interface + types |
  | 3 | `pkg/strategy/registry.go` | StrategyRegistry with platform defaults |

  ### Phase 2: Attestation Strategies (Files 4-5)

  | # | File | Description |
  |---|------|-------------|
  | 4 | `pkg/attestation/strategy/bls_strategy.go` | Extract from pkg/crypto/bls + pkg/execution |
  | 5 | `pkg/attestation/strategy/ed25519_strategy.go` | Extract from pkg/attestation/service.go |

  ### Phase 3: EVM Chain Strategy (Files 6-7)

  | # | File | Description |
  |---|------|-------------|
  | 6 | `pkg/chain/strategy/evm_strategy.go` | Extract from pkg/execution/ethereum_contracts.go |
  | 7 | `pkg/chain/strategy/evm_observer.go` | Extract from pkg/execution/external_chain_observer.go |

  ### Phase 4: Database & Repository (Files 8-9)

  | # | File | Description |
  |---|------|-------------|
  | 8 | `pkg/database/migrations/003_unified_multi_chain.sql` | New tables |
  | 9 | `pkg/database/repository_unified.go` | CRUD for new tables |

  ### Phase 5: Unified Orchestrator (Files 10-12)

  | # | File | Description |
  |---|------|-------------|
  | 10 | `pkg/execution/unified_orchestrator.go` | New unified orchestrator |
  | 11 | `pkg/execution/proof_cycle_orchestrator.go` | MODIFY: Delegate to unified |
  | 12 | `pkg/batch/processor.go` | MODIFY: Connect to unified orchestrator |

  ### Phase 6: Chain Strategy Stubs (Files 13-17)

  | # | File | Description |
  |---|------|-------------|
  | 13 | `pkg/chain/strategy/solana_strategy.go` | Stub with TODO |
  | 14 | `pkg/chain/strategy/cosmwasm_strategy.go` | Stub with TODO |
  | 15 | `pkg/chain/strategy/move_strategy.go` | Stub for Aptos/Sui |
  | 16 | `pkg/chain/strategy/ton_strategy.go` | Stub with TODO |
  | 17 | `pkg/chain/strategy/near_strategy.go` | Stub with TODO |

  ### Phase 7: Integration (Existing Files)

  | File | Changes |
  |------|---------|
  | `pkg/consensus/bft_integration.go` | Add target chain extraction, use registry |
  | `pkg/intent/discovery.go` | Extract target_chain from intent legs |
  | `pkg/batch/collector.go` | Store target_chain per transaction |
  | `main.go` | Initialize registry, wire strategies |

  ---

  ## 6. Existing Files to Modify

  | File | Changes |
  |------|---------|
  | `pkg/execution/proof_cycle_orchestrator.go` | Wrap with UnifiedOrchestrator adapter |
  | `pkg/execution/external_chain_observer.go` | Extract to EVMObserver, implement interface |
  | `pkg/execution/result_verifier.go` | Delegate to AttestationStrategy |
  | `pkg/batch/processor.go` | Add OnAnchorCallback → UnifiedOrchestrator |
  | `pkg/batch/collector.go` | Add target_chain field to TransactionData |
  | `pkg/intent/discovery.go` | Extract target_chain from intent.Legs[0].Chain |
  | `pkg/consensus/bft_integration.go` | Use StrategyRegistry for chain selection |
  | `pkg/database/types.go` | Add ChainPlatform, AttestationScheme enums |
  | `pkg/database/repositories.go` | Add UnifiedRepository |
  | `main.go` | Initialize StrategyRegistry, register all strategies |

  ---

  ## 7. Migration Strategy

  ### 7.1 Feature Flags

  ```go
  // pkg/config/feature_flags.go
  type FeatureFlags struct {
  UseUnifiedOrchestrator bool `env:"FF_UNIFIED_ORCHESTRATOR" default:"false"`
  EnableMultiChain       bool `env:"FF_MULTI_CHAIN" default:"false"`
  }
  ```

  ### 7.2 Rollout Plan

  1. **Stage 1**: Deploy with flags OFF - existing code unchanged
  2. **Stage 2**: Enable `FF_UNIFIED_ORCHESTRATOR` for on_cadence only
  3. **Stage 3**: Enable for both flows, monitor
  4. **Stage 4**: Enable `FF_MULTI_CHAIN`, deploy contracts to additional chains

  ### 7.3 Backward Compatibility

  - Existing `ProofCycleOrchestratorInterface` unchanged
  - UnifiedOrchestrator implements same interface
  - Old tables (bls_result_attestations, validator_attestations) kept for reads
  - New data written to unified tables

  ---

  ## 8. Supported Chains & Default Attestation

  | Platform | Chains | Default Attestation | Reason |
  |----------|--------|---------------------|--------|
  | EVM | Ethereum, Arbitrum, Optimism, Base, Polygon, Avalanche, BSC, TRON | BLS12-381 | ZK-verified on-chain |
  | CosmWasm | Osmosis, Neutron, Injective | Ed25519 | Native support, low cost |
  | Solana | Mainnet, Devnet | Ed25519 | Native support |
  | Move | Aptos, Sui | Ed25519 | Cost-effective |
  | TON | Mainnet | Ed25519 | Native support |
  | NEAR | Mainnet | Ed25519 | Native support |

  **Note:** Any chain can be configured to use BLS if desired (config override).

  ---

  ## 9. Testing Strategy

  ### Unit Tests
  - `pkg/attestation/strategy/*_test.go` - Test Sign/Verify/Aggregate
  - `pkg/chain/strategy/*_test.go` - Test with mock RPC clients

  ### Integration Tests
  - Full on_demand flow: Intent → EVM → BLS → proof_artifacts
  - Full on_cadence flow: Intent → Batch → EVM → BLS → proof_artifacts
  - Cross-chain: Solana intent → Ed25519 attestation

  ### Verification Queries
  ```sql
  -- Verify unified attestations populated
  SELECT scheme, COUNT(*) FROM unified_attestations GROUP BY scheme;

  -- Verify chain execution results
  SELECT chain_platform, chain_id, COUNT(*) FROM chain_execution_results
  GROUP BY chain_platform, chain_id;

  -- Verify proof artifacts have new columns
  SELECT attestation_scheme, chain_platform, COUNT(*) FROM proof_artifacts
  GROUP BY attestation_scheme, chain_platform;
  ```

  ---

  ## 10. Critical File Paths

  **Core Strategy Files (NEW):**
  - `pkg/attestation/strategy/interface.go`
  - `pkg/attestation/strategy/bls_strategy.go`
  - `pkg/attestation/strategy/ed25519_strategy.go`
  - `pkg/chain/strategy/interface.go`
  - `pkg/chain/strategy/evm_strategy.go`
  - `pkg/strategy/registry.go`
  - `pkg/execution/unified_orchestrator.go`

  **Key Files to Modify:**
  - `pkg/execution/proof_cycle_orchestrator.go` - Wrap with unified
  - `pkg/batch/processor.go` - Connect to unified orchestrator
  - `pkg/consensus/bft_integration.go` - Use registry
  - `pkg/intent/discovery.go` - Extract target chain
  - `main.go` - Wire everything together

  **Database:**
  - `pkg/database/migrations/003_unified_multi_chain.sql`
  - `pkg/database/repository_unified.go`

  ---

  ## 11. Summary

  This architecture achieves:

  1. **Unified Flow**: Both on_demand and on_cadence go through UnifiedProofCycleOrchestrator
  2. **Pluggable Attestation**: BLS12-381 for EVM, Ed25519 for others, easily extensible
  3. **Pluggable Chain Execution**: One interface, multiple implementations
  4. **Complete Data Collection**: All flows populate same PostgreSQL tables
  5. **Backward Compatible**: Feature flags, existing interfaces preserved
  6. **Future-Proof**: Easy to add Schnorr, threshold signatures, new chains