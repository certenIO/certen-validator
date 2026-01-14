# Certen Protocol Independent Validator Node
# Exhaustive Implementation Plan

**Version:** 1.0
**Date:** January 2026
**Source Reference:** `C:\Accumulate_Stuff\certen\certen-protocol\services\validator`

---

## START HERE

| Document | Purpose |
|----------|---------|
| **[PHASED_BUILD_PLAN.md](./PHASED_BUILD_PLAN.md)** | **Step-by-step build instructions** - Start here! |
| [QUICK_START.md](./QUICK_START.md) | Fast-track for experienced developers |
| [FILE_INVENTORY.md](./FILE_INVENTORY.md) | Complete list of files to copy |
| [DEPENDENCIES.md](./DEPENDENCIES.md) | All dependencies with versions |
| This document | Comprehensive reference (architecture, APIs, config) |

**For developers:** Follow `PHASED_BUILD_PLAN.md` phases 1-10 in order.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Complete File Inventory](#3-complete-file-inventory)
4. [Dependencies and Versions](#4-dependencies-and-versions)
5. [Build Instructions](#5-build-instructions)
6. [Configuration Reference](#6-configuration-reference)
7. [Key Generation](#7-key-generation)
8. [API Endpoints](#8-api-endpoints)
9. [Network Connectivity](#9-network-connectivity)
10. [Testing and Verification](#10-testing-and-verification)
11. [Operational Procedures](#11-operational-procedures)

---

## 1. Executive Summary

### 1.1 Purpose

This document provides an exhaustive implementation plan for creating a self-sufficient Certen Protocol validator node that can:

- Connect to a Certen BFT testnet
- Participate in CometBFT consensus
- Monitor Accumulate blockchain for CERTEN_INTENT transactions
- Generate 4-level cryptographic proofs (Chained L1-L3, Governance G0-G2, Anchor, Execution)
- Anchor proof batches to Ethereum via CertenAnchorV3 contract
- Participate in multi-validator attestation (2f+1 quorum)
- Expose HTTP API for proof retrieval and verification

### 1.2 Key Technologies

| Technology | Version | Purpose |
|------------|---------|---------|
| Go | 1.24+ | Runtime language |
| CometBFT | 0.38.0 | Byzantine Fault Tolerant consensus |
| gnark | 0.14.0 | Zero-Knowledge SNARK proofs |
| go-ethereum | 1.16.7 | Ethereum integration |
| PostgreSQL | 15 | Proof artifact storage |
| Redis | 7 (optional) | Caching layer |
| BLS12-381 | - | Aggregate signatures |

### 1.3 Validator Responsibilities

1. **Consensus Participation**: Join CometBFT network, propose/vote on blocks
2. **Intent Discovery**: Poll Accumulate blocks for CERTEN_INTENT transactions
3. **Proof Generation**: Generate L1-L4 chained proofs and G0-G2 governance proofs
4. **Batch Processing**: Collect transactions into on-cadence (~15 min) or on-demand batches
5. **Ethereum Anchoring**: Submit Merkle roots to CertenAnchorV3 contract
6. **Multi-Validator Attestation**: Collect 2f+1 BLS signatures for proof finality
7. **State Management**: Persist proofs, batches, and attestations to PostgreSQL
8. **API Serving**: Expose REST endpoints for proof queries and status

---

## 2. Architecture Overview

### 2.1 High-Level Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         INDEPENDENT VALIDATOR           │
                    ├─────────────────────────────────────────┤
                    │                                         │
  ┌─────────────┐   │   ┌─────────────────────────────────┐   │   ┌─────────────┐
  │  Accumulate │◄──┼───│      Intent Discovery           │   │   │   Ethereum  │
  │  Network    │   │   │  (polls for CERTEN_INTENT)      │   │   │   Sepolia   │
  └─────────────┘   │   └─────────────────────────────────┘   │   └─────────────┘
                    │                    │                     │         ▲
                    │                    ▼                     │         │
                    │   ┌─────────────────────────────────┐   │         │
                    │   │      Batch System               │   │         │
                    │   │  ┌───────────┐ ┌─────────────┐  │   │         │
                    │   │  │On-Cadence │ │ On-Demand   │  │   │         │
                    │   │  │(~15 min)  │ │ (immediate) │  │   │         │
                    │   │  └───────────┘ └─────────────┘  │   │         │
                    │   └─────────────────────────────────┘   │         │
                    │                    │                     │         │
                    │                    ▼                     │         │
                    │   ┌─────────────────────────────────┐   │         │
                    │   │      Proof Generation           │───┼─────────┘
                    │   │  L1-L3 Chained + G0-G2 Gov      │   │  (anchor)
                    │   └─────────────────────────────────┘   │
                    │                    │                     │
                    │                    ▼                     │
  ┌─────────────┐   │   ┌─────────────────────────────────┐   │
  │   Other     │◄──┼───│   Multi-Validator Attestation   │   │
  │ Validators  │───┼──►│      (2f+1 BLS quorum)          │   │
  └─────────────┘   │   └─────────────────────────────────┘   │
                    │                    │                     │
                    │                    ▼                     │
                    │   ┌─────────────────────────────────┐   │
                    │   │      CometBFT Consensus         │   │
                    │   │   (BFT block ordering)          │   │
                    │   └─────────────────────────────────┘   │
                    │                    │                     │
                    │                    ▼                     │
  ┌─────────────┐   │   ┌─────────────────────────────────┐   │   ┌─────────────┐
  │  HTTP API   │◄──┼───│      State Management           │───┼──►│ PostgreSQL  │
  │  Clients    │   │   │   (ledger, proofs, batches)     │   │   │   Database  │
  └─────────────┘   │   └─────────────────────────────────┘   │   └─────────────┘
                    │                                         │
                    └─────────────────────────────────────────┘
```

### 2.2 Component Interactions

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           VALIDATOR INITIALIZATION                          │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  1. Load Configuration (config.go)                                         │
│     └─► Environment variables, .env files                                  │
│                                                                            │
│  2. Initialize Database (database/client.go)                               │
│     └─► PostgreSQL connection pool (20 max, 5 min connections)             │
│     └─► Run migrations (001_initial_schema.sql)                            │
│                                                                            │
│  3. Initialize Accumulate Client (accumulate/liteclient_adapter.go)        │
│     └─► Connect to Accumulate RPC endpoint                                 │
│     └─► 30-second timeout, 3 retries                                       │
│                                                                            │
│  4. Initialize Ethereum Client (ethereum/client.go)                        │
│     └─► Connect to Ethereum RPC (Sepolia/Mainnet)                          │
│     └─► Load contract ABIs                                                 │
│                                                                            │
│  5. Initialize CometBFT (consensus/bft_integration.go)                     │
│     └─► Load/generate Ed25519 validator key                                │
│     └─► Start CometBFT node with ABCI application                          │
│     └─► Connect to persistent peers                                        │
│                                                                            │
│  6. Initialize Batch System (batch/*.go)                                   │
│     └─► Start Collector for transaction batching                           │
│     └─► Start Scheduler for 15-minute cadence                              │
│     └─► Start ConsensusCoordinator for attestations                        │
│                                                                            │
│  7. Start HTTP Server (server/*.go)                                        │
│     └─► Expose API endpoints on port 8080                                  │
│     └─► Health check, proof queries, batch status                          │
│                                                                            │
│  8. Start Intent Discovery (intent/discovery.go)                           │
│     └─► Poll Accumulate blocks for CERTEN_INTENT                           │
│     └─► Route to on-demand or on-cadence path                              │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Proof Generation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         4-LEVEL PROOF GENERATION                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LEVEL 1-3: CHAINED PROOF (LiteClientProofGenerator)                        │
│  ─────────────────────────────────────────────────────                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Account   │───►│     BPT     │───►│  Partition  │───►│   Network   │  │
│  │   (L1)      │    │    (L2)     │    │    (L3)     │    │   State     │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│                                                                             │
│  LEVEL 2: GOVERNANCE PROOF (GovernanceProofGenerator)                       │
│  ─────────────────────────────────────────────────────                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  G0: Inclusion & Finality                                           │   │
│  │      - Transaction exists in Accumulate                             │   │
│  │      - Block is finalized                                           │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  G1: Authority Validated                                            │   │
│  │      - Key page authority verification                              │   │
│  │      - Signature threshold met                                      │   │
│  │      - ADI governance compliance                                    │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  G2: Outcome Binding                                                │   │
│  │      - Payload verification (canonical txhash)                      │   │
│  │      - Effect verification                                          │   │
│  │      - Accumulate intent authorship                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  LEVEL 3: ANCHOR PROOF (Batch Merkle Root)                                  │
│  ─────────────────────────────────────────                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Merkle tree of all transactions in batch                         │   │
│  │  - Membership proof for each transaction                            │   │
│  │  - Anchor transaction reference (Ethereum tx hash)                  │   │
│  │  - Block number and timestamp                                       │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  LEVEL 4: EXECUTION PROOF (External Chain Observer)                         │
│  ─────────────────────────────────────────────────────                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  - Cross-chain execution status                                     │   │
│  │  - Transaction receipt from target chain                            │   │
│  │  - State update confirmation                                        │   │
│  │  - Result attestation from validators                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Complete File Inventory

### 3.1 Directory Structure

```
independant_validator/
├── main.go                                    # Entry point (~1200 lines)
├── go.mod                                     # Go module definition
├── go.sum                                     # Dependency checksums
├── Dockerfile                                 # Production multi-stage build
├── Dockerfile.dev                             # Development build
├── docker-compose.yml                         # Single-node orchestration
├── .env.example                               # Environment template
│
├── cmd/
│   ├── bls-zk-setup/
│   │   └── main.go                            # BLS ZK proving key generator
│   └── generate-vk/
│       └── main.go                            # Verification key generator
│
├── accumulate-lite-client-2/
│   └── liteclient/
│       ├── api/                               # Accumulate API client
│       │   └── *.go
│       ├── proof/
│       │   ├── consolidated_governance-proof/
│       │   │   └── main.go                    # G0/G1/G2 CLI tool (govproof)
│       │   └── *.go
│       └── cmd/
│           └── txhash/
│               └── main.go                    # Canonical tx hash tool
│
├── pkg/
│   ├── accumulate/                            # Accumulate network integration
│   │   ├── accumulate_client.go               # Client interface
│   │   └── liteclient_adapter.go              # LiteClientAdapter implementation
│   │
│   ├── anchor/                                # Anchor proof management
│   │   ├── anchor_manager.go                  # AnchorManager lifecycle
│   │   ├── event_watcher.go                   # Contract event monitoring
│   │   ├── proof_converter.go                 # Proof format conversion
│   │   └── scheduler.go                       # Anchor scheduling
│   │
│   ├── anchor_proof/                          # Cryptographic proof handling
│   │   ├── builder.go                         # Proof builder
│   │   ├── export.go                          # Proof export/serialization
│   │   ├── signer.go                          # Proof signing
│   │   ├── types.go                           # Type definitions
│   │   └── verifier.go                        # Proof verification
│   │
│   ├── attestation/                           # Multi-validator attestation
│   │   └── service.go                         # Attestation service
│   │
│   ├── batch/                                 # Batch processing & consensus
│   │   ├── anchor_adapter.go                  # Bridge to AnchorManager
│   │   ├── anchor_manager_wrapper.go          # Wrapper for batch interface
│   │   ├── attestation_broadcaster.go         # Broadcast attestations to peers
│   │   ├── bpt_extractor.go                   # BPT root extraction
│   │   ├── collector.go                       # Transaction batching
│   │   ├── confirmation_tracker.go            # Anchor finality tracking
│   │   ├── consensus_coordinator.go           # Multi-validator coordination
│   │   ├── cost_tracker.go                    # Gas cost tracking
│   │   ├── errors.go                          # Error definitions
│   │   ├── on_demand.go                       # Immediate anchoring path
│   │   ├── peer_manager.go                    # Validator peer management
│   │   ├── processor.go                       # Batch processing
│   │   ├── proof_helpers.go                   # Proof utility functions
│   │   └── scheduler.go                       # ~15 min batch scheduler
│   │
│   ├── commitment/                            # Commitment proofs
│   │   └── commitment.go                      # RFC8785 canonical JSON commitment
│   │
│   ├── config/                                # Configuration management
│   │   ├── anchor_config.go                   # Anchor-specific config
│   │   └── config.go                          # Main config loader
│   │
│   ├── consensus/                             # CometBFT integration
│   │   ├── abci_validator.go                  # ABCI application (ValidatorApp)
│   │   ├── bft_integration.go                 # BFTValidator core
│   │   ├── intent.go                          # Intent types for consensus
│   │   ├── types.go                           # Consensus type definitions
│   │   ├── validator_block.go                 # ValidatorBlock structure
│   │   ├── validator_block_builder.go         # Build ValidatorBlock from intent
│   │   └── validator_block_invariants.go      # Block validation rules
│   │
│   ├── crypto/
│   │   ├── bls/                               # BLS12-381 signatures
│   │   │   ├── bls.go                         # Core BLS operations
│   │   │   └── key_manager.go                 # Key management
│   │   └── bls_zkp/                           # ZK proofs for BLS
│   │       ├── circuit.go                     # Groth16 circuit definition
│   │       ├── prover.go                      # ZK prover
│   │       └── setup.go                       # Trusted setup
│   │
│   ├── database/                              # PostgreSQL persistence
│   │   ├── client.go                          # Database client
│   │   ├── errors.go                          # Error definitions
│   │   ├── proof_artifact_repository.go       # Proof storage
│   │   ├── proof_artifact_types.go            # Proof types
│   │   ├── repositories.go                    # Repository factory
│   │   ├── repository_anchor.go               # Anchor repository
│   │   ├── repository_attestation.go          # Attestation repository
│   │   ├── repository_batch.go                # Batch repository
│   │   ├── repository_proof.go                # Proof repository
│   │   ├── repository_request.go              # Request repository
│   │   ├── types.go                           # Database types
│   │   └── migrations/
│   │       └── 001_initial_schema.sql         # Initial database schema
│   │
│   ├── ethereum/                              # Ethereum integration
│   │   └── client.go                          # Ethereum RPC client
│   │
│   ├── execution/                             # Transaction execution
│   │   ├── accumulate_submitter.go            # Write-back to Accumulate
│   │   ├── bft_target_chain_integration.go    # BFT target chain
│   │   ├── commitment_builder.go              # Commitment construction
│   │   ├── contracts/                         # Contract ABI bindings
│   │   │   ├── account_v2.go                  # AccountV2 ABI
│   │   │   ├── anchor_v2.go                   # AnchorV2 ABI
│   │   │   ├── anchor_v2_extended.go          # Extended ABI
│   │   │   ├── anchor_v3.go                   # AnchorV3 ABI
│   │   │   └── anchor_v3_generated.go         # Generated bindings
│   │   ├── credit_checker.go                  # Credit balance checking
│   │   ├── cross_contract_verification.go     # Cross-contract calls
│   │   ├── errors.go                          # Error definitions
│   │   ├── ethereum_contracts.go              # Contract interaction
│   │   ├── executor.go                        # Execution orchestrator
│   │   ├── external_chain_observer.go         # Monitor external chains
│   │   ├── external_chain_result.go           # Execution results
│   │   ├── g2_outcome_binding.go              # G2 outcome binding
│   │   ├── g2_validator_block_integration.go  # G2 integration
│   │   ├── nonce_tracker.go                   # Transaction nonce tracking
│   │   ├── proof_cycle_orchestrator.go        # Proof cycle management
│   │   ├── result_attestation.go              # Result attestation
│   │   └── synthetic_transaction.go           # Synthetic tx generation
│   │
│   ├── intent/                                # Intent tracking
│   │   ├── conversion.go                      # Intent format conversion
│   │   ├── discovery.go                       # Block monitoring for intents
│   │   └── intent_model_alias.go              # Intent model aliases
│   │
│   ├── kvdb/                                  # Key-value DB abstraction
│   │   └── adapter.go                         # KV interface adapter
│   │
│   ├── ledger/                                # Ledger storage
│   │   ├── errors.go                          # Error definitions
│   │   ├── store.go                           # LedgerStore implementation
│   │   └── types.go                           # Ledger types
│   │
│   ├── merkle/                                # Merkle tree verification
│   │   ├── receipt.go                         # Merkle receipt
│   │   └── tree.go                            # Merkle tree construction
│   │
│   ├── proof/                                 # Proof generation
│   │   ├── artifact_service.go                # ProofArtifactService
│   │   ├── attestation.go                     # Attestation proofs
│   │   ├── batch_adapter.go                   # Batch proof adapter
│   │   ├── bundle_format.go                   # Proof bundle format
│   │   ├── canonical_blob_hash.go             # Canonical hashing
│   │   ├── certen_proof.go                    # CertenProof type
│   │   ├── governance_adapter.go              # Governance proof adapter
│   │   ├── governance_library.go              # Governance proof library
│   │   ├── governance_types.go                # Governance types
│   │   ├── lifecycle.go                       # Proof lifecycle
│   │   ├── liteclient_proof_generator.go      # L1-L3 proof generator
│   │   ├── proof_request_types.go             # Request types
│   │   └── *.go                               # Additional proof files
│   │
│   ├── protocol/                              # Protocol definitions
│   │   └── *.go                               # Protocol message types
│   │
│   ├── server/                                # HTTP API server
│   │   ├── attestation_handlers.go            # Attestation endpoints
│   │   ├── batch_handlers.go                  # Batch endpoints
│   │   ├── bulk_handlers.go                   # Bulk operation endpoints
│   │   ├── bundle_handlers.go                 # Bundle endpoints
│   │   ├── ledger_handlers.go                 # Ledger endpoints
│   │   └── proof_handlers.go                  # Proof endpoints
│   │
│   └── verification/                          # Verification engine
│       ├── unified_verifier.go                # UnifiedVerifier
│       └── *.go                               # Verification components
│
├── contracts/                                 # Solidity contracts (reference)
│   ├── BLSZKVerifier.sol
│   ├── CertenAnchorV3.sol
│   ├── CertenCrossContractVerification.sol
│   ├── CertenAnchorV2.abi.json
│   └── CertenAccountV2.abi.json
│
└── bls_zk_keys/                               # Pre-generated ZK proving keys
    ├── proving_key.bin
    └── verification_key.bin
```

### 3.2 File Count Summary

| Package | Files (excluding tests) | Lines (approx) |
|---------|------------------------|----------------|
| Root | 4 | ~1500 |
| cmd/ | 2 | ~200 |
| accumulate-lite-client-2/ | ~20 | ~3000 |
| pkg/accumulate | 2 | ~400 |
| pkg/anchor | 4 | ~600 |
| pkg/anchor_proof | 5 | ~800 |
| pkg/attestation | 1 | ~200 |
| pkg/batch | 14 | ~2500 |
| pkg/commitment | 1 | ~150 |
| pkg/config | 2 | ~300 |
| pkg/consensus | 7 | ~1800 |
| pkg/crypto | 4 | ~600 |
| pkg/database | 12 | ~1500 |
| pkg/ethereum | 1 | ~200 |
| pkg/execution | 17 | ~3000 |
| pkg/intent | 3 | ~500 |
| pkg/kvdb | 1 | ~100 |
| pkg/ledger | 3 | ~400 |
| pkg/merkle | 2 | ~300 |
| pkg/proof | ~20 | ~3000 |
| pkg/server | 6 | ~1200 |
| pkg/verification | ~5 | ~800 |
| **TOTAL** | **~130 files** | **~23,000 lines** |

---

## 4. Dependencies and Versions

### 4.1 Go Module (go.mod)

```go
module github.com/certen/independant-validator

go 1.24.0

require (
    // ═══════════════════════════════════════════════════════════════
    // CONSENSUS & NETWORKING
    // ═══════════════════════════════════════════════════════════════

    // CometBFT - Byzantine Fault Tolerant consensus engine
    github.com/cometbft/cometbft v0.38.0
    github.com/cometbft/cometbft-db v0.7.0

    // ═══════════════════════════════════════════════════════════════
    // CRYPTOGRAPHY
    // ═══════════════════════════════════════════════════════════════

    // gnark - ZK-SNARK library for BLS verification proofs
    github.com/consensys/gnark v0.14.0
    github.com/consensys/gnark-crypto v0.19.0

    // blst - BLS12-381 signature library
    github.com/supranational/blst v0.3.16

    // btcec - Elliptic curve cryptography
    github.com/btcsuite/btcd/btcec/v2 v2.3.2

    // ═══════════════════════════════════════════════════════════════
    // BLOCKCHAIN INTEGRATION
    // ═══════════════════════════════════════════════════════════════

    // go-ethereum - Ethereum client library
    github.com/ethereum/go-ethereum v1.16.7

    // Accumulate SDK - Accumulate blockchain integration
    gitlab.com/accumulatenetwork/accumulate v1.4.2
    gitlab.com/accumulatenetwork/core/schema v0.2.1

    // ═══════════════════════════════════════════════════════════════
    // DATABASE & STORAGE
    // ═══════════════════════════════════════════════════════════════

    // PostgreSQL driver
    github.com/lib/pq v1.10.9

    // LevelDB (CometBFT internal storage)
    github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7

    // ═══════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════

    // UUID generation
    github.com/google/uuid v1.6.0

    // HTTP router
    github.com/gorilla/mux v1.8.1

    // Logging
    github.com/rs/zerolog v1.31.0

    // Configuration
    github.com/spf13/viper v1.18.2

    // Testing
    github.com/stretchr/testify v1.8.4
)
```

### 4.2 Infrastructure Dependencies

| Component | Image/Version | Required | Purpose |
|-----------|---------------|----------|---------|
| PostgreSQL | postgres:15-alpine | Yes | Proof artifact storage, batches, attestations |
| Redis | redis:7-alpine | Optional | Caching, rate limiting |
| CometBFT | Built-in v0.38.0 | Yes | BFT consensus (embedded) |

### 4.3 Ethereum Contract Addresses

| Contract | Sepolia Address | Mainnet Address | Purpose |
|----------|-----------------|-----------------|---------|
| CertenAnchorV3 | `0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98` | TBD | Anchor creation & verification |
| BLSZKVerifier | `0x631B6444216b981561034655349F8a28962DcC5F` | TBD | BLS ZK proof verification |
| CertenAccountV2 | `0x043e3632d24F297dA199eEc420084E0c2e5CcDFf` | TBD | Account abstraction |

### 4.4 Accumulate Network Endpoints

| Network | RPC URL | CometBFT DN | CometBFT BVN |
|---------|---------|-------------|--------------|
| Devnet | http://localhost:26660/v3 | http://localhost:26657 | http://localhost:26757 |
| Kermit (Testnet) | https://kermit.accumulatenetwork.io/v3 | kermit-dn.comet.endpoint | kermit-bvn.comet.endpoint |
| Mainnet | https://mainnet.accumulatenetwork.io/v3 | mainnet-dn.comet.endpoint | mainnet-bvn.comet.endpoint |

---

## 5. Build Instructions

### 5.1 Prerequisites

```bash
# Install Go 1.24+
# Download from https://go.dev/dl/

# Verify installation
go version  # Should show go1.24.x

# Install required system packages (Linux/Alpine)
apk add --no-cache git gcc musl-dev

# Or for Ubuntu/Debian
apt-get install -y git gcc libc-dev
```

### 5.2 Non-Docker Build

```bash
# ═══════════════════════════════════════════════════════════════
# Step 1: Clone/Create Directory Structure
# ═══════════════════════════════════════════════════════════════
mkdir -p independant_validator
cd independant_validator

# ═══════════════════════════════════════════════════════════════
# Step 2: Initialize Go Module
# ═══════════════════════════════════════════════════════════════
go mod init github.com/certen/independant-validator

# ═══════════════════════════════════════════════════════════════
# Step 3: Copy Source Files from Reference Implementation
# ═══════════════════════════════════════════════════════════════
# Copy all files listed in Section 3.1 from:
# C:\Accumulate_Stuff\certen\certen-protocol\services\validator
#
# Structure should match exactly as documented

# ═══════════════════════════════════════════════════════════════
# Step 4: Download Dependencies
# ═══════════════════════════════════════════════════════════════
go mod download
go mod tidy

# ═══════════════════════════════════════════════════════════════
# Step 5: Build Main Validator Binary
# ═══════════════════════════════════════════════════════════════
CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o validator .

# ═══════════════════════════════════════════════════════════════
# Step 6: Build BLS ZK Setup Tool
# ═══════════════════════════════════════════════════════════════
cd cmd/bls-zk-setup
go build -o bls-zk-setup .
cd ../..

# ═══════════════════════════════════════════════════════════════
# Step 7: Generate BLS ZK Proving Keys (First Time Only)
# ═══════════════════════════════════════════════════════════════
mkdir -p bls_zk_keys
./cmd/bls-zk-setup/bls-zk-setup
# Creates: bls_zk_keys/proving_key.bin, verification_key.bin
# This step takes ~5-10 minutes

# ═══════════════════════════════════════════════════════════════
# Step 8: Build Governance Proof CLI
# ═══════════════════════════════════════════════════════════════
cd accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
go build -o govproof .
cp govproof ../../../../
cd ../../../..

# ═══════════════════════════════════════════════════════════════
# Step 9: Build TxHash Tool
# ═══════════════════════════════════════════════════════════════
cd accumulate-lite-client-2/liteclient/cmd/txhash
go build -o txhash .
cp txhash ../../../../
cd ../../../..

# ═══════════════════════════════════════════════════════════════
# Step 10: Verify Build
# ═══════════════════════════════════════════════════════════════
./validator --help
./govproof --help
./txhash --help
```

### 5.3 Docker Build

**Dockerfile:**

```dockerfile
# ═══════════════════════════════════════════════════════════════
# Build Stage
# ═══════════════════════════════════════════════════════════════
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

WORKDIR /build

# Copy dependency manifests first (for caching)
COPY go.mod go.sum ./
COPY accumulate-lite-client-2/ ./accumulate-lite-client-2/

# Download dependencies
RUN go mod download

# Copy all source code
COPY . ./

# Build main validator binary with CGO (required for gnark)
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o validator .

# Build governance proof CLI (pure Go, no CGO needed)
WORKDIR /build/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/govproof .

# Build txhash tool
WORKDIR /build/accumulate-lite-client-2/liteclient/cmd/txhash
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/txhash .

# Return to build root
WORKDIR /build

# Generate BLS ZK keys (deterministic, takes ~5-10 minutes)
RUN mkdir -p /build/bls_zk_keys && \
    go run ./cmd/bls-zk-setup 2>&1

# ═══════════════════════════════════════════════════════════════
# Production Stage
# ═══════════════════════════════════════════════════════════════
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create unprivileged user
RUN adduser -D -s /bin/sh validator

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/validator .
COPY --from=builder /build/govproof .
COPY --from=builder /build/txhash .
COPY --from=builder /build/bls_zk_keys/ /app/bls_zk_keys/

# Create directory structure
RUN mkdir -p /app/bft-keys \
             /app/data \
             /app/data/validator-ledger \
             /app/data/cometbft \
             /app/data/gov_proofs

# Set ownership
RUN chown -R validator:validator /app

# Switch to unprivileged user
USER validator

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 9090 26656 26657

# Environment defaults
ENV API_HOST=0.0.0.0 \
    API_PORT=8080 \
    METRICS_PORT=9090 \
    LOG_LEVEL=info \
    GOV_PROOF_CLI_PATH=/app/govproof \
    TXHASH_CLI_PATH=/app/txhash \
    BLS_ZK_KEYS_DIR=/app/bls_zk_keys \
    ENABLE_MERKLE_VERIFICATION=true \
    ENABLE_GOVERNANCE_VERIFICATION=true \
    ENABLE_BLS_VERIFICATION=true \
    ENABLE_COMMITMENT_VERIFICATION=true

# Start validator
CMD ["./validator"]
```

**docker-compose.yml (Single Node):**

```yaml
version: '3.8'

services:
  # ═══════════════════════════════════════════════════════════════
  # PostgreSQL Database
  # ═══════════════════════════════════════════════════════════════
  postgres:
    image: postgres:15-alpine
    container_name: certen-postgres
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: certen
      POSTGRES_USER: certen
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./pkg/database/migrations/001_initial_schema.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U certen -d certen"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  # ═══════════════════════════════════════════════════════════════
  # Redis Cache (Optional)
  # ═══════════════════════════════════════════════════════════════
  redis:
    image: redis:7-alpine
    container_name: certen-redis
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  # ═══════════════════════════════════════════════════════════════
  # Validator Node
  # ═══════════════════════════════════════════════════════════════
  validator:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: certen-validator
    command: ["./validator"]
    ports:
      - "8086:8080"    # HTTP API
      - "9086:9090"    # Prometheus Metrics
      - "26656:26656"  # CometBFT P2P
      - "26657:26657"  # CometBFT RPC
    env_file:
      - .env
    environment:
      # Validator Identity
      VALIDATOR_ID: ${VALIDATOR_ID:-validator-new}
      NETWORK_NAME: ${NETWORK_NAME:-testnet}

      # Database
      DATABASE_URL: postgres://certen:${POSTGRES_PASSWORD}@postgres:5432/certen?sslmode=disable
      DATABASE_MAX_CONNS: 20
      DATABASE_MIN_CONNS: 5

      # CometBFT Consensus
      COMETBFT_ENABLED: "true"
      COMETBFT_MODE: validator
      COMETBFT_CHAIN_ID: ${COMETBFT_CHAIN_ID:-certen-testnet}
      COMETBFT_P2P_LADDR: tcp://0.0.0.0:26656
      COMETBFT_RPC_LADDR: tcp://0.0.0.0:26657

      # Peer Configuration (set via .env for testnet connection)
      COMETBFT_P2P_PERSISTENT_PEERS: ${COMETBFT_P2P_PERSISTENT_PEERS:-}

      # Attestation (set via .env)
      ATTESTATION_PEERS: ${ATTESTATION_PEERS:-}
      ATTESTATION_REQUIRED_COUNT: ${ATTESTATION_REQUIRED_COUNT:-3}

      # Accumulate Network
      ACCUMULATE_URL: ${ACCUMULATE_URL:?ACCUMULATE_URL is required}
      ACCUMULATE_COMET_DN: ${ACCUMULATE_COMET_DN:-}
      ACCUMULATE_COMET_BVN: ${ACCUMULATE_COMET_BVN:-}

      # Ethereum Network
      ETHEREUM_URL: ${ETHEREUM_URL:?ETHEREUM_URL is required}
      ETH_CHAIN_ID: ${ETH_CHAIN_ID:-11155111}
      ETH_PRIVATE_KEY: ${ETH_PRIVATE_KEY:?ETH_PRIVATE_KEY is required}

      # Contract Addresses
      CERTEN_CONTRACT_ADDRESS: ${CERTEN_CONTRACT_ADDRESS:-0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98}
      CERTEN_ANCHOR_V3_ADDRESS: ${CERTEN_ANCHOR_V3_ADDRESS:-0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98}
      BLS_ZK_VERIFIER_ADDRESS: ${BLS_ZK_VERIFIER_ADDRESS:-0x631B6444216b981561034655349F8a28962DcC5F}

      # BLS ZK Testing Mode (disable for production)
      BLS_ZK_TESTING_MODE: ${BLS_ZK_TESTING_MODE:-false}

      # Proof Cycle Write-back (optional)
      PROOF_CYCLE_WRITEBACK: ${PROOF_CYCLE_WRITEBACK:-false}
    volumes:
      - validator_data:/app/data
      - validator_bft_keys:/app/bft-keys
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G

volumes:
  postgres_data:
  redis_data:
  validator_data:
  validator_bft_keys:

networks:
  default:
    name: certen-network
```

### 5.4 Build Commands

```bash
# Build Docker image
docker build -t certen-validator:latest .

# Start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f validator

# Stop
docker-compose down

# Clean rebuild
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

---

## 6. Configuration Reference

### 6.1 Required Environment Variables

```bash
# ═══════════════════════════════════════════════════════════════
# VALIDATOR IDENTITY
# ═══════════════════════════════════════════════════════════════

# Unique identifier for this validator
VALIDATOR_ID=validator-new

# Network name (devnet, kermit, mainnet)
NETWORK_NAME=testnet

# ═══════════════════════════════════════════════════════════════
# DATABASE CONFIGURATION
# ═══════════════════════════════════════════════════════════════

# PostgreSQL connection string
DATABASE_URL=postgres://certen:password@localhost:5432/certen?sslmode=require

# PostgreSQL password (used separately for docker-compose)
POSTGRES_PASSWORD=secure_password_here

# Connection pool settings
DATABASE_MAX_CONNS=20     # Maximum open connections
DATABASE_MIN_CONNS=5      # Minimum idle connections
DATABASE_MAX_IDLE_TIME=300s
DATABASE_MAX_LIFETIME=3600s

# ═══════════════════════════════════════════════════════════════
# ACCUMULATE NETWORK
# ═══════════════════════════════════════════════════════════════

# Accumulate RPC endpoint
ACCUMULATE_URL=https://kermit.accumulatenetwork.io/v3

# CometBFT endpoints (for L1-L3 chained proofs)
ACCUMULATE_COMET_DN=http://dn.cometbft.endpoint:26657
ACCUMULATE_COMET_BVN=http://bvn.cometbft.endpoint:26757

# ═══════════════════════════════════════════════════════════════
# ETHEREUM NETWORK
# ═══════════════════════════════════════════════════════════════

# Ethereum RPC endpoint (Alchemy, Infura, etc.)
ETHEREUM_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY

# Chain ID (11155111 = Sepolia, 1 = Mainnet)
ETH_CHAIN_ID=11155111

# Validator's Ethereum private key (for signing anchor transactions)
# WARNING: Store securely! Use secrets management in production.
ETH_PRIVATE_KEY=0x...

# ═══════════════════════════════════════════════════════════════
# CONTRACT ADDRESSES
# ═══════════════════════════════════════════════════════════════

# CertenAnchorV3 contract (unified anchor creation/verification)
CERTEN_CONTRACT_ADDRESS=0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98
CERTEN_ANCHOR_V3_ADDRESS=0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98

# BLS ZK Verifier contract
BLS_ZK_VERIFIER_ADDRESS=0x631B6444216b981561034655349F8a28962DcC5F

# Account Abstraction contract
ACCOUNT_ABSTRACTION_ADDRESS=0x043e3632d24F297dA199eEc420084E0c2e5CcDFf
```

### 6.2 CometBFT Configuration

```bash
# ═══════════════════════════════════════════════════════════════
# COMETBFT CONSENSUS
# ═══════════════════════════════════════════════════════════════

# Enable CometBFT consensus engine
COMETBFT_ENABLED=true

# Mode: validator (full participant) or observer
COMETBFT_MODE=validator

# Chain ID (must match all validators in network)
COMETBFT_CHAIN_ID=certen-testnet

# P2P listen address
COMETBFT_P2P_LADDR=tcp://0.0.0.0:26656

# RPC listen address
COMETBFT_RPC_LADDR=tcp://0.0.0.0:26657

# RPC URL (for internal queries)
COMETBFT_RPC_URL=http://127.0.0.1:26657

# ═══════════════════════════════════════════════════════════════
# PERSISTENT PEERS
# ═══════════════════════════════════════════════════════════════

# Format: nodeID1@host1:port1,nodeID2@host2:port2
# Get node IDs from network operator
COMETBFT_P2P_PERSISTENT_PEERS=0e895578ca3c2aade47a836050f3f5e505b3d014@validator-1.certen.network:26656,582637177487b78a470243fd25c317b381d7c0ac@validator-2.certen.network:26656

# ═══════════════════════════════════════════════════════════════
# GENESIS CONFIGURATION
# ═══════════════════════════════════════════════════════════════

# Genesis time (ISO 8601 format, must match network)
VALIDATOR_GENESIS_TIME=2026-01-01T00:00:00Z

# Initial validators are defined in genesis.json
# Obtain from network operator
```

### 6.3 Attestation Configuration

```bash
# ═══════════════════════════════════════════════════════════════
# MULTI-VALIDATOR ATTESTATION
# ═══════════════════════════════════════════════════════════════

# Other validators to request attestations from
# Format: comma-separated HTTP URLs
ATTESTATION_PEERS=http://validator-1.certen.network:8080,http://validator-2.certen.network:8080,http://validator-3.certen.network:8080

# Required attestation count for quorum (2f+1)
# For 4 validators: 3 required (tolerates 1 Byzantine fault)
ATTESTATION_REQUIRED_COUNT=3

# Attestation timeout
ATTESTATION_TIMEOUT=30s
```

### 6.4 Optional Configuration

```bash
# ═══════════════════════════════════════════════════════════════
# API SERVER
# ═══════════════════════════════════════════════════════════════

API_HOST=0.0.0.0
API_PORT=8080
METRICS_PORT=9090

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════

LOG_LEVEL=info    # debug, info, warn, error
LOG_FORMAT=json   # json or text

# ═══════════════════════════════════════════════════════════════
# BATCH PROCESSING
# ═══════════════════════════════════════════════════════════════

# On-cadence batch interval (default: 15 minutes)
BATCH_INTERVAL=15m

# Maximum transactions per batch
BATCH_MAX_SIZE=1000

# Maximum on-demand transactions
ON_DEMAND_MAX_SIZE=5

# ═══════════════════════════════════════════════════════════════
# VERIFICATION SETTINGS
# ═══════════════════════════════════════════════════════════════

ENABLE_MERKLE_VERIFICATION=true
ENABLE_GOVERNANCE_VERIFICATION=true
ENABLE_BLS_VERIFICATION=true
ENABLE_COMMITMENT_VERIFICATION=true
ENABLE_PARALLEL_VERIFICATION=true
VERIFICATION_TIMEOUT=30s

# ═══════════════════════════════════════════════════════════════
# BLS ZK CONFIGURATION
# ═══════════════════════════════════════════════════════════════

# Path to ZK proving keys
BLS_ZK_KEYS_DIR=/app/bls_zk_keys

# Testing mode (skip ZK proof generation for faster testing)
BLS_ZK_TESTING_MODE=false

# ═══════════════════════════════════════════════════════════════
# PROOF TOOLS
# ═══════════════════════════════════════════════════════════════

GOV_PROOF_CLI_PATH=/app/govproof
TXHASH_CLI_PATH=/app/txhash

# ═══════════════════════════════════════════════════════════════
# PROOF CYCLE WRITE-BACK (Phase 9)
# ═══════════════════════════════════════════════════════════════

# Enable write-back to Accumulate
PROOF_CYCLE_WRITEBACK=false

# Target account for write-back
ACCUMULATE_RESULTS_PRINCIPAL=acc://certenprotocol.acme/ext-exec-results

# Signer URL for write-back
ACCUMULATE_SIGNER_URL=acc://certenprotocol.acme/book/1

# Private key for signing write-back transactions
ACCUMULATE_WRITEBACK_PRIV_KEY=...

# ═══════════════════════════════════════════════════════════════
# KEY PATHS
# ═══════════════════════════════════════════════════════════════

# Ed25519 key for CometBFT consensus
ED25519_KEY_PATH=/app/bft-keys/ed25519_key.hex

# BLS key for attestations
BLS_KEY_PATH=/app/data/bls_key.hex
```

### 6.5 Sample .env File

```bash
# ═══════════════════════════════════════════════════════════════
# .env.example - Certen Independent Validator Configuration
# ═══════════════════════════════════════════════════════════════

# Validator Identity
VALIDATOR_ID=validator-new
NETWORK_NAME=testnet

# Database
POSTGRES_PASSWORD=change_me_in_production
DATABASE_URL=postgres://certen:${POSTGRES_PASSWORD}@postgres:5432/certen?sslmode=disable

# Accumulate Network (Kermit Testnet)
ACCUMULATE_URL=https://kermit.accumulatenetwork.io/v3
ACCUMULATE_COMET_DN=
ACCUMULATE_COMET_BVN=

# Ethereum Network (Sepolia)
ETHEREUM_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
ETH_CHAIN_ID=11155111
ETH_PRIVATE_KEY=0x_YOUR_PRIVATE_KEY_HERE

# Contract Addresses (Sepolia)
CERTEN_CONTRACT_ADDRESS=0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98
CERTEN_ANCHOR_V3_ADDRESS=0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98
BLS_ZK_VERIFIER_ADDRESS=0x631B6444216b981561034655349F8a28962DcC5F

# CometBFT
COMETBFT_ENABLED=true
COMETBFT_MODE=validator
COMETBFT_CHAIN_ID=certen-testnet
COMETBFT_P2P_PERSISTENT_PEERS=

# Attestation
ATTESTATION_PEERS=
ATTESTATION_REQUIRED_COUNT=3

# Development settings (disable for production)
BLS_ZK_TESTING_MODE=true
```

---

## 7. Key Generation

### 7.1 Ed25519 Keys (CometBFT Consensus)

Ed25519 keys are used for CometBFT consensus participation (proposing and voting on blocks).

**Auto-Generation:**
Keys are automatically generated on first startup at `$DATA_DIR/ed25519_key.hex`.

**Manual Generation:**
```bash
# Generate new Ed25519 keypair
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem
openssl pkey -in ed25519_private.pem -outform DER | tail -c 32 | xxd -p > ed25519_key.hex

# Or using Go:
go run -mod=mod gitlab.com/accumulatenetwork/accumulate/cmd/accumulate key generate ed25519
```

**Key Format:**
- File: `ed25519_key.hex`
- Content: 64 hex characters (32 bytes)
- Example: `a1b2c3d4e5f6...` (64 chars)

### 7.2 BLS Keys (Multi-Validator Attestation)

BLS12-381 keys are used for aggregate signatures in multi-validator attestations.

**Auto-Generation:**
Keys are generated deterministically from VALIDATOR_ID on first startup.

**Key Storage:**
- File: `$DATA_DIR/bls_key_${VALIDATOR_ID}.hex`
- Contains both private and public key material

**Key Format:**
```json
{
  "private_key": "hex_encoded_private_key",
  "public_key": "hex_encoded_public_key"
}
```

### 7.3 CometBFT Node Key

The CometBFT node key identifies the validator in P2P networking.

**Auto-Generation:**
Generated by CometBFT on first startup at `$DATA_DIR/cometbft/config/node_key.json`.

**Node ID:**
The node ID is derived from the public key:
```bash
# Extract node ID from running node
curl http://localhost:26657/status | jq -r '.result.node_info.id'
```

**Example node_key.json:**
```json
{
  "priv_key": {
    "type": "tendermint/PrivKeyEd25519",
    "value": "base64_encoded_private_key"
  }
}
```

### 7.4 Ethereum Keys

Ethereum keys are used for signing anchor transactions on Ethereum.

**Generation:**
```bash
# Using go-ethereum
geth account new --keystore ./keystore

# Or using ethers.js
const wallet = ethers.Wallet.createRandom();
console.log(wallet.privateKey);
```

**Security:**
- Store private key in secure secrets management (HashiCorp Vault, AWS Secrets Manager)
- Never commit to version control
- Use separate keys for each validator

### 7.5 BLS ZK Proving Keys

Groth16 proving keys for BLS ZK proofs.

**Generation:**
```bash
# Run during build or first startup
./cmd/bls-zk-setup/bls-zk-setup

# Creates:
# - bls_zk_keys/proving_key.bin (~50MB)
# - bls_zk_keys/verification_key.bin (~1KB)
```

**Trusted Setup:**
The proving keys are generated through a deterministic trusted setup. All validators can use the same keys.

---

## 8. API Endpoints

### 8.1 Health and Status

| Endpoint | Method | Description | Response |
|----------|--------|-------------|----------|
| `/health` | GET | Validator health status | `{"status":"ok","phase":"5","consensus":"cometbft",...}` |
| `/api/ledger/status` | GET | Ledger state | `{"latest_height":1234,...}` |
| `/api/system-ledger` | GET | System ledger entries | Array of ledger entries |
| `/api/anchor-ledger` | GET | Anchor ledger entries | Array of anchor entries |

**Health Response Schema:**
```json
{
  "status": "ok",           // ok, degraded, error
  "phase": "5",             // Current phase
  "consensus": "cometbft",  // Consensus engine
  "database": "connected",  // connected, disconnected
  "ethereum": "connected",  // connected, disconnected
  "accumulate": "connected",// connected, disconnected
  "batch_system": "active", // active, disabled
  "proof_cycle": "active",  // active, disabled
  "uptime_seconds": 3600
}
```

### 8.2 Batch and Proof APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/anchors/on-demand` | POST | Create immediate anchor |
| `/api/batches/current` | GET | Current batch status |
| `/api/batches/{id}` | GET | Batch by ID |
| `/api/proofs/{id}` | GET | Proof by ID |
| `/api/proofs/by-tx/{hash}` | GET | Proof by transaction hash |
| `/api/proofs/by-account/{url}` | GET | Proofs by account URL |
| `/api/costs` | GET | Cost statistics |
| `/api/costs/estimate` | GET | Estimate anchoring cost |

**On-Demand Anchor Request:**
```json
POST /api/anchors/on-demand
{
  "accum_tx_hash": "abc123...",
  "account_url": "acc://myorg.acme/data",
  "gov_level": "G1",
  "key_page": "acc://myorg.acme/book/1"
}
```

**Proof Response Schema:**
```json
{
  "id": "uuid",
  "batch_id": "uuid",
  "accum_tx_hash": "abc123...",
  "account_url": "acc://...",
  "chained_proof": {...},      // L1-L3
  "governance_proof": {...},   // G0-G2
  "anchor_proof": {...},       // Merkle root + membership
  "execution_proof": {...},    // External chain result
  "merkle_index": 5,
  "created_at": "2026-01-01T00:00:00Z"
}
```

### 8.3 Attestation APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/attestations` | GET | Attestation service info |
| `/api/attestations/request` | POST | Receive attestation from peer |
| `/api/attestations/status/{id}` | GET | Attestation status |
| `/api/attestations/bundle/{id}` | GET | Complete attestation bundle |
| `/api/attestations/peers` | GET | Configured peers |

**Attestation Request (from peer):**
```json
POST /api/attestations/request
Headers:
  X-Validator-ID: validator-1
  X-Request-Type: bls-attestation

Body:
{
  "batch_id": "uuid",
  "merkle_root": "hex_encoded_root",
  "tx_count": 50,
  "block_height": 1234,
  "requester_id": "validator-1",
  "expires_at": "2026-01-01T00:15:00Z"
}
```

**Attestation Response:**
```json
{
  "success": true,
  "attestation": {
    "batch_id": "uuid",
    "validator_id": "validator-2",
    "bls_signature": "hex_encoded_signature",
    "voting_power": 100,
    "timestamp": "2026-01-01T00:00:30Z"
  }
}
```

### 8.4 Advanced Proof APIs (v1)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/proofs/tx/{hash}` | GET | Proof by tx hash |
| `/api/v1/proofs/account/{url}` | GET | Proofs by account |
| `/api/v1/proofs/batch/{id}` | GET | Proofs in batch |
| `/api/v1/proofs/anchor/{hash}` | GET | Proofs by anchor |
| `/api/v1/proofs/query` | POST | Filtered query |
| `/api/v1/proofs/sync` | GET | Sync for auditing |
| `/api/v1/proofs/{id}` | GET | Full proof details |
| `/api/v1/batches/{id}/stats` | GET | Batch statistics |

**Query Request:**
```json
POST /api/v1/proofs/query
{
  "account_url": "acc://...",
  "from_time": "2026-01-01T00:00:00Z",
  "to_time": "2026-01-02T00:00:00Z",
  "gov_level": "G2",
  "limit": 100,
  "offset": 0
}
```

### 8.5 CometBFT RPC (Port 26657)

Standard CometBFT RPC endpoints:

| Endpoint | Description |
|----------|-------------|
| `/status` | Node status |
| `/net_info` | Network info |
| `/blockchain` | Blockchain info |
| `/block?height=N` | Block at height |
| `/validators` | Validator set |
| `/consensus_state` | Consensus state |
| `/health` | CometBFT health |

---

## 9. Network Connectivity

### 9.1 Port Requirements

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 8080 | HTTP | Inbound | Validator API |
| 9090 | HTTP | Inbound | Prometheus metrics |
| 26656 | TCP | Bidirectional | CometBFT P2P |
| 26657 | TCP | Inbound | CometBFT RPC |
| 5432 | TCP | Outbound | PostgreSQL |
| 443 | HTTPS | Outbound | Ethereum RPC |
| 443 | HTTPS | Outbound | Accumulate RPC |

### 9.2 Firewall Rules

```bash
# Allow inbound validator API
ufw allow 8080/tcp

# Allow inbound metrics
ufw allow 9090/tcp

# Allow CometBFT P2P
ufw allow 26656/tcp

# Allow CometBFT RPC (restrict to trusted IPs in production)
ufw allow from trusted_ip to any port 26657

# Allow outbound HTTPS for Ethereum/Accumulate
ufw allow out 443/tcp
```

### 9.3 Connecting to Testnet

**Step 1: Obtain Network Configuration**

Contact network operator for:
- Genesis file (`genesis.json`)
- Persistent peer list with node IDs
- Chain ID

**Step 2: Configure Genesis**

Place `genesis.json` at `$DATA_DIR/cometbft/config/genesis.json`:
```json
{
  "genesis_time": "2026-01-01T00:00:00Z",
  "chain_id": "certen-testnet",
  "validators": [
    {
      "address": "...",
      "pub_key": {"type": "tendermint/PubKeyEd25519", "value": "..."},
      "power": "100"
    }
  ],
  "app_hash": ""
}
```

**Step 3: Configure Persistent Peers**

Set environment variable:
```bash
COMETBFT_P2P_PERSISTENT_PEERS=0e895578ca3c2aade47a836050f3f5e505b3d014@validator-1.certen.network:26656,582637177487b78a470243fd25c317b381d7c0ac@validator-2.certen.network:26656
```

**Step 4: Configure Attestation Peers**

Set environment variable:
```bash
ATTESTATION_PEERS=http://validator-1.certen.network:8080,http://validator-2.certen.network:8080
```

**Step 5: Start Validator**

```bash
docker-compose up -d
```

**Step 6: Verify Connection**

```bash
# Check CometBFT status
curl http://localhost:26657/status | jq '.result.sync_info'

# Should show:
# - catching_up: false (when synced)
# - latest_block_height: matches network

# Check peers
curl http://localhost:26657/net_info | jq '.result.n_peers'
```

### 9.4 Deterministic Node IDs

Example node IDs for reference network:
- validator-1: `0e895578ca3c2aade47a836050f3f5e505b3d014`
- validator-2: `582637177487b78a470243fd25c317b381d7c0ac`
- validator-3: `6f376c0572f282ba90a9639492990b02e345746f`
- validator-4: `08e9acfc37c4e5b5d930bf4a1dfade72055aa67b`

---

## 10. Testing and Verification

### 10.1 Health Check

```bash
# Check validator health
curl http://localhost:8086/health | jq

# Expected response:
{
  "status": "ok",
  "phase": "5",
  "consensus": "cometbft",
  "database": "connected",
  "ethereum": "connected",
  "accumulate": "connected",
  "batch_system": "active",
  "proof_cycle": "active",
  "uptime_seconds": 3600
}
```

### 10.2 CometBFT Status

```bash
# Check CometBFT node status
curl http://localhost:26657/status | jq '.result'

# Key fields:
# - sync_info.catching_up: false (when synced)
# - sync_info.latest_block_height: current height
# - validator_info.voting_power: > 0 if active validator

# Check connected peers
curl http://localhost:26657/net_info | jq '.result.n_peers'
```

### 10.3 Database Verification

```bash
# Connect to PostgreSQL
docker exec -it certen-postgres psql -U certen -d certen

# Check tables exist
\dt

# Check batch tables
SELECT * FROM anchor_batches ORDER BY created_at DESC LIMIT 5;

# Check anchor records
SELECT * FROM anchor_records ORDER BY created_at DESC LIMIT 5;

# Check proof storage
SELECT * FROM certen_anchor_proofs ORDER BY created_at DESC LIMIT 5;

# Exit
\q
```

### 10.4 Submit Test Transaction

```bash
# Create on-demand anchor request
curl -X POST http://localhost:8086/api/anchors/on-demand \
  -H "Content-Type: application/json" \
  -d '{
    "accum_tx_hash": "test_hash_123",
    "account_url": "acc://test.acme/data",
    "gov_level": "G0"
  }' | jq

# Expected: Success response with batch/proof IDs
```

### 10.5 Verify Proof Generation

```bash
# Get proof by transaction hash
curl http://localhost:8086/api/proofs/by-tx/test_hash_123 | jq

# Check batch status
curl http://localhost:8086/api/batches/current | jq

# Check costs
curl http://localhost:8086/api/costs | jq
```

### 10.6 Attestation Testing

```bash
# Check attestation service
curl http://localhost:8086/api/attestations | jq

# Check configured peers
curl http://localhost:8086/api/attestations/peers | jq
```

### 10.7 Metrics Verification

```bash
# Check Prometheus metrics
curl http://localhost:9086/metrics | grep certen

# Key metrics:
# - certen_batch_processing_total
# - certen_proof_generation_duration_seconds
# - certen_attestation_requests_total
# - certen_consensus_block_height
```

### 10.8 Log Analysis

```bash
# View validator logs
docker-compose logs -f validator

# Key log entries to verify:
# - "CometBFT consensus started"
# - "Connected to Accumulate network"
# - "Connected to Ethereum network"
# - "Database connection established"
# - "Batch system initialized"
```

---

## 11. Operational Procedures

### 11.1 Starting the Validator

```bash
# Start with Docker Compose
docker-compose up -d

# Check startup
docker-compose logs -f validator

# Wait for health check to pass
while ! curl -s http://localhost:8086/health | grep -q '"status":"ok"'; do
  echo "Waiting for validator to become healthy..."
  sleep 5
done
echo "Validator is healthy!"
```

### 11.2 Stopping the Validator

```bash
# Graceful shutdown
docker-compose down

# Or send SIGTERM to process
docker-compose exec validator kill -SIGTERM 1
```

### 11.3 Backup Procedures

```bash
# Backup database
docker exec certen-postgres pg_dump -U certen certen > backup_$(date +%Y%m%d).sql

# Backup validator keys
cp -r validator_bft_keys/ backup_keys_$(date +%Y%m%d)/

# Backup data directory
cp -r validator_data/ backup_data_$(date +%Y%m%d)/
```

### 11.4 Restore Procedures

```bash
# Stop validator
docker-compose down

# Restore database
cat backup_20260101.sql | docker exec -i certen-postgres psql -U certen -d certen

# Restore keys
cp -r backup_keys_20260101/* validator_bft_keys/

# Restore data
cp -r backup_data_20260101/* validator_data/

# Start validator
docker-compose up -d
```

### 11.5 Key Rotation

```bash
# 1. Generate new keys
./validator --generate-keys --output new_keys/

# 2. Stop validator
docker-compose down

# 3. Backup old keys
mv validator_bft_keys/ old_keys_backup/

# 4. Install new keys
mv new_keys/ validator_bft_keys/

# 5. Update network configuration (if node ID changed)
# Coordinate with network operator

# 6. Start validator
docker-compose up -d
```

### 11.6 Monitoring Setup

**Prometheus Scrape Config:**
```yaml
scrape_configs:
  - job_name: 'certen-validator'
    static_configs:
      - targets: ['validator:9090']
    metrics_path: /metrics
    scheme: http
```

**Key Metrics to Alert On:**
- `certen_health_status != 1` (unhealthy)
- `certen_consensus_catching_up == 1` (not synced)
- `certen_attestation_failures > 0` (attestation issues)
- `certen_ethereum_balance_wei < threshold` (low gas)

### 11.7 Troubleshooting

**Issue: Validator not syncing**
```bash
# Check peer connections
curl http://localhost:26657/net_info | jq '.result.n_peers'

# If 0 peers, verify:
# 1. Persistent peers are configured correctly
# 2. Port 26656 is open and accessible
# 3. Node IDs match network configuration
```

**Issue: Attestation failures**
```bash
# Check attestation peers
curl http://localhost:8086/api/attestations/peers | jq

# Verify peer connectivity
for peer in $(echo $ATTESTATION_PEERS | tr ',' '\n'); do
  curl -s "$peer/health" && echo " - $peer OK" || echo " - $peer FAILED"
done
```

**Issue: Database connection errors**
```bash
# Check PostgreSQL status
docker-compose exec postgres pg_isready -U certen -d certen

# Check connection pool
docker-compose logs validator | grep -i "database"
```

**Issue: Ethereum transaction failures**
```bash
# Check Ethereum balance
curl -X POST $ETHEREUM_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["'$ETH_ADDRESS'","latest"],"id":1}' | jq

# Check gas prices
curl -X POST $ETHEREUM_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":1}' | jq
```

---

## Appendix A: Critical Source Files

These files are essential for understanding the validator implementation:

| File | Lines | Description |
|------|-------|-------------|
| `main.go` | ~1200 | Main entry point, component wiring |
| `pkg/consensus/bft_integration.go` | ~600 | CometBFT integration |
| `pkg/consensus/abci_validator.go` | ~500 | ABCI application |
| `pkg/consensus/validator_block_builder.go` | ~400 | Block construction |
| `pkg/batch/processor.go` | ~500 | Batch processing |
| `pkg/batch/consensus_coordinator.go` | ~400 | Multi-validator coordination |
| `pkg/proof/artifact_service.go` | ~600 | Proof orchestration |
| `pkg/proof/liteclient_proof_generator.go` | ~400 | L1-L3 proof generation |
| `pkg/database/migrations/001_initial_schema.sql` | ~300 | Database schema |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **BFT** | Byzantine Fault Tolerant - consensus that tolerates f failures in 3f+1 nodes |
| **CometBFT** | Consensus engine (formerly Tendermint) |
| **ABCI** | Application Blockchain Interface - CometBFT application protocol |
| **L1-L3** | Chained proof levels (Account → BPT → Partition → Network) |
| **G0-G2** | Governance proof levels (Inclusion → Authority → Outcome Binding) |
| **BLS** | Boneh-Lynn-Shacham signature scheme for aggregate signatures |
| **On-Cadence** | Batched anchoring (~15 min intervals, ~$0.05/proof) |
| **On-Demand** | Immediate anchoring (~$0.25/proof) |
| **Anchor** | Transaction recording proof commitment on external chain |
| **Attestation** | Validator signature confirming proof validity |
| **Quorum** | 2f+1 validators required for consensus (67%+) |

---

## Appendix C: Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Jan 2026 | Initial exhaustive implementation plan |

---

**End of Implementation Plan**
