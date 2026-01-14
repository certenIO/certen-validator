# Certen Independent Validator - Phased Build Plan

This document provides a **step-by-step execution plan** for developers to build the independent validator. Work through each phase in order - each phase builds on the previous one.

---

## Overview

| Phase | Name | Duration | Dependencies |
|-------|------|----------|--------------|
| 1 | Project Setup | 1-2 hours | None |
| 2 | Core Infrastructure | 2-4 hours | Phase 1 |
| 3 | Configuration & Database | 2-4 hours | Phase 2 |
| 4 | Cryptography Layer | 4-6 hours | Phase 3 |
| 5 | Consensus Engine | 4-8 hours | Phase 4 |
| 6 | Proof Generation | 6-10 hours | Phase 5 |
| 7 | Batch System | 4-6 hours | Phase 6 |
| 8 | HTTP API | 2-4 hours | Phase 7 |
| 9 | Integration & Testing | 4-8 hours | Phase 8 |
| 10 | Docker & Deployment | 2-4 hours | Phase 9 |

**Total Estimated Time:** 30-55 hours (1-2 developer weeks)

---

## Phase 1: Project Setup

**Goal:** Create the directory structure and initialize the Go module.

### Step 1.1: Create Directory Structure

```bash
cd C:\Accumulate_Stuff\certen\independant_validator

# Create all package directories
mkdir -p cmd/bls-zk-setup
mkdir -p cmd/generate-vk
mkdir -p pkg/accumulate
mkdir -p pkg/anchor
mkdir -p pkg/anchor_proof
mkdir -p pkg/attestation
mkdir -p pkg/batch
mkdir -p pkg/commitment
mkdir -p pkg/config
mkdir -p pkg/consensus
mkdir -p pkg/crypto/bls
mkdir -p pkg/crypto/bls_zkp
mkdir -p pkg/database/migrations
mkdir -p pkg/ethereum
mkdir -p pkg/execution/contracts
mkdir -p pkg/intent
mkdir -p pkg/kvdb
mkdir -p pkg/ledger
mkdir -p pkg/merkle
mkdir -p pkg/proof
mkdir -p pkg/protocol
mkdir -p pkg/server
mkdir -p pkg/verification
mkdir -p bls_zk_keys
mkdir -p data
```

### Step 1.2: Initialize Go Module

```bash
# Create go.mod
cat > go.mod << 'EOF'
module github.com/certen/independant-validator

go 1.24.0

require (
    github.com/cometbft/cometbft v0.38.0
    github.com/cometbft/cometbft-db v0.7.0
    github.com/consensys/gnark v0.14.0
    github.com/consensys/gnark-crypto v0.19.0
    github.com/ethereum/go-ethereum v1.16.7
    github.com/google/uuid v1.6.0
    github.com/gorilla/mux v1.8.1
    github.com/lib/pq v1.10.9
    github.com/rs/zerolog v1.31.0
    github.com/spf13/viper v1.18.2
    github.com/supranational/blst v0.3.16
    gitlab.com/accumulatenetwork/accumulate v1.4.2
)
EOF

go mod download
go mod tidy
```

### Step 1.3: Copy accumulate-lite-client-2

```bash
# This is a dependency - copy the entire directory
cp -r C:\Accumulate_Stuff\certen\certen-protocol\services\validator\accumulate-lite-client-2 .
```

### Checkpoint 1
- [ ] Directory structure exists
- [ ] `go mod download` succeeds
- [ ] accumulate-lite-client-2 directory present

---

## Phase 2: Core Infrastructure

**Goal:** Set up the foundational packages that other packages depend on.

### Step 2.1: Copy pkg/config

```bash
# Configuration loading - everything else depends on this
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\config\*.go pkg/config/
```

**Files to copy:**
- `config.go` - Main configuration loader
- `anchor_config.go` - Anchor-specific config

**Verify:** `go build ./pkg/config/...`

### Step 2.2: Copy pkg/kvdb

```bash
# Key-value database abstraction
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\kvdb\*.go pkg/kvdb/
```

**Files to copy:**
- `adapter.go` - KV interface

**Verify:** `go build ./pkg/kvdb/...`

### Step 2.3: Copy pkg/ledger

```bash
# Ledger storage (depends on kvdb)
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\ledger\*.go pkg/ledger/
```

**Files to copy:**
- `store.go` - LedgerStore implementation
- `types.go` - Ledger types
- `errors.go` - Error definitions

**Verify:** `go build ./pkg/ledger/...`

### Step 2.4: Copy pkg/merkle

```bash
# Merkle tree utilities
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\merkle\*.go pkg/merkle/
```

**Files to copy:**
- `tree.go` - Merkle tree construction
- `receipt.go` - Merkle receipt handling

**Verify:** `go build ./pkg/merkle/...`

### Step 2.5: Copy pkg/commitment

```bash
# Commitment proofs (RFC8785 canonical JSON)
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\commitment\*.go pkg/commitment/
```

**Files to copy:**
- `commitment.go`

**Verify:** `go build ./pkg/commitment/...`

### Checkpoint 2
- [ ] `go build ./pkg/config/...` succeeds
- [ ] `go build ./pkg/kvdb/...` succeeds
- [ ] `go build ./pkg/ledger/...` succeeds
- [ ] `go build ./pkg/merkle/...` succeeds
- [ ] `go build ./pkg/commitment/...` succeeds

---

## Phase 3: Configuration & Database

**Goal:** Set up database connectivity and migrations.

### Step 3.1: Copy pkg/database

```bash
# Copy all database files
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\database\*.go pkg/database/

# Copy migrations
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\database\migrations\*.sql pkg/database/migrations/
```

**Files to copy:**
- `client.go` - Database client with connection pooling
- `errors.go` - Error definitions
- `types.go` - Database types
- `repositories.go` - Repository factory
- `repository_batch.go` - Batch repository
- `repository_anchor.go` - Anchor repository
- `repository_attestation.go` - Attestation repository
- `repository_proof.go` - Proof repository
- `repository_request.go` - Request repository
- `proof_artifact_repository.go` - Proof artifact storage
- `proof_artifact_types.go` - Proof artifact types
- `migrations/001_initial_schema.sql` - Initial schema

**Verify:** `go build ./pkg/database/...`

### Step 3.2: Create .env.example

```bash
cat > .env.example << 'EOF'
# Validator Identity
VALIDATOR_ID=validator-1
NETWORK_NAME=testnet

# Database
POSTGRES_PASSWORD=change_me
DATABASE_URL=postgres://certen:${POSTGRES_PASSWORD}@localhost:5432/certen?sslmode=disable

# Accumulate Network
ACCUMULATE_URL=https://kermit.accumulatenetwork.io/v3

# Ethereum Network (Sepolia)
ETHEREUM_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
ETH_CHAIN_ID=11155111
ETH_PRIVATE_KEY=0x_YOUR_KEY

# Contract Addresses
CERTEN_CONTRACT_ADDRESS=0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98
BLS_ZK_VERIFIER_ADDRESS=0x631B6444216b981561034655349F8a28962DcC5F

# CometBFT
COMETBFT_ENABLED=true
COMETBFT_MODE=validator
COMETBFT_CHAIN_ID=certen-testnet

# Attestation (for multi-validator setup)
ATTESTATION_PEERS=
ATTESTATION_REQUIRED_COUNT=3

# Paths
GOV_PROOF_CLI_PATH=./govproof
TXHASH_CLI_PATH=./txhash
BLS_ZK_KEYS_DIR=./bls_zk_keys
EOF
```

### Step 3.3: Test Database Connection

```bash
# Start PostgreSQL (Docker)
docker run -d --name certen-postgres \
  -e POSTGRES_DB=certen \
  -e POSTGRES_USER=certen \
  -e POSTGRES_PASSWORD=testpass \
  -p 5432:5432 \
  postgres:15-alpine

# Wait for startup
sleep 5

# Apply migrations
cat pkg/database/migrations/001_initial_schema.sql | \
  docker exec -i certen-postgres psql -U certen -d certen
```

### Checkpoint 3
- [ ] `go build ./pkg/database/...` succeeds
- [ ] PostgreSQL running
- [ ] Migrations applied successfully
- [ ] `.env.example` created

---

## Phase 4: Cryptography Layer

**Goal:** Implement BLS signatures and ZK proof infrastructure.

### Step 4.1: Copy pkg/crypto/bls

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\crypto\bls\*.go pkg/crypto/bls/
```

**Files to copy:**
- `bls.go` - Core BLS12-381 operations
- `key_manager.go` - Key generation and management

**Verify:** `go build ./pkg/crypto/bls/...`

### Step 4.2: Copy pkg/crypto/bls_zkp

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\crypto\bls_zkp\*.go pkg/crypto/bls_zkp/
```

**Files to copy:**
- `circuit.go` - Groth16 circuit definition
- `prover.go` - ZK prover
- `setup.go` - Trusted setup

**Verify:** `go build ./pkg/crypto/bls_zkp/...`

### Step 4.3: Copy and Build BLS ZK Setup Tool

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\cmd\bls-zk-setup\*.go cmd/bls-zk-setup/

# Build the tool
cd cmd/bls-zk-setup
go build -o bls-zk-setup .
cd ../..

# Generate proving keys (takes 5-10 minutes)
./cmd/bls-zk-setup/bls-zk-setup
```

### Step 4.4: Copy pkg/anchor_proof

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\anchor_proof\*.go pkg/anchor_proof/
```

**Files to copy:**
- `builder.go` - Proof builder
- `signer.go` - Proof signing
- `verifier.go` - Proof verification
- `types.go` - Type definitions
- `export.go` - Proof serialization

**Verify:** `go build ./pkg/anchor_proof/...`

### Checkpoint 4
- [ ] `go build ./pkg/crypto/bls/...` succeeds
- [ ] `go build ./pkg/crypto/bls_zkp/...` succeeds
- [ ] BLS ZK setup tool builds and runs
- [ ] `bls_zk_keys/` contains proving_key.bin and verification_key.bin
- [ ] `go build ./pkg/anchor_proof/...` succeeds

---

## Phase 5: Consensus Engine

**Goal:** Implement CometBFT integration and block production.

### Step 5.1: Copy pkg/consensus

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\consensus\*.go pkg/consensus/
```

**Files to copy (in dependency order):**
1. `types.go` - Type definitions
2. `intent.go` - Intent types
3. `validator_block.go` - ValidatorBlock structure
4. `validator_block_builder.go` - Block construction
5. `validator_block_invariants.go` - Validation rules
6. `abci_validator.go` - ABCI application
7. `bft_integration.go` - CometBFT integration (main file)

**Verify:** `go build ./pkg/consensus/...`

### Step 5.2: Copy pkg/accumulate

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\accumulate\*.go pkg/accumulate/
```

**Files to copy:**
- `accumulate_client.go` - Client interface
- `liteclient_adapter.go` - LiteClientAdapter

**Verify:** `go build ./pkg/accumulate/...`

### Step 5.3: Copy pkg/ethereum

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\ethereum\*.go pkg/ethereum/
```

**Files to copy:**
- `client.go` - Ethereum RPC client

**Verify:** `go build ./pkg/ethereum/...`

### Checkpoint 5
- [ ] `go build ./pkg/consensus/...` succeeds
- [ ] `go build ./pkg/accumulate/...` succeeds
- [ ] `go build ./pkg/ethereum/...` succeeds

---

## Phase 6: Proof Generation

**Goal:** Implement the 4-level proof system.

### Step 6.1: Copy pkg/proof

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\proof\*.go pkg/proof/
```

**Key files (copy all .go files):**
- `certen_proof.go` - Main CertenProof type
- `artifact_service.go` - ProofArtifactService orchestrator
- `liteclient_proof_generator.go` - L1-L3 proof generation
- `governance_library.go` - G0-G2 governance proofs
- `governance_types.go` - Governance types
- `governance_adapter.go` - Governance adapter
- `batch_adapter.go` - Batch proof adapter
- `bundle_format.go` - Proof bundle format
- `canonical_blob_hash.go` - Canonical hashing
- `lifecycle.go` - Proof lifecycle
- `attestation.go` - Attestation proofs
- `proof_request_types.go` - Request types

**Verify:** `go build ./pkg/proof/...`

### Step 6.2: Copy pkg/verification

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\verification\*.go pkg/verification/
```

**Files to copy:**
- `unified_verifier.go` - Main verification engine
- Additional verifier files

**Verify:** `go build ./pkg/verification/...`

### Step 6.3: Copy pkg/anchor

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\anchor\*.go pkg/anchor/
```

**Files to copy:**
- `anchor_manager.go` - AnchorManager lifecycle
- `scheduler.go` - Anchor scheduling
- `event_watcher.go` - Contract event monitoring
- `proof_converter.go` - Proof format conversion

**Verify:** `go build ./pkg/anchor/...`

### Step 6.4: Build Governance Proof CLI

```bash
cd accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
go build -o govproof .
cp govproof ../../../../
cd ../../../..

# Build txhash tool
cd accumulate-lite-client-2/liteclient/cmd/txhash
go build -o txhash .
cp txhash ../../../../
cd ../../../..
```

### Checkpoint 6
- [ ] `go build ./pkg/proof/...` succeeds
- [ ] `go build ./pkg/verification/...` succeeds
- [ ] `go build ./pkg/anchor/...` succeeds
- [ ] `./govproof --help` works
- [ ] `./txhash --help` works

---

## Phase 7: Batch System

**Goal:** Implement transaction batching and multi-validator attestation.

### Step 7.1: Copy pkg/intent

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\intent\*.go pkg/intent/
```

**Files to copy:**
- `discovery.go` - Block monitoring for CERTEN_INTENT
- `conversion.go` - Intent format conversion
- `intent_model_alias.go` - Model aliases

**Verify:** `go build ./pkg/intent/...`

### Step 7.2: Copy pkg/execution

```bash
# Copy main files
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\execution\*.go pkg/execution/

# Copy contract bindings
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\execution\contracts\*.go pkg/execution/contracts/
```

**Files to copy:**
- `executor.go` - Execution orchestrator
- `ethereum_contracts.go` - Contract interaction
- `proof_cycle_orchestrator.go` - Proof cycle management
- `external_chain_observer.go` - External chain monitoring
- `external_chain_result.go` - Execution results
- `nonce_tracker.go` - Transaction nonce tracking
- `accumulate_submitter.go` - Write-back to Accumulate
- `commitment_builder.go` - Commitment construction
- `g2_outcome_binding.go` - G2 outcome binding
- `result_attestation.go` - Result attestation
- `contracts/*.go` - All contract ABI bindings

**Verify:** `go build ./pkg/execution/...`

### Step 7.3: Copy pkg/attestation

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\attestation\*.go pkg/attestation/
```

**Files to copy:**
- `service.go` - Attestation service

**Verify:** `go build ./pkg/attestation/...`

### Step 7.4: Copy pkg/batch

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\batch\*.go pkg/batch/
```

**Files to copy:**
- `collector.go` - Transaction batching
- `scheduler.go` - 15-minute batch scheduler
- `processor.go` - Batch processing
- `on_demand.go` - Immediate anchoring
- `consensus_coordinator.go` - Multi-validator coordination
- `attestation_broadcaster.go` - Broadcast attestations
- `peer_manager.go` - Validator peer management
- `confirmation_tracker.go` - Anchor finality
- `cost_tracker.go` - Gas cost tracking
- `anchor_adapter.go` - Bridge to AnchorManager
- `bpt_extractor.go` - BPT root extraction
- `proof_helpers.go` - Utility functions
- `errors.go` - Error definitions

**Verify:** `go build ./pkg/batch/...`

### Checkpoint 7
- [ ] `go build ./pkg/intent/...` succeeds
- [ ] `go build ./pkg/execution/...` succeeds
- [ ] `go build ./pkg/attestation/...` succeeds
- [ ] `go build ./pkg/batch/...` succeeds

---

## Phase 8: HTTP API

**Goal:** Implement the REST API server.

### Step 8.1: Copy pkg/server

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\pkg\server\*.go pkg/server/
```

**Files to copy:**
- `attestation_handlers.go` - Attestation endpoints
- `batch_handlers.go` - Batch endpoints
- `proof_handlers.go` - Proof query endpoints
- `bundle_handlers.go` - Bundle endpoints
- `bulk_handlers.go` - Bulk operations
- `ledger_handlers.go` - Ledger endpoints

**Verify:** `go build ./pkg/server/...`

### Checkpoint 8
- [ ] `go build ./pkg/server/...` succeeds
- [ ] All packages compile: `go build ./...`

---

## Phase 9: Main Entry Point & Integration

**Goal:** Wire everything together in main.go.

### Step 9.1: Copy main.go

```bash
cp C:\Accumulate_Stuff\certen\certen-protocol\services\validator\main.go .
```

**This is the main entry point (~1200 lines) that:**
- Loads configuration
- Initializes database
- Initializes Accumulate client
- Initializes Ethereum client
- Starts CometBFT consensus
- Starts batch system
- Starts HTTP server
- Handles graceful shutdown

### Step 9.2: Build the Validator

```bash
# Build with CGO (required for gnark/blst)
CGO_ENABLED=1 go build -o validator .
```

### Step 9.3: Test Startup

```bash
# Set minimal environment
export VALIDATOR_ID=test-validator
export DATABASE_URL="postgres://certen:testpass@localhost:5432/certen?sslmode=disable"
export ETHEREUM_URL="https://eth-sepolia.g.alchemy.com/v2/demo"
export ETH_CHAIN_ID=11155111
export ETH_PRIVATE_KEY="0x0000000000000000000000000000000000000000000000000000000000000001"
export ACCUMULATE_URL="https://kermit.accumulatenetwork.io/v3"
export CERTEN_CONTRACT_ADDRESS="0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98"
export COMETBFT_ENABLED=false  # Disable for initial test
export GOV_PROOF_CLI_PATH="./govproof"
export TXHASH_CLI_PATH="./txhash"
export BLS_ZK_KEYS_DIR="./bls_zk_keys"

# Run validator
./validator
```

### Step 9.4: Verify Health Endpoint

```bash
# In another terminal
curl http://localhost:8080/health

# Expected: {"status":"ok",...}
```

### Checkpoint 9
- [ ] `go build -o validator .` succeeds
- [ ] Validator starts without errors
- [ ] Health endpoint returns OK
- [ ] Database connection works

---

## Phase 10: Docker & Deployment

**Goal:** Package for production deployment.

### Step 10.1: Create Dockerfile

```bash
cat > Dockerfile << 'EOF'
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /build

COPY go.mod go.sum ./
COPY accumulate-lite-client-2/ ./accumulate-lite-client-2/
RUN go mod download

COPY . ./

# Build validator
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o validator .

# Build governance proof CLI
WORKDIR /build/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/govproof .

# Build txhash tool
WORKDIR /build/accumulate-lite-client-2/liteclient/cmd/txhash
RUN CGO_ENABLED=0 GOOS=linux go build -o /build/txhash .

WORKDIR /build

# Generate BLS ZK keys
RUN mkdir -p /build/bls_zk_keys && go run ./cmd/bls-zk-setup 2>&1

# Production image
FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -s /bin/sh validator

WORKDIR /app

COPY --from=builder /build/validator .
COPY --from=builder /build/govproof .
COPY --from=builder /build/txhash .
COPY --from=builder /build/bls_zk_keys/ /app/bls_zk_keys/

RUN mkdir -p /app/bft-keys /app/data /app/data/cometbft
RUN chown -R validator:validator /app

USER validator

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

EXPOSE 8080 9090 26656 26657

ENV GOV_PROOF_CLI_PATH=/app/govproof \
    TXHASH_CLI_PATH=/app/txhash \
    BLS_ZK_KEYS_DIR=/app/bls_zk_keys

CMD ["./validator"]
EOF
```

### Step 10.2: Create docker-compose.yml

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: certen
      POSTGRES_USER: certen
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?required}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./pkg/database/migrations/001_initial_schema.sql:/docker-entrypoint-initdb.d/01-schema.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U certen -d certen"]
      interval: 10s
      timeout: 5s
      retries: 5

  validator:
    build: .
    ports:
      - "8086:8080"
      - "9086:9090"
      - "26656:26656"
      - "26657:26657"
    env_file:
      - .env
    environment:
      DATABASE_URL: postgres://certen:${POSTGRES_PASSWORD}@postgres:5432/certen?sslmode=disable
    volumes:
      - validator_data:/app/data
      - validator_keys:/app/bft-keys
    depends_on:
      postgres:
        condition: service_healthy

volumes:
  postgres_data:
  validator_data:
  validator_keys:
EOF
```

### Step 10.3: Build and Run

```bash
# Copy .env.example to .env and configure
cp .env.example .env
# Edit .env with real values

# Build Docker image
docker build -t certen-validator:latest .

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f validator
```

### Final Checkpoint
- [ ] Docker build succeeds
- [ ] `docker-compose up -d` starts all services
- [ ] Health check passes: `curl http://localhost:8086/health`
- [ ] CometBFT status: `curl http://localhost:26657/status`

---

## Post-Implementation: Connect to Testnet

Once the validator is built and running locally:

1. **Get testnet configuration** from network operator:
   - genesis.json
   - Peer list with node IDs

2. **Configure peers** in .env:
   ```
   COMETBFT_P2P_PERSISTENT_PEERS=nodeID1@host1:26656,nodeID2@host2:26656
   ATTESTATION_PEERS=http://validator-1:8080,http://validator-2:8080
   ```

3. **Place genesis file**:
   ```bash
   cp genesis.json data/cometbft/config/
   ```

4. **Restart and sync**:
   ```bash
   docker-compose restart validator
   docker-compose logs -f validator
   ```

5. **Monitor sync progress**:
   ```bash
   curl http://localhost:26657/status | jq '.result.sync_info.catching_up'
   # Wait until: false
   ```

---

## Troubleshooting by Phase

| Phase | Common Issue | Solution |
|-------|--------------|----------|
| 1 | `go mod download` fails | Check Go version (need 1.24+), check network |
| 2-4 | Package won't compile | Check for missing files, run `go mod tidy` |
| 4 | BLS ZK setup hangs | Normal - takes 5-10 minutes, needs RAM |
| 5 | CometBFT errors | Check COMETBFT_ENABLED=false for testing |
| 9 | Database connection fails | Verify PostgreSQL running, check DATABASE_URL |
| 10 | Docker build fails | Check CGO dependencies, Alpine packages |

---

## Summary

Follow phases 1-10 in order. Each phase has a checkpoint - don't proceed until all checks pass. The entire build should take 1-2 developer weeks depending on experience with Go and blockchain systems.
