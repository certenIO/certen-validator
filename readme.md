# Certen Independent Validator

Byzantine Fault Tolerant consensus node for the Certen Protocol -- orchestrating multi-layer cryptographic proof generation, cross-chain state anchoring, and validator attestation across 13 blockchain networks.

## Overview

The Certen Independent Validator is a BFT consensus node that forms the backbone of the Certen Protocol network. It monitors the Accumulate blockchain for transaction intents, generates multi-layer cryptographic proofs binding account state to on-chain anchors, and coordinates with peer validators to produce aggregate attestations. Anchored state roots and proofs are submitted to target chains (EVM, Solana, Aptos, Sui, NEAR, TON, TRON) via chain-specific smart contracts, enabling trustless cross-chain verification.

Core functions:

1. **Intent Discovery**: Polls the Accumulate network for `CERTEN_INTENT` transactions and routes them for proof generation
2. **Multi-Layer Proof Generation**: Produces a 9-phase proof cycle covering lite-client proofs (L1-L4), governance proofs (G0-G2), BLS aggregate signatures, and Ethereum anchoring
3. **BFT Consensus**: Runs CometBFT consensus across the validator set, requiring 2/3+ honest participation
4. **Batch Management**: Groups transactions into on-cadence (time-based) or on-demand (immediate) batches with Merkle root computation
5. **Cross-Chain Anchoring**: Submits batch Merkle roots and comprehensive proofs to target chain smart contracts (EVM, Solana, Aptos, Sui, NEAR, TON, TRON)
6. **Attestation Collection**: Broadcasts proof requests to peer validators and collects 2f+1 BLS/Ed25519 signatures

## Architecture

```
+------------------------------------------------------------------+
|                    Certen Independent Validator                    |
+------------------------------------------------------------------+
|                                                                    |
|  +------------------+    +------------------+    +---------------+ |
|  |   CometBFT       |    |   Proof Cycle    |    |  Attestation  | |
|  |   Consensus      |    |   Orchestrator   |    |  Service      | |
|  +--------+---------+    +--------+---------+    +-------+-------+ |
|           |                       |                      |         |
|           v                       v                      v         |
|  +------------------+    +------------------+    +---------------+ |
|  |   P2P Network    |    |   Multi-Chain    |    |  Peer         | |
|  |   (26656/26657)  |    |   Anchoring      |    |  Validators   | |
|  +------------------+    +------------------+    +---------------+ |
|           |                       |                      |         |
|           v                       v                      v         |
|  +------------------+    +------------------+    +---------------+ |
|  |   Intent         |    |   Batch          |    |  PostgreSQL   | |
|  |   Discovery      |    |   Processor      |    |  Database     | |
|  +------------------+    +------------------+    +---------------+ |
|                                                                    |
+------------------------------------------------------------------+
                                  |
                                  v
+------------------------------------------------------------------+
|                      External Services                            |
+------------------------------------------------------------------+
|  - Accumulate Network (v3 API + CometBFT RPC)                    |
|  - EVM Chains (Ethereum, Arbitrum, Optimism, Base, BSC,           |
|    Polygon, Moonbeam — all testnets)                              |
|  - Non-EVM Chains (Solana, Aptos, Sui, NEAR, TON, TRON)          |
|  - CertenAnchor + BLSZKVerifier + AccountFactory contracts        |
+------------------------------------------------------------------+
```

## Features

- **BFT Consensus**: CometBFT-based consensus with configurable validator sets (minimum 4, recommended 7+)
- **9-Phase Proof Cycle**: Complete cryptographic proof pipeline from account state to Ethereum anchor
- **Multi-Chain Anchoring**: 13 target chains — EVM (Ethereum, Arbitrum, Optimism, Base, BSC, Polygon, Moonbeam) and non-EVM (Solana, Aptos, Sui, NEAR, TON, TRON)
- **BLS Aggregate Signatures**: Groth16 ZK-SNARK proofs for on-chain BLS12-381 verification
- **Governance Proofs**: Three-level governance verification (G0 inclusion, G1 correctness, G2 outcome binding)
- **Batch System**: On-cadence (~15 min) and on-demand batching with Merkle tree construction
- **REST API**: Proof discovery, batch status, and ledger state endpoints
- **Prometheus Metrics**: Consensus height, proofs generated, gas usage, batch sizes
- **Optional Firestore Sync**: Real-time proof status updates for the web application

## Prerequisites

- Go 1.24+
- PostgreSQL 15+
- Ethereum RPC endpoint (Alchemy, Infura, or self-hosted)
- Accumulate network access (Kermit Testnet or Mainnet)
- Pre-generated BLS ZK keys (via included `bls-zk-setup` tool)

## Quick Start

```bash
# Clone repository
git clone https://github.com/certenIO/independant_validator.git
cd independant_validator

# Copy environment template
cp .env.example .env
# Edit .env with your configuration

# Build the validator binary
go build -o validator .

# Generate BLS ZK proving/verification keys (first time, ~5-10 minutes)
go run ./cmd/bls-zk-setup

# Start the validator
./validator
```

## Installation

### Build from Source

```bash
# Install Go dependencies
go mod download

# Build all binaries
go build -o validator .
cd accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof && go build -o govproof .
cd cmd/txhash && go build -o txhash .
```

### Docker

```bash
# Build image (includes BLS key generation)
docker build -t certen/validator .

# Run single validator
docker run -d \
  --name certen-validator \
  -p 8080:8080 \
  -p 26656:26656 \
  -p 26657:26657 \
  --env-file .env \
  certen/validator
```

### Docker Compose (7-Validator Testnet)

```bash
# Start the full 7-validator network with PostgreSQL
docker compose up -d

# Check logs
docker compose logs -f validator-1

# Stop
docker compose down
```

The included `docker-compose.yml` deploys a complete testnet:

| Service | HTTP | P2P | RPC |
|---------|------|-----|-----|
| validator-1 | 8081 | 26656 | 26657 |
| validator-2 | 8082 | 26666 | 26667 |
| validator-3 | 8083 | 26676 | 26677 |
| validator-4 | 8084 | 26686 | 26687 |
| validator-5 | 8095 | 26696 | 26697 |
| validator-6 | 8086 | 26706 | 26707 |
| validator-7 | 8087 | 26716 | 26717 |
| postgres | - | - | 5432 |

## Configuration

### Environment Variables

#### Core Identity

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VALIDATOR_ID` | Yes | - | Unique validator identifier |
| `NETWORK_NAME` | No | testnet | Network name (devnet/kermit/mainnet) |

#### Database (PostgreSQL)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `DATABASE_MAX_CONNS` | No | 25 | Maximum connection pool size |
| `DATABASE_REQUIRED` | No | false | Fail startup if database unavailable |

#### Accumulate Integration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACCUMULATE_URL` | Yes | - | Accumulate v3 API endpoint |
| `ACCUMULATE_COMET_DN` | No | - | Directory Network CometBFT RPC |
| `ACCUMULATE_COMET_BVN` | No | - | Block Validation Network CometBFT RPC |

#### Ethereum and EVM Chains

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ETHEREUM_URL` | Yes | - | Ethereum RPC endpoint |
| `ETH_CHAIN_ID` | No | 11155111 | Chain ID (11155111 = Sepolia) |
| `ETH_PRIVATE_KEY` | Yes | - | Validator Ethereum signing key |
| `CERTEN_CONTRACT_ADDRESS` | Yes | - | Main anchor contract address |
| `CERTEN_ANCHOR_V3_ADDRESS` | No | - | CertenAnchorV3 contract address |
| `BLS_ZK_VERIFIER_ADDRESS` | No | - | BLSZKVerifier contract address |
| `ARBITRUM_SEPOLIA_RPC_URL` | No | - | Arbitrum Sepolia RPC |
| `OPTIMISM_SEPOLIA_RPC_URL` | No | - | Optimism Sepolia RPC |
| `BASE_SEPOLIA_RPC_URL` | No | - | Base Sepolia RPC |

#### CometBFT Consensus

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `COMETBFT_ENABLED` | No | true | Enable CometBFT consensus |
| `COMETBFT_MODE` | No | validator | Node mode (validator/full) |
| `COMETBFT_CHAIN_ID` | No | certen-testnet | CometBFT chain ID |
| `COMETBFT_P2P_SEEDS` | No | - | Seed nodes (addr@host:port,...) |
| `COMETBFT_P2P_LADDR` | No | tcp://0.0.0.0:26656 | P2P listen address |
| `COMETBFT_RPC_LADDR` | No | tcp://0.0.0.0:26657 | RPC listen address |

#### Non-EVM Chains

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SOLANA_DEVNET_RPC_URL` | No | - | Solana Devnet RPC |
| `SOLANA_ANCHOR_PROGRAM_ID` | No | - | Solana anchor program address |
| `APTOS_TESTNET_RPC_URL` | No | - | Aptos Testnet RPC |
| `APTOS_ANCHOR_PACKAGE` | No | - | Aptos anchor package address |
| `SUI_TESTNET_RPC_URL` | No | - | Sui Testnet RPC |
| `SUI_ANCHOR_PACKAGE` | No | - | Sui anchor package address |
| `NEAR_TESTNET_RPC_URL` | No | - | NEAR Testnet RPC |
| `NEAR_ANCHOR_CONTRACT` | No | - | NEAR anchor contract ID |
| `TON_TESTNET_API_URL` | No | - | TON Center API endpoint |
| `TON_ANCHOR_CONTRACT` | No | - | TON anchor contract address |
| `TON_BLS_VERIFIER_CONTRACT` | No | - | TON BLS ZK verifier address |
| `TON_ACCOUNT_FACTORY_CONTRACT` | No | - | TON account factory address |
| `TRON_SHASTA_RPC_URL` | No | - | TRON Shasta JSON-RPC endpoint |

#### Attestation

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ATTESTATION_PEERS` | Yes | - | Peer validator HTTP URLs (comma-separated) |
| `ATTESTATION_REQUIRED_COUNT` | No | 3 | Required attestation count (2f+1) |

#### Proof Generation

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BLS_ZK_TESTING_MODE` | No | false | Use test mode for BLS ZK proofs |
| `BLS_ZK_KEYS_DIR` | No | /app/bls_zk_keys | Groth16 keys directory |
| `GOV_PROOF_CLI_PATH` | No | /app/govproof | Governance proof CLI binary path |
| `ENABLE_MERKLE_VERIFICATION` | No | true | Enable Merkle proof verification |
| `ENABLE_GOVERNANCE_VERIFICATION` | No | true | Enable governance proof verification |
| `ENABLE_BLS_VERIFICATION` | No | true | Enable BLS signature verification |
| `ENABLE_PARALLEL_VERIFICATION` | No | true | Enable parallel proof verification |
| `VERIFICATION_TIMEOUT` | No | 30s | Verification timeout duration |

#### Optional Services

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PROOF_CYCLE_WRITEBACK` | No | false | Write results back to Accumulate |
| `FIRESTORE_ENABLED` | No | false | Enable Firestore real-time sync |
| `FIREBASE_PROJECT_ID` | No | - | Firebase project ID |
| `GOOGLE_APPLICATION_CREDENTIALS` | No | - | Service account JSON path |

### Network Endpoints

| Network | Accumulate v3 | CometBFT DN | CometBFT BVN |
|---------|---------------|-------------|---------------|
| Kermit Testnet | `https://kermit.accumulatenetwork.io/v3` | `http://host:16592` | `http://host:16692` |
| DevNet | `http://localhost:26660/v3` | `http://localhost:16592` | `http://localhost:16692` |
| Mainnet | `https://mainnet.accumulatenetwork.io/v3` | Production endpoints | Production endpoints |

## Proof Cycle

The validator executes a 9-phase cryptographic proof cycle for each transaction:

| Phase | Layer | Name | Description |
|-------|-------|------|-------------|
| L1 | Account | State Proof | Merkle inclusion of account state in Binary Patricia Tree |
| L2 | Block | BPT Commitment | BPT root committed in block hash |
| L3 | Consensus | Validator Signatures | Validator set signatures on block |
| L4 | Genesis | Trust Chain | Validator set traced to genesis (future) |
| G0 | Governance | Inclusion | Transaction included in block |
| G1 | Governance | Correctness | Authority and key page validation |
| G2 | Governance | Outcome Binding | Transaction hash bound to intent |
| BLS | Aggregation | ZK Proof | Groth16 proof of BLS12-381 aggregate signature |
| Anchor | Target Chain | State Anchoring | Merkle root submitted to CertenAnchor contract on target chain |

### Intent Processing Pipeline

```
Intent Discovery (poll Accumulate blocks)
    |
    v
Route by proof class: on_demand / on_cadence
    |
    v
Lite Client Proof Generation (L1-L4)
    |
    v
Governance Proof Generation (G0-G2)
    |
    v
CometBFT Consensus (2/3+ validators sign)
    |
    v
Batch Closed -> Merkle Root Computed
    |
    v
Anchor Manager submits to target chain
    |
    v
Attestation Collection (2f+1 signatures)
    |
    v
BLS Aggregation + Groth16 ZK Proof
    |
    v
Proof Artifacts stored in PostgreSQL
    |
    v
REST API serves proofs
```

## API Reference

### Health and Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Service health check with component status |
| `/health/ready` | GET | Kubernetes readiness probe |
| `/health/live` | GET | Kubernetes liveness probe |

Health response includes status of consensus, database, Ethereum, Accumulate, batch system, and proof cycle subsystems.

### Proof Discovery

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/proofs/tx/{tx_hash}` | GET | Get proof by Accumulate transaction hash |
| `/api/v1/proofs/{proof_id}` | GET | Get proof by UUID |
| `/api/v1/proofs/batch/{batch_id}` | GET | Get all proofs in a batch |

### Batch Queries

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/batches` | GET | List all batches |
| `/api/v1/batches/{batch_id}` | GET | Get batch details with transactions |

### Ledger and Intent

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ledger/state` | GET | Current ledger state |
| `/api/v1/intents/{intent_id}` | GET | Intent details and processing status |

### CometBFT RPC (Port 26657)

Standard CometBFT endpoints: `/status`, `/net_info`, `/validators`, `/consensus_state`, `/abci_query`

### Prometheus Metrics (Port 9090)

| Metric | Description |
|--------|-------------|
| `validator_consensus_height` | Current consensus block height |
| `validator_proofs_generated_total` | Total proofs generated |
| `validator_batch_size_histogram` | Batch size distribution |
| `validator_ethereum_gas_used_total` | Cumulative gas spent on anchoring |
| `validator_attestations_collected` | Total attestation signatures |

## Database Schema

The validator uses PostgreSQL with auto-applied migrations:

| Table | Description |
|-------|-------------|
| `batches` | Transaction batches with type, Merkle root, and lifecycle status |
| `batch_transactions` | Transaction-to-batch mappings with Merkle indices |
| `proofs` | Generated proof artifacts with JSON proof data |
| `anchors` | Ethereum anchor records with confirmation tracking |
| `attestations` | Validator signatures (BLS/Ed25519) on proofs |
| `consensus_entries` | CometBFT block and commit history |
| `proof_artifacts` | Complete proof bundles with metadata |

Migrations are located in `pkg/database/migrations/`:

| Migration | Description |
|-----------|-------------|
| `001_initial_schema.sql` | Core tables |
| `002_add_intent_tracking.sql` | Intent metadata |
| `003_unified_multi_chain.sql` | Multi-chain support |
| `004_add_proof_detail_tables.sql` | Extended proof details |
| `005_intent_metadata.sql` | Intent tracking |
| `006_add_merkle_path.sql` | Merkle path storage |

## CLI Tools

### Validator Binary

```bash
./validator [--validator-id validator-1]
```

Starts the complete validator node with all subsystems.

### Governance Proof CLI

```bash
./govproof --level G0|G1|G2 \
  --keypage acc://example.acme/page/1 \
  acc://example.acme \
  main \
  <transaction_hash>
```

Generates governance proofs with cryptographic verification against the Accumulate network.

### BLS ZK Setup

```bash
go run ./cmd/bls-zk-setup
```

Generates Groth16 proving and verification keys for BLS12-381 signature verification. This is a one-time operation that takes approximately 5-10 minutes.

### BLS Key Info

```bash
go run ./cmd/bls-key-info/main.go
```

Inspects and displays BLS key properties.

## Project Structure

```
independant_validator/
├── main.go                              # Entry point and service orchestration
├── go.mod / go.sum                      # Go module dependencies
├── Dockerfile                           # Multi-stage production build
├── docker-compose.yml                   # 7-validator testnet deployment
├── .env.example                         # Environment variable template
├── accumulate-lite-client-2/            # Embedded Accumulate lite client
│   └── liteclient/
│       ├── proof/
│       │   └── consolidated_governance-proof/  # G0/G1/G2 proof CLI
│       └── api/                         # Accumulate API client
├── cmd/
│   ├── bls-zk-setup/                   # Groth16 key generation tool
│   ├── bls-key-info/                   # BLS key inspection utility
│   └── generate-vk/                    # Verification key generation
├── pkg/
│   ├── config/                         # Configuration and .env loading
│   ├── database/                       # PostgreSQL client, repositories, migrations
│   ├── consensus/                      # CometBFT ABCI integration
│   ├── proof/                          # Lite client proof generation
│   ├── anchor/                         # Ethereum anchor management
│   ├── anchor_proof/                   # Anchor proof types and operations
│   ├── batch/                          # Transaction batching (collector, processor)
│   ├── execution/                      # Proof cycle orchestrator
│   ├── verification/                   # Unified proof verification engine
│   ├── attestation/                    # Multi-validator attestation service
│   ├── intent/                         # Intent discovery and routing
│   ├── accumulate/                     # Accumulate network client
│   ├── ethereum/                       # Ethereum RPC and contract bindings
│   ├── crypto/                         # BLS12-381 and ZK-SNARK operations
│   ├── chain/                          # Multi-chain execution strategies
│   │   └── strategy/                   # Per-chain strategies (EVM, Solana, Aptos, Sui, NEAR, TON, TRON)
│   ├── merkle/                         # Merkle tree construction and receipts
│   ├── ledger/                         # Ledger state management
│   ├── metrics/                        # Prometheus metrics
│   ├── server/                         # HTTP API handlers
│   └── firestore/                      # Optional Firestore real-time sync
├── scripts/                             # Deployment and setup scripts (Node.js)
│   ├── setup_certen_identity_kermit.js
│   ├── submit_intent_kermit.js
│   └── register_validators.js
└── implementation-planning-doc/         # Architecture documentation
```

## Development

### Building

```bash
# Build validator
go build -o validator .

# Build all binaries
go build -o validator . && \
  cd accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof && \
  go build -o govproof .
```

### Running Tests

```bash
# Unit tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test -v ./pkg/batch/...

# Integration tests
go test -tags=integration ./...
```

### Local Development

```bash
# Start PostgreSQL
docker run -d \
  --name certen-postgres \
  -e POSTGRES_USER=certen \
  -e POSTGRES_PASSWORD=certen \
  -e POSTGRES_DB=certen_validator \
  -p 5432:5432 \
  postgres:15-alpine

# Configure and run
export DATABASE_URL="postgres://certen:certen@localhost:5432/certen_validator?sslmode=disable"
export BLS_ZK_TESTING_MODE=true
go run .
```

## Deployment

### Pre-Deployment Checklist

- Generate unique Ed25519 keys per validator
- Fund validator wallets with gas tokens on each target chain (ETH, SOL, APT, SUI, NEAR, TON)
- Pre-generate BLS ZK keys via `bls-zk-setup`
- Set `BLS_ZK_TESTING_MODE=false` for production
- Configure `ATTESTATION_PEERS` with all peer validator URLs
- Use production Ethereum RPC endpoints
- Set strong PostgreSQL credentials

### Systemd Service

```ini
[Unit]
Description=Certen Independent Validator
After=network.target postgresql.service

[Service]
Type=simple
User=certen
WorkingDirectory=/opt/certen-validator
ExecStart=/opt/certen-validator/validator
Restart=always
RestartSec=10
EnvironmentFile=/opt/certen-validator/.env

[Install]
WantedBy=multi-user.target
```

### Scaling

| Validators | Byzantine Tolerance | Consensus Threshold |
|------------|--------------------|--------------------|
| 4 | 1 faulty | 3 of 4 |
| 7 | 2 faulty | 5 of 7 |
| 10 | 3 faulty | 7 of 10 |

Each validator requires its own Ethereum wallet, Ed25519 keypair, and BLS12-381 keys.

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

Returns component-level status:

```json
{
  "status": "ok",
  "consensus": "cometbft",
  "database": "connected",
  "ethereum": "connected",
  "accumulate": "connected",
  "batch_system": "active",
  "proof_cycle": "active",
  "uptime_seconds": 3600
}
```

### Prometheus

Metrics available at `http://localhost:9090/metrics` for integration with Grafana or other monitoring systems.

## Security Considerations

### Cryptographic Assets

| Asset | Algorithm | Purpose |
|-------|-----------|---------|
| Ethereum Private Key | secp256k1 | Signs anchor transactions |
| BLS12-381 Keys | BLS | Signs aggregate proof attestations |
| Ed25519 Keys | Ed25519 | CometBFT consensus signing |
| Groth16 Keys | BN254 | ZK-SNARK proving/verification |

### Operational Security

- Store private keys in environment variables, never in source control
- Use `sslmode=require` for PostgreSQL connections in production
- Restrict CometBFT P2P ports to known validator peers
- Monitor attestation counts for early detection of validator failures
- Enable all verification flags in production (`ENABLE_MERKLE_VERIFICATION`, `ENABLE_GOVERNANCE_VERIFICATION`, `ENABLE_BLS_VERIFICATION`)

## Related Components

| Component | Repository | Description |
|-----------|------------|-------------|
| Smart Contracts | `certen-contracts` | EVM, Solana, Aptos, Sui, NEAR, TON, TRON contract suites |
| Independent Miner | `independant_miner` | LXR proof-of-work audit nodes |
| Proofs Service | `proofs_service` | Proof storage and retrieval API |
| API Bridge | `api-bridge` | Accumulate integration REST API |
| Web App | `certen-web-app` | User interface for ADI management |
| Key Vault | `key-vault-signer` | Browser extension for transaction signing |

## License

Copyright 2026 Certen Protocol. All rights reserved.
