# Certen Independent Validator - Quick Start Guide

This guide provides the fastest path to building and running an independent validator.

---

## Prerequisites

- Go 1.24+ installed
- Docker and Docker Compose installed
- Git installed
- ~5GB disk space
- Network access to Ethereum RPC and Accumulate RPC

---

## Quick Start (Docker)

### Step 1: Copy Source Files

```bash
# Set source and target paths
SRC="C:\Accumulate_Stuff\certen\certen-protocol\services\validator"
TARGET="C:\Accumulate_Stuff\certen\independant_validator"

# Copy all source files (see FILE_INVENTORY.md for complete list)
cp -r $SRC/* $TARGET/
```

### Step 2: Configure Environment

```bash
cd $TARGET

# Copy environment template
cp .env.example .env

# Edit .env with your configuration:
# - VALIDATOR_ID=your-validator-name
# - POSTGRES_PASSWORD=secure_password
# - ETHEREUM_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
# - ETH_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
# - ACCUMULATE_URL=https://kermit.accumulatenetwork.io/v3
```

### Step 3: Build and Start

```bash
# Build Docker image (includes BLS ZK key generation, takes ~10 min first time)
docker build -t certen-validator:latest .

# Start services
docker-compose up -d

# Check logs
docker-compose logs -f validator
```

### Step 4: Verify

```bash
# Check health (wait ~60 seconds for startup)
curl http://localhost:8086/health

# Expected response:
# {"status":"ok","phase":"5","consensus":"cometbft",...}
```

---

## Quick Start (Non-Docker)

### Step 1: Build Binaries

```bash
cd $TARGET

# Download dependencies
go mod download
go mod tidy

# Build main validator
CGO_ENABLED=1 go build -o validator .

# Build BLS ZK setup tool and generate keys
cd cmd/bls-zk-setup && go build -o bls-zk-setup . && cd ../..
mkdir -p bls_zk_keys && ./cmd/bls-zk-setup/bls-zk-setup

# Build governance proof tool
cd accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
go build -o govproof . && mv govproof ../../../../
cd ../../../..

# Build txhash tool
cd accumulate-lite-client-2/liteclient/cmd/txhash
go build -o txhash . && mv txhash ../../../../
cd ../../../..
```

### Step 2: Start PostgreSQL

```bash
# Using Docker for database
docker run -d \
  --name certen-postgres \
  -e POSTGRES_DB=certen \
  -e POSTGRES_USER=certen \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:15-alpine

# Apply migrations
cat pkg/database/migrations/001_initial_schema.sql | \
  docker exec -i certen-postgres psql -U certen -d certen
```

### Step 3: Configure and Run

```bash
# Set required environment variables
export VALIDATOR_ID=validator-local
export DATABASE_URL="postgres://certen:password@localhost:5432/certen?sslmode=disable"
export ETHEREUM_URL="https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY"
export ETH_CHAIN_ID=11155111
export ETH_PRIVATE_KEY="0xYOUR_PRIVATE_KEY"
export ACCUMULATE_URL="https://kermit.accumulatenetwork.io/v3"
export CERTEN_CONTRACT_ADDRESS="0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98"
export COMETBFT_ENABLED=true
export COMETBFT_MODE=validator
export COMETBFT_CHAIN_ID=certen-testnet
export GOV_PROOF_CLI_PATH="./govproof"
export TXHASH_CLI_PATH="./txhash"
export BLS_ZK_KEYS_DIR="./bls_zk_keys"

# Run validator
./validator
```

---

## Connecting to Testnet

### Step 1: Obtain Network Configuration

Contact network operator for:
- `genesis.json` file
- Persistent peer list
- Chain ID

### Step 2: Configure Peers

```bash
# Add to .env
COMETBFT_P2P_PERSISTENT_PEERS=nodeID1@validator-1:26656,nodeID2@validator-2:26656
ATTESTATION_PEERS=http://validator-1:8080,http://validator-2:8080
ATTESTATION_REQUIRED_COUNT=3
```

### Step 3: Place Genesis File

```bash
mkdir -p data/cometbft/config
cp genesis.json data/cometbft/config/
```

### Step 4: Start and Sync

```bash
docker-compose up -d

# Monitor sync progress
curl http://localhost:26657/status | jq '.result.sync_info'

# Wait until catching_up: false
```

---

## API Quick Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health status |
| `/api/anchors/on-demand` | POST | Create immediate anchor |
| `/api/batches/current` | GET | Current batch status |
| `/api/proofs/by-tx/{hash}` | GET | Get proof by tx hash |
| `/api/attestations` | GET | Attestation service info |

---

## Troubleshooting

### "Database connection failed"
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
docker exec certen-postgres pg_isready -U certen
```

### "Ethereum connection failed"
```bash
# Test RPC endpoint
curl $ETHEREUM_URL -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### "CometBFT not syncing"
```bash
# Check peer connections
curl http://localhost:26657/net_info | jq '.result.n_peers'

# Verify persistent peers are reachable
```

### "BLS ZK keys not found"
```bash
# Generate keys manually
go run ./cmd/bls-zk-setup

# Verify keys exist
ls -la bls_zk_keys/
```

---

## Next Steps

1. Review full documentation: `IMPLEMENTATION_PLAN.md`
2. Review all files needed: `FILE_INVENTORY.md`
3. Configure production settings
4. Set up monitoring with Prometheus
5. Configure backup procedures
