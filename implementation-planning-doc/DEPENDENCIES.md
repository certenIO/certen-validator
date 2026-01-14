# Certen Independent Validator - Dependencies Reference

Complete reference of all dependencies required to build and run an independent validator.

---

## Go Module Dependencies (go.mod)

```go
module github.com/certen/independant-validator

go 1.24.0

require (
    // ═══════════════════════════════════════════════════════════════
    // CONSENSUS & NETWORKING
    // ═══════════════════════════════════════════════════════════════

    // CometBFT - Byzantine Fault Tolerant consensus engine
    // Used for: BFT consensus, P2P networking, block production
    github.com/cometbft/cometbft v0.38.0

    // CometBFT database abstraction
    github.com/cometbft/cometbft-db v0.7.0

    // ═══════════════════════════════════════════════════════════════
    // CRYPTOGRAPHY - ZK PROOFS
    // ═══════════════════════════════════════════════════════════════

    // gnark - Zero-Knowledge SNARK library
    // Used for: BLS signature verification proofs (Groth16)
    github.com/consensys/gnark v0.14.0

    // gnark-crypto - Cryptographic primitives for gnark
    // Used for: BLS12-381 curve operations, field arithmetic
    github.com/consensys/gnark-crypto v0.19.0

    // ═══════════════════════════════════════════════════════════════
    // CRYPTOGRAPHY - SIGNATURES
    // ═══════════════════════════════════════════════════════════════

    // blst - BLS12-381 signature library (CGO)
    // Used for: BLS aggregate signatures
    github.com/supranational/blst v0.3.16

    // btcec - Bitcoin elliptic curve library
    // Used for: secp256k1 operations (Ethereum compatibility)
    github.com/btcsuite/btcd/btcec/v2 v2.3.2

    // ═══════════════════════════════════════════════════════════════
    // BLOCKCHAIN INTEGRATION - ETHEREUM
    // ═══════════════════════════════════════════════════════════════

    // go-ethereum - Official Ethereum Go implementation
    // Used for: Contract interactions, transaction signing, RPC
    github.com/ethereum/go-ethereum v1.16.7

    // ═══════════════════════════════════════════════════════════════
    // BLOCKCHAIN INTEGRATION - ACCUMULATE
    // ═══════════════════════════════════════════════════════════════

    // Accumulate SDK - Official Accumulate blockchain SDK
    // Used for: Lite client proofs, intent discovery, ADI management
    gitlab.com/accumulatenetwork/accumulate v1.4.2

    // Accumulate schema definitions
    gitlab.com/accumulatenetwork/core/schema v0.2.1

    // ═══════════════════════════════════════════════════════════════
    // DATABASE
    // ═══════════════════════════════════════════════════════════════

    // PostgreSQL driver
    // Used for: Proof artifact storage, batch tracking
    github.com/lib/pq v1.10.9

    // LevelDB - Embedded key-value store
    // Used by: CometBFT for internal block storage
    github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7

    // ═══════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════

    // UUID generation
    github.com/google/uuid v1.6.0

    // HTTP router
    github.com/gorilla/mux v1.8.1

    // Structured logging
    github.com/rs/zerolog v1.31.0

    // Configuration management
    github.com/spf13/viper v1.18.2

    // JSON processing
    github.com/tidwall/gjson v1.17.0

    // ═══════════════════════════════════════════════════════════════
    // TESTING
    // ═══════════════════════════════════════════════════════════════

    github.com/stretchr/testify v1.8.4
)
```

---

## Infrastructure Dependencies

### PostgreSQL 15

**Purpose:** Proof artifact storage, batch tracking, attestation storage

**Docker Image:** `postgres:15-alpine`

**Required Configuration:**
```
POSTGRES_DB=certen
POSTGRES_USER=certen
POSTGRES_PASSWORD=<secure_password>
```

**Connection Pool Settings:**
- Max Open Connections: 20
- Min Idle Connections: 5
- Max Connection Lifetime: 1 hour
- Max Idle Time: 5 minutes

**Required Tables:**
- `anchor_batches` - Batch metadata
- `anchor_records` - Individual anchor records
- `certen_anchor_proofs` - Complete proof artifacts
- `attestations` - Multi-validator attestations
- `attestation_signatures` - BLS signatures

---

### Redis 7 (Optional)

**Purpose:** Caching, rate limiting

**Docker Image:** `redis:7-alpine`

**Configuration:**
```
REDIS_URL=redis://localhost:6379
```

**Features Used:**
- Key-value caching
- Rate limit counters

---

### CometBFT 0.38.0

**Purpose:** Byzantine Fault Tolerant consensus

**Embedded:** Built into validator binary (not separate service)

**Ports:**
- 26656: P2P networking
- 26657: RPC interface

**Storage:**
- LevelDB for block storage
- Configurable data directory

---

## Ethereum Dependencies

### go-ethereum v1.16.7

**Purpose:** Ethereum blockchain interaction

**Features Used:**
- Contract ABI encoding/decoding
- Transaction signing
- RPC client
- Gas estimation

**Supported Networks:**
- Ethereum Mainnet (Chain ID: 1)
- Sepolia Testnet (Chain ID: 11155111)
- Any EVM-compatible chain

---

### Smart Contracts

**CertenAnchorV3:**
- Sepolia: `0xEb17eBd351D2e040a0cB3026a3D04BEc182d8b98`
- Purpose: Unified anchor creation and verification

**BLSZKVerifier:**
- Sepolia: `0x631B6444216b981561034655349F8a28962DcC5F`
- Purpose: On-chain BLS ZK proof verification

**CertenAccountV2:**
- Sepolia: `0x043e3632d24F297dA199eEc420084E0c2e5CcDFf`
- Purpose: Account abstraction

---

## Accumulate Dependencies

### Accumulate SDK v1.4.2

**Purpose:** Accumulate blockchain integration

**Features Used:**
- Lite client for proof generation
- Transaction submission
- ADI management
- Block polling

**Network Endpoints:**
- Kermit (Testnet): `https://kermit.accumulatenetwork.io/v3`
- Mainnet: `https://mainnet.accumulatenetwork.io/v3`

---

## Cryptographic Dependencies

### gnark v0.14.0

**Purpose:** Zero-Knowledge SNARK proofs

**Algorithms:**
- Groth16 proving system
- BLS12-381 curve

**Generated Artifacts:**
- `proving_key.bin` (~50MB)
- `verification_key.bin` (~1KB)

**Build Requirement:** CGO_ENABLED=1

---

### gnark-crypto v0.19.0

**Purpose:** Cryptographic primitives

**Features:**
- BLS12-381 curve operations
- Field arithmetic
- Pairing computations

---

### blst v0.3.16

**Purpose:** BLS12-381 signatures

**Features:**
- Key generation
- Signing
- Verification
- Signature aggregation

**Build Requirement:** CGO_ENABLED=1

---

## Build Requirements

### CGO Dependencies

The following packages require CGO (C compiler):
- `gnark` - ZK circuit compilation
- `blst` - BLS signature library

**Linux Build:**
```bash
apk add --no-cache git gcc musl-dev  # Alpine
apt-get install -y git gcc libc-dev  # Debian/Ubuntu
```

**Build Command:**
```bash
CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o validator .
```

---

## Version Compatibility Matrix

| Component | Minimum Version | Tested Version | Notes |
|-----------|-----------------|----------------|-------|
| Go | 1.22 | 1.24 | CGO required |
| CometBFT | 0.37 | 0.38.0 | ABCI 2.0 |
| gnark | 0.13 | 0.14.0 | Groth16 support |
| go-ethereum | 1.13 | 1.16.7 | EIP-1559 support |
| PostgreSQL | 14 | 15 | JSON support |
| Accumulate SDK | 1.3 | 1.4.2 | Lite client proofs |

---

## Security Considerations

### Key Storage

| Key Type | Storage Location | Security Level |
|----------|------------------|----------------|
| Ed25519 (CometBFT) | File system | Encrypt at rest |
| BLS (Attestation) | File system | Encrypt at rest |
| Ethereum Private Key | Environment/Secrets | Never in files |

### Network Security

| Port | Protocol | Exposure | Recommendation |
|------|----------|----------|----------------|
| 8080 | HTTP API | Public | Add authentication |
| 9090 | Metrics | Internal | Restrict to monitoring |
| 26656 | P2P | Public | Firewall allow list |
| 26657 | RPC | Internal | Restrict access |

### Database Security

- Use SSL/TLS connections in production (`sslmode=require`)
- Rotate database credentials regularly
- Encrypt sensitive data at rest

---

## Resource Requirements

### Minimum Hardware

| Resource | Requirement |
|----------|-------------|
| CPU | 2 cores |
| Memory | 4 GB |
| Storage | 50 GB SSD |
| Network | 100 Mbps |

### Recommended Hardware

| Resource | Requirement |
|----------|-------------|
| CPU | 4+ cores |
| Memory | 8+ GB |
| Storage | 200+ GB NVMe |
| Network | 1 Gbps |

### Container Resources (Docker)

```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
    reservations:
      cpus: '1'
      memory: 1G
```
