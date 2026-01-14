# Dockerfile for Certen Protocol Independent Validator
# Production-Grade Multi-Stage Build

FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
COPY accumulate-lite-client-2/ ./accumulate-lite-client-2/

RUN go mod download

# Copy all source code
COPY . ./

# Build the validator service with CGO (required for gnark/blst)
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o validator .

# Generate BLS ZK keys (Groth16 proving and verification keys)
# These keys are deterministic within the same gnark version
# For production: pre-generate keys and include in build context
RUN mkdir -p /build/bls_zk_keys && \
    if [ ! -f /build/bls_zk_keys/proving_key.bin ]; then \
        echo "Generating BLS ZK keys (this may take 5-10 minutes)..." && \
        go run ./cmd/bls-zk-setup 2>&1 | head -50 && \
        cp -r ./bls_zk_keys/* /build/bls_zk_keys/ 2>/dev/null || true; \
    else \
        echo "Using pre-generated BLS ZK keys"; \
    fi

# Build the governance proof CLI (G0/G1/G2)
# Per CERTEN spec v3-governance-kpsw-exec-4.0
WORKDIR /build/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /build/govproof .

# Build the txhash tool for G2 payload verification
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /build/txhash ./cmd/txhash
WORKDIR /build

# ═══════════════════════════════════════════════════════════════
# Production Stage
# ═══════════════════════════════════════════════════════════════
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Create unprivileged user for security
RUN adduser -D -s /bin/sh validator

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/validator .
COPY --from=builder /build/govproof .
COPY --from=builder /build/txhash .

# Create directories for persistent storage
RUN mkdir -p /app/bft-keys \
             /app/data \
             /app/data/validator-ledger \
             /app/data/cometbft \
             /app/data/gov_proofs \
             /app/bls_zk_keys

# Copy BLS ZK keys (pre-generated Groth16 proving/verification keys)
COPY --from=builder /build/bls_zk_keys/ /app/bls_zk_keys/

# Set ownership to app user
RUN chown -R validator:validator /app

# Switch to unprivileged user
USER validator

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Expose ports
# 8080  - HTTP API
# 9090  - Prometheus Metrics
# 26656 - CometBFT P2P
# 26657 - CometBFT RPC
EXPOSE 8080 9090 26656 26657

# ═══════════════════════════════════════════════════════════════
# Environment Defaults (non-sensitive only)
# SECURITY: All secrets MUST be provided at runtime
# ═══════════════════════════════════════════════════════════════

# API Server
ENV API_HOST=0.0.0.0 \
    API_PORT=8080 \
    METRICS_PORT=9090 \
    LOG_LEVEL=info

# Governance Proof CLI
ENV GOV_PROOF_CLI_PATH=/app/govproof \
    GOV_PROOF_WORK_DIR=/app/data/gov_proofs \
    TXHASH_CLI_PATH=/app/txhash

# BLS ZK Prover
ENV BLS_ZK_KEYS_DIR=/app/bls_zk_keys

# Verification configuration
ENV ENABLE_MERKLE_VERIFICATION=true \
    ENABLE_GOVERNANCE_VERIFICATION=true \
    ENABLE_BLS_VERIFICATION=true \
    ENABLE_COMMITMENT_VERIFICATION=true \
    ENABLE_PARALLEL_VERIFICATION=true \
    VERIFICATION_TIMEOUT=30s

# Ethereum defaults (Sepolia testnet)
ENV ETH_CHAIN_ID=11155111

# CometBFT defaults
ENV COMETBFT_ENABLED=true \
    COMETBFT_MODE=validator

# Start the validator service
CMD ["./validator"]
