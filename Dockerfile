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

# VERIFY the BLS ZK keys. NEVER generate them.
#
# The previous rule here regenerated the Groth16 keys whenever proving_key.bin was absent from
# the build context. The comment above it claimed the keys were "deterministic within the same
# gnark version". They are not: pkg/crypto/bls_zkp/prover.go:192 calls groth16.Setup(cs), and
# gnark samples fresh toxic waste from crypto/rand on every invocation. Two runs of the same
# gnark version on the same circuit produce different keys, always.
#
# The failure that causes is silent and total. The image compiles, starts, signs, and emits
# structurally valid Groth16 proofs — every one of which the deployed BLSZKVerifierV2 rejects,
# because its verification key is compiled in and no longer corresponds. That takes down batch
# attestation AND the per-intent on_demand path, since both submit through generateBLSZKProof.
# It presents as a cryptographic bug rather than a build artifact problem.
#
# It also melted the production host: the setup is a Groth16 trusted setup over a BLS12-381
# pairing circuit inside BN254, and running it alongside seven live validators drove the load
# average past 5800 and stopped sshd from forking (2026-08-02).
#
# So the keys are a deployment artifact, verified by digest and never derived.
#
# The keys themselves are gitignored — a 215 MB proving key does not belong in git, and `git
# pull` therefore never delivers them. That is precisely how a host ends up without them and
# the old rule started a trusted setup. Their DIGESTS are tracked, at
# deploy/bls_zk_keys.SHA256SUMS, pinning the exact bytes that `cmd/vkcheck` proved match the
# DEPLOYED verifier element for element: alpha, the negated beta/gamma/delta, and all six IC
# points. A missing or altered key aborts the build here, where it costs nothing, instead of on
# chain where it costs settlement.
#
# To rotate keys: run the setup, deploy a verifier generated FROM those keys, re-run vkcheck
# against the newly deployed contract, then update the pinned digests. Never one without the
# others.
RUN set -eu; \
    [ -d /build/bls_zk_keys ] || { \
        echo "FATAL: bls_zk_keys/ is not in the build context."; \
        echo "       It is gitignored, so a git checkout will NOT contain it — stage it on the"; \
        echo "       build host from key custody. Do NOT generate it: a fresh trusted setup"; \
        echo "       samples new toxic waste and cannot match the deployed verifier."; \
        exit 1; }; \
    [ -f /build/deploy/bls_zk_keys.SHA256SUMS ] || { \
        echo "FATAL: deploy/bls_zk_keys.SHA256SUMS is missing; the keys cannot be verified."; \
        exit 1; }; \
    cd /build/bls_zk_keys; \
    for f in proving_key.bin verification_key.bin constraint_system.bin; do \
        [ -f "$f" ] || { echo "FATAL: bls_zk_keys/$f is missing. Restore it from key custody."; exit 1; }; \
    done; \
    sha256sum -c /build/deploy/bls_zk_keys.SHA256SUMS || { \
        echo "FATAL: BLS ZK key digests do not match the pinned values."; \
        echo "       These keys must not ship: every proof built with them would be structurally"; \
        echo "       valid and rejected on chain, taking down batch attestation AND the"; \
        echo "       per-intent on_demand path."; \
        exit 1; }; \
    echo "BLS ZK keys verified against pinned digests."

# Build the governance proof CLI (G0/G1/G2)
# Per CERTEN spec v3-governance-kpsw-exec-4.0
WORKDIR /build/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /build/govproof .

# Build the txhash tool for G2 payload verification
WORKDIR /build/accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/cmd/txhash
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /build/txhash .
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
             /app/bls_zk_keys \
             /app/bls_zk_keys_bls12381

# Copy BLS ZK keys (pre-generated Groth16 proving/verification keys)
COPY --from=builder /build/bls_zk_keys/ /app/bls_zk_keys/
COPY --from=builder /build/bls_zk_keys_bls12381/ /app/bls_zk_keys_bls12381/

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
ENV BLS_ZK_KEYS_BLS12381_DIR=/app/bls_zk_keys_bls12381

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
