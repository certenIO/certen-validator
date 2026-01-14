# Multi-stage build for Accumulate Lite Client
# Optimized for production deployment with minimal attack surface

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimization flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o liteclient \
    ./cmd/crystal-step1

# Build additional tools
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o crystal-step3 \
    ./cmd/crystal-step3

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o lc-verify \
    ./cmd/lc-verify

# Runtime stage
FROM scratch

# Copy CA certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy built binaries
COPY --from=builder /build/liteclient /usr/local/bin/liteclient
COPY --from=builder /build/crystal-step3 /usr/local/bin/crystal-step3
COPY --from=builder /build/lc-verify /usr/local/bin/lc-verify

# Copy configuration files
COPY --from=builder /build/config/production.json /etc/liteclient/config.json

# Create non-root user
USER 65534:65534

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/liteclient", "--health-check"]

# Default command
ENTRYPOINT ["/usr/local/bin/liteclient"]
CMD ["--config", "/etc/liteclient/config.json"]