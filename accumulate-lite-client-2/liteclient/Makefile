# Makefile for Accumulate Lite Client
# Provides common development tasks with cross-platform support
# Updated for Passes 3-5 implementation

# Configuration
BINARY_NAME = liteclient
CLI_BINARIES = lc-verify proof-runner proofcheck crystal-step1 crystal-step3
GO_VERSION = 1.21
COVERAGE_THRESHOLD = 80

# Build settings
LDFLAGS = -s -w
BUILD_FLAGS = -trimpath
TEST_FLAGS = -race -timeout=5m
COVERAGE_FLAGS = -cover -coverprofile=coverage.out

# Directories  
BIN_DIR = bin
DIST_DIR = dist
DOCS_DIR = docs
TEST_DATA_DIR = testdata

# Colors for output
RED = \033[0;31m
GREEN = \033[0;32m
YELLOW = \033[0;33m
BLUE = \033[0;34m
NC = \033[0m # No Color

.PHONY: help build test clean lint fmt vet coverage deps tools install docs fixtures verify

# Default target
all: clean fmt lint vet test build

help: ## Show this help message
	@echo "Accumulate Lite Client - Development Tasks"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  $(BLUE)%-15s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Development tasks
fmt: ## Format Go code
	@echo "$(YELLOW)Formatting code...$(NC)"
	@go fmt ./...
	@gofmt -s -w .
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

lint: ## Run linter
	@echo "$(YELLOW)Running linter...$(NC)"
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "$(YELLOW)golangci-lint not found, running basic checks$(NC)"; \
		go vet ./...; \
	fi

vet: ## Run go vet
	@echo "$(YELLOW)Running go vet...$(NC)"
	@go vet ./...

# Testing
test: ## Run tests
	@echo "$(YELLOW)Running tests...$(NC)"
	@go test $(TEST_FLAGS) ./...

test-offline: ## Run offline tests only (CI-safe)
	@echo "$(YELLOW)Running offline tests...$(NC)"
	@go test $(TEST_FLAGS) -tags=offline ./...

test-coverage: ## Run tests with coverage
	@echo "$(YELLOW)Running tests with coverage...$(NC)"
	@go test $(TEST_FLAGS) $(COVERAGE_FLAGS) ./...
	@go tool cover -func=coverage.out
	@echo "$(GREEN)Coverage report generated: coverage.out$(NC)"

test-html: test-coverage ## Generate HTML coverage report
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)HTML coverage report: coverage.html$(NC)"

# Test categories (Pass 3 implementation)
test-unit: ## Run unit tests only (no mocks, no network)
	@echo "$(YELLOW)Running unit tests...$(NC)"
	@go test $(TEST_FLAGS) ./api ./core ./types ./verifier

test-integration: ## Run integration tests (requires network)
	@echo "$(YELLOW)Running integration tests...$(NC)"
	@go test $(TEST_FLAGS) -tags=integration -timeout=10m ./...

test-proofs-pending: ## Run pending proof tests (will skip/fail)
	@echo "$(YELLOW)Running pending proof tests...$(NC)"
	@go test $(TEST_FLAGS) -tags=proofs_pending ./proof/...

test-mocks-disabled: ## Run legacy tests with mocks (disabled by default)
	@echo "$(YELLOW)Running legacy mock tests...$(NC)"
	@go test $(TEST_FLAGS) -tags=mock_disabled ./api ./core

# Anti-mock enforcement (Pass 3)
check-mocks: ## Check for unauthorized mock usage
	@echo "$(YELLOW)Checking for unauthorized mocks...$(NC)"
	@if grep -r "github.com/stretchr/testify/mock\|github.com/golang/mock\|go.uber.org/mock" --include="*.go" --exclude-dir=vendor .; then \
		echo "$(RED)Error: Mock libraries detected! This codebase is mock-free.$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✅ No unauthorized mocks found$(NC)"

# Crystal verification targets
verify-step1: ## Test Crystal Step 1 with known accounts
	@echo "$(YELLOW)Testing Crystal Step 1 verification...$(NC)"
	@go build -o $(BIN_DIR)/crystal-step1 ./proof/crystal/cmd/crystal-step1
	@./$(BIN_DIR)/crystal-step1 -account "acc://RenatoDAP.acme"
	@./$(BIN_DIR)/crystal-step1 -account "acc://DefiDevs.acme"

check-observer: ## Check if observer is enabled
	@echo "$(YELLOW)Checking observer status...$(NC)"
	@go run ./proof/crystal-observer/cmd/check-observer/main.go

# Building
build: ## Build main binary
	@echo "$(YELLOW)Building main binary...$(NC)"
	@mkdir -p $(BIN_DIR)
	@go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) .

build-cli: ## Build CLI tools
	@echo "$(YELLOW)Building CLI tools...$(NC)"
	@mkdir -p $(BIN_DIR)
	@for binary in $(CLI_BINARIES); do \
		echo "Building $$binary..."; \
		go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$$binary ./cmd/$$binary; \
	done

build-all: build build-cli ## Build all binaries

# Cross-compilation
build-windows: ## Build for Windows
	@echo "$(YELLOW)Building for Windows...$(NC)"
	@mkdir -p $(DIST_DIR)/windows
	@GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/windows/$(BINARY_NAME).exe .
	@for binary in $(CLI_BINARIES); do \
		GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/windows/$$binary.exe ./cmd/$$binary; \
	done

build-linux: ## Build for Linux
	@echo "$(YELLOW)Building for Linux...$(NC)"
	@mkdir -p $(DIST_DIR)/linux
	@GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/linux/$(BINARY_NAME) .
	@for binary in $(CLI_BINARIES); do \
		GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/linux/$$binary ./cmd/$$binary; \
	done

build-darwin: ## Build for macOS
	@echo "$(YELLOW)Building for macOS...$(NC)"
	@mkdir -p $(DIST_DIR)/darwin
	@GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/darwin/$(BINARY_NAME) .
	@for binary in $(CLI_BINARIES); do \
		GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/darwin/$$binary ./cmd/$$binary; \
	done

dist: build-windows build-linux build-darwin ## Build for all platforms

# Dependencies
deps: ## Download and verify dependencies
	@echo "$(YELLOW)Downloading dependencies...$(NC)"
	@go mod download
	@go mod verify

tidy: ## Clean up dependencies
	@echo "$(YELLOW)Tidying dependencies...$(NC)"
	@go mod tidy

# Tools installation
tools: ## Install development tools
	@echo "$(YELLOW)Installing development tools...$(NC)"
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@if ! command -v goimports >/dev/null 2>&1; then \
		echo "Installing goimports..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
	fi

# Fixtures and testing
fixtures: build-cli ## Record test fixtures from live network
	@echo "$(YELLOW)Recording test fixtures...$(NC)"
	@mkdir -p $(TEST_DATA_DIR)/proofs/strategy_f/success
	@mkdir -p $(TEST_DATA_DIR)/proofs/strategy_f/failure
	@echo "Run manually: ./bin/record-fixtures -account 'acc://example.acme' -strategy f"

fixtures-validate: ## Validate existing fixtures
	@echo "$(YELLOW)Validating fixtures...$(NC)"
	@if [ -f $(BIN_DIR)/record-fixtures ]; then \
		find $(TEST_DATA_DIR) -name "*.json" -exec $(BIN_DIR)/record-fixtures -validate {} \; ; \
	else \
		echo "$(RED)record-fixtures binary not found. Run 'make build-cli' first.$(NC)"; \
		exit 1; \
	fi

# Verification and proofs
prove: build-cli ## Generate proof for account (requires -account flag)
	@if [ -z "$(ACCOUNT)" ]; then \
		echo "$(RED)Usage: make prove ACCOUNT=acc://example.acme$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Generating proof for $(ACCOUNT)...$(NC)"
	@$(BIN_DIR)/prove -account "$(ACCOUNT)"

verify: build-cli ## Verify proof bundle (requires -bundle flag)
	@if [ -z "$(BUNDLE)" ]; then \
		echo "$(RED)Usage: make verify BUNDLE=path/to/bundle.json$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Verifying proof bundle $(BUNDLE)...$(NC)"
	@$(BIN_DIR)/lc-verify -bundle "$(BUNDLE)"

# Documentation
docs: ## Generate documentation
	@echo "$(YELLOW)Generating documentation...$(NC)"
	@if command -v godoc >/dev/null 2>&1; then \
		echo "$(GREEN)GoDoc available at: http://localhost:6060/pkg/gitlab.com/accumulatenetwork/core/liteclient/$(NC)"; \
		echo "Run: godoc -http=:6060"; \
	else \
		echo "$(YELLOW)Install godoc: go install golang.org/x/tools/cmd/godoc@latest$(NC)"; \
	fi

docs-serve: ## Serve documentation locally
	@echo "$(YELLOW)Serving documentation on :6060...$(NC)"
	@godoc -http=:6060

# Benchmarking
bench: ## Run benchmarks
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	@go test -bench=. -benchmem ./...

# Performance profiling
profile-cpu: ## Run CPU profiling
	@echo "$(YELLOW)Running CPU profiling...$(NC)"
	@go test -cpuprofile=cpu.prof -bench=. ./...
	@echo "$(GREEN)Analyze with: go tool pprof cpu.prof$(NC)"

profile-mem: ## Run memory profiling
	@echo "$(YELLOW)Running memory profiling...$(NC)"
	@go test -memprofile=mem.prof -bench=. ./...
	@echo "$(GREEN)Analyze with: go tool pprof mem.prof$(NC)"

# Database operations
db-init: build-cli ## Initialize SQLite database
	@echo "$(YELLOW)Initializing SQLite database...$(NC)"
	@go run -tags sqlite ./cmd/db-init

db-stats: build-cli ## Show database statistics
	@echo "$(YELLOW)Database statistics:$(NC)"
	@go run -tags sqlite ./cmd/db-stats

# Cleaning
clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning build artifacts...$(NC)"
	@rm -rf $(BIN_DIR) $(DIST_DIR)
	@rm -f coverage.out coverage.html
	@rm -f cpu.prof mem.prof
	@rm -f *.test
	@go clean -cache -testcache

clean-all: clean ## Clean everything including modules cache
	@echo "$(YELLOW)Cleaning modules cache...$(NC)"
	@go clean -modcache

# Installation
install: build ## Install binaries to GOPATH/bin
	@echo "$(YELLOW)Installing binaries...$(NC)"
	@go install .
	@for binary in $(CLI_BINARIES); do \
		go install ./cmd/$$binary; \
	done

# Development workflow
dev: clean fmt lint vet test build ## Full development workflow

# CI/CD workflow  
ci: deps tools dev test-coverage ## CI workflow
	@echo "$(GREEN)CI workflow completed successfully$(NC)"

# Release workflow
release: clean deps tools lint vet test dist ## Release workflow
	@echo "$(GREEN)Release artifacts generated in $(DIST_DIR)/$(NC)"

# Quick development tasks
quick: fmt test ## Quick development check

# Git hooks
hooks: ## Install git hooks
	@echo "$(YELLOW)Installing git hooks...$(NC)"
	@cp scripts/pre-commit .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "$(GREEN)Git hooks installed$(NC)"

# Version information
version: ## Show version information
	@echo "Go version: $(shell go version)"
	@echo "Git commit: $(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Git branch: $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
	@echo "Build date: $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')"

# Status check
status: ## Show project status
	@echo "$(BLUE)Accumulate Lite Client - Project Status$(NC)"
	@echo ""
	@make version
	@echo ""
	@echo "Dependencies status:"
	@go list -m all | head -10
	@echo ""
	@echo "Test status:"
	@go test -short ./... 2>/dev/null && echo "$(GREEN)✓ Tests passing$(NC)" || echo "$(RED)✗ Tests failing$(NC)"
	@echo ""
	@echo "Build status:"
	@go build . >/dev/null 2>&1 && echo "$(GREEN)✓ Build successful$(NC)" || echo "$(RED)✗ Build failing$(NC)"