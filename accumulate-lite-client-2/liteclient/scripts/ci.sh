#!/bin/bash
# CI Script for Accumulate Lite Client
# Runs comprehensive testing and validation for CI/CD pipelines

set -euo pipefail

# Configuration
COVERAGE_THRESHOLD=70
GO_VERSION_MIN="1.21"
TIMEOUT="10m"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get current Go version
get_go_version() {
    go version | sed -n 's/.*go\([0-9]\+\.[0-9]\+\).*/\1/p'
}

# Compare version numbers
version_compare() {
    printf '%s\n' "$1" "$2" | sort -C -V
}

# Validate environment
validate_environment() {
    log_info "Validating CI environment..."
    
    # Check Go version
    if ! command_exists go; then
        log_error "Go is not installed"
        exit 1
    fi
    
    local go_version
    go_version=$(get_go_version)
    if ! version_compare "$GO_VERSION_MIN" "$go_version"; then
        log_error "Go version $go_version is too old. Required: $GO_VERSION_MIN+"
        exit 1
    fi
    
    log_success "Go version $go_version meets requirements"
    
    # Check git
    if ! command_exists git; then
        log_warning "Git not found - version info will be limited"
    fi
    
    # Display environment info
    log_info "Environment Information:"
    echo "  OS: $(uname -s)"
    echo "  Architecture: $(uname -m)"
    echo "  Go Version: $go_version"
    echo "  Git Commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    echo "  Git Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
    echo "  PWD: $(pwd)"
}

# Install development tools
install_tools() {
    log_info "Installing development tools..."
    
    # Install golangci-lint if not available
    if ! command_exists golangci-lint; then
        log_info "Installing golangci-lint..."
        go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
    fi
    
    # Install goimports if not available
    if ! command_exists goimports; then
        log_info "Installing goimports..."
        go install golang.org/x/tools/cmd/goimports@latest
    fi
    
    log_success "Development tools installed"
}

# Download and verify dependencies
setup_dependencies() {
    log_info "Setting up dependencies..."
    
    # Clean module cache if requested
    if [[ "${CLEAN_CACHE:-}" == "true" ]]; then
        log_info "Cleaning module cache..."
        go clean -modcache
    fi
    
    # Download dependencies
    log_info "Downloading dependencies..."
    go mod download
    
    # Verify dependencies
    log_info "Verifying dependencies..."
    go mod verify
    
    # Tidy up
    log_info "Tidying dependencies..."
    go mod tidy
    
    # Check for changes after tidy
    if ! git diff --quiet go.mod go.sum 2>/dev/null; then
        log_warning "go.mod or go.sum changed after 'go mod tidy'"
        if [[ "${CI:-}" == "true" ]]; then
            log_error "Dependencies are not tidy. Run 'go mod tidy' locally."
            exit 1
        fi
    fi
    
    log_success "Dependencies setup complete"
}

# Format code and check for changes
check_formatting() {
    log_info "Checking code formatting..."
    
    # Run gofmt
    local fmt_output
    fmt_output=$(gofmt -d .)
    if [[ -n "$fmt_output" ]]; then
        log_error "Code is not properly formatted:"
        echo "$fmt_output"
        exit 1
    fi
    
    # Run goimports if available
    if command_exists goimports; then
        local imports_output
        imports_output=$(goimports -d .)
        if [[ -n "$imports_output" ]]; then
            log_error "Imports are not properly organized:"
            echo "$imports_output"
            exit 1
        fi
    fi
    
    log_success "Code formatting is correct"
}

# Run linter
run_linter() {
    log_info "Running linter..."
    
    if command_exists golangci-lint; then
        golangci-lint run --timeout="${TIMEOUT}" --issues-exit-code=1
        log_success "Linter passed"
    else
        log_warning "golangci-lint not available, running basic checks"
        go vet ./...
        log_success "Basic checks passed"
    fi
}

# Validate test fixtures
validate_fixtures() {
    log_info "Validating test fixtures..."
    
    # Build record-fixtures tool
    go build -o /tmp/record-fixtures ./cmd/record-fixtures
    
    # Find and validate all fixtures
    local fixture_count=0
    local failed_count=0
    
    while IFS= read -r -d '' fixture; do
        ((fixture_count++))
        echo -n "  Validating $(basename "$fixture")... "
        
        if /tmp/record-fixtures -validate "$fixture" >/dev/null 2>&1; then
            echo "✓"
        else
            echo "✗"
            ((failed_count++))
        fi
    done < <(find testdata -name "*.json" -print0 2>/dev/null || true)
    
    if [[ $fixture_count -eq 0 ]]; then
        log_warning "No test fixtures found"
    else
        log_info "Validated $fixture_count fixtures ($failed_count failed)"
        if [[ $failed_count -gt 0 ]]; then
            log_error "Some fixtures are invalid"
            exit 1
        fi
    fi
    
    # Clean up
    rm -f /tmp/record-fixtures
    
    log_success "Test fixtures validated"
}

# Run tests with coverage
run_tests() {
    log_info "Running tests with coverage..."
    
    # Run offline tests (no network access)
    go test -tags=offline -race -timeout="${TIMEOUT}" -cover -coverprofile=coverage.out ./...
    
    # Generate coverage report
    local coverage_percent
    coverage_percent=$(go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+')
    
    log_info "Test coverage: ${coverage_percent}%"
    
    # Check coverage threshold
    if (( $(echo "$coverage_percent < $COVERAGE_THRESHOLD" | bc -l) )); then
        log_error "Coverage $coverage_percent% is below threshold $COVERAGE_THRESHOLD%"
        exit 1
    fi
    
    # Generate HTML coverage report if requested
    if [[ "${HTML_COVERAGE:-}" == "true" ]]; then
        go tool cover -html=coverage.out -o coverage.html
        log_info "HTML coverage report generated: coverage.html"
    fi
    
    log_success "Tests passed with ${coverage_percent}% coverage"
}

# Build all binaries
build_binaries() {
    log_info "Building binaries..."
    
    # Create bin directory
    mkdir -p bin
    
    # Build main binary
    go build -trimpath -ldflags="-s -w" -o bin/liteclient .
    
    # Build CLI tools
    local cli_binaries=("lc-verify" "prove" "record-fixtures")
    for binary in "${cli_binaries[@]}"; do
        if [[ -d "cmd/$binary" ]]; then
            log_info "Building $binary..."
            go build -trimpath -ldflags="-s -w" -o "bin/$binary" "./cmd/$binary"
        else
            log_warning "Skipping $binary - directory not found"
        fi
    done
    
    # Verify binaries
    for binary in bin/*; do
        if [[ -x "$binary" ]]; then
            log_info "Built: $binary ($(du -h "$binary" | cut -f1))"
        fi
    done
    
    log_success "All binaries built successfully"
}

# Run security checks
security_checks() {
    log_info "Running security checks..."
    
    # Check for common security issues
    if command_exists gosec; then
        gosec ./...
        log_success "Security scan completed"
    else
        log_warning "gosec not available, skipping security scan"
    fi
    
    # Check for known vulnerabilities in dependencies
    if command_exists govulncheck; then
        govulncheck ./...
        log_success "Vulnerability check completed"
    else
        log_warning "govulncheck not available, skipping vulnerability check"
    fi
}

# Run benchmarks (optional)
run_benchmarks() {
    if [[ "${RUN_BENCHMARKS:-}" == "true" ]]; then
        log_info "Running benchmarks..."
        go test -bench=. -benchmem ./... > benchmarks.txt
        log_success "Benchmarks completed - see benchmarks.txt"
    fi
}

# Generate build artifacts for different platforms
cross_compile() {
    if [[ "${CROSS_COMPILE:-}" == "true" ]]; then
        log_info "Cross-compiling for multiple platforms..."
        
        platforms=("windows/amd64" "linux/amd64" "darwin/amd64")
        
        for platform in "${platforms[@]}"; do
            IFS='/' read -r -a platform_split <<< "$platform"
            local goos="${platform_split[0]}"
            local goarch="${platform_split[1]}"
            
            local output_dir="dist/${goos}_${goarch}"
            mkdir -p "$output_dir"
            
            log_info "Building for $goos/$goarch..."
            
            local ext=""
            if [[ "$goos" == "windows" ]]; then
                ext=".exe"
            fi
            
            GOOS="$goos" GOARCH="$goarch" go build \
                -trimpath -ldflags="-s -w" \
                -o "${output_dir}/liteclient${ext}" .
            
            # Build CLI tools for each platform
            for binary in lc-verify prove record-fixtures; do
                if [[ -d "cmd/$binary" ]]; then
                    GOOS="$goos" GOARCH="$goarch" go build \
                        -trimpath -ldflags="-s -w" \
                        -o "${output_dir}/${binary}${ext}" "./cmd/$binary"
                fi
            done
        done
        
        log_success "Cross-compilation completed"
    fi
}

# Generate reports
generate_reports() {
    log_info "Generating reports..."
    
    # Test report
    if [[ -f coverage.out ]]; then
        go tool cover -func=coverage.out > coverage-report.txt
        log_info "Coverage report: coverage-report.txt"
    fi
    
    # Build info
    cat > build-info.txt << EOF
Build Information
================
Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')
Git Branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')
Go Version: $(go version)
Platform: $(uname -s)/$(uname -m)

Binary Sizes:
EOF
    
    if [[ -d bin ]]; then
        du -h bin/* >> build-info.txt
    fi
    
    log_success "Reports generated"
}

# Cleanup temporary files
cleanup() {
    log_info "Cleaning up temporary files..."
    
    # Remove coverage files if not keeping them
    if [[ "${KEEP_COVERAGE:-}" != "true" ]]; then
        rm -f coverage.out coverage.html
    fi
    
    # Remove temporary directories
    rm -rf /tmp/liteclient-*
    
    log_success "Cleanup completed"
}

# Main CI pipeline
main() {
    local start_time
    start_time=$(date +%s)
    
    log_info "Starting CI pipeline..."
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    # Run CI steps
    validate_environment
    install_tools
    setup_dependencies
    check_formatting
    run_linter
    validate_fixtures
    run_tests
    build_binaries
    
    # Optional steps
    security_checks
    run_benchmarks
    cross_compile
    generate_reports
    
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "CI pipeline completed successfully in ${duration}s"
    
    # Summary
    echo ""
    echo "============================================"
    echo "           CI PIPELINE SUMMARY             "
    echo "============================================"
    echo "Status: SUCCESS"
    echo "Duration: ${duration}s"
    echo "Go Version: $(get_go_version)"
    if [[ -f coverage.out ]]; then
        local coverage_percent
        coverage_percent=$(go tool cover -func=coverage.out | grep total | grep -Eo '[0-9]+\.[0-9]+')
        echo "Coverage: ${coverage_percent}%"
    fi
    echo "Artifacts: bin/ $(if [[ -d dist ]]; then echo "dist/"; fi)"
    echo "============================================"
}

# Run main pipeline if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi