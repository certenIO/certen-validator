# Production Proof Testing Guide

## Overview

This guide explains how to comprehensively test the production proof implementation, ensuring Layers 1-3 are fully functional. Layer 4 testing will be added once the API exposes the necessary consensus data.

## Current Testing Status

| Layer | Description | Status | Test Coverage |
|-------|------------|--------|---------------|
| **Layer 1** | Account State → BPT Root | ✅ 100% Working | Full coverage with real data |
| **Layer 2** | BPT Root → Block Hash | ✅ 100% Working | Full coverage with real data |
| **Layer 3** | Block Hash → Validator Signatures | ⚠️ 90% Complete | Ed25519 verified, awaiting API data |
| **Layer 4** | Validators → Genesis Trust | ⏳ Blocked | Design complete, awaiting Layer 3 |

## Quick Start

### Prerequisites

1. **Start Devnet**:
```bash
cd ../../GitLabRepo/accumulate/test/load
./devnet_config.sh minimal  # Uses least memory
```

2. **Verify Devnet is Running**:
```bash
curl http://localhost:26660/v3/health
```

### Running Tests

#### Option 1: Interactive Testing (Recommended)

**Windows:**
```cmd
cd proof\production-proof
run_massive_tests.bat
```

**Linux/Mac:**
```bash
cd proof/production-proof
./run_massive_tests.sh
```

This will present an interactive menu:
1. Quick Verification - Tests existing accounts
2. Massive Test - Creates and tests 100+ accounts
3. Stress Test - Concurrent verification
4. Performance Benchmarks
5. Run all tests
6. Generate test report

#### Option 2: Command Line

```bash
# Quick test with existing accounts
go test -v -run TestQuickVerification ./proof/production-proof/

# Massive test creating 100 accounts
go test -v -run TestMassiveDevnet ./proof/production-proof/

# Stress test with concurrent workers
go test -v -run TestStressMode ./proof/production-proof/

# Performance benchmarks
go test -bench=. -benchmem ./proof/production-proof/
```

#### Option 3: Automated Full Suite

```bash
# Run everything and generate report
./run_massive_tests.sh all

# Or on Windows
run_massive_tests.bat all
```

## Test Types Explained

### 1. Quick Verification Test
- **Purpose**: Rapid validation using existing well-known accounts
- **Duration**: ~5 seconds
- **Accounts Tested**: dn.acme, alice.acme, bob.acme, charlie.acme
- **Use When**: Quick sanity check after changes

### 2. Massive Account Test
- **Purpose**: Comprehensive testing with many accounts
- **Duration**: 2-5 minutes
- **Default**: Creates 100 test accounts
- **Validates**: 
  - Account creation at scale
  - Merkle proof generation for all accounts
  - BPT root verification
  - Block inclusion checks
- **Use When**: Full regression testing needed

### 3. Stress Test
- **Purpose**: Test system limits and concurrent access
- **Duration**: 30 seconds
- **Concurrency**: 20 parallel workers
- **Metrics Collected**:
  - Requests per second
  - Success rate
  - Error patterns
- **Use When**: Performance validation required

### 4. Performance Benchmarks
- **Purpose**: Measure verification speed
- **Metrics**:
  - Layer 1 verification time
  - Layer 2 verification time
  - Memory allocation
- **Use When**: Optimizing code performance

## Understanding Test Results

### Layer 1 Results (Account → BPT Root)
```
Layer 1 (Account → BPT Root):
  ✅ Passed: 100/100 (100.0%)
  • Merkle proofs: ✅ Working
  • State hashing: ✅ Working  
  • Proof anchors: ✅ Working
```

**What it means:**
- ✅ 100%: Cryptographic proofs are fully functional
- ⚠️ 90-99%: Minor issues, likely network delays
- ❌ <90%: Serious issues requiring investigation

### Layer 2 Results (BPT Root → Block Hash)
```
Layer 2 (BPT Root → Block Hash):
  ✅ Passed: 100/100 (100.0%)
  • Block inclusion: ✅ Working
  • AppHash verification: ✅ Working
  • BPT commitment: ✅ Working
```

**What it means:**
- ✅ 100%: Block commitments verified correctly
- ⚠️ 90-99%: Possible sync issues
- ❌ <90%: Block verification failing

### Layer 3 Results (Block → Validator Signatures)
```
Layer 3 (Block → Validator Signatures):
  ⏳ Passed: 0/100 (0.0%)
  • Status: ⏳ Awaiting API support
  • Ed25519 verification: ✅ Proven working
  • Consensus data: ❌ Not exposed by API
```

**Current Status:**
- Ed25519 signature verification is proven working (see `breakthrough_proof_test.go`)
- Cannot complete full Layer 3 testing until API exposes validator data
- This is expected and not a failure

## Creating Test Accounts at Scale

### Using the Test Suite

```go
suite := NewTestSuite("http://localhost:26660/v3")

// Create 1000 test accounts
err := suite.CreateTestAccounts(t, 1000, "loadtest")

// Test all created accounts
suite.TestAllLayers(t)
```

### Manual Account Creation

```go
// Create accounts with specific names
accounts := []string{
    "testuser1",
    "testuser2", 
    "testcompany",
    "testtoken",
}

for _, name := range accounts {
    err := createAccount(name)
    if err != nil {
        log.Printf("Failed to create %s: %v", name, err)
    }
}
```

## Customizing Test Parameters

### Environment Variables

```bash
# API endpoint (default: http://localhost:26660/v3)
export API_ENDPOINT=http://your-node:26660/v3

# Number of test accounts to create (default: 100)
export TEST_ACCOUNT_COUNT=500

# Account name prefix (default: testacct)
export TEST_ACCOUNT_PREFIX=mytest

# Run massive test with custom settings
./run_massive_tests.sh massive
```

### Modifying Test Code

Edit `devnet_massive_test.go`:

```go
// Change concurrency for stress test
func TestStressMode(t *testing.T) {
    suite.StressTest(t, 50, 60*time.Second) // 50 workers, 60 seconds
}

// Modify account creation batch size
sem := make(chan struct{}, 20) // Increase from 10 to 20

// Add custom test accounts
suite.accounts = append(suite.accounts, []string{
    "acc://custom1.acme",
    "acc://custom2.acme",
}...)
```

## Interpreting Test Reports

### Generated Report Structure

```markdown
# Production Proof Test Report
Generated: 2025-01-26 10:30:00

## Environment
- API Endpoint: http://localhost:26660/v3
- Test Account Count: 100

## Test Results

### Quick Verification Test
✅ All 4 accounts verified successfully

### Massive Test Results  
📊 Overall Statistics:
  • Total Accounts Tested: 100
  • Layer 1 Passed: 100/100 (100.0%)
  • Layer 2 Passed: 100/100 (100.0%)
  • Layer 3 Passed: 0/100 (0.0%) - Expected, awaiting API

### Stress Test Results
📊 Stress Test Results:
  • Total Requests: 12,543
  • Successful: 12,401 (98.9%)
  • Requests/sec: 418.1
```

### Success Criteria

| Metric | Excellent | Good | Needs Work |
|--------|-----------|------|------------|
| Layer 1 Pass Rate | ≥99% | ≥95% | <95% |
| Layer 2 Pass Rate | ≥99% | ≥95% | <95% |
| Stress Test Success | ≥98% | ≥95% | <95% |
| Requests/Second | ≥500 | ≥200 | <200 |
| Account Creation Rate | ≥50/sec | ≥20/sec | <20/sec |

## Troubleshooting

### Common Issues and Solutions

#### Issue: "Devnet is not running"
**Solution:**
```bash
cd ../../GitLabRepo/accumulate/test/load
./devnet_config.sh minimal
# Wait 10 seconds for startup
curl http://localhost:26660/v3/health
```

#### Issue: "Account creation failing"
**Possible Causes:**
- Sponsor account (alice) has insufficient tokens
- Network congestion
- Too many concurrent requests

**Solution:**
```bash
# Reduce concurrency in test
sem := make(chan struct{}, 5) // Reduce from 10 to 5

# Or increase timeout
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
```

#### Issue: "Layer 1/2 verification failing"
**Debugging Steps:**
1. Check if specific accounts are failing:
```go
// Add detailed logging
fmt.Printf("Debugging account: %v\n", accountURL)
fmt.Printf("Receipt: %+v\n", resp.Receipt)
fmt.Printf("Proof: %+v\n", resp.Receipt.Proof)
```

2. Verify API is returning receipts:
```bash
curl -X POST http://localhost:26660/v3 \
  -H "Content-Type: application/json" \
  -d '{"method":"query","params":{"url":"acc://alice.acme","includeReceipt":true}}'
```

#### Issue: "Stress test low success rate"
**Optimizations:**
- Reduce concurrent workers
- Increase timeouts
- Use connection pooling
- Check system resources (CPU, memory)

## Advanced Testing Scenarios

### Testing Specific Accounts

```go
func TestSpecificAccounts(t *testing.T) {
    suite := NewTestSuite("http://localhost:26660/v3")
    
    // Test only specific accounts
    suite.accounts = []string{
        "acc://my-important-account.acme",
        "acc://critical-token.acme/tokens",
    }
    
    suite.TestAllLayers(t)
}
```

### Testing with Different Networks

```go
// Test against testnet
suite := NewTestSuite("https://testnet.accumulate.defidevs.io/v3")

// Test against mainnet (read-only)
suite := NewTestSuite("https://mainnet.accumulate.defidevs.io/v3")
```

### Custom Validation Logic

```go
// Add custom validation for specific requirements
func (ts *TestSuite) customValidation(accountURL *url.URL) error {
    // Your custom checks here
    result := ts.testLayer1(accountURL)
    
    if result.details["proof_entries"].(int) < 5 {
        return fmt.Errorf("insufficient proof depth")
    }
    
    return nil
}
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Proof Testing

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Start Devnet
      run: |
        cd GitLabRepo/accumulate/test/load
        ./devnet_config.sh minimal &
        sleep 10
    
    - name: Run Quick Tests
      run: |
        cd liteclient
        go test -v -run TestQuickVerification ./proof/production-proof/
    
    - name: Run Massive Tests
      run: |
        cd liteclient
        go test -v -run TestMassiveDevnet ./proof/production-proof/ -timeout 10m
    
    - name: Generate Report
      if: always()
      run: |
        cd liteclient/proof/production-proof
        ./run_massive_tests.sh report
    
    - name: Upload Test Results
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: |
          **/test_report_*.md
          **/*_test_results.log
```

## Next Steps

### When Layer 3-4 API Support is Added

Once the Accumulate API exposes validator consensus data:

1. **Update Layer 3 Tests**:
   - Remove "expected to fail" status
   - Add validator signature verification
   - Test consensus threshold validation

2. **Implement Layer 4 Tests**:
   - Validator set transition tracking
   - Genesis trust chain verification
   - Complete trustless proof validation

3. **Update Success Metrics**:
   - Layer 3 should achieve >95% pass rate
   - Layer 4 should achieve >95% pass rate
   - Full trustless verification should complete in <1 second

## Summary

The testing framework provides:
- ✅ **Comprehensive Layer 1-2 validation** with real blockchain data
- ✅ **Massive scale testing** with 100+ accounts
- ✅ **Stress testing** for performance validation
- ✅ **Automated reporting** for CI/CD integration
- ⏳ **Ready for Layer 3-4** once API support is added

Use these tests to ensure the production proof implementation remains robust and performant as development continues.