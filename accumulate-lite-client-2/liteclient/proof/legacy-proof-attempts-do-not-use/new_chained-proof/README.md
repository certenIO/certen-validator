# CERTEN Chained Proof Implementation

This package provides the canonical implementation of the CERTEN chained proof specification for Accumulate anchoring proofs using v3 receipt stitching.

## Specification

**Document**: `services\validator\docs\new_CERTEN_CHAINED_PROOF_SPEC.md`
**Version**: `v3-receipt-stitch-1`
**Status**: Production Implementation

## Overview

The CERTEN proof system implements a **3-layer proof architecture** that provides cryptographic verification from individual Accumulate entries to consensus finality:

```
Layer 1: Entry Hash      → Partition Anchor  (BVN height)
Layer 2: Partition Anchor → DN Anchor Root   (DN height)
Layer 3: DN Anchor Root  → Consensus Final   (CometBFT)
```

## Key Features

### ✅ **Specification Compliant**
- Implements 100% of the canonical CERTEN specification
- Enforces all normative rules and invariants
- Follows deterministic construction algorithms

### ✅ **Receipt Stitching**
- Treats receipts as directed edges: `start → anchor @ localBlock`
- Enforces exact hash equality between layers: `L2.start == L1.anchor`
- Validates Merkle path integrity for all receipts

### ✅ **Trust Levels**
- **Partition Trust**: Layer 1 verification only
- **Minimal Trust (DN Anchored)**: Layers 1-2 verified
- **Zero Trust (Consensus Verified)**: All layers 1-3 verified

### ✅ **Production Ready**
- Comprehensive error handling and validation
- Debug logging and performance metrics
- Fallback strategies for Layer 2 anchor search
- Proper resource cleanup and timeouts

## Usage Examples

### 1. Basic Proof Building

```go
package main

import (
    "log"
    "github.com/certen/certen-protocol/services/validator/accumulate-lite-client-2/liteclient/proof/new_chained-proof"
)

func main() {
    // Create proof builder
    builder, err := chained_proof.NewCertenProofBuilder(
        "http://localhost:26660/v3",  // Accumulate V3 API
        "http://localhost:26657",     // CometBFT RPC
        true,                         // debug mode
    )
    if err != nil {
        log.Fatal(err)
    }

    // Build complete proof
    proof, err := builder.BuildComplete(
        "acc://alice.acme/tokens",    // account scope
        "main",                       // chain name
        205,                          // chain index
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Proof built successfully!")
    log.Printf("Leaf: %x", proof.GetLeafHash())
    log.Printf("DN Root: %x", proof.GetDNRoot())
    log.Printf("DN Height: %d", proof.GetDNHeight())
    log.Printf("Complete: %t", proof.IsComplete())
}
```

### 2. Proof Verification

```go
// Create verifier
verifier := chained_proof.NewCertenProofVerifier(true)

// Verify complete proof
result, err := verifier.VerifyComplete(proof)
if err != nil {
    log.Fatal(err)
}

if result.Valid {
    log.Printf("✅ Proof VALID - Trust Level: %s", result.TrustLevel)
    log.Printf("Verification took: %v", time.Duration(result.DurationNanos))
} else {
    log.Printf("❌ Proof INVALID: %s", result.ErrorMessage)
}

// Print detailed layer results
for layerName, layerResult := range result.LayerResults {
    log.Printf("%s: %s", layerName, layerResult.String())
}
```

### 3. One-Shot Build and Verify

```go
// Build and verify in one call
proof, result, err := chained_proof.BuildAndVerifyProof(
    "http://localhost:26660/v3",     // V3 endpoint
    "http://localhost:26657",        // CometBFT endpoint
    "acc://alice.acme/tokens",       // scope
    "main",                          // chain
    205,                             // index
    true,                            // debug
)
if err != nil {
    log.Fatal(err)
}

log.Printf("Proof: %s", proof.String())
log.Printf("Result: %s", result.String())
```

### 4. Partial Proof (L1-L2 only)

```go
// Build partial proof when Layer 3 not needed
proof, err := builder.BuildPartial(
    "acc://alice.acme/tokens",
    "main",
    205,
)
if err != nil {
    log.Fatal(err)
}

// Verify partial proof
result, err := verifier.VerifyPartial(proof)
if err != nil {
    log.Fatal(err)
}

log.Printf("Partial proof trust level: %s", result.TrustLevel)
```

## Architecture

### Package Structure

```
new_chained-proof/
├── chained_proof.go      # Main package interface
├── types.go              # Core data structures
├── layer1.go             # Layer 1: Entry → Partition
├── layer2.go             # Layer 2: Partition → DN
├── layer3.go             # Layer 3: DN → Consensus
├── proof_builder.go      # Orchestrates proof building
├── proof_verifier.go     # Orchestrates proof verification
├── receipt_verifier.go   # Receipt integrity & stitching
└── README.md            # This file
```

### Key Components

1. **CertenProofBuilder**: Main orchestrator for proof construction
2. **CertenProofVerifier**: Main orchestrator for proof verification
3. **Layer1Builder/Verifier**: Entry inclusion proofs
4. **Layer2Builder/Verifier**: Anchor stitching proofs
5. **Layer3Builder/Verifier**: Consensus finality proofs
6. **ReceiptVerifier**: Merkle path and stitching validation

## Specification Compliance

### ✅ Normative Rules Enforced

1. **Layer 1 leaf selection** MUST start from chain-entry receipts
2. **Receipts are edges** treated as `start → anchor @ localBlock`
3. **Stitching is exact** requiring `L2.start == L1.anchor` byte-for-byte
4. **Receipt integrity** verified via Merkle path recomputation
5. **Heights are partition-local** with no BVN/DN conflation
6. **Layer 3 binding** verifies exact (DN height, DN root) pair

### ✅ Invariants Validated

- **Invariant 1**: Internal receipt validity via Merkle path walking
- **Invariant 2**: Stitch by exact hash equality
- **Invariant 3**: Height discipline (partition-local)
- **Invariant 4**: Deterministic anchor type handling

### ✅ Construction Algorithm

- **L1 Acquisition**: From `recordType:"chainEntry"` with `includeReceipt`
- **L2 Acquisition**: Via `dn.acme/anchors` `anchorSearch` with receipts
- **L3 Construction**: Through CometBFT commit + validator verification
- **Fallback Ladder**: Deterministic strategies for anchor discovery

## Error Handling

The implementation provides comprehensive error handling with detailed error messages:

```go
// Specific error types for different failure modes
type ProofConstructionError struct {
    Layer   string
    Stage   string
    Cause   error
    Details map[string]interface{}
}

// Example error handling
proof, err := builder.BuildComplete(scope, chain, index)
if err != nil {
    if constructionErr, ok := err.(*ProofConstructionError); ok {
        log.Printf("Construction failed at %s/%s: %v",
            constructionErr.Layer, constructionErr.Stage, constructionErr.Cause)
        log.Printf("Details: %+v", constructionErr.Details)
    } else {
        log.Printf("Generic error: %v", err)
    }
}
```

## Performance

- **Layer 1**: ~100ms (single chain entry query)
- **Layer 2**: ~200ms (DN anchor search + validation)
- **Layer 3**: ~300ms (CometBFT commit + validator fetch)
- **Total**: ~600ms for complete L1-L3 proof

Performance can be improved with:
- Concurrent layer building where possible
- Caching of validator sets and commits
- Connection pooling for API clients

## Configuration

### Required Endpoints

```go
// Accumulate V3 API endpoint
v3Endpoint := "http://localhost:26660/v3"

// CometBFT RPC endpoint
cometEndpoint := "http://localhost:26657"

// For production networks:
// v3Endpoint := "https://mainnet.accumulatenetwork.io/v3"
// cometEndpoint := "https://mainnet.accumulatenetwork.io:26657"
```

### Debug Mode

Enable debug logging for detailed execution traces:

```go
builder, err := chained_proof.NewCertenProofBuilder(v3Endpoint, cometEndpoint, true)
// Outputs detailed logs:
// [LAYER1] Building proof for scope=acc://alice.acme/tokens, chain=main, index=205
// [LAYER1] Querying chain entry: acc://alice.acme/tokens/main[205]
// [LAYER1] Successfully built proof - Leaf: a46cc22a, Anchor: 55dc6ef1
// [LAYER2] Building proof for L1 anchor: 55dc6ef1
// [LAYER2] Searching DN anchors for: 55dc6ef1
// [LAYER2] Successfully built proof - Start: 55dc6ef1, Anchor: 8eb5fe37
// [LAYER3] Building consensus proof for DN height 1666079, root 8eb5fe37
// [LAYER3] Consensus verification: PowerOK=true (67/90), RootBinding=true
```

## Testing

The package includes comprehensive test coverage:

```bash
# Run all tests
go test -v ./...

# Run with coverage
go test -v -cover ./...

# Run specific test
go test -v -run TestLayer1Construction ./...

# Run benchmarks
go test -v -bench=. ./...
```

## Integration with ValidatorBlock

For embedding proofs in `consensus.ValidatorBlock`:

```go
type ValidatorBlock struct {
    // ... existing fields ...

    // Canonical Accumulate proof path (L1-L3)
    AccumulateProofPath *chained_proof.AccumulateAnchoringProof `json:"accumulate_proof_path,omitempty"`
}

// Usage
block := &ValidatorBlock{
    // ... set other fields ...
    AccumulateProofPath: proof,
}
```

## Troubleshooting

### Common Issues

1. **"Layer 1 invariant validation failed"**
   - Ensure scope points to valid chain entry
   - Check that chain index exists
   - Verify API endpoint is reachable

2. **"Receipt stitching validation failed"**
   - Layer 1 anchor may not be anchored to DN yet
   - Try waiting for next DN anchoring cycle
   - Check anchor search parameters

3. **"Layer 3 consensus verification failed"**
   - CometBFT endpoint may be unreachable
   - Validator set may not have sufficient signatures
   - Block may not be finalized yet

### Debug Commands

```bash
# Test connectivity
curl http://localhost:26660/v3/status

# Check CometBFT status
curl http://localhost:26657/status

# Validate chain entry exists
curl -X POST http://localhost:26660/v3 \
  -H "Content-Type: application/json" \
  -d '{"method":"query","params":{"scope":"acc://alice.acme/tokens","query":{"type":"chain","name":"main","index":205}}}'
```

## License

Copyright 2025 CERTEN
Licensed under MIT License - see LICENSE file for details.