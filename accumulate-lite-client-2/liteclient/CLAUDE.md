# CLAUDE.md - Lite Client Cryptographic Proof System

NO MOCKS, FAKES, PLACEHOLDERS or WORKAROUNDS! EVER!

## ⚠️ CRITICAL: NO FALSE CLAIMS ABOUT WORKING CODE
**NEVER claim something "works" or is "complete" unless verified with REAL DATA**
- If using mock validators → say "consensus logic implemented, NOT VERIFIED"
- If using test data → say "implementation ready, awaiting real data"
- Only claim "WORKING" when proven with actual blockchain data from devnet/testnet/mainnet 

## 🎯 Executive Summary: Complete Trustless Verification

The Accumulate Lite Client implements a 4-layer cryptographic proof system that enables complete trustless verification of account states using only:
- **Genesis block hash** (trusted root)
- **Mathematical cryptography** (SHA256, Ed25519)
- **Zero trust** in APIs, servers, or third parties

**Key Achievement**: When fully implemented with API support, this will be the first blockchain lite client to provide complete cryptographic proof from any account state back to genesis.

## 📐 The Complete Proof Architecture

### Understanding Accumulate's Chain-of-Chains

In Accumulate's unique architecture:
1. **Accounts live on BVNs** (Block Validation Networks) - each account is assigned to a specific BVN
2. **BVNs anchor to DN** (Directory Network) - BVNs periodically submit their state roots to the DN  
3. **DN aggregates all states** - The DN's state root includes all anchored BVN states
4. **DN validators provide consensus** - The DN's validators sign blocks containing the entire network state

### The Full Technical Proof Path
```
Account → BVN BPT → BVN Block → BVN Anchor → DN BPT → DN Block → Validators → Genesis
```

### The Simplified Proof Path (Mathematically Equivalent)
```
Account → DN BPT (includes BVN anchor) → DN Block → Validators → Genesis
```

Both paths are cryptographically equivalent because the DN's state subsumes all anchored BVN states.

## 🔗 The 4-Layer Proof System

### Layer 1: Account State → BPT Root
**What It Proves**: The account's complete state is included in a Binary Patricia Tree root.
**Security**: Cannot forge without breaking SHA256 (2^128 operations)

### Layer 2: BPT Root → Block Hash (AppHash)  
**What It Proves**: The BPT root is committed in a block.
**Note**: In full architecture, this happens at both BVN and DN levels.

### Layer 3: Block Hash → Validator Signatures
**What It Proves**: Validators signed the block containing the state.
**Security**: Requires forging Ed25519 signatures (computationally infeasible)

### Layer 4: Validator Set → Genesis Trust
**What It Proves**: Current validators trace back to genesis through signed transitions.
**Trust Root**: Genesis block hash (must be obtained from trusted source)

## 🏗️ Architecture: BVN vs DN

### Why Paul Snow Said "Prove Account State is in the DN"
Paul Snow's statement is correct because:
1. **DN is authoritative** - Account states only become final when anchored in DN
2. **DN includes all BVN states** - Through the anchoring mechanism
3. **DN validators provide consensus** - Their signatures secure the entire network

### Why the Proof Can Abstract Away BVNs
1. **Mathematical Equivalence**: DN's BPT root includes BVN's BPT root via anchoring
2. **Security Equivalence**: DN validators signing = BVN state validated
3. **Implementation Simplicity**: One proof path instead of tracing through partitions
4. **Future Proof**: BVN architecture could change, DN remains authoritative

## 🚨 ACTIVE DEVELOPMENT: Production Proof Implementation

**Status**: 90% Complete - Layers 1-3 implemented and tested with real blockchain data
**Location**: `proof/production-proof/`
**Blocker**: API needs to expose consensus data for Layer 3-4 completion

### Quick Navigation
```
proof/
├── production-proof/           # ✅ ACTIVE - 90% complete implementation
│   ├── README.md              # Start here for production proof
│   ├── verification.go        # Core Layer 1-2 verification
│   ├── layer3_working_verification.go  # Layer 3 consensus
│   └── breakthrough_proof_test.go      # Real validator signatures!
├── README.md                  # Proof system overview
└── proof.go                   # Integration with lite client
```

## 📚 Complete Documentation Reference

### Primary Technical Documentation
- **[docs/README.md](docs/README.md)** - Documentation index and navigation
- **[docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md](docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md)** - Complete architecture analysis
- **[docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md)** - Deep analysis of all proof strategies
- **[docs/proof/GROUND_TRUTH.md](docs/proof/GROUND_TRUTH.md)** - Definitive cryptographic proof specification
- **[docs/proof/IMPLEMENTATION_PATH.md](docs/proof/IMPLEMENTATION_PATH.md)** - Roadmap to trustless verification
- **[docs/proof/PROOF_KNOWLEDGE_CONSOLIDATED.md](docs/proof/PROOF_KNOWLEDGE_CONSOLIDATED.md)** - Consolidated proof knowledge
- **[docs/proof/BREAKTHROUGH_BPT_PROOFS_WORKING.md](docs/proof/BREAKTHROUGH_BPT_PROOFS_WORKING.md)** - BPT proof breakthrough documentation

### Production Proof Documentation
- **[proof/production-proof/README.md](proof/production-proof/README.md)** - Production implementation guide
- **[proof/production-proof/LAYER3_BREAKTHROUGH.md](proof/production-proof/LAYER3_BREAKTHROUGH.md)** - Consensus verification breakthrough
- **[proof/production-proof/COMPLETE_IMPLEMENTATION_SUMMARY.md](proof/production-proof/COMPLETE_IMPLEMENTATION_SUMMARY.md)** - Implementation summary

### Canonical BPT Documentation
- **[new_documentation/docs/bpt-complete-guide.md](new_documentation/docs/bpt-complete-guide.md)** - Paul Snow's BPT specification
- **[new_documentation/docs/README.md](new_documentation/docs/README.md)** - BPT documentation index

### Reference Material
- **[docs/Accumulate-Whitepaper.pdf](docs/Accumulate-Whitepaper.pdf)** - Official Accumulate whitepaper

## Current Repository Structure

```
liteclient/
├── api/                       # Public API interface
├── backend/                   # Data retrieval backends (v2/v3)
├── cache/                     # LRU caching layer
├── cmd/                       # Command-line tools
│   ├── test-devnet/          # Test devnet proofs
│   ├── test-accounts/        # Test account verification
│   └── verify-bpt/           # Verify BPT proofs
├── core/                      # Core orchestration (LiteClient)
├── docs/                      # All documentation
│   ├── technical/            # Architecture documentation
│   └── proof/                # Proof system documentation
├── proof/                     # Proof implementation
│   ├── production-proof/     # ✅ Active implementation (90% complete)
│   └── archive/              # Historical implementations
├── types/                     # Type definitions
├── verifier/                  # Trustless verification engine
└── visualizer/               # Next.js UI (optional)
```

## Development Workflow

### For Every Development Session

1. **Check Status**: Review [proof/production-proof/README.md](proof/production-proof/README.md#current-status)
2. **Understand Architecture**: See [docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md](docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md)
3. **Follow Proof Layers**: Reference [docs/proof/GROUND_TRUTH.md](docs/proof/GROUND_TRUTH.md)
4. **Test with Real Data**: Use devnet/testnet/mainnet - NO MOCKS
5. **Update Documentation**: Keep all docs current

## Build and Test Commands

```bash
# Build core packages
go build ./api ./core ./types ./verifier ./proof

# Test production proof (MAIN FOCUS)
go test -v ./proof/production-proof/

# Test specific breakthrough
go test -v -run TestBreakthroughValidatorSignature ./proof/production-proof/

# Integration testing
./cmd/test-devnet/test-devnet -endpoint "http://localhost:26660" -account "acc://alice/tokens"

# Verify BPT proofs
./cmd/verify-bpt/verify-bpt -account "acc://alice/tokens"
```

## Key Development Principles

1. **Real Data Only**: No mocks, fakes, or placeholders
2. **Clean Architecture**: Follow patterns in [docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md](docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md#architecture-strengths)
3. **Cryptographic Rigor**: Mathematical proofs per [docs/proof/GROUND_TRUTH.md](docs/proof/GROUND_TRUTH.md)
4. **Production Ready**: Error handling, logging, metrics
5. **Documentation**: Update docs with every change

## Current Implementation Status

### ✅ What's Working (90% Complete)

#### Layer 1: Account State → BPT Root
- **Status**: 100% verified with real blockchain data
- **Code**: `proof/production-proof/verification.go`
- **Docs**: [docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md#layer-1-account-state--bpt-root--100-complete)

#### Layer 2: BPT Root → Block Hash
- **Status**: 100% verified with real blockchain data
- **Code**: `proof/production-proof/verification.go`
- **Docs**: [docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md#layer-2-bpt-root--block-hash--100-complete)

#### Layer 3: Block Hash → Validator Signatures
- **Status**: 90% implemented, tested with real signatures
- **Code**: `proof/production-proof/layer3_working_verification.go`
- **Breakthrough**: See `proof/production-proof/breakthrough_proof_test.go`
- **Docs**: [proof/production-proof/LAYER3_BREAKTHROUGH.md](proof/production-proof/LAYER3_BREAKTHROUGH.md)

### ⏳ What's Blocked (10% Remaining)

#### Layer 4: Validators → Genesis Trust
- **Status**: Design complete, awaiting Layer 3 API data
- **Blocker**: Validator set transitions not exposed
- **Docs**: [docs/proof/IMPLEMENTATION_PATH.md](docs/proof/IMPLEMENTATION_PATH.md)

## Integration Points

### Where Accumulate API Changes Needed
Location: `../../GitLabRepo/accumulate/pkg/api/v3/`

Required endpoints:
1. **ConsensusProofQuery**: Validator signatures for blocks
2. **ValidatorSetQuery**: Validator public keys and voting power
3. **ValidatorTransitionQuery**: Historical validator changes

See [docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md#critical-missing-api-endpoints) for details.

## Success Metrics

### Current Capability
```bash
# This works RIGHT NOW
./cmd/verify-bpt/verify-bpt -account acc://alice/tokens
✅ Layers 1-2 cryptographically verified
```

### Target Capability (Blocked on API)
```bash
# This will work when API exposes consensus data
./cmd/verify-bpt/verify-bpt -account acc://alice/tokens --trustless
✅ Account cryptographically verified from genesis (zero trust)
```

## Quick Reference for Common Tasks

### Understanding the Proof System
1. Start with [docs/proof/GROUND_TRUTH.md](docs/proof/GROUND_TRUTH.md) for theory
2. Review [docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md) for implementation
3. Check [proof/production-proof/README.md](proof/production-proof/README.md) for current status

### Working with Production Proof
1. Main code: `proof/production-proof/verification.go`
2. Integration: `proof/proof.go`
3. Tests: `proof/production-proof/*_test.go`

### Architecture Questions
1. Overall design: [docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md](docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md)
2. Proof layers: [docs/proof/PROOF_STRATEGIES_ANALYSIS.md](docs/proof/PROOF_STRATEGIES_ANALYSIS.md#cryptographic-proof-layers-analysis)
3. API integration: [docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md](docs/technical/LITECLIENT_DEEP_ARCHITECTURE_ANALYSIS.md#api--networking-layer)

## Important Notes

- **Archive**: Historical implementations in `proof/archive/` are for reference only
- **No Mocks**: The `nomocks.go` file enforces no mock usage
- **Production Focus**: All new work goes in `proof/production-proof/`
- **Documentation First**: Update docs before and after implementation

---
**Current Focus**: Complete Layer 3-4 integration once API data is available
**Status**: 90% complete, production-ready for Layers 1-2
**Timeline**: 2-3 days to 100% once API provides consensus data