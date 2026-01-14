# Accumulate Lite Client

A lightweight client implementation for generating and verifying cryptographic proofs of account state on the Accumulate network.

## Core Documentation

- **[GROUND_TRUTH.md](GROUND_TRUTH.md)** - Definitive specification of cryptographic proof components
- **[IMPLEMENTATION_PATH.md](IMPLEMENTATION_PATH.md)** - Roadmap for achieving complete proofs
- **[new_documentation/docs/](new_documentation/docs/)** - Paul Snow's canonical BPT documentation

## Quick Start

```bash
# Build core packages
go build ./api ./core ./types ./verifier

# Build proof implementation
go build ./proof/crystal/...

# Test account state hashing
go build -o crystal-step1 ./cmd/crystal-step1
./crystal-step1 -account "acc://RenatoDAP.acme"

# Test with devnet (observer mode required)
go build -o test-devnet ./cmd/test-devnet
./test-devnet -endpoint "http://localhost:26660" -account "acc://dn.acme"
```

## Architecture

The lite client implements cryptographic proof generation following the chain:

```
Account State → BPT → Block → Anchor → Consensus
```

Each step provides mathematical proof linking to the next, creating an unbreakable chain of trust from individual account state to network consensus.

## Project Structure

```
├── api/                    # API client for Accumulate network
├── core/                   # Core lite client logic
├── types/                  # Type definitions and parsers
├── verifier/              # Proof verification logic
├── proof/
│   ├── crystal/           # Crystal proof implementation
│   └── devnet/            # Devnet testing utilities
├── cmd/                   # Command-line tools
└── new_documentation/     # Paul Snow's BPT documentation
```

## Development Principles

1. **Ground Truth**: Follow protocol implementation, not assumptions
2. **No Workarounds**: Fix issues at the source, not with hacks
3. **Cryptographic Integrity**: Every claim must be mathematically provable
4. **Complete Verification**: Enable trustless verification of any account

## Implementation Phases

### Phase 1: API Extensions
Extend Accumulate core API to provide necessary proof components

### Phase 2: Client Implementation
Build proof assembly and verification logic

### Phase 3: Integration Testing
Comprehensive testing on devnet and testnet

### Phase 4: Production Deployment
Release for mainnet with full cryptographic proof support

## Contributing

See [IMPLEMENTATION_PATH.md](IMPLEMENTATION_PATH.md) for detailed development roadmap.

## License

MIT