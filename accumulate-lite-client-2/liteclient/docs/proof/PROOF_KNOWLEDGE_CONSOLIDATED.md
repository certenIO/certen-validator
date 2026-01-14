# Cryptographic Proof Architecture

## Canonical References
- **[GROUND_TRUTH.md](GROUND_TRUTH.md)** - Complete proof components
- **[IMPLEMENTATION_PATH.md](IMPLEMENTATION_PATH.md)** - Implementation roadmap
- **Paul's BPT Documentation**: `/new_documentation/docs/`

## Core Proof Path: Account → BPT → Block → Anchor → Consensus

### The Essential Formula
Every cryptographic proof follows this path:
1. **Account State** - Prove the account exists with specific state
2. **BVN (Block Validator Network)** - Prove the BVN acknowledges the account
3. **DN (Directory Network)** - Prove consensus across the network

## BPT (Binary Patricia Tree) - The Foundation

### What It Is
- **Dual-purpose structure**: Validation tree AND database index
- **Keys**: Database paths to account records
- **Values**: Hashes that also serve as database keys
- **Purpose**: Prove complete state with a single root hash

### The Four Components (ALWAYS)
```
BPT_Value = MerkleHash(
    Component1: SimpleHash(Main State),      // Account data
    Component2: MerkleHash(Secondary State), // Directory + Events  
    Component3: MerkleHash(Chains),         // Transaction history
    Component4: MerkleHash(Pending)         // Pending transactions
)
```

### Critical Insight
The BPT doesn't store data - it references it. The hash IS a database key for lookups.

## Implementation Steps (Mini Steps)

## The Five Proof Components

### 1. Account State Hash
```go
AccountStateHash = MerkleHash(
    MainState,      // Account protocol object
    SecondaryState, // Directory and events
    Chains,         // Transaction chain roots
    Pending         // Pending transactions
)
```

### 2. BPT Inclusion Proof
```go
// Merkle proof from account to BPT root
bptProof := account.BptReceipt()
VerifyMerkleProof(accountHash, bptProof, bptRoot)
```

### 3. Block Commitment
```go
// BPT root included in block
block := GetBlock(height)
Verify(block.BPTRoot == bptRoot)
```

### 4. Cross-Partition Anchoring
```go
// BVN anchors to Directory Network
anchor := GetAnchor(block.AnchorHash)
Verify(anchor.SourceBlock == block.Height)
```

### 5. Consensus Verification
```go
// Validator signatures prove consensus
validators := GetValidators(height)
VerifySignatures(block, validators, signatures)
```

## Account Types & BPT Representation

### ADI (Accumulate Digital Identity)
- Main: ADI{Url, Authorities}
- Secondary: Directory of sub-accounts (**important**)
- Chains: ADI transaction history
- Pending: Multi-sig transactions

### Token Account
- Main: TokenAccount{Balance, TokenUrl, Authorities}
- Secondary: Empty (no sub-accounts)
- Chains: Token transfer history
- Pending: Pending transfers

### Key Page
- Main: KeyPage{Keys, CreditBalance, Thresholds}
- Secondary: Empty
- Chains: Key update history
- Pending: References parent KeyBook

## Working Code Locations

### Core Implementation
- `/api/` - API client (working)
- `/core/` - Core types (working)
- `/types/` - Type definitions (working)
- `/proof/crystal/` - Crystal proof implementation (Step 1 working)

### Test Commands
```bash
# Step 1 - Mainnet
./crystal-step1.exe -account "acc://RenatoDAP.acme"
# Expected: BPT hash 92b6ccf2b1fbd2d96f69df1a2f6b17fad8b07b9c3fe5971784f4726cdb9f1346

# Full proof - Devnet (observer enabled)
./test-devnet.exe -endpoint "http://localhost:26660" -account "acc://dn.acme"
```

## Implementation Status

### Currently Implemented
1. **Account state hashing** via `DidChangeAccount` observer
2. **BPT structure** in `pkg/database/bpt/`
3. **Merkle proof generation** via `BptReceipt()`
4. **Receipt validation** in `pkg/database/merkle/`

### Required API Extensions
1. **BPT proof inclusion** in account queries
2. **Block header access** with BPT roots
3. **Anchor chain queries** for cross-partition proofs
4. **Validator set access** for consensus verification

## Architectural Issues (From Paul's Review)

### Current Flaw
Large collections (directories, pending, authorities) stored in state rather than chains:
- Hard limit: 100-1000 accounts per ADI
- O(n) performance for n sub-accounts
- Memory pressure from loading entire collections

### Solution
Automatic migration to chain-based storage:
- No network downtime
- Transparent migration on modification
- 15,000x performance improvement

## Development Approach

### Phase 1: API Extensions (Weeks 1-2)
- Extend `queryAccount` with BPT proofs
- Implement chain query methods
- Expose validator information

### Phase 2: Lite Client (Weeks 3-4)
- Implement proof assembler
- Build complete verifier
- Create test infrastructure

### Phase 3: Integration (Weeks 5-6)
- End-to-end testing
- Performance optimization
- Security audit

### Phase 4: Production (Weeks 7-8)
- Deploy to testnet
- Monitor and optimize
- Mainnet deployment

## Success Criteria

Complete cryptographic proof enables:
1. Independent verification without trust
2. Mathematical certainty via cryptography
3. Consensus validation via signatures
4. Tamper-proof account state
5. Cross-partition integrity

---

**Reference**: See GROUND_TRUTH.md for complete specification