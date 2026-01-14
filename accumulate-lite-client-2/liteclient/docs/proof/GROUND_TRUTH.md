# Ground Truth: Accumulate Cryptographic Account State Proofs

## Definition of Complete Cryptographic Proof

A complete cryptographic proof of account state allows independent verification without trusting any intermediary. It consists of five essential components that chain together to prove an account's state is legitimate and consensus-approved.

## The Five Components of Complete Proof

### Component 1: Account State Hash
The account state is deterministically hashed from four sub-components:
```
AccountStateHash = MerkleHash(
    MainState,      // Protocol-defined account object
    SecondaryState, // Directory URLs and events
    Chains,         // All transaction chain merkle roots
    Pending         // Pending transaction hashes
)
```

### Component 2: BPT (Binary Patricia Tree) Inclusion
The account state hash must be proven to exist in the BPT:
- BPT stores account URL → state hash mappings
- Merkle proof from account entry to BPT root
- BPT root represents all accounts in a partition

### Component 3: Block Commitment
The BPT root must be committed in a block:
- Block contains BPT root hash
- Block header includes height, timestamp, previous hash
- Block is signed by validators

### Component 4: Cross-Partition Anchoring
Partition blocks anchor to the Directory Network:
- BVN produces anchor containing its state root
- Anchor is submitted to Directory Network
- DN acknowledges and includes anchor in its chain

### Component 5: Consensus Verification
Validator signatures prove legitimate consensus:
- Block must have 2/3+ validator signatures
- Validators must be from the active validator set
- Signatures must be cryptographically valid

## Proof Verification Flow

```
1. Compute account state hash from components
2. Verify state hash matches BPT entry via merkle proof
3. Verify BPT root is in block via inclusion proof
4. Verify block is anchored to DN via anchor chain
5. Verify validators signed block via signature validation
```

## Data Structures Required

### Account State Receipt
```go
type AccountReceipt struct {
    AccountHash    [32]byte        // Computed state hash
    BPTProof       []MerkleEntry   // Proof to BPT root
    BPTRoot        [32]byte        // BPT root at block
}
```

### Block Receipt
```go
type BlockReceipt struct {
    BlockHeight    uint64          // Block number
    BlockTime      time.Time       // Block timestamp
    BPTRoot        [32]byte        // BPT root in block
    BlockHash      [32]byte        // Block header hash
}
```

### Anchor Receipt
```go
type AnchorReceipt struct {
    SourceBlock    uint64          // BVN block that created anchor
    AnchorHash     [32]byte        // Anchor transaction hash
    DNBlock        uint64          // DN block containing anchor
    Proof          []MerkleEntry   // Proof of inclusion in DN
}
```

### Consensus Receipt
```go
type ConsensusReceipt struct {
    ValidatorSet   []Validator     // Active validators at height
    Signatures     []Signature     // Validator signatures
    VotingPower    uint64          // Total voting power
    SignedPower    uint64          // Power that signed (must be >2/3)
}
```

## Implementation Requirements

### Required API Methods

1. **Account State Query**
   - Returns account with all components
   - Includes merkle state for hash verification

2. **BPT Proof Generation**
   - Returns merkle proof from account to BPT root
   - Must handle both direct entries and KeyHash entries

3. **Block Query**
   - Returns block header with BPT root
   - Includes block metadata (height, time, hash)

4. **Anchor Chain Query**
   - Returns anchor entries from partition chains
   - Includes merkle proofs of anchor inclusion

5. **Validator Set Query**
   - Returns active validators at specific height
   - Includes voting power distribution

### Cryptographic Primitives

1. **SHA-256**: Primary hash function
2. **Ed25519**: Validator signatures
3. **Merkle Trees**: Proof construction
4. **Binary Patricia Tree**: Account organization

## Proof Combination

Complete proof requires combining multiple receipts:

```go
func CombineProofs(
    account AccountReceipt,
    block BlockReceipt,
    anchor AnchorReceipt,
    consensus ConsensusReceipt,
) (CompleteProof, error) {
    // Verify account → BPT
    if !VerifyMerkleProof(account.AccountHash, account.BPTProof, account.BPTRoot) {
        return nil, ErrInvalidAccountProof
    }
    
    // Verify BPT → Block
    if account.BPTRoot != block.BPTRoot {
        return nil, ErrBPTRootMismatch
    }
    
    // Verify Block → Anchor
    if block.BlockHeight != anchor.SourceBlock {
        return nil, ErrBlockAnchorMismatch
    }
    
    // Verify Consensus
    if consensus.SignedPower <= consensus.VotingPower*2/3 {
        return nil, ErrInsufficientSignatures
    }
    
    return CompleteProof{...}, nil
}
```

## Trust Model

The complete proof eliminates trust requirements:
- No trust in API servers (proofs are self-verifying)
- No trust in individual validators (requires 2/3+ consensus)
- No trust in timestamps (proven via consensus)
- Mathematical certainty via cryptographic verification

## Storage Requirements

For a complete proof:
- Account data: ~1-10 KB
- Merkle proofs: ~1-2 KB per proof
- Block headers: ~500 bytes
- Validator signatures: ~100 bytes per validator
- **Total**: ~5-15 KB for complete proof

## Performance Characteristics

- Proof generation: O(log n) for n accounts
- Proof verification: O(m) for m proof steps
- Storage: O(1) per account (constant size)
- Network: Single round-trip per component

---

*This document represents the ground truth of what constitutes a complete cryptographic proof in Accumulate. It is derived from the protocol implementation and Paul Snow's canonical BPT documentation.*