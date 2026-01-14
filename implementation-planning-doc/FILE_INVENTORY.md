# Certen Independent Validator - Complete File Inventory

This document lists every file that must be copied from the reference implementation to create an independent validator.

**Source:** `C:\Accumulate_Stuff\certen\certen-protocol\services\validator`
**Target:** `C:\Accumulate_Stuff\certen\independant_validator`

---

## Root Files

| File | Purpose | Priority |
|------|---------|----------|
| `main.go` | Entry point, component initialization | Critical |
| `go.mod` | Go module definition | Critical |
| `go.sum` | Dependency checksums | Critical |
| `Dockerfile` | Production container build | Critical |
| `Dockerfile.dev` | Development build | Optional |
| `.env.example` | Environment template | Critical |

---

## cmd/ - Command Line Tools

### cmd/bls-zk-setup/
| File | Purpose |
|------|---------|
| `main.go` | BLS ZK proving key generator (Groth16 trusted setup) |

### cmd/generate-vk/
| File | Purpose |
|------|---------|
| `main.go` | Verification key generator |

---

## accumulate-lite-client-2/ - Accumulate Integration

### accumulate-lite-client-2/liteclient/api/
| File | Purpose |
|------|---------|
| `client.go` | Accumulate API client |
| `types.go` | API type definitions |
| `*.go` | Additional API files |

### accumulate-lite-client-2/liteclient/proof/
| File | Purpose |
|------|---------|
| `proof.go` | Proof construction |
| `types.go` | Proof types |
| `*.go` | Additional proof files |

### accumulate-lite-client-2/liteclient/proof/consolidated_governance-proof/
| File | Purpose |
|------|---------|
| `main.go` | G0/G1/G2 governance proof CLI tool (govproof) |

### accumulate-lite-client-2/liteclient/cmd/txhash/
| File | Purpose |
|------|---------|
| `main.go` | Canonical transaction hash tool |

---

## pkg/accumulate/ - Accumulate Network Integration

| File | Lines | Purpose |
|------|-------|---------|
| `accumulate_client.go` | ~200 | Client interface definition |
| `liteclient_adapter.go` | ~200 | LiteClientAdapter implementation |

---

## pkg/anchor/ - Anchor Proof Management

| File | Lines | Purpose |
|------|-------|---------|
| `anchor_manager.go` | ~200 | Core AnchorManager lifecycle |
| `event_watcher.go` | ~150 | Contract event monitoring |
| `proof_converter.go` | ~100 | Proof format conversion |
| `scheduler.go` | ~150 | Anchor scheduling |

---

## pkg/anchor_proof/ - Cryptographic Proof Handling

| File | Lines | Purpose |
|------|-------|---------|
| `builder.go` | ~200 | Proof builder |
| `export.go` | ~100 | Proof export/serialization |
| `signer.go` | ~150 | Proof signing with validator keys |
| `types.go` | ~100 | Type definitions |
| `verifier.go` | ~250 | Proof verification |

---

## pkg/attestation/ - Multi-Validator Attestation

| File | Lines | Purpose |
|------|-------|---------|
| `service.go` | ~200 | Attestation service coordination |

---

## pkg/batch/ - Batch Processing & Consensus

| File | Lines | Purpose |
|------|-------|---------|
| `anchor_adapter.go` | ~100 | Bridge to AnchorManager |
| `anchor_manager_wrapper.go` | ~100 | Wrapper for batch interface |
| `attestation_broadcaster.go` | ~200 | Broadcast attestations to peers |
| `bpt_extractor.go` | ~100 | BPT root extraction |
| `collector.go` | ~300 | Transaction batching (on-cadence/on-demand) |
| `confirmation_tracker.go` | ~150 | Anchor finality tracking |
| `consensus_coordinator.go` | ~400 | Multi-validator coordination |
| `cost_tracker.go` | ~100 | Gas cost tracking |
| `errors.go` | ~50 | Error definitions |
| `on_demand.go` | ~200 | Immediate anchoring path |
| `peer_manager.go` | ~200 | Validator peer management |
| `processor.go` | ~500 | Core batch processing |
| `proof_helpers.go` | ~100 | Proof utility functions |
| `scheduler.go` | ~150 | ~15 min batch scheduler |

---

## pkg/commitment/ - Commitment Proofs

| File | Lines | Purpose |
|------|-------|---------|
| `commitment.go` | ~150 | RFC8785 canonical JSON commitment |

---

## pkg/config/ - Configuration Management

| File | Lines | Purpose |
|------|-------|---------|
| `anchor_config.go` | ~100 | Anchor-specific configuration |
| `config.go` | ~200 | Main config loader from environment |

---

## pkg/consensus/ - CometBFT Integration

| File | Lines | Purpose |
|------|-------|---------|
| `abci_validator.go` | ~500 | ABCI application (ValidatorApp) |
| `bft_integration.go` | ~600 | BFTValidator core implementation |
| `intent.go` | ~100 | Intent types for consensus |
| `types.go` | ~150 | Consensus type definitions |
| `validator_block.go` | ~300 | ValidatorBlock structure |
| `validator_block_builder.go` | ~400 | Build ValidatorBlock from intent |
| `validator_block_invariants.go` | ~100 | Block validation rules |

---

## pkg/crypto/ - Cryptography

### pkg/crypto/bls/
| File | Lines | Purpose |
|------|-------|---------|
| `bls.go` | ~300 | Core BLS12-381 operations |
| `key_manager.go` | ~150 | Key generation and management |

### pkg/crypto/bls_zkp/
| File | Lines | Purpose |
|------|-------|---------|
| `circuit.go` | ~200 | Groth16 circuit definition |
| `prover.go` | ~150 | ZK prover |
| `setup.go` | ~100 | Trusted setup |

---

## pkg/database/ - PostgreSQL Persistence

| File | Lines | Purpose |
|------|-------|---------|
| `client.go` | ~200 | Database client with connection pooling |
| `errors.go` | ~50 | Error definitions |
| `proof_artifact_repository.go` | ~200 | Proof artifact storage |
| `proof_artifact_types.go` | ~100 | Proof artifact types |
| `repositories.go` | ~100 | Repository factory |
| `repository_anchor.go` | ~150 | Anchor repository |
| `repository_attestation.go` | ~150 | Attestation repository |
| `repository_batch.go` | ~200 | Batch repository |
| `repository_proof.go` | ~150 | Proof repository |
| `repository_request.go` | ~100 | Request repository |
| `types.go` | ~100 | Database types |

### pkg/database/migrations/
| File | Lines | Purpose |
|------|-------|---------|
| `001_initial_schema.sql` | ~300 | Initial database schema |

---

## pkg/ethereum/ - Ethereum Integration

| File | Lines | Purpose |
|------|-------|---------|
| `client.go` | ~200 | Ethereum RPC client |

---

## pkg/execution/ - Transaction Execution

| File | Lines | Purpose |
|------|-------|---------|
| `accumulate_submitter.go` | ~150 | Write-back to Accumulate |
| `bft_target_chain_integration.go` | ~200 | BFT target chain integration |
| `commitment_builder.go` | ~150 | Commitment construction |
| `credit_checker.go` | ~100 | Credit balance checking |
| `cross_contract_verification.go` | ~150 | Cross-contract calls |
| `errors.go` | ~50 | Error definitions |
| `ethereum_contracts.go` | ~300 | Contract interaction |
| `executor.go` | ~400 | Execution orchestrator |
| `external_chain_observer.go` | ~200 | Monitor external chains |
| `external_chain_result.go` | ~100 | Execution results |
| `g2_outcome_binding.go` | ~200 | G2 outcome binding |
| `g2_validator_block_integration.go` | ~150 | G2 integration |
| `nonce_tracker.go` | ~100 | Transaction nonce tracking |
| `proof_cycle_orchestrator.go` | ~300 | Proof cycle management |
| `result_attestation.go` | ~150 | Result attestation |
| `synthetic_transaction.go` | ~100 | Synthetic tx generation |

### pkg/execution/contracts/
| File | Lines | Purpose |
|------|-------|---------|
| `account_v2.go` | ~200 | AccountV2 ABI bindings |
| `anchor_v2.go` | ~200 | AnchorV2 ABI bindings |
| `anchor_v2_extended.go` | ~150 | Extended ABI |
| `anchor_v3.go` | ~250 | AnchorV3 ABI bindings |
| `anchor_v3_generated.go` | ~500 | Generated contract bindings |

---

## pkg/intent/ - Intent Tracking

| File | Lines | Purpose |
|------|-------|---------|
| `conversion.go` | ~150 | Intent format conversion |
| `discovery.go` | ~300 | Block monitoring for CERTEN_INTENT |
| `intent_model_alias.go` | ~50 | Intent model aliases |

---

## pkg/kvdb/ - Key-Value Database

| File | Lines | Purpose |
|------|-------|---------|
| `adapter.go` | ~100 | KV interface adapter |

---

## pkg/ledger/ - Ledger Storage

| File | Lines | Purpose |
|------|-------|---------|
| `errors.go` | ~50 | Error definitions |
| `store.go` | ~200 | LedgerStore implementation |
| `types.go` | ~150 | Ledger types (SystemLedger, AnchorLedger) |

---

## pkg/merkle/ - Merkle Tree

| File | Lines | Purpose |
|------|-------|---------|
| `receipt.go` | ~150 | Merkle receipt handling |
| `tree.go` | ~150 | Merkle tree construction |

---

## pkg/proof/ - Proof Generation

| File | Lines | Purpose |
|------|-------|---------|
| `artifact_service.go` | ~600 | ProofArtifactService orchestrator |
| `attestation.go` | ~150 | Attestation proofs |
| `batch_adapter.go` | ~100 | Batch proof adapter |
| `bundle_format.go` | ~150 | Proof bundle format |
| `canonical_blob_hash.go` | ~100 | Canonical hashing |
| `certen_proof.go` | ~200 | CertenProof type definition |
| `governance_adapter.go` | ~150 | Governance proof adapter |
| `governance_library.go` | ~200 | Governance proof library |
| `governance_types.go` | ~100 | Governance types |
| `lifecycle.go` | ~150 | Proof lifecycle management |
| `liteclient_proof_generator.go` | ~400 | L1-L3 proof generator |
| `proof_request_types.go` | ~100 | Request type definitions |

---

## pkg/server/ - HTTP API Server

| File | Lines | Purpose |
|------|-------|---------|
| `attestation_handlers.go` | ~200 | Attestation endpoints |
| `batch_handlers.go` | ~200 | Batch endpoints |
| `bulk_handlers.go` | ~150 | Bulk operation endpoints |
| `bundle_handlers.go` | ~150 | Bundle endpoints |
| `ledger_handlers.go` | ~150 | Ledger endpoints |
| `proof_handlers.go` | ~350 | Proof query endpoints |

---

## pkg/verification/ - Verification Engine

| File | Lines | Purpose |
|------|-------|---------|
| `unified_verifier.go` | ~400 | UnifiedVerifier for all proof types |
| `merkle_verifier.go` | ~150 | Merkle verification |
| `governance_verifier.go` | ~200 | Governance verification |
| `bls_verifier.go` | ~150 | BLS signature verification |

---

## contracts/ - Solidity Contract References

| File | Purpose |
|------|---------|
| `BLSZKVerifier.sol` | BLS ZK proof verification contract |
| `CertenAnchorV3.sol` | Unified anchor contract |
| `CertenCrossContractVerification.sol` | Cross-contract verification |
| `CertenAnchorV2.abi.json` | AnchorV2 ABI |
| `CertenAccountV2.abi.json` | AccountV2 ABI |

---

## Summary Statistics

| Category | File Count | Approximate Lines |
|----------|------------|-------------------|
| Root | 6 | 1,500 |
| cmd/ | 2 | 200 |
| accumulate-lite-client-2/ | ~20 | 3,000 |
| pkg/accumulate | 2 | 400 |
| pkg/anchor | 4 | 600 |
| pkg/anchor_proof | 5 | 800 |
| pkg/attestation | 1 | 200 |
| pkg/batch | 14 | 2,500 |
| pkg/commitment | 1 | 150 |
| pkg/config | 2 | 300 |
| pkg/consensus | 7 | 1,800 |
| pkg/crypto | 5 | 750 |
| pkg/database | 12 | 1,500 |
| pkg/ethereum | 1 | 200 |
| pkg/execution | 17 | 3,000 |
| pkg/intent | 3 | 500 |
| pkg/kvdb | 1 | 100 |
| pkg/ledger | 3 | 400 |
| pkg/merkle | 2 | 300 |
| pkg/proof | ~15 | 2,500 |
| pkg/server | 6 | 1,200 |
| pkg/verification | ~4 | 900 |
| contracts/ | 5 | N/A |
| **TOTAL** | **~130** | **~23,000** |

---

## Copy Commands

```bash
# Create directory structure
mkdir -p independant_validator/{cmd/{bls-zk-setup,generate-vk},accumulate-lite-client-2,pkg/{accumulate,anchor,anchor_proof,attestation,batch,commitment,config,consensus,crypto/{bls,bls_zkp},database/migrations,ethereum,execution/contracts,intent,kvdb,ledger,merkle,proof,server,verification},contracts,bls_zk_keys}

# Copy from reference implementation
# Replace $SRC with: C:\Accumulate_Stuff\certen\certen-protocol\services\validator

cp $SRC/main.go independant_validator/
cp $SRC/go.mod independant_validator/
cp $SRC/go.sum independant_validator/
cp $SRC/Dockerfile independant_validator/
cp $SRC/.env.example independant_validator/

# Copy each package...
cp -r $SRC/cmd/* independant_validator/cmd/
cp -r $SRC/accumulate-lite-client-2/* independant_validator/accumulate-lite-client-2/
cp -r $SRC/pkg/* independant_validator/pkg/

# Note: Contracts are reference only - deployed contracts already exist on-chain
```
